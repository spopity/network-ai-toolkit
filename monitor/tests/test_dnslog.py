"""AdGuardHome query log archive: cursor paging, hidden domains, advance-only-after-success."""
import json
from datetime import UTC, datetime

import pytest

from router_agent import db, dnslog
from router_agent.dnslog import (
    AdGuardClient,
    DnsLog,
    aggregate,
    is_hidden,
    parse_ns,
    summarize,
)

from .conftest import FakeNamer

MAC = "02:00:00:00:00:01"


def test_parse_ns_handles_trimmed_fractions_and_offsets():
    assert parse_ns("2026-11-14T09:00:00Z") == int(datetime(2026, 11, 14, 9, tzinfo=UTC).timestamp()) * 10**9
    assert parse_ns("2026-11-14T09:00:00.5Z") % 10**9 == 500_000_000
    assert parse_ns("2026-11-14T09:00:00.123456789Z") % 10**9 == 123_456_789
    assert parse_ns("2026-11-14T10:00:00+01:00") == parse_ns("2026-11-14T09:00:00Z")
    with pytest.raises(ValueError):
        parse_ns("yesterday")


@pytest.mark.parametrize(("domain", "hidden"), [
    ("secret.example", True),
    ("www.secret.example", True),
    ("notsecret.example", False),
    ("secret.example.org", False),
])
def test_is_hidden_matches_domain_and_subdomains_only(domain, hidden):
    assert is_hidden(domain, ["secret.example"]) is hidden


def _entry(ts: str, name: str, client: str = "192.0.2.10", reason: str = "NotFilteredNotFound", **extra) -> dict:
    e = {"time": ts, "client": client, "question": {"name": name, "type": "A"}, "reason": reason, **extra}
    e["_ns"] = parse_ns(ts)
    return e


def test_aggregate_drops_hidden_domains_before_archiving():
    entries = [
        _entry("2026-11-14T09:00:00Z", "Secret.Example."),        # case + trailing dot
        _entry("2026-11-14T09:00:01Z", "cdn.secret.example"),     # subdomain
        _entry("2026-11-14T09:00:02Z", "ok.example"),
    ]
    rows = aggregate(entries, FakeNamer(), hidden=["secret.example."])
    assert [r["domain"] for r in rows] == ["ok.example"]


def test_aggregate_groups_per_hour_device_domain_and_blocked():
    namer = FakeNamer({"192.0.2.10": MAC}, {MAC: "Camera"})
    entries = [
        _entry("2026-11-14T09:00:00Z", "a.example"),
        _entry("2026-11-14T09:59:59Z", "a.example"),
        _entry("2026-11-14T10:00:00Z", "a.example"),
        _entry("2026-11-14T09:10:00Z", "ads.example", reason="FilteredBlackList",
               rules=[{"text": "||ads.example^"}]),
        _entry("2026-11-14T09:20:00Z", "a.example", client="192.0.2.99"),
    ]
    rows = {(r["hour"].hour, r["device_key"], r["domain"], r["blocked"]): r for r in aggregate(entries, namer)}
    nine = rows[(9, MAC, "a.example", False)]
    assert nine["count"] == 2 and nine["device"] == "Camera"
    assert nine["first_seen"] < nine["last_seen"]
    assert rows[(10, MAC, "a.example", False)]["count"] == 1
    blocked = rows[(9, MAC, "ads.example", True)]
    assert blocked["rule"] == "||ads.example^"
    assert rows[(9, "ip:192.0.2.99", "a.example", False)]["mac"] is None


def test_summarize_totals_per_network():
    rows = [
        {"network": "IoT", "count": 3, "blocked": True, "domain": "ads.example", "device": "Cam"},
        {"network": "IoT", "count": 2, "blocked": False, "domain": "a.example", "device": "Cam"},
        {"network": "LAN", "count": 5, "blocked": False, "domain": "b.example", "device": "PC"},
    ]
    s = summarize(rows, new_domains=[])
    assert s["queries"] == 10 and s["blocked"] == 3
    assert s["by_network"]["IoT"] == {"queries": 5, "blocked": 3}
    assert s["top_blocked_domains"] == {"ads.example": 3}
    assert s["top_blocked_devices"] == {"Cam [IoT]": 3}


class FakeAdGuard(AdGuardClient):
    """Serves a fixed query log newest-first in pages, like /control/querylog."""

    def __init__(self, entries: list[dict], page: int = 2):
        super().__init__("http://agh.invalid", "u", "p")
        self.log = sorted(entries, key=lambda e: parse_ns(e["time"]), reverse=True)
        self.page = page

    def _get(self, path, **params):
        assert path == "querylog"
        start = 0
        if params.get("older_than"):
            start = next(i for i, e in enumerate(self.log) if e["time"] == params["older_than"]) + 1
        data = [{k: v for k, v in e.items() if k != "_ns"} for e in self.log[start:start + self.page]]
        return {"data": data, "oldest": data[-1]["time"] if data else ""}


def test_entries_since_pages_and_never_returns_an_entry_twice(monkeypatch):
    monkeypatch.setattr(dnslog, "PAGE", 2)
    log = [_entry(f"2026-11-14T09:00:0{i}Z", f"d{i}.example") for i in range(5)]
    agh = FakeAdGuard(log)
    cursor = {"ns": parse_ns("2026-11-14T08:00:00Z"), "keys": []}
    out, cur, truncated = agh.entries_since(cursor)
    assert [e["question"]["name"] for e in out] == [f"d{i}.example" for i in range(5)]  # oldest first
    assert not truncated
    assert agh.entries_since(cur) == ([], cur, False)

    # a new entry in the same nanosecond as the cursor is still picked up, once
    agh.log.insert(0, _entry("2026-11-14T09:00:04Z", "same-ns.example"))
    out, cur2, _ = agh.entries_since(cur)
    assert [e["question"]["name"] for e in out] == ["same-ns.example"]
    assert agh.entries_since(cur2)[0] == []


class StubClient:
    def __init__(self, entries, cursor):
        self.entries, self.cursor = entries, cursor

    def entries_since(self, cursor):
        return self.entries, self.cursor, False


def _dnslog(tmp_path, monkeypatch, entries, hide=()):
    dl = DnsLog(tmp_path, {"url": "http://agh.invalid", "hide_domains": list(hide)})
    monkeypatch.setattr(dl, "_client", lambda: StubClient(entries, {"ns": 42, "keys": ["k"]}))
    return dl


def test_collect_does_not_advance_cursor_when_archive_fails(tmp_path, monkeypatch):
    dl = _dnslog(tmp_path, monkeypatch, [_entry("2026-11-14T09:00:00Z", "a.example")])
    out = dl.collect({}, {})
    assert out["status"] == "archive_unavailable"
    assert not dl.cursor_path.exists()


def test_collect_advances_cursor_after_archive_and_never_archives_hidden(tmp_path, monkeypatch):
    archived = []
    monkeypatch.setattr(db, "insert_dns_rows", lambda rows, grace: archived.extend(rows) or [])
    entries = [_entry("2026-11-14T09:00:00Z", "a.example"), _entry("2026-11-14T09:00:01Z", "x.secret.example")]
    dl = _dnslog(tmp_path, monkeypatch, entries, hide=["secret.example"])
    out = dl.collect({}, {})
    assert out["entries"] == 2 and out["queries"] == 1
    assert [r["domain"] for r in archived] == ["a.example"]
    assert json.loads(dl.cursor_path.read_text()) == {"ns": 42, "keys": ["k"]}


def test_collect_reports_unreachable_adguard(tmp_path, monkeypatch):
    dl = DnsLog(tmp_path, {})
    monkeypatch.setattr(dl, "_client", lambda: type("C", (), {"entries_since": lambda self, c: 1 / 0})())
    assert dl.collect({}, {})["status"] == "adguard_unreachable"
    assert DnsLog(tmp_path, {}).collect({}, {}) is None  # not configured
