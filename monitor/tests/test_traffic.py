"""Traffic Analyzer archive: parsing, hidden apps, advance-only-after-success."""
import json
from datetime import UTC, datetime

import pytest

from router_agent import db, traffic
from router_agent.traffic import (
    TrafficLog,
    aggregate,
    bucket,
    parse,
    read_cmd,
    summarize,
)

from .conftest import FakeCollector, FakeNamer

MAC = "02:00:00:00:00:01"
TS = int(datetime(2026, 11, 14, 10, 20, tzinfo=UTC).timestamp())


def test_parse_skips_malformed_rows():
    out = f"1763115000\n{MAC.lower()}|YouTube|Media|{TS}|10|20\nbroken|row\nx|y|z|notanint|1|2\n{MAC}|||{TS}||5"
    now, rows = parse(out)
    assert now == 1763115000
    assert rows == [(MAC, "YouTube", "Media", TS, 10, 20), (MAC, "Unknown", "Unknown", TS, 0, 5)]


def test_parse_rejects_unexpected_output():
    with pytest.raises(ValueError):
        parse("sqlite3: not found")


def test_read_cmd_uses_cursor_and_settle_window():
    cmd = read_cmd(12345)
    assert "timestamp > 12345" in cmd and f"- {traffic.SETTLE_SECONDS}" in cmd


def test_bucket_files_a_write_under_the_hour_of_its_midpoint():
    assert bucket(TS) == datetime(2026, 11, 14, 9, tzinfo=UTC)  # 10:20 write covers ~09:20-10:20


def test_aggregate_sums_skips_zero_and_hidden_apps():
    namer = FakeNamer({"192.0.2.10": MAC}, {MAC: "TV"})
    rows = [
        (MAC, "YouTube", "Media", TS, 10, 100),
        (MAC, "YouTube", "Media", TS + 5, 1, 1),
        (MAC, "Secret App", "Other", TS, 50, 50),
        (MAC, "Idle", "Other", TS, 0, 0),
        ("02:00:00:00:00:99", "Steam", "Games", TS, 0, 7),
    ]
    out = {(r["mac"], r["app"]): r for r in aggregate(rows, namer, hidden_apps=["secret app"])}
    assert set(out) == {(MAC, "YouTube"), ("02:00:00:00:00:99", "Steam")}
    yt = out[(MAC, "YouTube")]
    assert (yt["tx"], yt["rx"], yt["device"], yt["ip"]) == (11, 101, "TV", "192.0.2.10")
    offline = out[("02:00:00:00:00:99", "Steam")]
    assert offline["device"] == "unnamed device" and offline["network"] == "Other"
    s = summarize(list(out.values()))
    assert (s["rx"], s["tx"], s["devices"]) == (108, 11, 2)
    assert s["top_devices"][0]["device"] == "TV"


def _out(*rows) -> str:
    return "1763115000\n" + "\n".join("|".join(map(str, r)) for r in rows)


def test_collect_keeps_cursor_when_archive_fails(tmp_path):
    col = FakeCollector(_out((MAC, "YouTube", "Media", TS, 1, 2)))
    out = TrafficLog(tmp_path).collect(col, {}, {})
    assert out["status"] == "archive_unavailable"
    assert not (tmp_path / ".traffic_cursor.json").exists()
    assert col.closed


def test_collect_advances_cursor_to_newest_row(tmp_path, monkeypatch):
    archived = []
    monkeypatch.setattr(db, "insert_traffic_rows", archived.extend)
    (tmp_path / ".traffic_cursor.json").write_text(json.dumps({"ts": TS - 3600}))
    col = FakeCollector(_out((MAC, "YouTube", "Media", TS, 1, 2), (MAC, "Hidden", "x", TS + 9, 1, 2)))
    out = TrafficLog(tmp_path, {"hide_apps": ["hidden"]}).collect(col, {}, {})
    assert f"timestamp > {TS - 3600}" in col.commands[0]
    assert [r["app"] for r in archived] == ["YouTube"]
    assert out["new_rows"] == 2
    assert json.loads((tmp_path / ".traffic_cursor.json").read_text()) == {"ts": TS + 9}


def test_collect_leaves_a_possibly_split_write_for_next_time(tmp_path, monkeypatch):
    monkeypatch.setattr(traffic, "MAX_ROWS", 2)
    monkeypatch.setattr(db, "insert_traffic_rows", lambda rows: None)
    col = FakeCollector(_out((MAC, "A", "x", TS, 1, 1), (MAC, "B", "x", TS + 60, 1, 1)))
    out = TrafficLog(tmp_path).collect(col, {}, {})
    assert out["more_pending"] is True
    assert json.loads((tmp_path / ".traffic_cursor.json").read_text()) == {"ts": TS}


def test_collect_reports_unreadable_router(tmp_path):
    out = TrafficLog(tmp_path).collect(FakeCollector(exc=OSError("ssh down")), {}, {})
    assert out["status"] == "router_unreadable"
