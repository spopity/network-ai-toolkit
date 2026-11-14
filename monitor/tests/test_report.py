"""Weekly / monthly report: windows, facts from the archive, LLM fallback, Telegram, API."""
import json
from datetime import UTC, datetime

import pytest

from router_agent import db, notify, report
from router_agent.notify import Notifier


def test_week_window_is_last_full_monday_to_monday():
    prev, start, end = report.window("week", datetime(2026, 11, 18, 9, 0, tzinfo=UTC))  # a Wednesday
    assert (prev.date().isoformat(), start.date().isoformat(), end.date().isoformat()) == (
        "2026-11-02", "2026-11-09", "2026-11-16")
    # run on Monday 04:30 -> the week that just ended
    assert report.window("week", datetime(2026, 11, 16, 4, 30, tzinfo=UTC))[1].date().isoformat() == "2026-11-09"


@pytest.mark.parametrize(("now", "expected"), [
    (datetime(2026, 12, 1, 5, 0, tzinfo=UTC), ("2026-10-01", "2026-11-01", "2026-12-01")),
    (datetime(2027, 1, 1, 5, 0, tzinfo=UTC), ("2026-11-01", "2026-12-01", "2027-01-01")),
    (datetime(2026, 3, 15, tzinfo=UTC), ("2026-01-01", "2026-02-01", "2026-03-01")),
])
def test_month_window_is_last_calendar_month(now, expected):
    assert tuple(d.date().isoformat() for d in report.window("month", now)) == expected


def test_unknown_period_is_refused():
    with pytest.raises(ValueError):
        report.window("year")


def _known_clients(tmp_path):
    (tmp_path / "known_clients.json").write_text(json.dumps({
        "02:00:00:00:00:01": {"name": "new_Tablet", "vendor": "Apple", "first_seen": "2026-11-10T08:00:00+00:00"},
        "02:00:00:00:00:02": {"name": "old_TV", "first_seen": "2026-11-10T09:00:00+00:00", "baseline": True},
        "02:00:00:00:00:03": {"name": "last_week", "first_seen": "2026-11-03T09:00:00+00:00"},
    }))


NOW = datetime(2026, 11, 16, 4, 30, tzinfo=UTC)


def test_postgres_down_still_gives_new_devices_and_lists_what_is_missing(tmp_path):
    _known_clients(tmp_path)
    facts = report.gather(tmp_path, "week", NOW)   # conftest: every Postgres connection fails
    assert (facts["start"], facts["end"]) == ("2026-11-09", "2026-11-15")
    assert facts["internet"] is None and facts["traffic"] is None
    assert [d["device"] for d in facts["new_devices"]] == ["new_Tablet"]   # baseline / out of window skipped
    assert {e.split(":")[0] for e in facts["errors"]} >= {"wan", "line", "traffic", "dns", "events"}
    assert report.headline(facts) == ["1 new device(s)"]


def _fake_archive(monkeypatch):
    def traffic(bucket, top, start, end, **kw):
        big = start.day == 9  # this week vs the previous one
        series = [{"period": "2026-11-09T00:00:00+00:00", "rx": 30e9 if big else 10e9, "tx": 2e9, "devices": 3}]
        return {"series": series, "devices": [{"mac": "02:00:00:00:00:09", "device": "TV", "network": "LAN",
                                               "rx": 25e9, "tx": 1e9}]}

    monkeypatch.setattr(db, "get_traffic_history", traffic)
    monkeypatch.setattr(db, "get_dns_history", lambda bucket, top, start, end, **kw: {
        "series": [{"period": "x", "queries": 1000, "blocked": 125}],
        "devices": [{"device_key": "k", "device": "TV", "network": "LAN", "queries": 800, "blocked": 100}]})
    monkeypatch.setattr(db, "get_check_stats", lambda start, end: {
        "checks": 2016, "wan_up_checks": 2010, "clients_avg": 30, "clients_max": 40,
        "mem_used_pct_avg": 60, "mem_used_pct_max": 70, "reboots": 1})
    monkeypatch.setattr(db, "get_line_stats", lambda start, end: {
        "speedtests": [{"at": "a", "download_mbps": 900.0, "upload_mbps": 300.0, "latency_ms": 2.0},
                       {"at": "b", "download_mbps": 940.0, "upload_mbps": 310.0, "latency_ms": 3.0}],
        "connmon": {"ping_ms_avg": 7.2}})
    monkeypatch.setattr(db, "get_events_between", lambda start, end: [
        {"ts": "2026-11-10T10:00:00+00:00", "event": "down_detected", "detail": {}},
        {"ts": "2026-11-10T10:03:00+00:00", "event": "recovered", "detail": {"downtime_seconds": 180}},
        {"ts": "2026-11-11T10:00:00+00:00", "event": "anomaly",
         "detail": {"device": "Cam", "kind": "upload", "mac": "02:00:00:00:00:05"}},
    ])


def test_facts_from_the_archive(tmp_path, monkeypatch):
    _fake_archive(monkeypatch)
    f = report.gather(tmp_path, "week", NOW)
    assert "errors" not in f
    assert f["internet"]["wan_up_pct"] == 99.7 and f["internet"]["outages_measured"] == 1
    assert f["internet"]["downtime_min"] == 3.0 and f["internet"]["router_reboots"] == 1
    assert f["line"]["download_mbps_avg"] == 920.0 and f["line"]["download_mbps_min"] == 900.0
    assert f["traffic"]["download_gb"] == 30.0 and f["previous"]["traffic"]["download_gb"] == 10.0
    assert "top_devices" not in f["previous"]["traffic"]   # comparison totals only
    assert f["dns"]["blocked_pct"] == 12.5 and f["dns"]["top_devices"][0]["blocked_pct"] == 12.5
    assert f["events"]["counts"] == {"down_detected": 1, "recovered": 1, "anomaly": 1}
    # notable events keep a few fields only (no MACs, nothing hidden-list related)
    assert f["events"]["notable"] == [{"at": "2026-11-11T10:00", "event": "anomaly", "device": "Cam", "kind": "upload"}]
    # per device only: no domain or app names reach the facts (hidden list)
    text = json.dumps(f)
    assert "domain" not in text and '"app' not in text
    assert report.prompt(f).count("FACTS:") == 1


class FakeLLM:
    def __init__(self, answer):
        self.answer, self.prompts = answer, []

    def ask(self, prompt):
        self.prompts.append(prompt)
        return self.answer


def _notifier(tmp_path, monkeypatch, events):
    sent = []
    n = Notifier("token", "1", tmp_path, events=events)
    monkeypatch.setattr(n, "send", sent.append)
    monkeypatch.setattr(notify, "configure", lambda cfg, log_dir: n)
    return sent


def test_run_saves_and_sends_when_report_is_enabled(tmp_path, monkeypatch):
    _fake_archive(monkeypatch)
    sent = _notifier(tmp_path, monkeypatch, events=("report",))
    llm = FakeLLM({"source": "claude", "text": "- All good <b>really</b>\n- TV used most"})
    rec = report.run({}, tmp_path, "week", llm=llm, now=NOW)
    saved = json.loads((tmp_path / "reports" / "week-2026-11-09.json").read_text())
    assert saved["summary"] == rec["summary"] and saved["source"] == "claude"
    assert len(llm.prompts) == 1
    assert len(sent) == 1 and "Weekly network report" in sent[0]
    assert "&lt;b&gt;really&lt;/b&gt;" in sent[0]   # LLM text is escaped for Telegram HTML
    assert "Internet up 99.7%" in sent[0]


def test_report_is_opt_in_and_works_without_llm(tmp_path, monkeypatch):
    _fake_archive(monkeypatch)
    sent = _notifier(tmp_path, monkeypatch, events=notify.DEFAULT_EVENTS)
    assert "report" not in notify.DEFAULT_EVENTS
    rec = report.run({}, tmp_path, "month", llm=FakeLLM({"source": "none", "error": "all backends failed"}),
                     now=datetime(2026, 12, 1, 5, 0, tzinfo=UTC))
    assert sent == []
    assert rec["summary"] is None and rec["error"] == "all backends failed"
    assert rec["headline"]   # the numbers are still there
    assert (tmp_path / "reports" / "month-2026-11-01.json").exists()


def test_no_send_skips_telegram(tmp_path, monkeypatch):
    _fake_archive(monkeypatch)
    sent = _notifier(tmp_path, monkeypatch, events=("report",))
    report.run({}, tmp_path, "week", llm=None, send=False, now=NOW)
    assert sent == []


def test_latest_newest_first_and_by_period(tmp_path):
    d = tmp_path / "reports"
    d.mkdir()
    for name in ("week-2026-11-02", "week-2026-11-09", "month-2026-10-01"):
        (d / f"{name}.json").write_text(json.dumps({"period": name.split("-")[0], "start": name[name.index("-") + 1:]}))
    (d / "week-2026-11-16.tmp").write_text("partial")
    assert [r["start"] for r in report.latest(tmp_path)] == ["2026-11-09", "2026-11-02", "2026-10-01"]
    assert [r["start"] for r in report.latest(tmp_path, "week", 1)] == ["2026-11-09"]
    assert report.latest(tmp_path / "nothing") == []



def test_empty_archive_is_not_collected_not_zero(tmp_path, monkeypatch):
    _fake_archive(monkeypatch)
    monkeypatch.setattr(db, "get_dns_history", lambda bucket, top, start, end, **kw: {"series": [], "devices": []})
    f = report.gather(tmp_path, "week", NOW)
    assert f["dns"] == {"not_collected": True} and f["previous"]["dns"] == {"not_collected": True}
    assert not any(h.startswith("DNS") for h in report.headline(f))
    assert "not_collected" in report.prompt(f)


def test_partial_period_has_coverage(tmp_path, monkeypatch):
    _fake_archive(monkeypatch)   # one day of traffic in a 7-day week
    f = report.gather(tmp_path, "week", NOW)
    assert f["traffic"]["coverage"] == "1 of 7 days"
    assert "coverage" in report.prompt(f)
