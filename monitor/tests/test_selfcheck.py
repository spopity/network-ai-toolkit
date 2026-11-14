"""Monitor the monitor: each problem alerts once (after its grace), recovery alerts once."""
import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from router_agent import db, notify, selfcheck
from router_agent.notify import Notifier
from router_agent.selfcheck import (
    check_backup,
    check_checks,
    check_daily,
    check_disk,
    check_watchdog,
    run,
    update_state,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def _latest(log_dir, collected_at: datetime):
    (log_dir / "latest.json").write_text(json.dumps({"snapshot": {"collected_at": collected_at.isoformat()}}))


def _touch(path, when: datetime, body: str = "{}"):
    path.write_text(body) if not path.is_dir() else None
    os.utime(path, (when.timestamp(), when.timestamp()))


def test_checks_fresh_stale_missing(tmp_path):
    assert check_checks(tmp_path, NOW, timedelta(minutes=20)) == "no check has written logs/latest.json yet"
    _latest(tmp_path, NOW - timedelta(minutes=6))
    assert check_checks(tmp_path, NOW, timedelta(minutes=20)) is None
    _latest(tmp_path, NOW - timedelta(minutes=45))
    assert "45 min ago" in check_checks(tmp_path, NOW, timedelta(minutes=20))


def test_daily_missing_old_failed(tmp_path):
    assert check_daily(tmp_path, NOW, timedelta(hours=26)) is None  # nothing yet: fresh install
    ok = tmp_path / "rt-2026-11-14T03-00-00+00-00.json"
    _touch(ok, NOW - timedelta(hours=9), json.dumps({"analysis": {"source": "claude"}}))
    assert check_daily(tmp_path, NOW, timedelta(hours=26)) is None
    _touch(ok, NOW - timedelta(hours=30), json.dumps({"analysis": {"source": "claude"}}))
    assert "30 h" in check_daily(tmp_path, NOW, timedelta(hours=26))
    _touch(ok, NOW - timedelta(hours=9), json.dumps({"analysis": {"source": "none", "error": "claude failed (quota)"}}))
    assert "failed: claude failed (quota)" in check_daily(tmp_path, NOW, timedelta(hours=26))


def test_backup_age_ignores_partial(tmp_path):
    assert check_backup(tmp_path / "missing", NOW, timedelta(hours=26)) is None
    assert "no completed" in check_backup(tmp_path, NOW, timedelta(hours=26))
    old, partial = tmp_path / "2026-11-12T034007Z", tmp_path / ".partial-x"
    old.mkdir()
    partial.mkdir()
    _touch(old, NOW - timedelta(hours=56))
    _touch(partial, NOW)
    assert "2 days old" in check_backup(tmp_path, NOW, timedelta(hours=26))
    _touch(old, NOW - timedelta(hours=8))
    assert check_backup(tmp_path, NOW, timedelta(hours=26)) is None


def test_disk(tmp_path):
    assert check_disk(tmp_path, 0) is None
    assert "free" in check_disk(tmp_path, 101)


def test_watchdog_status(tmp_path):
    assert "not running" in check_watchdog(tmp_path, NOW)
    (tmp_path / "watchdog_status.json").write_text(json.dumps({"checked_at": (NOW - timedelta(seconds=40)).isoformat()}))
    assert check_watchdog(tmp_path, NOW) is None
    (tmp_path / "watchdog_status.json").write_text(json.dumps({"checked_at": (NOW - timedelta(minutes=12)).isoformat()}))
    assert "silent for 12 min" in check_watchdog(tmp_path, NOW)


def test_traffic_freshness(tmp_path):
    from router_agent.selfcheck import check_traffic

    assert check_traffic(tmp_path, NOW, timedelta(hours=3)) is None  # nothing archived yet
    (tmp_path / ".traffic_cursor.json").write_text(json.dumps({"ts": int((NOW - timedelta(hours=1)).timestamp())}))
    assert check_traffic(tmp_path, NOW, timedelta(hours=3)) is None
    (tmp_path / ".traffic_cursor.json").write_text(json.dumps({"ts": int((NOW - timedelta(hours=18)).timestamp())}))
    assert "18 h" in check_traffic(tmp_path, NOW, timedelta(hours=3))
    # only checked when the Traffic Analyzer archive is configured
    assert selfcheck.gather({}, tmp_path, NOW, only=("traffic",)) == {"traffic": None}
    assert selfcheck.gather({"traffic_analyzer": True}, tmp_path, NOW, only=("traffic",))["traffic"]


def test_postgres_check(monkeypatch):
    monkeypatch.delenv("PGHOST", raising=False)
    assert selfcheck.check_postgres() is None  # archive not configured
    monkeypatch.setenv("PGHOST", "db.invalid")
    assert "unreachable" in selfcheck.check_postgres()  # conftest: connections fail
    monkeypatch.setattr(db, "ping", lambda: None)
    assert selfcheck.check_postgres() is None


def test_update_state_alerts_once_after_grace_then_recovers():
    state = {}
    t = NOW
    assert update_state(state, {"postgres": "down"}, t) == []            # grace: 15 min
    assert update_state(state, {"postgres": "down"}, t + timedelta(minutes=10)) == []
    ev = update_state(state, {"postgres": "down"}, t + timedelta(minutes=16))
    assert [e["event"] for e in ev] == ["monitor_problem"] and ev[0]["since"] == t.isoformat(timespec="seconds")
    assert update_state(state, {"postgres": "still down"}, t + timedelta(minutes=30)) == []
    ev = update_state(state, {"postgres": None}, t + timedelta(minutes=40))
    assert [e["event"] for e in ev] == ["monitor_ok"] and state == {}


def test_blip_within_grace_never_alerts():
    state = {}
    update_state(state, {"dashboard": "down"}, NOW)
    assert update_state(state, {"dashboard": None}, NOW + timedelta(minutes=5)) == []
    assert state == {}


def test_checks_without_grace_alert_immediately():
    ev = update_state({}, {"backup": "old"}, NOW)
    assert ev[0]["title"] == "router backup" and ev[0]["problem"] == "old"


@pytest.fixture
def telegram(tmp_path, monkeypatch):
    sent = []
    n = Notifier("token", "1", tmp_path)
    monkeypatch.setattr(n, "send", sent.append)
    monkeypatch.setattr(notify, "_notifier", n)
    return sent


def test_run_end_to_end_events_and_telegram(tmp_path, telegram):
    cfg = {"monitor": {"backup_dir": str(tmp_path / "backups")}}
    _latest(tmp_path, NOW - timedelta(hours=2))
    run(cfg, tmp_path, only=("checks",), now=NOW)                          # grace starts
    run(cfg, tmp_path, only=("checks",), now=NOW + timedelta(minutes=11))  # alert
    run(cfg, tmp_path, only=("checks",), now=NOW + timedelta(minutes=16))  # quiet
    _latest(tmp_path, NOW + timedelta(minutes=19))
    run(cfg, tmp_path, only=("checks",), now=NOW + timedelta(minutes=20))  # recovered
    events = [json.loads(line)["event"] for line in (tmp_path / "router_events.log").read_text().splitlines()]
    assert events == ["monitor_problem", "monitor_ok"]
    assert len(telegram) == 2
    assert "5-minute checks problem" in telegram[0] and "OK again" in telegram[1]


def test_run_skip_only_and_never_raises(tmp_path, monkeypatch):
    res = run({}, tmp_path, only=("watchdog",), now=NOW)
    assert set(res) == {"watchdog"}
    res = run({"dashboard": {"host": "127.0.0.1", "port": 1}}, tmp_path, skip=("watchdog", "postgres", "daily", "backup", "traffic", "iot_lan"), now=NOW)
    assert set(res) == {"checks", "dashboard", "disk"}
    assert "not answering" in res["dashboard"]

    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(selfcheck, "gather", boom)
    assert run({}, tmp_path) == {}


def test_heartbeat_only_while_checks_are_fresh(monkeypatch):
    pinged = []
    monkeypatch.setattr(selfcheck.requests, "get", lambda url, timeout: pinged.append(url))
    cfg = {"monitor": {"heartbeat_url": "https://hc.invalid/abc"}}
    selfcheck.heartbeat(cfg, {"checks": None})
    selfcheck.heartbeat(cfg, {"checks": "stale"})
    selfcheck.heartbeat(cfg, {"watchdog": None})
    selfcheck.heartbeat({}, {"checks": None})
    assert pinged == ["https://hc.invalid/abc"]


def test_monitor_alerts_can_be_switched_off(tmp_path, monkeypatch):
    n = Notifier("token", "1", tmp_path, events=("wan",))
    sent = []
    monkeypatch.setattr(n, "send", sent.append)
    n.router_event({"event": "monitor_problem", "check": "disk", "title": "disk space", "problem": "x", "since": NOW.isoformat()})
    assert sent == []
