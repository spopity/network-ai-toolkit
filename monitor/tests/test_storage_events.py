"""Snapshot storage, client tracking, retention and router events."""
import gzip
import json
import os
import time
from datetime import UTC, datetime, timedelta

from router_agent import db
from router_agent.events import (
    append_router_event,
    read_router_events,
    watchdog_summary,
)
from router_agent.storage import SnapshotStore


def test_write_survives_postgres_outage_and_updates_latest(tmp_path):
    store = SnapshotStore(tmp_path)
    rec = {"snapshot": {"x": 1}}
    daily = store.write("rt", rec)                     # db._connect refuses: must not raise
    check = store.write("rt", {"snapshot": {"x": 2}}, kind="check")
    assert json.loads(daily.read_text()) == rec
    assert json.loads(gzip.decompress(check.read_bytes())) == {"snapshot": {"x": 2}}
    assert store.latest() == {"snapshot": {"x": 2}}
    assert not (tmp_path / "latest.json.tmp").exists()


def test_prune_only_removes_old_timestamped_records(tmp_path):
    store = SnapshotStore(tmp_path, retention_days=1, check_retention_hours=1)
    old = time.time() - 3 * 86400
    files = {
        "old_daily": tmp_path / "rt-2026-11-01T03-00-00+00-00.json",
        "new_daily": tmp_path / "rt-2026-11-14T03-00-00+00-00.json",
        "old_check": tmp_path / "checks" / "rt-2026-11-01T03-05-00+00-00.json.gz",
        "latest": tmp_path / "latest.json",
        "known": tmp_path / "known_clients.json",
        "rollup": tmp_path / "rollup.json",
    }
    for name, f in files.items():
        f.write_text("{}")
        if name != "new_daily":
            os.utime(f, (old, old))
    assert store.prune() == 2
    assert {n for n, f in files.items() if f.exists()} == {"new_daily", "latest", "known", "rollup"}


def _wifi(*macs):
    return {"nodes": [{}], "clients": [{"mac": m, "name": f"dev {m[-2:]}"} for m in macs]}


def test_track_clients_baseline_then_new_devices(tmp_path, monkeypatch):
    monkeypatch.setattr("router_agent.storage.wifi_client_macs", lambda wifi: [c["mac"] for c in wifi["clients"]])
    store = SnapshotStore(tmp_path)
    assert store.track_clients(_wifi("02:00:00:00:00:01")) is None   # no history yet: everything is baseline
    assert store.track_clients(_wifi("02:00:00:00:00:01", "02:00:00:00:00:02")) == ["02:00:00:00:00:02"]
    known = json.loads((tmp_path / "known_clients.json").read_text())
    assert known["02:00:00:00:00:02"]["name"] == "dev 02"

    # a device unseen for the retention period is forgotten at the next check without it ...
    stale = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    known["02:00:00:00:00:01"].update(last_seen=stale)
    (tmp_path / "known_clients.json").write_text(json.dumps(known))
    assert store.track_clients(_wifi("02:00:00:00:00:02")) == ["02:00:00:00:00:02"]
    assert "02:00:00:00:00:01" not in json.loads((tmp_path / "known_clients.json").read_text())
    # ... and counts as new when it comes back
    assert store.track_clients(_wifi("02:00:00:00:00:01", "02:00:00:00:00:02")) == [
        "02:00:00:00:00:01", "02:00:00:00:00:02"]


def test_router_events_roundtrip_newest_first(tmp_path):
    for i in range(3):
        append_router_event(tmp_path, {"ts": f"2026-11-14T09:00:0{i}+00:00", "event": f"e{i}"})
    (tmp_path / "router_events.log").open("a").write("not json\n")
    assert [e["event"] for e in read_router_events(tmp_path, limit=2)] == ["e2", "e1"]
    assert read_router_events(tmp_path / "nope") == []


def test_router_event_is_archived_when_postgres_is_up(tmp_path, monkeypatch):
    got = []
    monkeypatch.setattr(db, "insert_watchdog_event", got.append)
    append_router_event(tmp_path, {"ts": "2026-11-14T09:00:00+00:00", "event": "x"})
    assert got == [{"ts": "2026-11-14T09:00:00+00:00", "event": "x"}]


def test_watchdog_summary(tmp_path):
    now = datetime.now(UTC)
    lines = [
        {"ts": (now - timedelta(hours=1)).isoformat(), "event": "recovered", "downtime_seconds": 30},
        {"ts": (now - timedelta(hours=2)).isoformat(), "event": "recovered", "downtime_seconds": 90.4},
        {"ts": (now - timedelta(hours=2)).isoformat(), "event": "restart_triggered"},
        {"ts": (now - timedelta(days=3)).isoformat(), "event": "recovered", "downtime_seconds": 999},
    ]
    (tmp_path / "watchdog.log").write_text("\n".join(map(json.dumps, lines)) + "\nbroken\n")
    assert watchdog_summary(tmp_path) == {"outages": 2, "total_downtime_s": 120, "longest_s": 90, "auto_restarts": 1}
