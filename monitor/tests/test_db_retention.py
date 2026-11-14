"""Postgres retention: the daily run deletes old time-series rows, nothing else."""
from contextlib import contextmanager

from router_agent import db


class FakeCursor:
    def __init__(self, rowcount=3):
        self.sql, self.rowcount = [], rowcount

    def execute(self, sql, params=None):
        if "pg_extension" not in sql:  # TimescaleDB probe: plain Postgres here (test_db_timescale.py)
            self.sql.append((sql, params))

    def fetchone(self):
        return None


def fake_db(monkeypatch, cur):
    @contextmanager
    def cursor():
        yield cur

    monkeypatch.setattr(db, "_cursor", cursor)
    monkeypatch.setattr(db, "_SCHEMA_READY", True)


def test_prunes_only_time_series_tables(monkeypatch):
    cur = FakeCursor()
    fake_db(monkeypatch, cur)
    assert db.prune_old(90) == {"snapshots": 3, "dns_lookups": 3, "traffic_usage": 3}
    assert all(params == (90,) for _, params in cur.sql)
    sql = " ".join(s for s, _ in cur.sql)
    # daily analyses stay: only 5-minute check rows are deleted from snapshots
    assert "DELETE FROM snapshots WHERE collected_at < now() - make_interval(days => %s) AND kind = 'check'" in sql
    # the "new domain" detection needs every (device, domain) ever seen; events are the outage history
    for kept in ("dns_first_seen", "dns_devices", "watchdog_events", "tshoot_audit"):
        assert kept not in sql


def test_zero_or_missing_means_keep_forever(monkeypatch):
    cur = FakeCursor()
    fake_db(monkeypatch, cur)
    assert db.prune_old(0) == {}
    assert db.prune_old(None) == {}
    assert cur.sql == []


def test_tiny_values_are_refused(monkeypatch):
    cur = FakeCursor()
    fake_db(monkeypatch, cur)
    assert db.prune_old(1) is None
    assert cur.sql == []


def test_never_raises_when_postgres_is_down():
    # conftest makes every connection fail
    assert db.prune_old(90) is None
