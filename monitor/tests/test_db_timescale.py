"""TimescaleDB setup and chunk-based retention, with a scripted fake cursor (no database)."""
from contextlib import contextmanager

import pytest

from router_agent import db


class FakeCursor:
    """Answers the catalog queries from `state`; records every statement."""

    def __init__(self, state):
        self.state, self.sql, self._rows, self.rowcount = state, [], [], 7

    def execute(self, sql, params=None):
        self.sql.append((" ".join(sql.split()), params))
        s = self.sql[-1][0]
        if "FROM pg_extension" in s:
            self._rows = [{"?column?": 1}] if self.state["timescale"] else []
        elif "FROM timescaledb_information.hypertables" in s:
            self._rows = [{"hypertable_name": t, "compression_enabled": c} for t, c in self.state["hyper"].items()]
        elif "FROM timescaledb_information.continuous_aggregates" in s:
            self._rows = [{"view_name": v} for v in self.state["views"]]
        elif s.startswith("SELECT count(*) AS n FROM"):
            self._rows = [{"n": self.state["counts"].pop(0)}]
        else:
            self._rows = []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class FakeConn:
    def __init__(self, cur):
        self.cur, self.autocommit, self.closed = cur, False, False

    def cursor(self, cursor_factory=None):
        return self.cur

    def close(self):
        self.closed = True


def fake_db(monkeypatch, state):
    cur = FakeCursor(state)

    @contextmanager
    def cursor():
        yield cur

    conn = FakeConn(cur)
    monkeypatch.setattr(db, "_cursor", cursor)
    monkeypatch.setattr(db, "_connect", lambda: conn)
    monkeypatch.setattr(db, "_SCHEMA_READY", True)
    return cur, conn


def _state(timescale=True, hyper=None, views=(), counts=()):
    return {"timescale": timescale, "hyper": dict(hyper or {}), "views": list(views), "counts": list(counts)}


def test_plain_postgres_is_left_alone(monkeypatch):
    cur, _ = fake_db(monkeypatch, _state(timescale=False))
    assert db.ensure_timescale() == []
    assert not any("create_hypertable" in s or "MATERIALIZED" in s for s, _ in cur.sql)


def test_first_run_converts_compresses_and_summarizes(monkeypatch):
    cur, conn = fake_db(monkeypatch, _state())
    done = db.ensure_timescale()
    assert done == ["dns_lookups: hypertable", "dns_lookups: compression after 14 days",
                    "traffic_usage: hypertable", "traffic_usage: compression after 14 days",
                    "traffic_daily: daily summary", "dns_daily: daily summary"]
    assert conn.autocommit and conn.closed
    sql = [s for s, _ in cur.sql]
    assert sum("create_hypertable" in s and "migrate_data => true" in s for s in sql) == 2
    views = [s for s in sql if s.startswith("CREATE MATERIALIZED VIEW")]
    assert len(views) == 2
    # privacy: the summaries outlive the raw rows the hidden list purges -> no domains/apps
    for v in views:
        assert " domain" not in v and " app" not in v
    assert any(p == ("traffic_daily", "30 days") for s, p in cur.sql if "add_continuous_aggregate_policy" in s)
    assert sum(s.startswith("CALL refresh_continuous_aggregate") for s in sql) == 2


def test_second_run_does_nothing(monkeypatch):
    cur, _ = fake_db(monkeypatch, _state(hyper={"dns_lookups": True, "traffic_usage": True},
                                         views=["traffic_daily", "dns_daily"]))
    assert db.ensure_timescale() == []
    assert not any(s.startswith(("SELECT create_", "ALTER", "CREATE", "CALL")) for s, _ in cur.sql)


def test_ensure_timescale_never_raises_when_postgres_is_down():
    assert db.ensure_timescale() is None   # conftest makes every connection fail


@pytest.mark.parametrize(("days", "keep"), [(90, 90), (10, db.SUMMARY_REFRESH_DAYS + 1)])
def test_prune_drops_chunks_on_hypertables(monkeypatch, days, keep):
    cur, _ = fake_db(monkeypatch, _state(hyper={"dns_lookups": True, "traffic_usage": True},
                                         counts=[100, 60, 50, 50]))
    assert db.prune_old(days) == {"snapshots": 7, "dns_lookups": 40, "traffic_usage": 0}
    drops = [p for s, p in cur.sql if "drop_chunks" in s]
    # never inside the window the summaries still refresh from
    assert drops == [("dns_lookups", keep), ("traffic_usage", keep)]
    # snapshots keep their row DELETE: daily analyses must survive, only check rows go
    assert any(s.startswith("DELETE FROM snapshots") and p == (days,) for s, p in cur.sql)


@pytest.mark.parametrize(("views", "source"), [(["traffic_daily"], "FROM traffic_daily s"),
                                               ([], "FROM (SELECT date_trunc('day', hour) AS day")])
def test_history_reads_summary_or_raw_table(monkeypatch, views, source):
    cur, _ = fake_db(monkeypatch, _state(timescale=bool(views), views=views))
    assert db.get_traffic_history(365, "week", device="tv") == {"series": [], "devices": []}
    queries = [s for s, _ in cur.sql if "AS period" in s or "ARRAY_AGG" in s]
    assert len(queries) == 2 and all(source in q for q in queries)
    assert "date_trunc('week', s.day)" in queries[0]
    with pytest.raises(ValueError):
        db.get_traffic_history(30, "year")
