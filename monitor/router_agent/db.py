import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

_SCHEMA_READY = False

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS snapshots (
    id BIGSERIAL PRIMARY KEY,
    router TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    client_count INT,
    mem_used_pct NUMERIC,
    uptime_seconds NUMERIC,
    wan_up BOOLEAN,
    analysis_source TEXT,
    snapshot JSONB NOT NULL,
    analysis JSONB
);
CREATE INDEX IF NOT EXISTS idx_snapshots_collected_at ON snapshots (collected_at DESC);
-- 'check' = 5-minute collection (no LLM), 'daily' = collection + LLM analysis
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'daily';

CREATE TABLE IF NOT EXISTS watchdog_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    event TEXT NOT NULL,
    detail JSONB
);
CREATE INDEX IF NOT EXISTS idx_watchdog_events_ts ON watchdog_events (ts DESC);
"""


def _connect():
    return psycopg2.connect(
        host=os.environ["PGHOST"],
        port=int(os.getenv("PGPORT", 5432)),
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
        connect_timeout=5,
    )


@contextmanager
def _cursor():
    conn = _connect()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                yield cur
    finally:
        conn.close()


def ensure_schema():
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _cursor() as cur:
        cur.execute(SCHEMA_SQL)
    _SCHEMA_READY = True


# raw log text and per-window summaries: kept in daily rows, dropped from the 5-minute
# rows (~65 KB -> ~10 KB each; the local gzipped check files keep them for 48 h)
_CHECK_DROP_SECURITY_KEYS = ("syslog_tail", "syslog_summary", "security_log_tail", "security_log_summary",
                             "aae_log_tail", "aae_log_summary")


def _slim(snap: dict) -> dict:
    sec = {k: v for k, v in snap.get("security", {}).items() if k not in _CHECK_DROP_SECURITY_KEYS}
    return {**snap, "security": sec}


def insert_snapshot(record: dict, kind: str = "daily"):
    """Best-effort archive write. Never raises -- caller's pipeline must not
    depend on Postgres being reachable."""
    try:
        ensure_schema()
        snap = record["snapshot"]
        # check rows carry the previous day's analysis forward; don't archive copies of it
        analysis = record.get("analysis", {}) if kind == "daily" else {}
        system = snap.get("system", {})
        wan = snap.get("wan", {})
        wifi = snap.get("wifi", {})
        mem_used_pct = None
        if system.get("mem_total_kb"):
            avail = system.get("mem_available_kb") or system.get("mem_free_kb", 0)
            mem_used_pct = round(100 * (1 - avail / system["mem_total_kb"]), 1)

        with _cursor() as cur:
            cur.execute(
                """
                INSERT INTO snapshots
                    (router, collected_at, kind, client_count, mem_used_pct, uptime_seconds, wan_up, analysis_source,
                     snapshot, analysis)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    snap.get("router"),
                    snap.get("collected_at"),
                    kind,
                    wifi.get("client_count"),
                    mem_used_pct,
                    system.get("uptime_seconds"),
                    bool(wan.get("pppd_running")),
                    analysis.get("source"),
                    json.dumps(snap if kind == "daily" else _slim(snap)),
                    json.dumps(analysis) if analysis else None,
                ),
            )
    except Exception as e:
        logger.warning("Postgres insert_snapshot failed (continuing without it): %s", e)


def insert_watchdog_event(event: dict):
    """Best-effort archive write. Never raises."""
    try:
        ensure_schema()
        with _cursor() as cur:
            cur.execute(
                "INSERT INTO watchdog_events (ts, event, detail) VALUES (%s, %s, %s)",
                (event.get("ts"), event.get("event"), json.dumps(event)),
            )
    except Exception as e:
        logger.warning("Postgres insert_watchdog_event failed (continuing without it): %s", e)


def _jsonable_value(v):
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    return v


def _jsonable(row: dict) -> dict:
    return {k: _jsonable_value(v) for k, v in row.items()}


def get_snapshot_history(days: int = 30) -> list:
    ensure_schema()
    with _cursor() as cur:
        cur.execute(
            """
            SELECT collected_at, kind, client_count, mem_used_pct, uptime_seconds, wan_up, analysis_source
            FROM snapshots
            WHERE collected_at >= now() - (%s || ' days')::interval
              -- 5-minute checks at full resolution only for short windows; ~hourly beyond 2 days
              AND (kind = 'daily' OR %s <= 2 OR extract(minute FROM collected_at) < 5)
            ORDER BY collected_at ASC
            """,
            (days, days),
        )
        return [_jsonable(dict(r)) for r in cur.fetchall()]


def get_watchdog_event_history(days: int = 30) -> list:
    ensure_schema()
    with _cursor() as cur:
        cur.execute(
            """
            SELECT ts, event, detail
            FROM watchdog_events
            WHERE ts >= now() - (%s || ' days')::interval
            ORDER BY ts DESC
            """,
            (days,),
        )
        return [_jsonable(dict(r)) for r in cur.fetchall()]
