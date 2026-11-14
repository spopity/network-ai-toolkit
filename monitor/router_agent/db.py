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

-- AdGuardHome query log, aggregated per hour (router_agent/dnslog.py)
CREATE TABLE IF NOT EXISTS dns_lookups (
    hour TIMESTAMPTZ NOT NULL,
    device_key TEXT NOT NULL,          -- MAC, "ip:<addr>" when the MAC is unknown, or "router"
    domain TEXT NOT NULL,
    blocked BOOLEAN NOT NULL,
    count INT NOT NULL,
    mac TEXT,
    device TEXT,
    network TEXT,
    client_ip TEXT,
    rule TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (hour, device_key, domain, blocked)
);
CREATE INDEX IF NOT EXISTS idx_dns_lookups_device ON dns_lookups (device_key, hour DESC);
CREATE INDEX IF NOT EXISTS idx_dns_lookups_domain ON dns_lookups (domain, hour DESC);

CREATE TABLE IF NOT EXISTS dns_devices (
    device_key TEXT PRIMARY KEY,
    mac TEXT,
    device TEXT,
    network TEXT,
    client_ip TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_first_seen (
    device_key TEXT NOT NULL,
    domain TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_key, domain)
);
CREATE INDEX IF NOT EXISTS idx_dns_first_seen_ts ON dns_first_seen (first_seen DESC);

-- Traffic Analyzer WAN bytes per device/app, aggregated per hour (router_agent/traffic.py)
CREATE TABLE IF NOT EXISTS traffic_usage (
    hour TIMESTAMPTZ NOT NULL,
    mac TEXT NOT NULL,
    app TEXT NOT NULL,
    category TEXT,
    rx BIGINT NOT NULL,                -- download (internet -> device), bytes
    tx BIGINT NOT NULL,                -- upload
    device TEXT,
    network TEXT,
    ip TEXT,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (hour, mac, app)
);
CREATE INDEX IF NOT EXISTS idx_traffic_usage_mac ON traffic_usage (mac, hour DESC);
"""


def _connect():
    return psycopg2.connect(
        host=os.environ["PGHOST"],
        port=int(os.getenv("PGPORT", "5432")),
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
        connect_timeout=5,
    )


@contextmanager
def _cursor():
    conn = _connect()
    try:
        with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
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
    out = {**snap, "security": sec}
    if isinstance(snap.get("lan"), dict):  # the DHCP/ARP host table is only for the live map
        out["lan"] = {k: v for k, v in snap["lan"].items() if k != "hosts"}
    return out


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


# Retention (prune_old, run by the daily job): time-series tables that grow with every
# check, as (table, time column, extra condition). Everything else is kept: daily
# snapshots (the LLM analyses, ~15 KB/day), watchdog_events (outage history), dns_devices
# and dns_first_seen (the "new domain" detection needs every domain a device ever used),
# and Tshoot's tshoot_audit.
RETENTION_TABLES = (
    ("snapshots", "collected_at", "kind = 'check'"),
    ("dns_lookups", "hour", None),
    ("traffic_usage", "hour", None),
)
MIN_RETENTION_DAYS = 7  # a typo like `db_retention_days: 1` must not wipe the archive


def prune_old(days: int | None = 90) -> dict | None:
    """Delete RETENTION_TABLES rows older than `days`. -> {table: rows deleted}, {} when
    retention is off (days 0/None), None when refused or Postgres failed. Best-effort:
    never raises (the daily run must not fail on it); one transaction, so a failure
    deletes nothing. TimescaleDB hypertables lose whole chunks instead (drop_chunks: a
    row goes once its 7-day chunk is entirely older than the cutoff), never inside the
    window the daily summaries still refresh from."""
    if not days:
        return {}
    if int(days) < MIN_RETENTION_DAYS:
        logger.warning("db_retention_days=%s is below %s, not pruning", days, MIN_RETENTION_DAYS)
        return None
    try:
        ensure_schema()
        deleted = {}
        with _cursor() as cur:
            hyper = _hypertables(cur)
            for table, column, extra in RETENTION_TABLES:
                if table in hyper:
                    keep = max(int(days), SUMMARY_REFRESH_DAYS + 1)
                    cur.execute(f"SELECT count(*) AS n FROM {table}")
                    before = cur.fetchone()["n"]
                    cur.execute("SELECT drop_chunks(%s, older_than => now() - make_interval(days => %s))", (table, keep))
                    cur.execute(f"SELECT count(*) AS n FROM {table}")
                    deleted[table] = before - cur.fetchone()["n"]
                    continue
                cur.execute(
                    f"DELETE FROM {table} WHERE {column} < now() - make_interval(days => %s)"
                    + (f" AND {extra}" if extra else ""),
                    (int(days),),
                )
                deleted[table] = cur.rowcount
        return deleted
    except Exception as e:
        logger.warning("Postgres prune_old failed (nothing deleted): %s", e)
        return None


# ------------------------------------------------------------------ TimescaleDB (optional)
# Used when the `timescaledb` extension is installed in the database; on plain Postgres
# everything above works unchanged and the *_history queries read the raw tables.
#
# - dns_lookups / traffic_usage become hypertables (7-day chunks), compressed once 14 days
#   old: the Traffic Analyzer catch-up writes up to ~2 weeks back, and upserts into
#   compressed chunks work but are slow.
# - Daily per-DEVICE summaries (continuous aggregates) keep long-term history after the
#   raw rows are pruned. Deliberately without domain or app names: the hidden list
#   (`hidden.domains` / `hidden.apps`) purges raw rows, and summaries that outlive them
#   must not carry those names. Summaries are kept forever (~50 rows a day each).
HYPERTABLES = {  # table: (time column, compress segmentby, compress orderby)
    "dns_lookups": ("hour", "device_key", "hour DESC, domain"),
    "traffic_usage": ("hour", "mac", "hour DESC, app"),
}
CHUNK_INTERVAL = "7 days"
COMPRESS_AFTER = "14 days"
# The refresh policy re-aggregates the last SUMMARY_REFRESH_DAYS from the raw table, so raw
# rows inside that window must never be dropped (prune_old keeps at least this much).
SUMMARY_REFRESH_DAYS = 30
SUMMARIES = {
    "traffic_daily": """
        SELECT time_bucket('1 day', hour) AS day, mac, sum(rx) AS rx, sum(tx) AS tx,
               last(device, last_seen) AS device, last(network, last_seen) AS network
        FROM traffic_usage GROUP BY 1, 2""",
    "dns_daily": """
        SELECT time_bucket('1 day', hour) AS day, device_key, sum(count) AS queries,
               sum(CASE WHEN blocked THEN count ELSE 0 END) AS blocked,
               last(device, last_seen) AS device, last(network, last_seen) AS network
        FROM dns_lookups GROUP BY 1, 2""",
}


def _has_timescale(cur) -> bool:
    cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'")
    return cur.fetchone() is not None


def _hypertables(cur) -> set:
    if not _has_timescale(cur):
        return set()
    cur.execute("SELECT hypertable_name FROM timescaledb_information.hypertables")
    return {r["hypertable_name"] for r in cur.fetchall()}


def _summaries(cur) -> set:
    if not _has_timescale(cur):
        return set()
    cur.execute("SELECT view_name FROM timescaledb_information.continuous_aggregates")
    return {r["view_name"] for r in cur.fetchall()}


def ensure_timescale() -> list | None:
    """Set up the hypertables, compression and daily summaries that are missing. Idempotent,
    run by the daily job. -> the steps done ([] = nothing to do or no TimescaleDB), None
    when Postgres failed. Never raises. Converting an existing table locks it while its
    rows are moved into chunks (seconds at this size)."""
    try:
        ensure_schema()
        conn = _connect()
        conn.autocommit = True  # CALL refresh_continuous_aggregate refuses to run in a transaction
        done = []
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if not _has_timescale(cur):
                return []
            cur.execute("SELECT hypertable_name, compression_enabled FROM timescaledb_information.hypertables")
            compressed = {r["hypertable_name"]: r["compression_enabled"] for r in cur.fetchall()}
            for table, (column, segment_by, order_by) in HYPERTABLES.items():
                if table not in compressed:
                    cur.execute("SELECT create_hypertable(%s, by_range(%s, %s::interval), migrate_data => true)",
                                (table, column, CHUNK_INTERVAL))
                    done.append(f"{table}: hypertable")
                if not compressed.get(table):
                    cur.execute(f"ALTER TABLE {table} SET (timescaledb.compress, "
                                "timescaledb.compress_segmentby = %s, timescaledb.compress_orderby = %s)",
                                (segment_by, order_by))
                    cur.execute("SELECT add_compression_policy(%s, %s::interval, if_not_exists => true)",
                                (table, COMPRESS_AFTER))
                    done.append(f"{table}: compression after {COMPRESS_AFTER}")
            existing = _summaries(cur)
            for view, sql in SUMMARIES.items():
                if view in existing:
                    continue
                cur.execute(f"CREATE MATERIALIZED VIEW {view} WITH (timescaledb.continuous, "
                            f"timescaledb.materialized_only = false) AS {sql} WITH NO DATA")
                cur.execute("SELECT add_continuous_aggregate_policy(%s, start_offset => %s::interval, "
                            "end_offset => interval '1 hour', schedule_interval => interval '1 hour', "
                            "if_not_exists => true)", (view, f"{SUMMARY_REFRESH_DAYS} days"))
                cur.execute("CALL refresh_continuous_aggregate(%s, NULL, NULL)", (view,))  # everything still raw
                done.append(f"{view}: daily summary")
        finally:
            conn.close()
        return done
    except Exception as e:
        logger.warning("Postgres ensure_timescale failed (continuing without it): %s", e)
        return None


def ping() -> None:
    """Raises when the archive is unreachable (used by selfcheck)."""
    with _cursor() as cur:
        cur.execute("SELECT 1")


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


# ------------------------------------------------------------------ DNS lookups (AdGuardHome)

def insert_dns_rows(rows: list, grace) -> list:
    """Archive aggregated query-log rows in one transaction. Raises on failure (the caller
    keeps its cursor so the entries are retried). Returns the lookups that are a device's
    first ever for that domain, for devices watched longer than `grace`."""
    ensure_schema()
    new = []
    with _cursor() as cur:
        devices = {}
        for r in rows:
            d = devices.setdefault(r["device_key"], dict(r))
            d["first_seen"] = min(d["first_seen"], r["first_seen"])
            d["last_seen"] = max(d["last_seen"], r["last_seen"])
        cur.execute("SELECT device_key, first_seen FROM dns_devices WHERE device_key = ANY(%s)", (list(devices),))
        watched_since = {row["device_key"]: row["first_seen"] for row in cur.fetchall()}
        psycopg2.extras.execute_values(cur, """
            INSERT INTO dns_devices (device_key, mac, device, network, client_ip, first_seen, last_seen) VALUES %s
            ON CONFLICT (device_key) DO UPDATE SET mac = COALESCE(EXCLUDED.mac, dns_devices.mac),
                device = EXCLUDED.device, network = EXCLUDED.network, client_ip = EXCLUDED.client_ip,
                last_seen = GREATEST(dns_devices.last_seen, EXCLUDED.last_seen)
            """, [(k, d["mac"], d["device"], d["network"], d["client_ip"], d["first_seen"], d["last_seen"])
                  for k, d in devices.items()])
        psycopg2.extras.execute_values(cur, """
            INSERT INTO dns_lookups (hour, device_key, domain, blocked, count, mac, device, network, client_ip, rule,
                                     first_seen, last_seen) VALUES %s
            ON CONFLICT (hour, device_key, domain, blocked) DO UPDATE SET count = dns_lookups.count + EXCLUDED.count,
                device = EXCLUDED.device, network = EXCLUDED.network, client_ip = EXCLUDED.client_ip,
                rule = COALESCE(EXCLUDED.rule, dns_lookups.rule),
                first_seen = LEAST(dns_lookups.first_seen, EXCLUDED.first_seen),
                last_seen = GREATEST(dns_lookups.last_seen, EXCLUDED.last_seen)
            """, [(r["hour"], r["device_key"], r["domain"], r["blocked"], r["count"], r["mac"], r["device"],
                   r["network"], r["client_ip"], r["rule"], r["first_seen"], r["last_seen"]) for r in rows])
        firsts = {}
        for r in rows:
            k = (r["device_key"], r["domain"])
            if k not in firsts or r["first_seen"] < firsts[k]["first_seen"]:
                firsts[k] = r
        inserted = psycopg2.extras.execute_values(cur, """
            INSERT INTO dns_first_seen (device_key, domain, first_seen) VALUES %s
            ON CONFLICT DO NOTHING RETURNING device_key, domain, first_seen
            """, [(k[0], k[1], r["first_seen"]) for k, r in firsts.items()], fetch=True)
        for row in inserted:
            since = watched_since.get(row["device_key"])
            if since is not None and row["first_seen"] - since >= grace:
                r = firsts[(row["device_key"], row["domain"])]
                new.append({"device": r["device"], "network": r["network"], "domain": row["domain"],
                            "blocked": r["blocked"], "at": row["first_seen"].isoformat(timespec="seconds")})
    return new


_DNS_DEVICE_FILTER = """
    (%(device)s::text IS NULL OR l.device_key = %(device)s OR l.device ILIKE '%%' || %(device)s || '%%'
         OR l.client_ip = %(device)s OR l.mac ILIKE %(device)s)
"""


def get_dns_devices(hours: int = 24, network: str | None = None) -> list:
    """Per-device totals over the window, busiest first."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute("""
            SELECT l.device_key, d.device, d.network, d.client_ip, d.mac,
                   SUM(l.count)::bigint AS queries,
                   COALESCE(SUM(l.count) FILTER (WHERE l.blocked), 0)::bigint AS blocked,
                   COUNT(DISTINCT l.domain) AS domains,
                   MAX(l.last_seen) AS last_seen, d.first_seen AS watched_since,
                   (SELECT COUNT(*) FROM dns_first_seen f
                     WHERE f.device_key = l.device_key AND f.first_seen >= now() - (%(hours)s || ' hours')::interval
                       AND f.first_seen - d.first_seen >= interval '24 hours') AS new_domains
            FROM dns_lookups l JOIN dns_devices d USING (device_key)
            WHERE l.hour >= date_trunc('hour', now() - (%(hours)s || ' hours')::interval)
              AND (%(network)s::text IS NULL OR d.network = %(network)s)
            GROUP BY l.device_key, d.device, d.network, d.client_ip, d.mac, d.first_seen
            ORDER BY queries DESC
            """, {"hours": hours, "network": network})
        return [_jsonable(dict(r)) for r in cur.fetchall()]


def get_dns_lookups(hours: int = 24, device: str | None = None, domain: str | None = None, network: str | None = None,
                    blocked_only: bool = False, new_only: bool = False, limit: int = 200) -> list:
    """(device, domain) pairs over the window. `device` matches key, name (substring), IP or MAC;
    `domain` is a substring. new_only = the device's first lookup of that domain fell in the window
    (and the device was already watched for 24h)."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute(f"""
            SELECT l.device_key, d.device, d.network, l.domain,
                   SUM(l.count)::bigint AS count,
                   COALESCE(SUM(l.count) FILTER (WHERE l.blocked), 0)::bigint AS blocked,
                   MAX(l.rule) AS rule, MIN(l.first_seen) AS first_seen, MAX(l.last_seen) AS last_seen,
                   (f.first_seen >= now() - (%(hours)s || ' hours')::interval
                    AND f.first_seen - d.first_seen >= interval '24 hours') AS new,
                   f.first_seen AS first_ever
            FROM dns_lookups l
            JOIN dns_devices d USING (device_key)
            LEFT JOIN dns_first_seen f ON f.device_key = l.device_key AND f.domain = l.domain
            WHERE l.hour >= date_trunc('hour', now() - (%(hours)s || ' hours')::interval)
              AND {_DNS_DEVICE_FILTER}
              AND (%(domain)s::text IS NULL OR l.domain ILIKE '%%' || %(domain)s || '%%')
              AND (%(network)s::text IS NULL OR d.network = %(network)s)
            GROUP BY l.device_key, d.device, d.network, d.first_seen, l.domain, f.first_seen
            HAVING (NOT %(blocked_only)s OR SUM(l.count) FILTER (WHERE l.blocked) > 0)
               AND (NOT %(new_only)s OR (f.first_seen >= now() - (%(hours)s || ' hours')::interval
                                         AND f.first_seen - d.first_seen >= interval '24 hours'))
            ORDER BY count DESC
            LIMIT %(limit)s
            """, {"hours": hours, "device": device, "domain": domain, "network": network,
                  "blocked_only": blocked_only, "new_only": new_only, "limit": limit})
        return [_jsonable(dict(r)) for r in cur.fetchall()]


# ------------------------------------------------------------------ internet usage (Traffic Analyzer)

def insert_traffic_rows(rows: list) -> None:
    """Add aggregated Traffic Analyzer rows (bytes are summed into existing hours). Raises on failure."""
    ensure_schema()
    with _cursor() as cur:
        psycopg2.extras.execute_values(cur, """
            INSERT INTO traffic_usage (hour, mac, app, category, rx, tx, device, network, ip, last_seen) VALUES %s
            ON CONFLICT (hour, mac, app) DO UPDATE SET rx = traffic_usage.rx + EXCLUDED.rx,
                tx = traffic_usage.tx + EXCLUDED.tx, category = EXCLUDED.category,
                device = EXCLUDED.device, network = EXCLUDED.network, ip = COALESCE(EXCLUDED.ip, traffic_usage.ip),
                last_seen = GREATEST(traffic_usage.last_seen, EXCLUDED.last_seen)
            """, [(r["hour"], r["mac"], r["app"], r["category"], r["rx"], r["tx"], r["device"], r["network"],
                   r["ip"], r["last_seen"]) for r in rows], page_size=1000)


_TRAFFIC_WINDOW = "t.hour >= date_trunc('hour', now() - (%(hours)s || ' hours')::interval)"
_TRAFFIC_DEVICE = """
    (%(device)s::text IS NULL OR t.mac ILIKE %(device)s OR t.ip = %(device)s
         OR t.device ILIKE '%%' || %(device)s || '%%')
"""


def get_traffic_devices(hours: int = 24, network: str | None = None) -> list:
    """Per-device download/upload over the window, busiest first, with each device's top apps.
    Name/network/IP are the device's most recent ones."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute(f"""
            WITH w AS (SELECT * FROM traffic_usage t WHERE {_TRAFFIC_WINDOW}),
            latest AS (SELECT DISTINCT ON (mac) mac, device, network, ip FROM w ORDER BY mac, last_seen DESC),
            apps AS (SELECT mac, app, SUM(rx + tx) AS bytes,
                            ROW_NUMBER() OVER (PARTITION BY mac ORDER BY SUM(rx + tx) DESC) AS n
                     FROM w GROUP BY mac, app)
            SELECT w.mac, l.device, l.network, l.ip,
                   SUM(w.rx)::bigint AS rx, SUM(w.tx)::bigint AS tx, MAX(w.last_seen) AS last_seen,
                   (SELECT json_agg(json_build_object('app', a.app, 'bytes', a.bytes) ORDER BY a.n)
                      FROM apps a WHERE a.mac = w.mac AND a.n <= 3) AS top_apps
            FROM w JOIN latest l USING (mac)
            WHERE (%(network)s::text IS NULL OR l.network = %(network)s)
            GROUP BY w.mac, l.device, l.network, l.ip
            ORDER BY SUM(w.rx + w.tx) DESC
            """, {"hours": hours, "network": network})
        return [_jsonable(dict(r)) for r in cur.fetchall()]


def get_traffic_apps(hours: int = 24, device: str | None = None, network: str | None = None, limit: int = 50) -> list:
    """Per-app download/upload over the window, for one device (MAC, IP or name substring),
    one network, or everything."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute(f"""
            SELECT t.app, MAX(t.category) AS category, SUM(t.rx)::bigint AS rx, SUM(t.tx)::bigint AS tx,
                   COUNT(DISTINCT t.mac) AS devices, MAX(t.last_seen) AS last_seen
            FROM traffic_usage t
            WHERE {_TRAFFIC_WINDOW} AND {_TRAFFIC_DEVICE}
              AND (%(network)s::text IS NULL OR t.network = %(network)s)
            GROUP BY t.app ORDER BY SUM(t.rx + t.tx) DESC LIMIT %(limit)s
            """, {"hours": hours, "device": device, "network": network, "limit": limit})
        return [_jsonable(dict(r)) for r in cur.fetchall()]


def get_traffic_series(hours: int = 24, device: str | None = None, network: str | None = None) -> list:
    """Hourly download/upload (one device, one network, or everything); empty hours are 0."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute(f"""
            SELECT h.hour, COALESCE(SUM(t.rx), 0)::bigint AS rx, COALESCE(SUM(t.tx), 0)::bigint AS tx
            FROM generate_series(date_trunc('hour', now() - (%(hours)s || ' hours')::interval),
                                 date_trunc('hour', now()), interval '1 hour') AS h(hour)
            LEFT JOIN traffic_usage t ON t.hour = h.hour AND {_TRAFFIC_DEVICE}
                 AND (%(network)s::text IS NULL OR t.network = %(network)s)
            GROUP BY h.hour ORDER BY h.hour
            """, {"hours": hours, "device": device, "network": network})
        return [_jsonable(dict(r)) for r in cur.fetchall()]


# ---- device behaviour baselines (router_agent/anomaly.py) ----

def get_new_domains_since(since) -> tuple[list, dict]:
    """First lookups (dns_first_seen) after `since`, with the device's watch start, plus
    {device_key: [every domain the device looked up before `since`]} for those devices."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute("""
            SELECT f.device_key, f.domain, f.first_seen, d.device, d.network, d.mac, d.first_seen AS watched_since
            FROM dns_first_seen f JOIN dns_devices d USING (device_key)
            WHERE f.first_seen > %s ORDER BY f.first_seen""", (since,))
        recent = [dict(r) for r in cur.fetchall()]
        keys = sorted({r["device_key"] for r in recent})
        known: dict = {k: [] for k in keys}
        if keys:
            cur.execute("SELECT device_key, domain FROM dns_first_seen WHERE device_key = ANY(%s) AND first_seen <= %s",
                        (keys, since))
            for r in cur.fetchall():
                known[r["device_key"]].append(r["domain"])
    return recent, known


def get_hourly_upload(days: int = 14) -> list:
    """Upload bytes per device per hour over the last `days`: [{mac, device, network, hour, tx}]."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute("""
            SELECT mac, hour, SUM(tx)::bigint AS tx,
                   (ARRAY_AGG(device ORDER BY last_seen DESC))[1] AS device,
                   (ARRAY_AGG(network ORDER BY last_seen DESC))[1] AS network
            FROM traffic_usage WHERE hour > now() - make_interval(days => %s)
            GROUP BY mac, hour ORDER BY mac, hour""", (int(days),))
        return [dict(r) for r in cur.fetchall()]


# ---- long-range history (daily summaries; raw tables when TimescaleDB is absent) ----

_RAW_DAILY = {  # same columns as SUMMARIES, computed from the raw table
    "traffic_daily": "(SELECT date_trunc('day', hour) AS day, mac, rx, tx, device, network FROM traffic_usage)",
    "dns_daily": "(SELECT date_trunc('day', hour) AS day, device_key, count AS queries,"
                 " CASE WHEN blocked THEN count ELSE 0 END AS blocked, device, network FROM dns_lookups)",
}
HISTORY_BUCKETS = ("day", "week", "month")


def _daily_source(cur, view: str) -> str:
    return view if view in _summaries(cur) else _RAW_DAILY[view]


def _history(view: str, key: str, sums: tuple, rank: str, days: int, bucket: str, device, network, top: int,
             start=None, end=None) -> dict:
    """{series: [{period, <sums>}], devices: [{<key>, device, network, <sums>}]} over the last
    `days` (whole days, UTC) or [start, end), one point per day/week/month; devices = the `top` by `rank`."""
    if bucket not in HISTORY_BUCKETS:
        raise ValueError(f"bucket must be one of {HISTORY_BUCKETS}")
    ensure_schema()
    totals = ", ".join(f"COALESCE(SUM(s.{c}), 0)::bigint AS {c}" for c in sums)
    where = f"""s.day >= COALESCE(%(start)s::timestamptz, date_trunc('day', now() - make_interval(days => %(days)s)))
        AND (%(end)s::timestamptz IS NULL OR s.day < %(end)s)
        AND (%(device)s::text IS NULL OR s.{key} ILIKE %(device)s OR s.device ILIKE '%%' || %(device)s || '%%')
        AND (%(network)s::text IS NULL OR s.network = %(network)s)"""
    params = {"days": int(days), "device": device, "network": network, "top": int(top), "start": start, "end": end}
    with _cursor() as cur:
        src = _daily_source(cur, view)
        cur.execute(f"""
            SELECT date_trunc('{bucket}', s.day) AS period, {totals}, COUNT(DISTINCT s.{key}) AS devices
            FROM {src} s WHERE {where} GROUP BY 1 ORDER BY 1""", params)
        series = [_jsonable(dict(r)) for r in cur.fetchall()]
        cur.execute(f"""
            SELECT s.{key}, (ARRAY_AGG(s.device ORDER BY s.day DESC))[1] AS device,
                   (ARRAY_AGG(s.network ORDER BY s.day DESC))[1] AS network, {totals}
            FROM {src} s WHERE {where} GROUP BY s.{key}
            ORDER BY {rank} DESC LIMIT %(top)s""", params)
        devices = [_jsonable(dict(r)) for r in cur.fetchall()]
    return {"series": series, "devices": devices}


def get_traffic_history(days: int = 90, bucket: str = "day", device: str | None = None,
                        network: str | None = None, top: int = 20, start=None, end=None) -> dict:
    """Internet usage per day/week/month (rx = download, tx = upload) and the top devices."""
    return _history("traffic_daily", "mac", ("rx", "tx"), "SUM(s.rx + s.tx)", days, bucket, device, network, top,
                    start, end)


def get_dns_history(days: int = 90, bucket: str = "day", device: str | None = None,
                    network: str | None = None, top: int = 20, start=None, end=None) -> dict:
    """DNS queries and blocked queries per day/week/month and the top devices."""
    return _history("dns_daily", "device_key", ("queries", "blocked"), "SUM(s.queries)", days, bucket, device, network,
                    top, start, end)


# ---- weekly / monthly report (router_agent/report.py): one window [start, end) ----

def get_check_stats(start, end) -> dict:
    """From the 5-minute check rows: how many, WAN up share, clients, memory, router reboots
    (uptime going backwards between consecutive checks)."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute("""
            WITH c AS (SELECT collected_at, wan_up, client_count, mem_used_pct, uptime_seconds,
                              lag(uptime_seconds) OVER (ORDER BY collected_at) AS prev_uptime
                       FROM snapshots WHERE kind = 'check' AND collected_at >= %s AND collected_at < %s)
            SELECT count(*) AS checks, count(*) FILTER (WHERE wan_up) AS wan_up_checks,
                   round(avg(client_count), 1) AS clients_avg, max(client_count) AS clients_max,
                   round(avg(mem_used_pct), 1) AS mem_used_pct_avg, max(mem_used_pct) AS mem_used_pct_max,
                   count(*) FILTER (WHERE uptime_seconds < prev_uptime) AS reboots
            FROM c""", (start, end))
        return _jsonable(dict(cur.fetchone()))


def get_line_stats(start, end) -> dict:
    """spdMerlin speedtests that ran in the window (one per distinct test) and connmon's
    24h ping/jitter averages as reported by the checks."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute("""
            SELECT DISTINCT ON (st->>'last_at') st->>'last_at' AS at,
                   (st->>'download_mbps')::float AS download_mbps, (st->>'upload_mbps')::float AS upload_mbps,
                   (st->>'latency_ms')::float AS latency_ms
            FROM (SELECT snapshot->'wan'->'speedtest' AS st FROM snapshots
                  WHERE kind = 'check' AND collected_at >= %s AND collected_at < %s + interval '1 day') x
            WHERE st->>'last_at' IS NOT NULL AND (st->>'last_at')::timestamptz >= %s
              AND (st->>'last_at')::timestamptz < %s
            ORDER BY st->>'last_at'""", (start, end, start, end))
        tests = [dict(r) for r in cur.fetchall()]
        cur.execute("""
            SELECT round(avg((snapshot->'wan'->'connmon'->>'ping_ms_avg')::numeric), 2) AS ping_ms_avg,
                   max((snapshot->'wan'->'connmon'->>'ping_ms_max')::numeric) AS ping_ms_max,
                   round(avg((snapshot->'wan'->'connmon'->>'jitter_ms_avg')::numeric), 2) AS jitter_ms_avg,
                   min((snapshot->'wan'->'connmon'->>'line_quality_min_pct')::numeric) AS line_quality_min_pct
            FROM snapshots WHERE kind = 'check' AND collected_at >= %s AND collected_at < %s""", (start, end))
        connmon = _jsonable(dict(cur.fetchone()))
    return {"speedtests": tests, "connmon": connmon}


def get_events_between(start, end) -> list:
    """watchdog_events (watchdog + router events) in the window, oldest first: [{ts, event, detail}]."""
    ensure_schema()
    with _cursor() as cur:
        cur.execute("SELECT ts, event, detail FROM watchdog_events WHERE ts >= %s AND ts < %s ORDER BY ts",
                    (start, end))
        return [_jsonable(dict(r)) for r in cur.fetchall()]
