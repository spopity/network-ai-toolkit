"""Audit trail: every command Tshoot runs, proposes or is refused.

Always appended to logs/audit.jsonl; also archived (best-effort) to a
``tshoot_audit`` table so it survives log rotation. Postgres being down never
blocks troubleshooting.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tshoot_audit (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    session_id TEXT,
    event TEXT NOT NULL,
    command TEXT,
    kind TEXT,
    decision TEXT,
    exit_code INT,
    duration_ms INT,
    detail JSONB
);
CREATE INDEX IF NOT EXISTS idx_tshoot_audit_ts ON tshoot_audit (ts DESC);
"""


class AuditLog:
    def __init__(self, path: Path, pg_enabled: bool = True):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.pg_enabled = pg_enabled and bool(os.getenv("PGHOST"))
        self._schema_ready = False
        self._pg_down_until = 0.0
        self._lock = threading.Lock()

    def record(self, event: str, session_id: str = None, command: str = None, kind: str = None,
               decision: str = None, exit_code: int = None, duration_ms: int = None, **detail):
        row = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "session_id": session_id, "event": event, "command": command, "kind": kind,
            "decision": decision, "exit_code": exit_code, "duration_ms": duration_ms, "detail": detail,
        }
        with self._lock:
            with self.path.open("a") as f:
                f.write(json.dumps(row) + "\n")
        if self.pg_enabled:
            threading.Thread(target=self._to_pg, args=(row,), daemon=True).start()

    def recent(self, limit: int = 100) -> list:
        if not self.path.exists():
            return []
        lines = self.path.read_text().splitlines()[-limit:]
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _to_pg(self, row: dict):
        if time.time() < self._pg_down_until:
            return
        try:
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(
                host=os.environ["PGHOST"], port=int(os.getenv("PGPORT", 5432)),
                dbname=os.environ["PGDATABASE"], user=os.environ["PGUSER"],
                password=os.environ["PGPASSWORD"], connect_timeout=3,
            )
            try:
                with conn, conn.cursor() as cur:
                    if not self._schema_ready:
                        cur.execute(SCHEMA_SQL)
                        self._schema_ready = True
                    cur.execute(
                        "INSERT INTO tshoot_audit (ts, session_id, event, command, kind, decision, exit_code, duration_ms, detail)"
                        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (row["ts"], row["session_id"], row["event"], row["command"], row["kind"],
                         row["decision"], row["exit_code"], row["duration_ms"], psycopg2.extras.Json(row["detail"])),
                    )
            finally:
                conn.close()
        except Exception as e:
            self._pg_down_until = time.time() + 60
            logger.warning("audit: postgres archive unavailable (%s); JSONL only for 60s", e)
