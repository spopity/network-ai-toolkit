import gzip
import json
import logging
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from . import db
from .snapshot import wifi_client_macs

logger = logging.getLogger(__name__)

NEW_CLIENT_WINDOW = timedelta(hours=24)  # a client stays "new" for a day after it first appears


class SnapshotStore:
    """Daily (LLM-analyzed) records live in base/ as plain JSON for retention_days;
    5-minute checks go to base/checks/ gzipped for check_retention_hours.
    latest.json always mirrors the newest record of either kind."""

    def __init__(self, base_dir: str = "logs", retention_days: int = 14, check_retention_hours: int = 48):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self.checks = self.base / "checks"
        self.checks.mkdir(exist_ok=True)
        self.retention_days = retention_days
        self.check_retention_hours = check_retention_hours

    def write(self, router_name: str, record: dict, kind: str = "daily") -> Path:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(":", "-")
        body = json.dumps(record, indent=2)
        if kind == "check":
            path = self.checks / f"{router_name}-{ts}.json.gz"
            path.write_bytes(gzip.compress(json.dumps(record, separators=(",", ":")).encode()))
        else:
            path = self.base / f"{router_name}-{ts}.json"
            path.write_text(body)
        tmp = self.base / "latest.json.tmp"
        tmp.write_text(body)
        tmp.replace(self.base / "latest.json")  # atomic: the dashboard/Tshoot never read a half-written file

        try:
            db.insert_snapshot(record, kind=kind)
        except Exception as e:
            # local JSON write above is the source of truth; Postgres is best-effort archival
            logger.warning("Postgres archival failed (local write already succeeded): %s", e)

        return path

    def latest(self) -> dict:
        try:
            return json.loads((self.base / "latest.json").read_text())
        except (OSError, ValueError):
            return {}

    def track_clients(self, wifi: dict) -> Optional[List[str]]:
        """Record the current wifi clients in known_clients.json and return those first
        seen within NEW_CLIENT_WINDOW (None when there is no history yet to compare to).
        Only mesh-wide snapshots are tracked: older ones saw just the main router's radios."""
        path = self.base / "known_clients.json"
        now = datetime.now(timezone.utc)
        try:
            known = json.loads(path.read_text())
            baseline = False
        except (OSError, ValueError):
            known, baseline = self._seed_known_clients(), True

        for mac in (m.upper() for m in wifi_client_macs(wifi)):
            entry = known.setdefault(mac, {"first_seen": now.isoformat(timespec="seconds"), "baseline": baseline})
            entry["last_seen"] = now.isoformat(timespec="seconds")

        # forget devices unseen for the retention period -- they count as new if they come back
        cutoff = now - timedelta(days=self.retention_days)
        known = {m: e for m, e in known.items() if datetime.fromisoformat(e["last_seen"]) >= cutoff}
        path.write_text(json.dumps(known, indent=1))

        if baseline:
            return None
        current = {m.upper() for m in wifi_client_macs(wifi)}
        return [
            m for m in sorted(current)
            if not known[m].get("baseline") and now - datetime.fromisoformat(known[m]["first_seen"]) < NEW_CLIENT_WINDOW
        ]

    def _seed_known_clients(self) -> dict:
        """Start the registry from retained mesh-wide daily snapshots, all as baseline."""
        known = {}
        for f in self.base.glob("*-????-??-??T*.json"):
            try:
                wifi = json.loads(f.read_text())["snapshot"]["wifi"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if "nodes" not in wifi:
                continue
            seen = datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")
            for m in wifi_client_macs(wifi):
                known.setdefault(m.upper(), {"first_seen": seen, "baseline": True})["last_seen"] = seen
        return known

    def prune(self) -> int:
        removed = 0
        # only timestamped record files ("<router>-2026-10-14T03-00-54+00-00.json"), never state files
        for pattern_dir, pattern, max_age in (
            (self.base, "*-????-??-??T*.json", self.retention_days * 86400),
            (self.checks, "*-????-??-??T*.json.gz", self.check_retention_hours * 3600),
        ):
            cutoff = time.time() - max_age
            for f in pattern_dir.glob(pattern):
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    removed += 1
        return removed
