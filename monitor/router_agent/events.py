"""Events pushed by the router itself (Merlin /jffs/scripts/wan-event hook).

They complement the watchdog: the watchdog sees outages from the LAN side by
pinging the internet, the router reports its own WAN state transitions
(connecting / connected / disconnected / stopped) as they happen. Stored next
to the watchdog's events -- JSONL file as the source of truth, Postgres
`watchdog_events` table as the best-effort archive.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from . import db

ROUTER_EVENTS_FILE = "router_events.log"


def append_router_event(log_dir: Path, event: dict):
    with open(Path(log_dir) / ROUTER_EVENTS_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    db.insert_watchdog_event(event)


def read_router_events(log_dir: Path, limit: int = 20, since_hours: float = None) -> List[dict]:
    """Most recent first."""
    path = Path(log_dir) / ROUTER_EVENTS_FILE
    if not path.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours) if since_hours else None
    events = []
    for line in reversed(path.read_text().splitlines()):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if cutoff and datetime.fromisoformat(e["ts"]) < cutoff:
            break
        events.append(e)
        if len(events) >= limit:
            break
    return events


def watchdog_summary(log_dir: Path, since_hours: float = 24, watchdog_log: str = "watchdog.log") -> dict:
    """Outages the LAN-side watchdog measured in the window: count, total/longest downtime, auto-restarts."""
    path = Path(log_dir) / watchdog_log
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    downtimes, restarts = [], 0
    if path.exists():
        for line in path.read_text().splitlines()[-2000:]:
            try:
                e = json.loads(line)
                if datetime.fromisoformat(e["ts"]) < cutoff:
                    continue
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
            if e.get("event") == "recovered":
                downtimes.append(e.get("downtime_seconds") or 0)
            elif e.get("event") == "restart_triggered":
                restarts += 1
    return {
        "outages": len(downtimes),
        "total_downtime_s": round(sum(downtimes)),
        "longest_s": round(max(downtimes)) if downtimes else 0,
        "auto_restarts": restarts,
    }
