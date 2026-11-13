"""Per-device internet usage from the router's Traffic Analyzer.

The firmware's Traffic Analyzer (bwdpi, "Traffic Analyzer > Statistic", nvram
bwdpi_db_enable=1) writes per-device, per-app WAN byte counts to SQLite on the
router about once an hour: rows (mac, app_name, cat_name, timestamp, tx, rx), where
tx/rx are the bytes since the previous write and one write spans a few consecutive
seconds. The router keeps roughly two weeks of it.

Every 5-minute check reads only the rows newer than the last one archived (a
timestamp cursor in .traffic_cursor.json), names each MAC the same way the DNS
archive does, and adds the bytes into Postgres `traffic_usage`, one row per
(hour, device, app). Rows from the last 30 s are left for the next check in case
the router is still writing that batch. The cursor only advances after Postgres
accepted the batch. Nothing here calls an LLM.

tx = upload (device -> internet), rx = download.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .dnslog import DEFAULT_NETWORKS, Namer

logger = logging.getLogger(__name__)

TA_DB = "/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db"
SETTLE_SECONDS = 30
MAX_ROWS = 200_000  # first run reads the router's whole history (~66k rows for 13 days)


def read_cmd(after: int) -> str:
    # first line: router clock, then the new rows (| separated; app names never contain |)
    return (
        f"date +%s; [ -f {TA_DB} ] && sqlite3 -separator '|' {TA_DB} "
        f"\"SELECT mac, app_name, cat_name, timestamp, tx, rx FROM traffic "
        f"WHERE timestamp > {int(after)} AND timestamp <= strftime('%s','now') - {SETTLE_SECONDS} "
        f"ORDER BY timestamp LIMIT {MAX_ROWS}\""
    )


def parse(out: str):
    """-> (router_now, [(mac, app, cat, ts, tx, rx), ...])"""
    lines = out.splitlines()
    if not lines or not lines[0].strip().isdigit():
        raise ValueError(f"unexpected Traffic Analyzer output: {out[:120]!r}")
    rows = []
    for line in lines[1:]:
        p = line.split("|")
        if len(p) != 6:
            continue
        try:
            rows.append((p[0].upper(), p[1] or "Unknown", p[2] or "Unknown", int(p[3]), int(p[4] or 0), int(p[5] or 0)))
        except ValueError:
            continue
    return int(lines[0]), rows


def bucket(ts: int) -> datetime:
    """A write covers the ~hour before it; file it under the hour its midpoint falls in."""
    return datetime.fromtimestamp(ts - 1800, timezone.utc).replace(minute=0, second=0, microsecond=0)


def aggregate(rows, namer: Namer, hidden_apps=()) -> List[Dict]:
    hidden_apps = {a.lower() for a in hidden_apps}
    mac_ip = {}
    for ip, mac in namer.ip_mac.items():
        # prefer the IPv4 address a device holds on one of the known networks
        if mac not in mac_ip or (":" in mac_ip[mac] and ":" not in ip):
            mac_ip[mac] = ip
    who: Dict[str, Dict] = {}
    out: Dict[tuple, Dict] = {}
    for mac, app, cat, ts, tx, rx in rows:
        if not (tx or rx) or app.lower() in hidden_apps:
            continue
        w = who.get(mac)
        if w is None:
            ip = mac_ip.get(mac)
            if ip:
                w = namer(ip)
            else:  # not currently on the network: name it from what we know, network unknown
                w = {"device": namer.names.get(mac) or "unnamed device", "network": "Other"}
            w = who[mac] = {"device": w["device"], "network": w["network"], "ip": ip}
        hour = bucket(ts)
        k = (hour, mac, app)
        r = out.get(k)
        if r is None:
            r = out[k] = {"hour": hour, "mac": mac, "app": app, "category": cat, "tx": 0, "rx": 0,
                          "device": w["device"], "network": w["network"], "ip": w["ip"],
                          "last_seen": datetime.fromtimestamp(ts, timezone.utc)}
        r["tx"] += tx
        r["rx"] += rx
        r["last_seen"] = max(r["last_seen"], datetime.fromtimestamp(ts, timezone.utc))
    return list(out.values())


def summarize(rows: List[Dict], top: int = 5) -> Dict:
    dev: Dict[str, Dict] = {}
    for r in rows:
        d = dev.setdefault(r["mac"], {"device": r["device"], "network": r["network"], "rx": 0, "tx": 0})
        d["rx"] += r["rx"]
        d["tx"] += r["tx"]
    busiest = sorted(dev.values(), key=lambda d: d["rx"] + d["tx"], reverse=True)[:top]
    return {
        "rx": sum(d["rx"] for d in dev.values()),
        "tx": sum(d["tx"] for d in dev.values()),
        "devices": len(dev),
        "top_devices": busiest,
    }


class TrafficLog:
    def __init__(self, base: Path, cfg: Optional[Dict] = None):
        cfg = cfg or {}
        self.base = Path(base)
        self.cursor_path = self.base / ".traffic_cursor.json"
        self.networks = cfg.get("networks") or DEFAULT_NETWORKS
        self.aliases = cfg.get("aliases")
        self.hide_apps = cfg.get("hide_apps") or ()

    def collect(self, collector, snapshot: Dict, grouped: Dict[str, List[Dict]]) -> Optional[Dict]:
        """Archive new Traffic Analyzer rows; return a small summary for the snapshot
        (or {"status": ...} when the router or Postgres is unavailable)."""
        from . import db

        try:
            after = int(json.loads(self.cursor_path.read_text())["ts"])
        except (OSError, ValueError, KeyError, TypeError):
            after = 0
        try:
            res = collector.run_command(read_cmd(after), timeout=60)
            _, rows = parse(res["out"])
        except Exception as e:
            logger.warning("Traffic Analyzer unreadable: %s", e)
            return {"status": "router_unreadable", "error": str(e)[:200]}
        finally:
            collector.close()
        more = len(rows) >= MAX_ROWS
        if more:  # the cap may have split the newest write; leave all of it for the next check
            cut = rows[-1][3]
            rows = [r for r in rows if r[3] < cut]
        if not rows:
            return {"new_rows": 0}
        agg = aggregate(rows, Namer(self.base, snapshot, grouped, self.networks, self.aliases), self.hide_apps)
        try:
            db.insert_traffic_rows(agg)
        except Exception as e:
            logger.warning("Postgres traffic archive failed; will retry these rows next check: %s", e)
            return {"status": "archive_unavailable", "error": str(e)[:200]}
        newest = max(r[3] for r in rows)
        self.cursor_path.write_text(json.dumps({"ts": newest}))
        summary = summarize(agg)
        summary["new_rows"] = len(rows)
        summary["through"] = datetime.fromtimestamp(newest, timezone.utc).isoformat(timespec="seconds")
        if more:
            summary["more_pending"] = True
        return summary
