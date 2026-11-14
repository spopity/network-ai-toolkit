"""Unusual device behaviour, from the DNS and traffic archives. No LLM.

Every 5-minute check looks for two things an appliance (camera, plug, TV, speaker,
NAS, server: anything that isn't a phone, tablet or computer) should not do:

  new_domains  >= `new_domains_per_hour` (4) new *base* domains (example.com, not
               every cdn1.example.com) within the last hour. Measured 2026-11-14 on this
               network: appliances never went above 2 an hour, while phones and
               laptops reach 30-50 (normal browsing -- which is why they're skipped).
  upload       an hour with >= `upload_min_mb` (100 MB) uploaded AND >= `upload_factor`
               (10x) the device's usual peak (95th percentile of its hourly uploads over
               the last 14 days). A camera clip upload (~50 MB) stays below the floor.

A device needs `min_history_hours` (72) of baseline first: DNS watch time for
new_domains, hours with traffic for upload. The Guest network is skipped (visitors'
phones), as are names in `anomaly.ignore_devices`. Each (kind, device) alerts at most
once per `cooldown_hours` (24) as an `anomaly` router event -> Events card, Postgres,
Telegram (`anomaly`). State: logs/.anomaly_state.json; the first run (no state file)
records current findings silently.
"""
import json
import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .netmap import classify_type

logger = logging.getLogger(__name__)

STATE_FILE = ".anomaly_state.json"
BROWSING = {"phone", "tablet", "laptop", "computer"}
SKIP_NETWORKS = {"Guest"}
DEFAULTS = {"new_domains_per_hour": 4, "upload_min_mb": 100, "upload_factor": 10,
            "min_history_hours": 72, "cooldown_hours": 24, "ignore_devices": []}
# second-level labels under which registrations happen one level deeper (example.co.uk)
_SLD = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go"}


def base_domain(domain: str) -> str:
    p = domain.lower().rstrip(".").split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in _SLD:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def is_appliance(device: str | None, network: str | None, mac: str | None, ignore) -> bool:
    if (network or "") in SKIP_NETWORKS:
        return False
    names = {x.lower() for x in ignore or []}
    if (device or "").lower() in names or (mac or "").lower() in names:
        return False
    return classify_type(device or "", None, None, (mac or "").upper()) not in BROWSING


def find_new_domain_bursts(recent: list[dict], known: dict[str, list[str]], now: datetime, cfg: dict) -> list[dict]:
    """recent: dns_first_seen rows of the last hour (with device info); known: each device's
    earlier domains. -> one finding per appliance with too many new base domains."""
    min_watch = timedelta(hours=cfg["min_history_hours"])
    seen = {k: {base_domain(d) for d in v} for k, v in known.items()}
    new: dict[str, dict] = {}
    for r in sorted(recent, key=lambda r: r["first_seen"]):
        k = r["device_key"]
        if r["first_seen"] - r["watched_since"] < min_watch:
            continue
        if not is_appliance(r["device"], r["network"], r.get("mac"), cfg["ignore_devices"]):
            continue
        b = base_domain(r["domain"])
        if b in seen.setdefault(k, set()):
            continue
        seen[k].add(b)
        f = new.setdefault(k, {"kind": "new_domains", "key": k, "device": r["device"], "network": r["network"],
                               "mac": r.get("mac"), "domains": []})
        f["domains"].append(b)
    out = []
    for f in new.values():
        if len(f["domains"]) >= cfg["new_domains_per_hour"]:
            f["summary"] = f"contacted {len(f['domains'])} new sites within an hour (usually at most 1-2)"
            out.append(f)
    return out


def find_upload_bursts(rows: list[dict], now: datetime, cfg: dict, gap: dict | None = None) -> list[dict]:
    """rows: hourly upload per device (db.get_hourly_upload). -> findings for appliances
    whose upload in the last 3 hours is far above their own baseline. `gap` ({"from", "to"}
    epoch seconds, traffic.GAP_FILE): the first write after a data gap holds the whole gap's
    bytes in one hour, so hours up to one past the gap's end are not judged."""
    recent_from = now - timedelta(hours=3)
    skip_until = datetime.fromtimestamp(int(gap["to"]), UTC) + timedelta(hours=1) if gap else None
    by_mac: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_mac[r["mac"]].append(r)
    floor = cfg["upload_min_mb"] * 1_000_000
    out = []
    for mac, hours in by_mac.items():
        latest = hours[-1]
        if not is_appliance(latest["device"], latest["network"], mac, cfg["ignore_devices"]):
            continue
        base = sorted(int(h["tx"]) for h in hours if h["hour"] < recent_from)
        if len(base) < cfg["min_history_hours"]:
            continue
        p95 = base[int(0.95 * (len(base) - 1))]
        burst = max((h for h in hours if h["hour"] >= recent_from and not (skip_until and h["hour"] <= skip_until)),
                    key=lambda h: int(h["tx"]), default=None)
        if burst is None:
            continue
        tx = int(burst["tx"])
        if tx >= floor and tx >= cfg["upload_factor"] * max(p95, 1):
            out.append({"kind": "upload", "key": mac, "device": latest["device"], "network": latest["network"],
                        "mac": mac, "hour": burst["hour"].isoformat(), "tx_mb": round(tx / 1e6),
                        "usual_mb": round(p95 / 1e6, 1),
                        "summary": f"uploaded {tx / 1e6:.0f} MB in an hour (usual peak {p95 / 1e6:.1f} MB)"})
    return out


def run(base: Path, cfg: dict | None, now: datetime | None = None) -> list[dict]:
    """Detect, apply the cooldown, emit `anomaly` router events. Never raises.
    -> the findings that were reported this time."""
    from . import db
    from .events import append_router_event

    now = now or datetime.now(UTC)
    c = {**DEFAULTS, **((cfg or {}).get("anomaly") or {})}
    findings: list[dict] = []
    try:
        recent, known = db.get_new_domains_since(now - timedelta(hours=1))
        findings += find_new_domain_bursts(recent, known, now, c)
    except Exception as e:
        logger.warning("anomaly: DNS baseline unavailable: %s", e)
    try:
        from .traffic import GAP_FILE

        try:
            gap = json.loads((Path(base) / GAP_FILE).read_text())
        except (OSError, ValueError):
            gap = None
        findings += find_upload_bursts(db.get_hourly_upload(14), now, c, gap)
    except Exception as e:
        logger.warning("anomaly: traffic baseline unavailable: %s", e)

    path = Path(base) / STATE_FILE
    try:
        state = json.loads(path.read_text())
        baseline = False
    except (OSError, ValueError):
        state, baseline = {}, True  # first run: record what is going on now, alert on nothing
    cooldown = timedelta(hours=c["cooldown_hours"])
    state = {k: v for k, v in state.items() if now - datetime.fromisoformat(v) < cooldown}
    reported = []
    for f in findings:
        k = f"{f['kind']}|{f['key']}"
        if k in state:
            continue
        state[k] = now.isoformat(timespec="seconds")
        if baseline:
            continue
        reported.append(f)
        try:
            append_router_event(base, {"ts": now.isoformat(timespec="seconds"), "event": "anomaly",
                                       **{x: f.get(x) for x in ("kind", "device", "network", "mac", "summary",
                                                                "domains", "tx_mb", "usual_mb")}})
        except Exception as e:
            logger.warning("anomaly: event not recorded: %s", e)
    try:
        path.write_text(json.dumps(state, indent=1))
    except OSError as e:
        logger.warning("anomaly: state not saved: %s", e)
    return reported
