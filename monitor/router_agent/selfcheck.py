"""Monitor the monitor: is network-ai itself still doing its job?

The watchdog (always running) calls run() every few minutes for:

  checks     no successful 5-minute check for `check_max_age_minutes` (default 20):
             the timer stopped, SSH to the router fails, or the check crashes
  daily      no daily analysis for `daily_max_age_hours` (26), or the last one failed
  backup     newest router backup older than `backup_max_age_hours` (26)
  postgres   the archive is unreachable (after 15 min, short blips are ignored)
  dashboard  http://<dashboard.host>:<port>/api/state does not answer (after 10 min)
  disk       less than `disk_min_free_pct` (10 %) free where logs/ lives
  traffic    no new Traffic Analyzer rows for `traffic_max_age_hours` (3) while
             `traffic_analyzer:` is on: the router stopped writing its statistics
  iot_lan    the router's IoT -> LAN LOG rule is gone while `iot_lan:` is on
             (router_agent/iotlan.py; reinstalled by router/firewall-start)
  cert       the certificate the router's web UI serves (/etc/cert.pem, usually Let's
             Encrypt for the DDNS name) expires in under `cert_min_days` (20): renewal
             (every 60 days, cron `LetsEncrypt`) has failed or is switched off
  router_setup  something the router's hook scripts / add-ons set up and that was there
             before is missing: a rule, redirect, cron job, process or script
             (router_agent/routersetup.py; 15 min grace for reboots)

and the 5-minute check calls run(only=("watchdog",)) to watch the watchdog in turn
(its status file older than 5 minutes = it died or hangs), so each guards the other.

Each problem is reported once when it starts (after its grace period) as a
`monitor_problem` router event -> Events card, Postgres, Telegram (`monitor`), and
once more as `monitor_ok` when it clears. State: logs/.selfcheck.json.

If the whole host is down nothing local can report it: set `monitor.heartbeat_url`
(e.g. a free healthchecks.io check) and the watchdog pings it while the checks are
fresh; the external service alerts when the pings stop.
"""
import fcntl
import json
import logging
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

from . import remedy

logger = logging.getLogger(__name__)

STATE_FILE = ".selfcheck.json"
TITLES = {
    "checks": "5-minute checks", "daily": "daily analysis", "backup": "router backup",
    "postgres": "Postgres archive", "dashboard": "dashboard", "disk": "disk space", "watchdog": "watchdog",
    "traffic": "Traffic Analyzer data", "iot_lan": "IoT → LAN logging", "router_setup": "router setup", "cert": "router certificate",
}
# alert only once a problem persisted this long (a restart or reboot would otherwise alert on stale
# files that the next run refreshes); unlisted checks alert at once
GRACE = {"checks": timedelta(minutes=10), "postgres": timedelta(minutes=15), "dashboard": timedelta(minutes=10),
         "router_setup": timedelta(minutes=15)}
WATCHDOG_MAX_AGE = timedelta(minutes=5)


def _age(ts: datetime, now: datetime) -> str:
    s = int((now - ts).total_seconds())
    if s < 3600:
        return f"{s // 60} min"
    if s < 2 * 86400:
        return f"{s // 3600} h {s % 3600 // 60:02d} min"
    return f"{s // 86400} days"


def _parse_ts(v) -> datetime | None:
    try:
        t = datetime.fromisoformat(v)
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _read(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- individual checks
# each returns a problem description, or None when fine

def check_checks(log_dir: Path, now: datetime, max_age: timedelta) -> str | None:
    t = _parse_ts(((_read(log_dir / "latest.json") or {}).get("snapshot") or {}).get("collected_at"))
    if t is None:
        return "no check has written logs/latest.json yet"
    if now - t > max_age:
        return f"last successful check {_age(t, now)} ago — timer stopped, router SSH failing or the check crashing"
    return None


def check_daily(log_dir: Path, now: datetime, max_age: timedelta) -> str | None:
    records = sorted(log_dir.glob("*-????-??-??T*.json"), key=lambda p: p.stat().st_mtime)
    if not records:
        return None  # fresh install: nothing to compare against yet
    newest = records[-1]
    t = datetime.fromtimestamp(newest.stat().st_mtime, UTC)
    if now - t > max_age:
        return f"last daily analysis {_age(t, now)} ago (network-ai-collect.timer)"
    analysis = (_read(newest) or {}).get("analysis") or {}
    if analysis.get("source") == "none" or analysis.get("error"):
        return f"last daily analysis failed: {str(analysis.get('error') or 'no LLM answered')[:200]}"
    return None


def check_backup(backup_dir: Path, now: datetime, max_age: timedelta) -> str | None:
    if not backup_dir.is_dir():
        return None  # backups not set up on this host
    done = [p for p in backup_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]
    if not done:
        return f"no completed router backup in {backup_dir}"
    t = datetime.fromtimestamp(max(p.stat().st_mtime for p in done), UTC)
    if now - t > max_age:
        return f"newest router backup is {_age(t, now)} old (router-backup.timer)"
    return None


def check_postgres() -> str | None:
    if not os.getenv("PGHOST"):
        return None  # archive not configured
    from . import db

    try:
        db.ping()
    except Exception as e:
        return f"unreachable: {str(e).strip().splitlines()[0][:160] if str(e).strip() else type(e).__name__}"
    return None


def check_dashboard(host: str, port: int) -> str | None:
    host = "127.0.0.1" if host in ("", "0.0.0.0") else host
    try:
        r = requests.get(f"http://{host}:{port}/api/state", timeout=5)
        r.raise_for_status()
    except requests.RequestException as e:
        return f"http://{host}:{port} not answering ({type(e).__name__})"
    return None


def check_disk(path: Path, min_free_pct: float) -> str | None:
    u = shutil.disk_usage(path)
    free = 100 * u.free / u.total
    if free < min_free_pct:
        return f"only {free:.0f} % free ({u.free // 2**30} GB) on the disk holding {path}"
    return None


def check_traffic(log_dir: Path, now: datetime, max_age: timedelta) -> str | None:
    cur = _read(log_dir / ".traffic_cursor.json") or {}
    if not cur.get("ts"):
        return None  # nothing archived yet
    t = datetime.fromtimestamp(int(cur["ts"]), UTC)
    if now - t > max_age:
        return (f"newest Traffic Analyzer row is {_age(t, now)} old: the router stopped writing "
                "/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db (is the firmware's hour_monitor running?)")
    return None


def check_iot_lan(log_dir: Path) -> str | None:
    snap = (_read(log_dir / "latest.json") or {}).get("snapshot") or {}
    if (snap.get("iot_lan") or {}).get("logging") is False:
        return ("the router's IoT → LAN LOG rule is missing (firewall restarted without "
                "/jffs/scripts/firewall-start?): blocked attempts are no longer seen")
    return None


def check_router_setup(log_dir: Path) -> str | None:
    from .routersetup import describe_missing

    snap = (_read(log_dir / "latest.json") or {}).get("snapshot") or {}
    missing = (snap.get("router_setup") or {}).get("missing")
    if missing:
        return f"missing on the router: {describe_missing(missing)}"
    return None


def check_cert(log_dir: Path, now: datetime, min_days: float) -> str | None:
    snap = (_read(log_dir / "latest.json") or {}).get("snapshot") or {}
    services = snap.get("services") or {}
    cert = services.get("cert") or {}
    end = _parse_ts(cert.get("not_after"))
    if end is None:
        return None  # no certificate read (older check, or openssl missing)
    left = end - now
    if left >= timedelta(days=min_days):
        return None
    what = f"{cert.get('subject') or 'router'} ({cert.get('issuer') or 'unknown issuer'})"
    days = abs(left.total_seconds()) / 86400
    span = f"{days:.0f} days" if days >= 2 else f"{days * 24:.0f} h"
    when = f"expired {span} ago" if left <= timedelta(0) else f"expires in {span}"
    renew = ""
    if cert.get("lets_encrypt"):
        le = (services.get("nvram") or {}).get("le_enable")
        renew = (" Let's Encrypt renewal is switched off (le_enable=" + str(le) + ")." if le not in (None, "1")
                 else " Let's Encrypt renewal is on but has not succeeded: check port 80 reachability and DDNS.")
    return f"certificate {what} {when} ({end:%Y-%m-%d}).{renew}"


def check_watchdog(log_dir: Path, now: datetime) -> str | None:
    t = _parse_ts((_read(log_dir / "watchdog_status.json") or {}).get("checked_at"))
    if t is None or now - t > WATCHDOG_MAX_AGE:
        return ("not running" if t is None else f"silent for {_age(t, now)}") + \
            " — WAN outages are not detected or auto-fixed (network-ai-watchdog.service)"
    return None


def gather(cfg: dict, log_dir: Path, now: datetime, only=None, skip=()) -> dict[str, str | None]:
    m = (cfg or {}).get("monitor") or {}
    checks = {
        "checks": lambda: check_checks(log_dir, now, timedelta(minutes=m.get("check_max_age_minutes", 20))),
        "daily": lambda: check_daily(log_dir, now, timedelta(hours=m.get("daily_max_age_hours", 26))),
        "backup": lambda: check_backup(Path(m.get("backup_dir", "/var/backups/router")), now,
                                       timedelta(hours=m.get("backup_max_age_hours", 26))),
        "postgres": check_postgres,
        "dashboard": lambda: check_dashboard(((cfg or {}).get("dashboard") or {}).get("host", "127.0.0.1"),
                                             ((cfg or {}).get("dashboard") or {}).get("port", 8080)),
        "disk": lambda: check_disk(log_dir, m.get("disk_min_free_pct", 10)),
        "watchdog": lambda: check_watchdog(log_dir, now),
        "traffic": lambda: check_traffic(log_dir, now, timedelta(hours=m.get("traffic_max_age_hours", 3)))
        if (cfg or {}).get("traffic_analyzer") else None,
        "iot_lan": lambda: check_iot_lan(log_dir) if (cfg or {}).get("iot_lan") is not None else None,
        "cert": lambda: check_cert(log_dir, now, m.get("cert_min_days", 20)),
        "router_setup": lambda: check_router_setup(log_dir) if (cfg or {}).get("router_setup", {}) is not False else None,
    }
    out = {}
    for name, fn in checks.items():
        if (only and name not in only) or name in skip:
            continue
        try:
            out[name] = fn()
        except Exception as e:  # a broken check must not hide the others
            out[name] = f"check itself failed: {e}"
    return out


# ---------------------------------------------------------------- state + events

def update_state(state: dict, results: dict[str, str | None], now: datetime) -> list[dict]:
    """Fold results into `state` (mutated); return the router events to emit."""
    events = []
    ts = now.isoformat(timespec="seconds")
    for name, problem in results.items():
        cur = state.get(name)
        if problem:
            if cur is None:
                cur = state[name] = {"since": ts, "alerted": False}
            cur["problem"] = problem
            since = _parse_ts(cur["since"]) or now
            if not cur["alerted"] and now - since >= GRACE.get(name, timedelta(0)):
                cur["alerted"] = True
                events.append({"ts": ts, "event": "monitor_problem", "check": name, "title": TITLES.get(name, name),
                               "problem": problem, "since": cur["since"]})
        elif cur is not None:
            if cur.get("alerted"):
                events.append({"ts": ts, "event": "monitor_ok", "check": name, "title": TITLES.get(name, name),
                               "since": cur["since"], "problem": cur.get("problem")})
            del state[name]
    return events


def run(cfg: dict, log_dir, only=None, skip=(), now: datetime | None = None) -> dict:
    """Run the checks, record transitions as router events. Never raises."""
    from .events import append_router_event

    log_dir = Path(log_dir)
    now = now or datetime.now(UTC)
    try:
        results = gather(cfg, log_dir, now, only=only, skip=skip)
        with open(log_dir / ".selfcheck.lock", "w") as lock:  # watchdog and check both write the state
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = _read(log_dir / STATE_FILE) or {}
            events = update_state(state, results, now)
            (log_dir / STATE_FILE).write_text(json.dumps(state, indent=1))
        for e in events:
            if e["event"] == "monitor_problem":  # known fixes: Telegram buttons / auto (router_agent/remedy.py)
                e["fixes"] = [{"id": f, "title": remedy.FIXES[f].title, "auto": remedy.FIXES[f].auto}
                              for f in remedy.fixes_for(e["check"], log_dir)]
            append_router_event(log_dir, e)
        # only the checks this process evaluated: watchdog and the 5-minute check each fix their own
        remedy.auto_fix(cfg, log_dir, {k: state[k] for k in results if k in state}, now)
        heartbeat(cfg, results)
        return results
    except Exception as e:
        logger.warning("selfcheck failed: %s", e)
        return {}


def heartbeat(cfg: dict, results: dict) -> None:
    """Ping the external dead-man's switch while the 5-minute checks are healthy."""
    url = ((cfg or {}).get("monitor") or {}).get("heartbeat_url")
    if not url or "checks" not in results or results["checks"]:
        return
    try:
        requests.get(url, timeout=10)
    except requests.RequestException as e:
        logger.info("heartbeat ping failed: %s", e)
