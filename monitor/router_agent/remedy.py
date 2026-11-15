"""Known fixes for self-check problems: run on their own (auto) or from a Telegram button.

The catalogue (FIXES) is fixed code, never chosen by an LLM: each fix is one command on
the router (over the monitor's SSH key) or on this host (systemctl), plus a verify command
that decides "fixed" / "fix failed". Which fixes apply to a problem comes from the
self-check name and, for `router_setup`, from the missing items (snapshot.router_setup).

  auto=True   low-risk and idempotent: the self-check runs it once the problem has been
              alerted, at most AUTO_MAX_PER_DAY times per fix in 24 h and not more often
              than every AUTO_MIN_GAP (remedy.auto: false in config.yml switches this off)
  auto=False  only on request: a [Fix] button under the Telegram alert (router_agent/
              telegram_bot.py) or `python -m router_agent.remedy --run <fix>`

Every attempt becomes a `remedy` router event (Events card, Postgres, Telegram `monitor`).

Buttons are tapped in the unprivileged bot (user netai), which only appends a request to
logs/.remedy-requests.jsonl; network-ai-remedy.path then starts network-ai-remedy.service
as root, which runs `--run-queue` here: requests are validated against FIXES again and
dropped when older than REQUEST_MAX_AGE.
"""
import argparse
import fcntl
import json
import logging
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_FILE = ".remedy.json"
REQUESTS_FILE = ".remedy-requests.jsonl"
LOCK_FILE = ".remedy.lock"
AUTO_MAX_PER_DAY = 2
AUTO_MIN_GAP = timedelta(minutes=15)
REQUEST_MAX_AGE = timedelta(minutes=10)


@dataclass(frozen=True)
class Fix:
    id: str
    title: str            # "Restart hour_monitor" -- button label and message headline
    where: str            # "router" | "host"
    cmd: str
    verify: str | None    # exit 0 = fixed; None = the next check will tell
    auto: bool
    note: str = ""        # what it touches, shown with the result


FIXES: dict[str, Fix] = {f.id: f for f in (
    Fix("hour_monitor", "Restart hour_monitor", "router",
        "pidof hour_monitor >/dev/null || (nohup /sbin/hour_monitor </dev/null >/dev/null 2>&1 &); sleep 3",
        "pidof hour_monitor", auto=True,
        note="firmware daemon that saves Traffic Analyzer statistics (`service start_hour_monitor` does not work)"),
    Fix("syslog_ng", "Restart syslog-ng", "router",
        "/opt/etc/init.d/S01syslog-ng restart; sleep 3", "pidof syslog-ng", auto=True,
        note="scribe's syslog-ng (router log collection)"),
    Fix("nat_start", "Re-run nat-start", "router",
        "sh /jffs/scripts/nat-start", "iptables -t nat -S DNSFILTER | grep -q REDIRECT", auto=True,
        note="Guest/IoT DNS + NTP redirects (idempotent: deletes then re-adds its rules)"),
    Fix("services_start", "Re-run services-start", "router",
        "sh /jffs/scripts/services-start", "[ -s /home/root/.ssh/authorized_keys ] && kill -0 \"$(cat /var/run/ntp-sdn.pid)\"",
        auto=True, note="root's SSH keys (Tshoot's key lives only there; every password change (chpass) empties "
                        "them) and the Guest/IoT NTP server (not restarted if running)"),
    Fix("firewall_start", "Re-run firewall-start", "router",
        'sh /jffs/scripts/firewall-start "$(nvram get wan0_pppoe_ifname)"', "iptables -S SDN_IA | grep -q 'br0 -o br54'",
        auto=False, note="restarts Skynet (reloads its blocklists, ~1 min) and the LAN/IoT rules"),
    Fix("dashboard", "Restart the dashboard", "host",
        "systemctl restart network-ai-dashboard.service; sleep 3", "systemctl is-active --quiet network-ai-dashboard.service",
        auto=True),
    Fix("watchdog", "Restart the watchdog", "host",
        "systemctl restart network-ai-watchdog.service; sleep 3", "systemctl is-active --quiet network-ai-watchdog.service",
        auto=True),
    Fix("run_check", "Run a check now", "host",
        "systemctl start network-ai-check.service", "systemctl is-active --quiet network-ai-check.timer", auto=False,
        note="one 5-minute check right away (shows whether SSH to the router works)"),
)}

# self-check name -> fixes (router_setup is resolved per missing item below)
CHECK_FIXES = {
    "traffic": ("hour_monitor",),
    "iot_lan": ("firewall_start",),
    "dashboard": ("dashboard",),
    "watchdog": ("watchdog",),
    "checks": ("run_check",),
}
# router_setup item prefix -> fix (first match wins)
ITEM_FIXES = (
    ("hour_monitor", "hour_monitor"),
    ("syslog_", "syslog_ng"),
    ("dns_redirect:", "nat_start"), ("ntp_redirect:", "nat_start"),
    ("sdn_accept:", "firewall_start"), ("skynet_", "firewall_start"),
    ("ntp_sdn", "services_start"), ("root_ssh_keys", "services_start"),
)


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def fixes_for(check: str, log_dir: Path) -> list[str]:
    """Fix ids that may cure self-check `check` (ordered, unique)."""
    out = list(CHECK_FIXES.get(check, ()))
    if check == "router_setup":
        snap = (_read_json(Path(log_dir) / "latest.json").get("snapshot") or {})
        for item in (snap.get("router_setup") or {}).get("missing") or []:
            fid = next((f for prefix, f in ITEM_FIXES if item.startswith(prefix)), None)
            if fid:
                out.append(fid)
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- running a fix

def _router_cfg(cfg: dict) -> dict | None:
    routers = (cfg or {}).get("routers") or []
    return routers[0] if routers else None


def _run_router(cfg: dict, fix: Fix) -> tuple[bool, str]:
    from .collector import SSHCollector

    r = _router_cfg(cfg)
    if not r:
        return False, "no router configured"
    c = SSHCollector(host=r["host"], port=r.get("port", 22), username=r.get("username"),
                     password=r.get("password"), key_filename=r.get("key_filename"))
    try:
        res = c.run_command(fix.cmd, timeout=90)
        out = (res.get("out") or "") + (res.get("err") or "")
        if not fix.verify:
            return True, out
        v = c.run_command(f"{fix.verify} >/dev/null 2>&1 && echo FIX_OK || echo FIX_FAILED", timeout=30)
        return "FIX_OK" in (v.get("out") or ""), out
    finally:
        c.close()


def _run_host(fix: Fix) -> tuple[bool, str]:
    r = subprocess.run(fix.cmd, check=False, shell=True, capture_output=True, text=True, timeout=120)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        return False, out
    if not fix.verify:
        return True, out
    return subprocess.run(fix.verify, check=False, shell=True, timeout=30).returncode == 0, out


def run_fix(cfg: dict, log_dir, fix_id: str, trigger: str, by: str = "", check: str = "") -> dict:
    """Run one fix, record it as a `remedy` router event. Never raises. -> the event."""
    from .events import append_router_event

    log_dir = Path(log_dir)
    fix = FIXES.get(fix_id)
    now = datetime.now(UTC).isoformat(timespec="seconds")
    event = {"ts": now, "event": "remedy", "fix": fix_id, "trigger": trigger, "by": by or None,
             "check": check or None}
    if fix is None:
        event.update(title=fix_id, ok=False, detail="unknown fix")
    else:
        event.update(title=fix.title, where=fix.where, note=fix.note or None)
        started = time.monotonic()
        try:
            ok, out = _run_router(cfg, fix) if fix.where == "router" else _run_host(fix)
        except Exception as e:
            ok, out = False, f"{type(e).__name__}: {e}"
        event.update(ok=ok, detail=out.strip()[-300:] or None, duration_s=round(time.monotonic() - started, 1))
    try:
        with _locked(log_dir):
            state = _read_json(log_dir / STATE_FILE)
            state.setdefault(fix_id, []).append({"ts": now, "trigger": trigger, "ok": event["ok"]})
            state[fix_id] = state[fix_id][-20:]
            (log_dir / STATE_FILE).write_text(json.dumps(state, indent=1))
        append_router_event(log_dir, event)
    except Exception as e:
        logger.warning("remedy: recording %s failed: %s", fix_id, e)
    return event


@contextmanager
def _locked(log_dir: Path):
    with open(log_dir / LOCK_FILE, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


# ---------------------------------------------------------------- automatic fixes

def auto_due(log_dir: Path, fix_id: str, now: datetime) -> bool:
    attempts = [a for a in _read_json(Path(log_dir) / STATE_FILE).get(fix_id, []) if a.get("trigger") == "auto"]
    times = [datetime.fromisoformat(a["ts"]) for a in attempts]
    if sum(1 for t in times if now - t < timedelta(hours=24)) >= AUTO_MAX_PER_DAY:
        return False
    return not times or now - max(times) >= AUTO_MIN_GAP


def auto_fix(cfg: dict, log_dir, state: dict, now: datetime | None = None, runner=None) -> list[dict]:
    """Run due auto fixes for problems the self-check has already alerted. Never raises.

    `state` is the self-check state ({check: {"alerted": bool, ...}}); `runner` replaces
    run_fix in tests."""
    if ((cfg or {}).get("remedy") or {}).get("auto", True) is False:
        return []
    log_dir = Path(log_dir)
    now = now or datetime.now(UTC)
    runner = runner or run_fix
    done, results = set(), []
    try:
        for check, cur in state.items():
            if not cur.get("alerted"):
                continue
            for fid in fixes_for(check, log_dir):
                fix = FIXES.get(fid)
                if not fix or not fix.auto or fid in done or not auto_due(log_dir, fid, now):
                    continue
                done.add(fid)
                results.append(runner(cfg, log_dir, fid, "auto", check=check))
    except Exception as e:
        logger.warning("remedy: auto fix failed: %s", e)
    return results


# ---------------------------------------------------------------- requests from the bot

def request_fix(log_dir, fix_id: str, by: str, check: str = "") -> bool:
    """Called by the unprivileged Telegram bot: queue a fix for network-ai-remedy.service."""
    if fix_id not in FIXES:
        return False
    log_dir = Path(log_dir)
    with _locked(log_dir), open(log_dir / REQUESTS_FILE, "a") as f:
        f.write(json.dumps({"ts": datetime.now(UTC).isoformat(timespec="seconds"), "fix": fix_id,
                            "by": by, "check": check}) + "\n")
    return True


def run_queue(cfg: dict, log_dir, now: datetime | None = None, runner=None) -> list[dict]:
    log_dir = Path(log_dir)
    now = now or datetime.now(UTC)
    runner = runner or run_fix
    with _locked(log_dir):
        path = log_dir / REQUESTS_FILE
        try:
            lines = path.read_text().splitlines()
        except OSError:
            lines = []
        if lines:
            path.write_text("")
    out = []
    for line in lines:
        try:
            req = json.loads(line)
            ts = datetime.fromisoformat(req["ts"])
        except (ValueError, KeyError, TypeError):
            continue
        if req.get("fix") not in FIXES or now - ts > REQUEST_MAX_AGE:
            logger.warning("remedy: dropped request %s", line[:200])
            continue
        out.append(runner(cfg, log_dir, req["fix"], "telegram", by=str(req.get("by") or ""),
                          check=str(req.get("check") or "")))
    return out


def main():
    import os

    import yaml
    from dotenv import load_dotenv

    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--config", default=os.getenv("NETWORK_AI_CONFIG", "config.yml"))
    p.add_argument("--list", action="store_true", help="show the fix catalogue")
    p.add_argument("--run", metavar="FIX", help="run one fix now (trigger=cli)")
    p.add_argument("--run-queue", action="store_true", help="run fixes requested from Telegram")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    root = Path(args.config).resolve().parent
    load_dotenv(root / ".env")
    cfg = yaml.safe_load(Path(args.config).read_text()) or {}
    log_dir = root / cfg.get("log_dir", "logs")
    from . import notify
    notify.configure(cfg, log_dir)
    if args.list:
        for f in FIXES.values():
            print(f"{f.id:16} {'auto' if f.auto else 'tap ':4} {f.where:6} {f.title}  -- {f.cmd}")
    elif args.run:
        print(json.dumps(run_fix(cfg, log_dir, args.run, "cli", by="cli"), indent=1))
    elif args.run_queue:
        for e in run_queue(cfg, log_dir):
            print(json.dumps(e))
    else:
        p.print_help()


if __name__ == "__main__":
    main()
