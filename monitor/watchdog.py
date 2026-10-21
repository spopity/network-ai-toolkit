import argparse
import json
import logging
import os
import socket
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

from router_agent.collector import SSHCollector
from router_agent import db

logger = logging.getLogger(__name__)

HISTORY_MAXLEN = 1440  # 30s interval * 1440 = 12h of sparkline history


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_up(targets, port, timeout=5) -> bool:
    for host in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def append_log(log_path: Path, event: dict):
    try:
        db.insert_watchdog_event(event)
    except Exception as e:
        logger.warning("Postgres archival failed (local log write still happens): %s", e)
    with log_path.open("a") as f:
        f.write(json.dumps(event) + "\n")


def write_status(status_path: Path, state: dict, history: deque):
    payload = {**state, "history": list(history)}
    status_path.write_text(json.dumps(payload, indent=2))


def restart_wan(router_cfg: dict, wan_unit: int):
    collector = SSHCollector(
        host=router_cfg["host"],
        port=router_cfg.get("port", 22),
        username=router_cfg.get("username"),
        password=router_cfg.get("password"),
        key_filename=router_cfg.get("key_filename"),
    )
    return collector.run_command(f"service restart_wan_if {wan_unit}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default=os.getenv("NETWORK_AI_CONFIG", "config.yml"))
    p.add_argument("--dry-run", action="store_true", help="log what would happen but never actually run the WAN restart command")
    p.add_argument("--max-iterations", type=int, default=None, help="exit after N checks (testing only)")
    args = p.parse_args()

    cfg_path = Path(args.config)
    cfg = yaml.safe_load(cfg_path.read_text())
    wd_cfg = cfg.get("watchdog", {})
    router_cfg = cfg["routers"][0]

    targets = wd_cfg.get("ping_targets", ["1.1.1.1", "8.8.8.8"])
    port = wd_cfg.get("ping_port", 443)
    check_interval = wd_cfg.get("check_interval_seconds", 30)
    down_threshold = wd_cfg.get("down_threshold_seconds", 300)
    cooldown = wd_cfg.get("restart_cooldown_seconds", 600)
    wan_unit = wd_cfg.get("wan_unit", 0)

    log_dir = Path(cfg.get("log_dir", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / Path(wd_cfg.get("log_file", "logs/watchdog.log")).name
    status_path = log_dir / "watchdog_status.json"

    history = deque(maxlen=HISTORY_MAXLEN)
    first_failure_at = None
    last_restart_at = None
    currently_up = True

    print(f"watchdog started: targets={targets} interval={check_interval}s "
          f"down_threshold={down_threshold}s cooldown={cooldown}s dry_run={args.dry_run}")

    iterations = 0
    while True:
        iterations += 1
        up = is_up(targets, port)
        ts = now_iso()
        history.append({"ts": ts, "up": up})

        if up:
            if not currently_up:
                downtime = time.time() - first_failure_at if first_failure_at else 0
                append_log(log_path, {"ts": ts, "event": "recovered", "downtime_seconds": round(downtime, 1)})
            currently_up = True
            first_failure_at = None
        else:
            if currently_up:
                append_log(log_path, {"ts": ts, "event": "down_detected"})
                first_failure_at = time.time()
            currently_up = False

            down_duration = time.time() - first_failure_at
            cooldown_ok = last_restart_at is None or (time.time() - last_restart_at) >= cooldown
            if down_duration >= down_threshold and cooldown_ok:
                append_log(log_path, {
                    "ts": ts, "event": "restart_triggered",
                    "down_duration_seconds": round(down_duration, 1),
                    "dry_run": args.dry_run,
                })
                if args.dry_run:
                    append_log(log_path, {"ts": now_iso(), "event": "restart_result", "ok": True, "dry_run": True})
                else:
                    try:
                        result = restart_wan(router_cfg, wan_unit)
                        append_log(log_path, {"ts": now_iso(), "event": "restart_result", "ok": True, "detail": result})
                    except Exception as e:
                        append_log(log_path, {"ts": now_iso(), "event": "restart_result", "ok": False, "error": str(e)})
                last_restart_at = time.time()

        write_status(status_path, {
            "up": currently_up,
            "checked_at": ts,
            "down_since": datetime.fromtimestamp(first_failure_at, tz=timezone.utc).isoformat(timespec="seconds") if first_failure_at else None,
            "last_restart_at": datetime.fromtimestamp(last_restart_at, tz=timezone.utc).isoformat(timespec="seconds") if last_restart_at else None,
        }, history)

        if args.max_iterations and iterations >= args.max_iterations:
            break

        time.sleep(check_interval)


if __name__ == "__main__":
    main()
