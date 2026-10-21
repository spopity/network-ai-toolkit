"""Router checks: collect over SSH, summarize, store.

  --mode check   every 5 minutes (systemd timer): collection, log templating, firewall
                 aggregation, wifi/mesh client tracking, 24h rollup. Never calls an LLM.
  --mode daily   once a day at 03:00: the same check, then ONE LLM pass over the 24h
                 rollup of all the checks, then a fresh rollup is started.
"""
import argparse
import fcntl
import os
import socket
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

from router_agent.collector import SSHCollector
from router_agent.snapshot import build_snapshot
from router_agent.llm_client import GeminiClient, OllamaClient, LLMRouter
from router_agent.rollup import Rollup, render as render_rollup
from router_agent.storage import SnapshotStore
from router_agent.events import read_router_events, watchdog_summary


def local_ip_towards(host: str):
    """This machine's LAN IP as the router sees it (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=os.getenv("NETWORK_AI_CONFIG", "config.yml"))
    p.add_argument("--mode", choices=("check", "daily"), default="check",
                   help="check: collect + summarize, no LLM (default). daily: also run the LLM over the 24h rollup.")
    args = p.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        raise SystemExit(f"Config not found: {cfg_path}. Copy config.example.yml and edit.")
    cfg = yaml.safe_load(cfg_path.read_text())

    store = SnapshotStore(
        base_dir=cfg.get("log_dir", "logs"),
        retention_days=cfg.get("retention_days", 14),
        check_retention_hours=cfg.get("check_retention_hours", 48),
    )
    # one run at a time: the 03:00 daily run, the 5-minute timer and the dashboard's
    # "Check now" all share the rollup and its log cursor
    lock = open(store.base / ".run.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)

    router_llm = None
    if args.mode == "daily":
        llm_cfg = cfg.get("llm", {})
        gemini_cfg = llm_cfg.get("gemini", {})
        ollama_cfg = llm_cfg.get("ollama", {})
        gemini = GeminiClient(timeout=gemini_cfg.get("timeout", 20))
        ollama = OllamaClient(
            url=ollama_cfg.get("url", "http://127.0.0.1:11434"),
            model=ollama_cfg.get("model", "llama3"),
            timeout=ollama_cfg.get("timeout", 30),
        )
        router_llm = LLMRouter(gemini, ollama)

    exit_code = 0
    for r in cfg.get("routers", []):
        name = r.get("name") or r.get("host")
        collector = SSHCollector(
            host=r["host"],
            port=r.get("port", 22),
            username=r.get("username"),
            password=r.get("password"),
            key_filename=r.get("key_filename"),
        )
        try:
            grouped = collector.collect_grouped()
        except Exception as e:
            print(f"[{name}] collection failed: {e}", file=sys.stderr)
            exit_code = 1
            continue

        snapshot = build_snapshot(name, r["host"], grouped)
        snapshot["collector_ip"] = local_ip_towards(r["host"])
        snapshot["wifi"]["new_clients"] = store.track_clients(snapshot["wifi"])
        snapshot["wan"]["watchdog_24h"] = watchdog_summary(store.base, since_hours=24)
        snapshot["wan"]["router_events_24h"] = [
            {k: e.get(k) for k in ("ts", "event", "state", "ip")}
            for e in read_router_events(store.base, limit=50, since_hours=24)
        ]
        # rollup.json is shared by all routers in the config; with one router (the usual
        # case) it is exactly that router's day
        rollup = Rollup(store.base)
        roll = rollup.update(grouped, snapshot)

        if router_llm:
            day = render_rollup(roll, skynet_banned=(snapshot["security"].get("firewall_drops") or {}).get("skynet_banned"))
            analysis = router_llm.analyze(snapshot, day)
            analysis["analyzed_at"] = snapshot["collected_at"]
            analysis["window"] = [day["since"], day["until"]]
            record = {"snapshot": snapshot, "analysis": analysis, "day_summary": day}
            path = store.write(name, record, kind="daily")
            rollup.reset()
            print(f"[{name}] wrote {path} (analysis source: {analysis.get('source')}, {day['checks']} checks rolled up)")
        else:
            # carry the last daily analysis forward so the dashboard and Tshoot keep showing it
            prev = store.latest()
            analysis = prev.get("analysis")
            if analysis and not analysis.get("analyzed_at"):
                analysis["analyzed_at"] = (prev.get("snapshot") or {}).get("collected_at")
            path = store.write(name, {"snapshot": snapshot, "analysis": analysis}, kind="check")
            print(f"[{name}] wrote {path} (check, no LLM)")
        store.prune()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
