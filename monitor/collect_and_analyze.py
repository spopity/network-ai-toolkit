"""Router checks: collect over SSH, summarize, store.

  --mode check   every 5 minutes (systemd timer): collection, log templating, firewall
                 aggregation, wifi/mesh client tracking, 24h rollup. Never calls an LLM.
  --mode daily   once a day at 03:00: the same check, then ONE LLM pass over the 24h
                 rollup of all the checks, then a fresh rollup is started.
"""
import argparse
import fcntl
import json
import os
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

from router_agent import anomaly, db, notify, selfcheck, upnp
from router_agent.claude_client import ClaudeClient
from router_agent.collector import CONNMON_POINTS_CMD, SSHCollector
from router_agent.devices import device_names
from router_agent.dnshealth import DnsHealth
from router_agent.dnslog import DEFAULT_NETWORKS, DnsLog, Namer
from router_agent.events import read_router_events, watchdog_summary
from router_agent.llm_client import GeminiClient, LLMRouter, OllamaClient
from router_agent.netmap import lan_snapshot, parse_services
from router_agent.rollup import Rollup
from router_agent.rollup import render as render_rollup
from router_agent.snapshot import _out, build_snapshot, parse_connmon_points
from router_agent.storage import SnapshotStore
from router_agent.traffic import TrafficLog
from router_agent.upnp import UPNP_CMD


def local_ip_towards(host: str):
    """This machine's LAN IP as the router sees it (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def write_connmon_points(base: Path, collector) -> None:
    """Copy connmon's last 7 days to logs/connmon.json for the dashboard chart (best-effort;
    the dashboard itself never SSHes to the router)."""
    try:
        out = collector.run_command(CONNMON_POINTS_CMD, timeout=30)["out"]
        tmp = base / "connmon.json.tmp"
        tmp.write_text(json.dumps({"fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
                                   "points": parse_connmon_points(out)}, separators=(",", ":")))
        tmp.replace(base / "connmon.json")
    except Exception as e:
        print(f"connmon points unavailable: {e}", file=sys.stderr)
    finally:
        collector.close()


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
    lock = open(store.base / ".run.lock", "w")  # noqa: SIM115 -- held for the whole run
    fcntl.flock(lock, fcntl.LOCK_EX)
    notifier = notify.configure(cfg, store.base)  # Telegram, if notify: is configured (None otherwise)

    router_llm = None
    if args.mode == "daily":
        llm_cfg = cfg.get("llm", {})
        backends = []
        for b in llm_cfg.get("order") or ["gemini", "ollama"]:
            bcfg = llm_cfg.get(b) or {}
            if b == "claude":
                if ClaudeClient.configured():
                    backends.append((b, ClaudeClient(model=bcfg.get("model", "opus"), timeout=bcfg.get("timeout", 180))))
            elif b == "gemini":
                backends.append((b, GeminiClient(timeout=bcfg.get("timeout", 20))))
            elif b == "ollama":
                if bcfg.get("url") and bcfg.get("model"):  # no guessed defaults: set both in config.yml
                    backends.append((b, OllamaClient(url=bcfg["url"], model=bcfg["model"], timeout=bcfg.get("timeout", 180))))
            else:
                print(f"warning: unknown llm backend {b!r} in llm.order, ignored", file=sys.stderr)
        router_llm = LLMRouter(backends)

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
        if notifier and store.first_seen_now:
            by_mac = {(c.get("mac") or "").upper(): c for c in snapshot["wifi"].get("clients", [])}
            notifier.new_devices([by_mac.get(m) or {"mac": m} for m in store.first_seen_now])
        # network map: wired topology, DHCP/ARP hosts and the router's services (dashboard only, never sent to an LLM)
        snapshot["lan"] = lan_snapshot(grouped, snapshot)
        snapshot["services"] = parse_services(grouped)
        # ports LAN devices opened to the internet via UPnP; a device doing it for the first time -> event + Telegram
        adg = cfg.get("adguard") or {}
        namer = Namer(store.base, snapshot, grouped, adg.get("networks") or DEFAULT_NETWORKS)
        names = {**namer.names, **{namer.ip_mac[ip]: a for ip, a in (adg.get("aliases") or {}).items() if ip in namer.ip_mac}}
        snapshot["upnp"] = upnp.check_and_record(store.base, _out(grouped.get("services", []), UPNP_CMD),
                                                 namer.ip_mac, names)
        hidden = cfg.get("hidden") or {}  # never archived: DNS domains (+ subdomains), Traffic Analyzer apps
        if cfg.get("adguard"):
            # per-device DNS lookups from AdGuardHome (archived in Postgres; summary only here)
            dnslog = DnsLog(store.base, {**cfg["adguard"], "hide_domains": hidden.get("domains")})
            snapshot["dns"] = dnslog.collect(snapshot, grouped)
            # is DNS answered, and filtered by an active AdGuardHome? (state changes -> events)
            snapshot["dns_health"] = DnsHealth(store.base, r["host"], dnslog._client()).check(collector)
        if cfg.get("traffic_analyzer"):
            # per-device internet usage from the firmware's Traffic Analyzer (archived in Postgres)
            tcfg = {**{k: v for k, v in (cfg.get("adguard") or {}).items() if k in ("networks", "aliases")},
                    **(cfg["traffic_analyzer"] if isinstance(cfg["traffic_analyzer"], dict) else {}),
                    "hide_apps": hidden.get("apps")}
            snapshot["traffic"] = TrafficLog(store.base, tcfg).collect(collector, snapshot, grouped)
        if cfg.get("adguard") or cfg.get("traffic_analyzer"):
            # unusual appliance behaviour vs its own baseline (new sites, upload bursts) -> events + Telegram
            snapshot["anomalies"] = anomaly.run(store.base, cfg)
        write_connmon_points(store.base, collector)
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
            analysis = router_llm.analyze(snapshot, day, names=device_names(store.base, snapshot))
            analysis["analyzed_at"] = snapshot["collected_at"]
            analysis["window"] = [day["since"], day["until"]]
            record = {"snapshot": snapshot, "analysis": analysis, "day_summary": day}
            path = store.write(name, record, kind="daily")
            rollup.reset()
            if notifier:
                notifier.daily(analysis)
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

    if args.mode == "daily":
        # Postgres retention: 5-minute snapshots, DNS lookups and traffic older than N days
        deleted = db.prune_old(cfg.get("db_retention_days", 90))
        if deleted is not None:
            print(f"postgres retention ({cfg.get('db_retention_days', 90)} days): deleted {deleted}")

    # the watchdog runs the other self-checks; this run watches the watchdog in turn
    selfcheck.run(cfg, store.base, only=("watchdog",))
    if notifier:
        notifier.flush()  # anything queued while Telegram was unreachable
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
