"""Weekly and monthly network report: one LLM call over compact facts from the archive.

    python -m router_agent.report --config config.yml --period week    # last full week (Mon-Sun, UTC)
    python -m router_agent.report --config config.yml --period month   # last full calendar month
    python -m router_agent.report --period week --dry-run              # facts only: no LLM, nothing saved/sent

Run by systemd/network-ai-report@.service (week: Mondays, month: the 1st). Facts come from
Postgres (check rows, speedtests, events, the daily traffic/DNS summaries) and
logs/known_clients.json -- per device only, never domain or app names (hidden list).
The report is saved to logs/reports/<period>-<start>.json (the dashboard's Report card
reads it) and pushed to Telegram as `report` (opt-in in notify.events). Each part is
best-effort: Postgres down -> those facts are missing; no LLM -> the numbers alone.
"""
import argparse
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from router_agent import db, notify

REPORTS_DIR = "reports"
PERIODS = ("week", "month")
TOP = 5
NOTABLE = ("anomaly", "upnp_new_device", "iot_lan", "monitor_problem", "dns_down", "dns_unfiltered",
           "router_firmware_available")

PROMPT = """You are writing the {label} report for a home network (ASUS router with AiMesh,
AdGuardHome DNS filtering, a LAN-side WAN watchdog). Below are the facts for {start} to {end}
(UTC), with the {prev_label} for comparison where given. Bytes are already converted to GB.

Write 5-8 short bullet points (start each with "- "), plain text, no markdown headings:
the overall verdict first (was the internet reliable, was anything worrying), then notable
changes versus the previous period, the biggest users, new devices, security-relevant events,
and at most two concrete recommendations if anything needs attention. A part marked
"not_collected" had no data archived for that period (the source was set up later or was off):
say so neutrally once, it is not a fault and not a recommendation. A "coverage" below the full
period means collection started (or paused) part-way: compare and judge only what was covered,
low totals there are not a counting problem. Routine things
(ordinary DNS block rates, a few new devices, normal speedtest spread) are fine to mention
briefly but are not problems. Do not invent numbers that are not in the facts.

FACTS:
{facts}
"""


def window(period: str, now: datetime | None = None) -> tuple[datetime, datetime, datetime]:
    """(prev_start, start, end): the last full week (Monday 00:00 UTC to Monday) or calendar
    month before `now`, and the start of the period before it."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        end = today - timedelta(days=today.weekday())
        return end - timedelta(days=14), end - timedelta(days=7), end
    if period == "month":
        end = today.replace(day=1)
        start = (end - timedelta(days=1)).replace(day=1)
        return (start - timedelta(days=1)).replace(day=1), start, end
    raise ValueError(f"period must be one of {PERIODS}")


def _gb(n) -> float:
    return round((n or 0) / 1e9, 1)


def _pct(part, whole) -> float | None:
    return round(100 * part / whole, 1) if whole else None


def _safe(errors: list, name: str, fn):
    try:
        return fn()
    except Exception as e:
        errors.append(f"{name}: {str(e)[:150]}")
        return None


def _traffic(start, end) -> dict:
    h = db.get_traffic_history(bucket="day", top=TOP, start=start, end=end)
    rx, tx = sum(p["rx"] for p in h["series"]), sum(p["tx"] for p in h["series"])
    return {"download_gb": _gb(rx), "upload_gb": _gb(tx), "days_with_data": len(h["series"]),
            "per_day_gb": [{"day": p["period"][:10], "down": _gb(p["rx"]), "up": _gb(p["tx"])} for p in h["series"]],
            "top_devices": [{"device": d["device"], "network": d["network"], "down_gb": _gb(d["rx"]),
                             "up_gb": _gb(d["tx"])} for d in h["devices"]]}


def _dns(start, end) -> dict:
    h = db.get_dns_history(bucket="day", top=TOP, start=start, end=end)
    q, b = sum(p["queries"] for p in h["series"]), sum(p["blocked"] for p in h["series"])
    return {"queries": q, "blocked": b, "blocked_pct": _pct(b, q), "days_with_data": len(h["series"]),
            "top_devices": [{"device": d["device"], "network": d["network"], "queries": d["queries"],
                             "blocked_pct": _pct(d["blocked"], d["queries"])} for d in h["devices"]]}


def _wan(start, end) -> dict:
    checks = db.get_check_stats(start, end)
    events = db.get_events_between(start, end)
    downtimes = [(e["detail"] or {}).get("downtime_seconds") or 0 for e in events if e["event"] == "recovered"]
    return {"checks": checks["checks"], "wan_up_pct": _pct(checks["wan_up_checks"], checks["checks"]),
            "outages_measured": len(downtimes), "downtime_min": round(sum(downtimes) / 60, 1),
            "longest_outage_min": round(max(downtimes) / 60, 1) if downtimes else 0,
            "auto_restarts": sum(e["event"] == "restart_triggered" for e in events),
            "router_wan_disconnects": sum(e["event"] == "router_wan_disconnected" for e in events),
            "router_reboots": checks["reboots"],
            "clients_avg": checks["clients_avg"], "clients_max": checks["clients_max"],
            "router_mem_used_pct_max": checks["mem_used_pct_max"]}


def _line(start, end) -> dict:
    s = db.get_line_stats(start, end)
    tests = s["speedtests"]

    def avg(k):
        vals = [t[k] for t in tests if t.get(k) is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    return {"speedtests": len(tests), "download_mbps_avg": avg("download_mbps"),
            "download_mbps_min": min((t["download_mbps"] for t in tests if t.get("download_mbps")), default=None),
            "upload_mbps_avg": avg("upload_mbps"), "latency_ms_avg": avg("latency_ms"), **s["connmon"]}


def _events(start, end) -> dict:
    events = db.get_events_between(start, end)
    counts: dict[str, int] = {}
    for e in events:
        counts[e["event"]] = counts.get(e["event"], 0) + 1
    notable = []
    for e in events:
        if e["event"] in NOTABLE:
            d = e["detail"] or {}
            notable.append({"at": e["ts"][:16], "event": e["event"],
                            **{k: d[k] for k in ("device", "kind", "check", "title", "version", "problems") if k in d}})
    return {"counts": counts, "notable": notable[-15:]}


def _new_devices(log_dir: Path, start, end) -> list:
    try:
        known = json.loads((log_dir / "known_clients.json").read_text())
    except (OSError, ValueError):
        return []
    out = []
    for entry in known.values():
        first = (entry or {}).get("first_seen")
        if first and not entry.get("baseline") and start <= datetime.fromisoformat(first) < end:
            out.append({"device": entry.get("name") or "unnamed", "vendor": entry.get("vendor"),
                        "first_seen": first[:16]})
    return sorted(out, key=lambda d: d["first_seen"])


def gather(log_dir: Path, period: str, now: datetime | None = None) -> dict:
    """The report's facts, no LLM. Missing parts are listed in `errors`."""
    prev_start, start, end = window(period, now)
    errors: list[str] = []
    facts = {
        "period": period, "start": start.date().isoformat(), "end": (end - timedelta(days=1)).date().isoformat(),
        "internet": _safe(errors, "wan", lambda: _wan(start, end)),
        "line": _safe(errors, "line", lambda: _line(start, end)),
        "traffic": _safe(errors, "traffic", lambda: _traffic(start, end)),
        "dns": _safe(errors, "dns", lambda: _dns(start, end)),
        "events": _safe(errors, "events", lambda: _events(start, end)),
        "new_devices": _new_devices(log_dir, start, end),
        "previous": {
            "internet": _safe(errors, "wan (previous)", lambda: _wan(prev_start, start)),
            "line": _safe(errors, "line (previous)", lambda: _line(prev_start, start)),
            "traffic": _safe(errors, "traffic (previous)", lambda: _traffic(prev_start, start)),
            "dns": _safe(errors, "dns (previous)", lambda: _dns(prev_start, start)),
        },
    }
    days = (end - start).days  # previous period: same length for weeks, close enough for months
    for where in (facts, facts["previous"]):  # an empty archive is "not collected", not "zero"
        for part in ("traffic", "dns"):
            if where[part] is not None and not where[part]["days_with_data"]:
                where[part] = {"not_collected": True}
            elif where[part] is not None and where[part]["days_with_data"] < days:
                where[part]["coverage"] = f"{where[part]['days_with_data']} of {days} days"
        line = where["line"]
        if line is not None and not line["speedtests"] and line.get("ping_ms_avg") is None:
            where["line"] = {"not_collected": True}
    for part in ("traffic", "dns"):  # the per-day/per-device detail of the previous period isn't needed
        if facts["previous"][part]:
            for k in ("per_day_gb", "top_devices"):
                facts["previous"][part].pop(k, None)
    if errors:
        facts["errors"] = errors
    return facts


def prompt(facts: dict) -> str:
    label = "weekly" if facts["period"] == "week" else "monthly"
    prev = "previous week" if facts["period"] == "week" else "previous month"
    return PROMPT.format(label=label, prev_label=prev, start=facts["start"], end=facts["end"],
                         facts=json.dumps(facts, separators=(",", ":"), default=str))


def report_path(log_dir: Path, facts: dict) -> Path:
    return Path(log_dir) / REPORTS_DIR / f"{facts['period']}-{facts['start']}.json"


def latest(log_dir: Path, period: str | None = None, limit: int = 12) -> list[dict]:
    """Saved reports, newest first (for /api/reports)."""
    d = Path(log_dir) / REPORTS_DIR
    files = sorted(d.glob(f"{period or '*'}-*.json"), key=lambda p: p.name.split("-", 1)[1], reverse=True)
    out = []
    for p in files[:limit]:
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, ValueError):
            continue
    return out


def headline(facts: dict) -> list[str]:
    """Key numbers for Telegram and the dashboard (no LLM)."""
    lines = []
    def got(part):
        v = facts.get(part)
        return v if v and not v.get("not_collected") else None

    i, t, d, line = got("internet"), got("traffic"), got("dns"), got("line")
    if i and i.get("checks"):
        lines.append(f"Internet up {i['wan_up_pct']}% · {i['outages_measured']} outage(s), {i['downtime_min']} min down")
    if line and line.get("speedtests"):
        lines.append(f"Speedtest avg {line['download_mbps_avg']}↓ / {line['upload_mbps_avg']}↑ Mbps")
    if t:
        lines.append(f"Traffic {t['download_gb']} GB down · {t['upload_gb']} GB up")
    if d and d.get("queries"):
        lines.append(f"DNS {d['queries']:,} queries · {d['blocked_pct']}% blocked")
    if facts.get("new_devices"):
        lines.append(f"{len(facts['new_devices'])} new device(s)")
    return lines


def run(cfg: dict, log_dir: Path, period: str, llm=None, send: bool = True, now: datetime | None = None) -> dict:
    facts = gather(log_dir, period, now)
    analysis = llm.ask(prompt(facts)) if llm else {"source": "none", "error": "no LLM backend configured"}
    record = {"period": period, "start": facts["start"], "end": facts["end"],
              "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
              "summary": analysis.get("text"), "source": analysis.get("source"),
              **{k: analysis[k] for k in ("error", "fallback_reason") if k in analysis},
              "headline": headline(facts), "facts": facts}
    path = report_path(log_dir, facts)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=1, default=str))
    os.replace(tmp, path)
    n = notify.configure(cfg, log_dir) if send else None
    if n:
        n.report(record)
    return record


def main():
    import yaml
    from dotenv import load_dotenv

    from router_agent.llm_client import build_router

    load_dotenv()
    p = argparse.ArgumentParser(description="Weekly / monthly network report")
    p.add_argument("--config", default=os.getenv("NETWORK_AI_CONFIG", "config.yml"))
    p.add_argument("--period", choices=PERIODS, default="week")
    p.add_argument("--dry-run", action="store_true", help="print the facts only: no LLM, nothing saved or sent")
    p.add_argument("--no-send", action="store_true", help="save the report but don't push it to Telegram")
    args = p.parse_args()
    cfg_path = Path(args.config)
    cfg = yaml.safe_load(cfg_path.read_text())
    log_dir = (cfg_path.parent / cfg.get("log_dir", "logs")).resolve()
    if args.dry_run:
        print(json.dumps(gather(log_dir, args.period), indent=1, default=str))
        return 0
    record = run(cfg, log_dir, args.period, llm=build_router(cfg, warn=lambda m: print(m, file=sys.stderr)),
                 send=not args.no_send)
    print(f"{record['period']} report {record['start']}..{record['end']} via {record['source']}: "
          f"{report_path(log_dir, record['facts'])}")
    if record.get("error"):
        print(f"no summary: {record['error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
