"""Day-long aggregation of the 5-minute checks, handed to the LLM once a day.

Every check tails the router's logs; consecutive tails overlap, so each check
first cuts its tail down to the lines newer than the previous check's (a
timestamp cursor kept in .log_cursor.json), then folds just those lines into
rollup.json: syslog templates (summarize.group_lines/merge_groups), firewall-drop
counters and peak/min system and wifi numbers. The daily analysis renders the
rollup into the same compact shapes the LLM prompts already expect, then starts
a fresh one. Nothing here calls an LLM.
"""
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .collector import FIREWALL_DROPS_CMD, SYSLOG_TAIL_CMD
from .snapshot import _out
from .summarize import _earlier, _later, group_lines, merge_groups, render_groups

_TS = re.compile(r"^(\w{3} [ \d]\d \d\d:\d\d:\d\d)")
MAX_COUNTER_KEYS = 1000  # internet scanners alone can be thousands of IPs a day; keep the heaviest


def _line_time(line: str, now: datetime) -> datetime | None:
    m = _TS.match(line)
    if not m:
        return None
    try:
        t = datetime.strptime(f"{now.year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    # syslog has no year: a December line read in January belongs to last year
    return t.replace(year=t.year - 1) if t > now + timedelta(days=1) else t


def new_lines(lines: list[str], cursor: dict | None) -> tuple[list[str], dict | None]:
    """Lines newer than the cursor, and the cursor to store for next time.
    The cursor is the newest timestamp seen plus the lines carrying it (several
    lines can share a second). Lines without a timestamp are ignored."""
    now = datetime.now()
    dated = [(t, ln) for ln in lines if (t := _line_time(ln, now))]
    if not dated:
        return [], cursor
    cur_t = datetime.fromisoformat(cursor["ts"]) if cursor else None
    seen = set(cursor.get("lines", [])) if cursor else set()
    fresh = [ln for t, ln in dated if cur_t is None or t > cur_t or (t == cur_t and ln not in seen)]
    newest = max(t for t, _ in dated)
    if cur_t and cur_t > newest:  # router clock went back / log rotated under us: keep the old cursor
        return fresh, cursor
    return fresh, {"ts": newest.isoformat(), "lines": [ln for t, ln in dated if t == newest][-50:]}


def _empty() -> dict:
    return {
        "since": datetime.now(UTC).isoformat(timespec="seconds"),
        "checks": 0,
        "syslog": {"lines": 0, "window": None, "groups": []},
        "drops": {"rows": 0, "window": None, "by_kind": {}, "ports": {}, "sources": {},
                  "outbound_devices": {}, "outbound_dest": {}},
        "stats": {},
        "dns": {"checks": 0, "queries": 0, "blocked": 0, "by_network": {}, "blocked_domains": {},
                "blocked_devices": {}, "new_domains": [], "unavailable_checks": 0},
    }


MAX_NEW_DOMAINS = 100


def _fold_dns(acc: dict, dns: dict | None) -> dict:
    """Fold one check's AdGuardHome summary (dnslog.summarize) into the day."""
    if not dns:
        return acc
    acc = dict(acc)
    if dns.get("status"):  # AdGuardHome or the archive was unreachable this check
        acc["unavailable_checks"] = acc.get("unavailable_checks", 0) + 1
        return acc
    acc["checks"] += 1
    acc["queries"] += dns.get("queries", 0)
    acc["blocked"] += dns.get("blocked", 0)
    nets = {k: dict(v) for k, v in acc["by_network"].items()}
    for net, v in (dns.get("by_network") or {}).items():
        n = nets.setdefault(net, {"queries": 0, "blocked": 0})
        n["queries"] += v.get("queries", 0)
        n["blocked"] += v.get("blocked", 0)
    acc["by_network"] = nets
    acc["blocked_domains"] = _merge_counter(acc["blocked_domains"], Counter(dns.get("top_blocked_domains") or {}), MAX_COUNTER_KEYS)
    acc["blocked_devices"] = _merge_counter(acc["blocked_devices"], Counter(dns.get("top_blocked_devices") or {}), MAX_COUNTER_KEYS)
    acc["new_domains"] = (acc["new_domains"] + (dns.get("new_domains") or []))[:MAX_NEW_DOMAINS]
    return acc


def _merge_counter(acc: dict, new: Counter, cap: int | None = None) -> dict:
    c = Counter(acc) + new
    return dict(c.most_common(cap)) if cap else dict(c)


def _fold_drops(acc: dict, rows_raw: list[str]) -> dict:
    rows = [line.split("|") for line in rows_raw if line.count("|") == 5]
    if not rows:
        return acc
    inbound = [r for r in rows if "OUTBOUND" not in r[1]]
    outbound = [r for r in rows if "OUTBOUND" in r[1]]
    w = acc.get("window") or [None, None]
    # rows come from two concatenated logs, so take min/max rather than first/last
    start, end = w
    for r in rows:
        start, end = _earlier(start, r[0]), _later(end, r[0])
    return {
        "rows": acc["rows"] + len(inbound),
        "window": [start, end],
        "by_kind": _merge_counter(acc["by_kind"], Counter(r[1] for r in rows)),
        "ports": _merge_counter(acc["ports"], Counter(f"{r[4]}/{r[5]}" if r[5] else r[4] for r in inbound), MAX_COUNTER_KEYS),
        "sources": _merge_counter(acc["sources"], Counter(r[2] for r in inbound), MAX_COUNTER_KEYS),
        "outbound_devices": _merge_counter(acc["outbound_devices"], Counter(r[2] for r in outbound)),
        "outbound_dest": _merge_counter(
            acc["outbound_dest"], Counter(f"{r[3]}:{r[5]}" if r[5] else r[3] for r in outbound), MAX_COUNTER_KEYS
        ),
    }


def _fold_stats(stats: dict, snapshot: dict) -> dict:
    s = dict(stats)
    system, wan, wifi = snapshot.get("system", {}), snapshot.get("wan", {}), snapshot.get("wifi", {})

    def peak(key, v, fn=max):
        if v is not None:
            s[key] = v if s.get(key) is None else fn(s[key], v)

    temps = system.get("temps_c") or {}
    peak("cpu_temp_c_max", temps.get("cpu"))
    peak("radio_2g_temp_c_max", temps.get("radio_2g"))
    peak("radio_5g_temp_c_max", temps.get("radio_5g"))
    if system.get("loadavg"):
        peak("load1_max", float(system["loadavg"][0]))
    if system.get("mem_total_kb"):
        avail = system.get("mem_available_kb") or system.get("mem_free_kb", 0)
        peak("mem_used_pct_max", round(100 * (1 - avail / system["mem_total_kb"]), 1))
    peak("wifi_clients_max", wifi.get("client_count"))
    peak("wifi_clients_min", wifi.get("client_count"), min)
    if not wan.get("pppd_running"):
        s["checks_with_wan_down"] = s.get("checks_with_wan_down", 0) + 1
    if system.get("uptime_seconds") is not None:
        # uptime going backwards between checks = the router rebooted
        if s.get("_last_uptime") is not None and system["uptime_seconds"] < s["_last_uptime"]:
            s["router_reboots"] = s.get("router_reboots", 0) + 1
        s["_last_uptime"] = system["uptime_seconds"]
    return s


class Rollup:
    def __init__(self, base: Path):
        self.path = base / "rollup.json"
        self.cursor_path = base / ".log_cursor.json"

    def _read(self, path: Path, default):
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return default

    def load(self) -> dict:
        return self._read(self.path, None) or _empty()

    def update(self, grouped_results: dict[str, list[dict]], snapshot: dict) -> dict:
        """Fold one check into the rollup; returns the updated rollup."""
        roll = self.load()
        cursor = self._read(self.cursor_path, {})
        sec = grouped_results.get("security", [])

        syslog, cursor["syslog"] = new_lines(_out(sec, SYSLOG_TAIL_CMD).splitlines(), cursor.get("syslog"))
        drops, cursor["drops"] = new_lines(_out(sec, FIREWALL_DROPS_CMD).splitlines(), cursor.get("drops"))

        roll["syslog"] = merge_groups(roll["syslog"], group_lines(syslog))
        roll["drops"] = _fold_drops(roll["drops"], drops)
        roll["stats"] = _fold_stats(roll["stats"], snapshot)
        roll["dns"] = _fold_dns(roll.get("dns") or _empty()["dns"], snapshot.get("dns"))
        health = (snapshot.get("dns_health") or {}).get("state")
        if health:
            hc = dict(roll.get("dns_health") or {})
            hc[health] = hc.get(health, 0) + 1
            roll["dns_health"] = hc
        roll["checks"] += 1
        roll["until"] = snapshot.get("collected_at")

        self.path.write_text(json.dumps(roll, separators=(",", ":")))
        self.cursor_path.write_text(json.dumps(cursor))
        return roll

    def reset(self) -> None:
        """Start a new day; the cursor is kept so no log line is counted twice."""
        roll = _empty()
        last_uptime = self.load()["stats"].get("_last_uptime")
        if last_uptime is not None:
            roll["stats"]["_last_uptime"] = last_uptime
        self.path.write_text(json.dumps(roll, separators=(",", ":")))


def render(roll: dict, skynet_banned: dict | None = None, top: int = 8) -> dict:
    """The rollup in the shapes the LLM section builders use for a single snapshot."""
    d = roll["drops"]
    top_of = lambda c, n=top: Counter(c).most_common(n)
    return {
        "since": roll.get("since"),
        "until": roll.get("until"),
        "checks": roll.get("checks"),
        "syslog_summary": render_groups(roll["syslog"], top=40),
        "firewall_drops": {
            "total": d["rows"],
            "window_start": (d.get("window") or [None])[0],
            "window_end": (d.get("window") or [None, None])[1],
            "by_kind": d["by_kind"],
            "unique_sources": len(d["sources"]),  # approximate past MAX_COUNTER_KEYS
            "top_ports": [{"port": p, "count": c} for p, c in top_of(d["ports"])],
            "top_sources": [{"ip": ip, "count": c} for ip, c in top_of(d["sources"])],
            "outbound": {
                "total": sum(d["outbound_devices"].values()),
                "by_lan_device": [{"ip": ip, "count": c} for ip, c in top_of(d["outbound_devices"])],
                "top_destinations": [{"dest": k, "count": c} for k, c in top_of(d["outbound_dest"])],
            },
            "skynet_banned": skynet_banned,
        },
        "peaks": {k: v for k, v in roll["stats"].items() if not k.startswith("_")},
        "dns": _render_dns(roll.get("dns"), top, roll.get("dns_health")),
    }


def _render_dns(dns: dict | None, top: int, health: dict | None = None) -> dict | None:
    if not dns or not (dns.get("checks") or dns.get("unavailable_checks")):
        return {"filter_health_checks": health} if health else None
    new = dns.get("new_domains") or []
    # IoT/Guest first: a camera or plug suddenly resolving something new is the interesting signal
    rank = {"IoT": 0, "Guest": 1}
    new = sorted(new, key=lambda d: rank.get(d.get("network"), 2))
    return {
        "queries": dns["queries"],
        "blocked": dns["blocked"],
        "by_network": dns["by_network"],
        "top_blocked_domains": dict(Counter(dns["blocked_domains"]).most_common(top)),
        "top_blocked_devices": dict(Counter(dns["blocked_devices"]).most_common(top)),
        "new_domains_by_watched_devices": [
            {k: d.get(k) for k in ("device", "network", "domain", "blocked")} for d in new[:25]
        ],
        "new_domains_total": len(new),
        "checks_without_dns_data": dns.get("unavailable_checks", 0),
        # 5-minute AdGuardHome health checks by state: ok / unfiltered (dnsmasq fallback,
        # protection off) / down (router not answering DNS)
        "filter_health_checks": health,
    }
