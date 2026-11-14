"""AdGuardHome query log -> per-device DNS lookups.

Every 5-minute check pulls the query-log entries that are new since the last check
(a nanosecond timestamp cursor in .dns_cursor.json), names each client (IP -> MAC via
the router's ARP table and DHCP leases, MAC -> name the same way the rest of
network-ai does) and folds them into Postgres:

  dns_lookups     one row per (hour, device, domain, blocked) with a count
  dns_first_seen  when each device first looked up each domain
  dns_devices     when each device was first/last seen in the log

"New" domains are first lookups by a device that has already been watched for
NEW_DOMAIN_GRACE (before that, everything a device does is new and says nothing).
The cursor only advances after Postgres accepted the batch, so an outage is caught
up on the next check (AdGuardHome keeps 90 days of log). Nothing here calls an LLM.
"""
import json
import logging
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

from .collector import ARP_CMD, LEASES_CMD
from .devices import device_names, label
from .snapshot import _client_names, _out

logger = logging.getLogger(__name__)

PAGE = 500
MAX_PAGES = 200            # 100k entries per check; a longer backlog (days of outage) is skipped, not replayed
FIRST_RUN_HOURS = 24       # how far back the very first run reads
NEW_DOMAIN_GRACE = timedelta(hours=24)
ROUTER_IPS = {"127.0.0.1", "::1"}

DEFAULT_NETWORKS = {"192.168.1.": "LAN", "192.168.52.": "Guest", "192.168.107.": "IoT", "10.6.0.": "VPN"}

_TIME = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def parse_ns(ts: str) -> int:
    """AdGuardHome's RFC3339 time (nanoseconds, trailing zeros trimmed) -> epoch ns."""
    m = _TIME.match(ts)
    if not m:
        raise ValueError(f"unrecognized time {ts!r}")
    base = datetime.fromisoformat(m.group(1) + ("+00:00" if m.group(3) == "Z" else m.group(3)))
    frac = (m.group(2) or "").ljust(9, "0")[:9]
    return int(base.timestamp()) * 1_000_000_000 + int(frac)


def _entry_key(e: dict) -> str:
    q = e.get("question") or {}
    return f"{e.get('time')}|{e.get('client')}|{q.get('name')}|{q.get('type')}"


# ------------------------------------------------------------------ AdGuardHome API

class AdGuardClient:
    def __init__(self, url: str, username: str, password: str, timeout: int = 15):
        self.url = url.rstrip("/")
        self.auth = (username, password)
        self.timeout = timeout

    def _get(self, path: str, **params) -> dict:
        r = requests.get(f"{self.url}/control/{path}", params=params, auth=self.auth, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def entries_since(self, cursor: dict | None) -> tuple[list[dict], dict | None, bool]:
        """Query-log entries newer than `cursor`, oldest first, plus the next cursor and
        whether the page cap stopped the read early (older entries were skipped)."""
        if cursor:
            stop_ns, seen = cursor["ns"], set(cursor.get("keys", []))
        else:
            stop_ns = int((datetime.now(UTC) - timedelta(hours=FIRST_RUN_HOURS)).timestamp() * 1e9)
            seen = set()
        out: list[dict] = []
        older_than = None
        truncated = False
        for page_no in range(MAX_PAGES):
            params = {"limit": PAGE}
            if older_than:
                params["older_than"] = older_than
            page = self._get("querylog", **params)
            data = page.get("data") or []
            done = False
            for e in data:
                ns = parse_ns(e["time"])
                if ns < stop_ns or (ns == stop_ns and (not cursor or _entry_key(e) in seen)):
                    done = True
                    break
                e["_ns"] = ns
                out.append(e)
            older_than = page.get("oldest")
            if done or len(data) < PAGE or not older_than:
                break
        else:
            truncated = True
        if not out:
            return [], cursor, False
        out.reverse()
        if truncated:
            # the API pages newest -> oldest, so entries older than the cap can't be fetched
            # without re-reading everything newer; after an outage that long, accept the gap
            logger.warning("AdGuardHome query log: read cap hit (%d entries); older entries skipped", len(out))
        newest_ns = out[-1]["_ns"]
        keys = [_entry_key(e) for e in out if e["_ns"] == newest_ns]
        if cursor and newest_ns == cursor["ns"]:
            keys = list(seen | set(keys))
        return out, {"ns": newest_ns, "keys": keys[-200:]}, truncated


# ------------------------------------------------------------------ client naming

def ip_macs(grouped: dict[str, list[dict]]) -> dict[str, str]:
    """{IP: MAC} from DHCP leases (all three dnsmasq instances) and the ARP table."""
    wifi = grouped.get("wifi", [])
    m: dict[str, str] = {}
    for line in _out(wifi, LEASES_CMD).splitlines():
        p = line.split()
        if len(p) >= 3 and ":" in p[1]:
            m[p[2]] = p[1].upper()
    for line in _out(wifi, ARP_CMD).splitlines()[1:]:
        p = line.split()
        if len(p) >= 4 and p[2] != "0x0" and p[3] != "00:00:00:00:00:00":
            m[p[0]] = p[3].upper()
    return m


def lease_names(grouped: dict[str, list[dict]]) -> dict[str, str]:
    """{MAC: DHCP hostname} -- a last resort for devices networkmap never named."""
    names = {}
    for line in _out(grouped.get("wifi", []), LEASES_CMD).splitlines():
        p = line.split()
        if len(p) >= 4 and p[3] != "*":
            names[p[1].upper()] = p[3]
    return names


class Namer:
    def __init__(self, log_dir, snapshot: dict, grouped: dict[str, list[dict]], networks: dict[str, str],
                 aliases: dict[str, str] | None = None):
        self.aliases = aliases or {}
        self.ip_mac = ip_macs(grouped)
        self.names = device_names(log_dir, snapshot)
        # wired devices aren't in the snapshot's wifi clients; networkmap/custom names cover them
        for mac, info in _client_names(grouped.get("wifi", [])).items():
            if (mac not in self.names or self.names[mac].startswith("unnamed")) and (info.get("name") or info.get("vendor")):
                self.names[mac] = label(info)
        for mac, host in lease_names(grouped).items():
            if mac not in self.names or self.names[mac].startswith("unnamed"):
                self.names[mac] = host
        self.networks = networks

    def network(self, ip: str) -> str:
        if ip in ROUTER_IPS:
            return "Router"
        return next((n for prefix, n in self.networks.items() if ip.startswith(prefix)), "Other")

    def __call__(self, ip: str, agh_name: str = "") -> dict:
        if ip in ROUTER_IPS:
            return {"key": "router", "mac": None, "device": "Router (itself)", "network": "Router"}
        mac = self.ip_mac.get(ip)
        if ip in self.aliases:  # config override, e.g. VMs/containers networkmap only knows by vendor
            return {"key": mac or f"ip:{ip}", "mac": mac, "device": self.aliases[ip], "network": self.network(ip)}
        if mac:
            name = self.names.get(mac) or (agh_name if agh_name and agh_name != ip else None) or "unnamed device"
            return {"key": mac, "mac": mac, "device": name, "network": self.network(ip)}
        return {"key": f"ip:{ip}", "mac": None, "device": agh_name or ip, "network": self.network(ip)}


# ------------------------------------------------------------------ aggregation

def _blocked(e: dict) -> bool:
    return str(e.get("reason", "")).startswith("Filtered")


def _rule(e: dict) -> str | None:
    rules = e.get("rules") or []
    return (rules[0].get("text") or None) if rules and isinstance(rules[0], dict) else None


def is_hidden(domain: str, hidden: Iterable[str]) -> bool:
    """True for a hidden domain or any of its subdomains."""
    return any(domain == h or domain.endswith("." + h) for h in hidden)


def aggregate(entries: Iterable[dict], namer: Namer, hidden: Iterable[str] = ()) -> list[dict]:
    """(hour, device, domain, blocked) rows with counts. Domains in `hidden` (and their
    subdomains) are dropped before anything is archived."""
    hidden = [h.lower().strip(".") for h in hidden]
    rows: dict[tuple, dict] = {}
    for e in entries:
        q = e.get("question") or {}
        domain = (q.get("name") or "").rstrip(".").lower()
        if not domain or is_hidden(domain, hidden):
            continue
        ip = e.get("client") or ""
        who = namer(ip, ((e.get("client_info") or {}).get("name") or "").strip())
        t = datetime.fromtimestamp(e["_ns"] / 1e9, UTC)
        hour = t.replace(minute=0, second=0, microsecond=0)
        blocked = _blocked(e)
        k = (hour, who["key"], domain, blocked)
        r = rows.get(k)
        if r is None:
            r = rows[k] = {"hour": hour, "device_key": who["key"], "mac": who["mac"], "device": who["device"],
                           "network": who["network"], "client_ip": ip, "domain": domain, "blocked": blocked,
                           "rule": _rule(e) if blocked else None, "count": 0, "first_seen": t, "last_seen": t}
        r["count"] += 1
        r["first_seen"] = min(r["first_seen"], t)
        r["last_seen"] = max(r["last_seen"], t)
    return list(rows.values())


def summarize(rows: list[dict], new_domains: list[dict], top: int = 8) -> dict:
    """Small per-check summary that goes into the snapshot and the daily rollup."""
    by_net: dict[str, dict[str, int]] = {}
    blocked_domains: Counter = Counter()
    blocked_devices: Counter = Counter()
    for r in rows:
        n = by_net.setdefault(r["network"], {"queries": 0, "blocked": 0})
        n["queries"] += r["count"]
        if r["blocked"]:
            n["blocked"] += r["count"]
            blocked_domains[r["domain"]] += r["count"]
            blocked_devices[f"{r['device']} [{r['network']}]"] += r["count"]
    return {
        "queries": sum(n["queries"] for n in by_net.values()),
        "blocked": sum(n["blocked"] for n in by_net.values()),
        "by_network": by_net,
        "top_blocked_domains": dict(blocked_domains.most_common(top)),
        "top_blocked_devices": dict(blocked_devices.most_common(top)),
        "new_domains": new_domains[:50],
    }


# ------------------------------------------------------------------ entry point

class DnsLog:
    def __init__(self, base: Path, cfg: dict):
        self.cursor_path = Path(base) / ".dns_cursor.json"
        self.base = Path(base)
        self.cfg = cfg
        self.networks = cfg.get("networks") or DEFAULT_NETWORKS

    def _client(self) -> AdGuardClient | None:
        user, pw = self.cfg.get("username"), self.cfg.get("password")
        cred = self.cfg.get("credentials_file")
        if cred and not pw:
            try:
                kv = dict(l.strip().split("=", 1) for l in Path(cred).read_text().splitlines() if "=" in l)
                user, pw = user or kv.get("username"), kv.get("password")
            except OSError as e:
                logger.warning("AdGuardHome credentials unreadable (%s): %s", cred, e)
                return None
        if not (self.cfg.get("url") and user and pw):
            return None
        return AdGuardClient(self.cfg["url"], user, pw)

    def collect(self, snapshot: dict, grouped: dict[str, list[dict]]) -> dict | None:
        """Pull new log entries, archive them, return the snapshot's `dns` summary
        (or a {"status": ...} dict when AdGuardHome or Postgres is unavailable)."""
        from . import (
            db,  # Postgres is optional for the rest of network-ai; import lazily
        )

        client = self._client()
        if client is None:
            return None
        try:
            cursor = json.loads(self.cursor_path.read_text())
        except (OSError, ValueError):
            cursor = None
        try:
            entries, new_cursor, truncated = client.entries_since(cursor)
        except Exception as e:
            logger.warning("AdGuardHome query log unavailable: %s", e)
            return {"status": "adguard_unreachable", "error": str(e)[:200]}
        rows = aggregate(entries, Namer(self.base, snapshot, grouped, self.networks, self.cfg.get("aliases")),
                         self.cfg.get("hide_domains") or ())
        if rows:
            try:
                new_domains = db.insert_dns_rows(rows, NEW_DOMAIN_GRACE)
            except Exception as e:
                logger.warning("Postgres DNS archive failed; will retry these entries next check: %s", e)
                return {"status": "archive_unavailable", "error": str(e)[:200]}
        else:
            new_domains = []
        if new_cursor:
            self.cursor_path.write_text(json.dumps(new_cursor))
        summary = summarize(rows, new_domains)
        summary["entries"] = len(entries)
        if truncated:
            summary["gap"] = True  # read cap hit: some older entries were skipped
        return summary
