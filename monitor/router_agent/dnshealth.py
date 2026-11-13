"""AdGuardHome health check (every 5-minute check, no LLM).

Answers "is DNS on the router working, and is it filtered?" from four signals:

  - who owns port 53 on the router (AdGuardHome, or dnsmasq after a fallback:
    the AdGuardHome add-on hands :53 back to dnsmasq while AdGuardHome is down,
    so DNS keeps working but nothing is filtered)
  - AdGuardHome's own status (running, protection enabled) via its API
  - whether a known ad domain is still matched by the blocklists (API check_host,
    no DNS query, so nothing extra lands in the query log)
  - a real DNS query from this host to the router (answered? how fast?)

state: "ok" | "unfiltered" (DNS answers, but not through an active AdGuardHome)
       | "down" (the router does not answer DNS).
State changes are written as router events (dns_ok / dns_unfiltered / dns_down),
which the dashboard's events list shows and the daily rollup counts.
"""
import json
import random
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

PROBE_NAME = "example.com"
BLOCK_TEST = "doubleclick.net"  # in AdGuard DNS filter; check_host only, never resolved
STATE_FILE = ".dns_health.json"

# udp :53 listeners -> "count process" lines; AdGuardHome pid; supervisor ("monitor-start") processes
ROUTER_CMD = (
    "netstat -lnup 2>/dev/null | awk '$4 ~ /:53$/ {print $NF}' | sed 's#.*/##' | sort | uniq -c; "
    "echo \"agh_pid=$(pidof AdGuardHome)\"; "
    "echo \"monitors=$(ps w | grep -c '[m]onitor-start')\""
)


def dns_probe(server: str, name: str = PROBE_NAME, timeout: float = 3.0) -> Dict:
    """One A query over UDP. -> {"ok", "ms", "rcode", "answers"} or {"ok": False, "error"}."""
    qid = random.randint(0, 0xFFFF)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.monotonic()
        s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
        ms = round((time.monotonic() - t0) * 1000, 1)
        flags, _, ancount = struct.unpack(">HHH", data[2:8])
        rcode = flags & 0xF
        return {"ok": rcode == 0 and ancount > 0, "ms": ms, "rcode": rcode, "answers": ancount}
    except OSError as e:
        return {"ok": False, "error": str(e) or e.__class__.__name__}
    finally:
        s.close()


def parse_router(out: str) -> Dict:
    owners, agh_pid, monitors = [], None, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("agh_pid="):
            agh_pid = line.split("=", 1)[1] or None
        elif line.startswith("monitors="):
            try:
                monitors = int(line.split("=", 1)[1])
            except ValueError:
                pass
        elif line:
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                owners.append(parts[1])
    return {"owners_53": sorted(set(owners)), "agh_pid": agh_pid, "monitors": monitors}


def evaluate(router: Optional[Dict], api: Optional[Dict], blocking: Optional[bool], probe: Dict) -> Dict:
    """Pure decision logic (unit-testable)."""
    problems: List[str] = []
    if not probe.get("ok"):
        why = probe.get("error") or f"rcode {probe.get('rcode')}, {probe.get('answers', 0)} answers"
        problems.append(f"router does not answer DNS ({why})")
    owners = (router or {}).get("owners_53") or []
    if router is not None:
        if not owners:
            problems.append("nothing listens on port 53")
        elif "AdGuardHome" not in owners:
            problems.append(f"port 53 served by {', '.join(owners)} (AdGuardHome fallback: unfiltered)")
        elif len(owners) > 1:
            others = ", ".join(o for o in owners if o != "AdGuardHome")
            problems.append(f"{others} also listens on port 53 (some networks may be unfiltered)")
        if router.get("agh_pid") and router.get("monitors") == 0:
            problems.append("AdGuardHome supervisor not running (no automatic restart)")
    if api is None:
        problems.append("AdGuardHome API unreachable")
    else:
        if not api.get("running"):
            problems.append("AdGuardHome reports DNS not running")
        if not api.get("protection_enabled"):
            problems.append("AdGuardHome protection is turned off")
    if blocking is False:
        problems.append(f"blocklists inactive ({BLOCK_TEST} not matched)")

    if not probe.get("ok"):
        state = "down"
    elif (router is not None and owners != ["AdGuardHome"]) or api is None or not api.get("running") \
            or not api.get("protection_enabled") or blocking is False:
        state = "unfiltered"
    else:
        state = "ok"
    # a missing supervisor alone doesn't make DNS unhealthy now, but it's worth surfacing
    return {"state": state, "problems": problems}


class DnsHealth:
    def __init__(self, base: Path, router_ip: str, adguard_client=None):
        self.base = Path(base)
        self.router_ip = router_ip
        self.client = adguard_client

    def check(self, collector) -> Dict:
        try:
            router = parse_router(collector.run_command(ROUTER_CMD, timeout=20)["out"])
        except Exception:
            router = None
        finally:
            collector.close()
        api, blocking = None, None
        if self.client is not None:
            try:
                api = self.client._get("status")
                hit = self.client._get("filtering/check_host", name=BLOCK_TEST)
                blocking = str(hit.get("reason", "")).startswith("FilteredBlack")
            except Exception:
                pass
        probe = dns_probe(self.router_ip)
        result = evaluate(router, api, blocking, probe)
        result.update({
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "owners_53": (router or {}).get("owners_53"),
            "supervisor": (router or {}).get("monitors"),
            "agh_running": (api or {}).get("running"),
            "protection": (api or {}).get("protection_enabled"),
            "agh_version": (api or {}).get("version"),
            "blocking_test": blocking,
            "probe_ms": probe.get("ms"),
        })
        self._record_transition(result)
        return result

    def _record_transition(self, result: Dict) -> None:
        from .events import append_router_event

        path = self.base / STATE_FILE
        try:
            prev = json.loads(path.read_text())
        except (OSError, ValueError):
            prev = {}
        state = result["state"]
        if prev.get("state") != state and (prev.get("state") or state != "ok"):
            append_router_event(self.base, {
                "ts": result["checked_at"],
                "event": f"dns_{state}",
                "previous": prev.get("state"),
                "problems": result["problems"][:4],
                "since": prev.get("since"),
            })
            since = result["checked_at"]
        else:
            since = prev.get("since") or result["checked_at"]
        result["since"] = since
        path.write_text(json.dumps({"state": state, "since": since}))
