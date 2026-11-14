"""UPnP / NAT-PMP port mappings: which LAN devices opened ports to the internet.

Every 5-minute check reads the router's miniupnpd lease file (/tmp/upnp.leases, lines
"PROTO:EXT_PORT:LAN_IP:INT_PORT:LIFETIME:DESCRIPTION", lifetime 0 = permanent) and
names each device (IP -> MAC from DHCP leases/ARP, MAC -> name as elsewhere).

A mapping counts as *exposing* when it is TCP or permanent: that is what services
like a NAS login page use. Short-lived UDP mappings (Tailscale, game consoles, VoIP
renew theirs every few hours) are listed but never alerted on.

Alerts are per device, once: logs/.upnp_known.json remembers every device that ever
held an exposing mapping. A device that is not on that list opening one emits an
`upnp_new_device` router event (Events card, Postgres, Telegram); a known device
closing and re-opening its ports, or opening other ports, stays quiet. The very first
run records whatever is open as known without alerting. Nothing here calls an LLM.
"""
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

UPNP_CMD = "cat /tmp/upnp.leases 2>/dev/null; echo \"upnp_enable=$(nvram get upnp_enable)\""
KNOWN_FILE = ".upnp_known.json"


def parse(out: str) -> tuple[list[dict], bool | None]:
    """-> (mappings, UPnP enabled on the router?). Malformed lines are skipped."""
    mappings, enabled = [], None
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("upnp_enable="):
            v = line.split("=", 1)[1]
            enabled = v == "1" if v else None
            continue
        p = line.split(":", 5)
        if len(p) < 5 or p[0].upper() not in ("TCP", "UDP"):
            continue
        try:
            ext, port, life = int(p[1]), int(p[3]), int(p[4])
        except ValueError:
            continue
        mappings.append({"proto": p[0].upper(), "ext_port": ext, "ip": p[2], "port": port,
                         "permanent": life == 0, "description": p[5] if len(p) > 5 else ""})
    return mappings, enabled


def exposing(m: dict) -> bool:
    return m["proto"] == "TCP" or m["permanent"]


def describe(m: dict) -> str:
    """"TCP 65280 → 5001 (permanent, upnpclient)"."""
    extra = ", ".join(x for x in ("permanent" if m["permanent"] else "", m.get("description") or "") if x)
    return f"{m['proto']} {m['ext_port']} → {m['port']}" + (f" ({extra})" if extra else "")


class UpnpWatch:
    def __init__(self, base: Path):
        self.path = Path(base) / KNOWN_FILE

    def check(self, out: str, ip_mac: dict[str, str], names: dict[str, str]) -> dict:
        """Parse the router output, update the known-device list and return the
        snapshot's `upnp` summary; `new_devices` lists devices to alert about."""
        mappings, enabled = parse(out)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        by_dev: dict[str, dict] = {}
        for m in mappings:
            mac = ip_mac.get(m["ip"])
            m["mac"] = mac
            m["device"] = (names.get(mac) if mac else None) or m["ip"]
            if exposing(m):
                key = mac or f"ip:{m['ip']}"
                d = by_dev.setdefault(key, {"key": key, "mac": mac, "ip": m["ip"], "device": m["device"], "mappings": []})
                d["mappings"].append(m)

        try:
            known = json.loads(self.path.read_text())
            baseline = False
        except (OSError, ValueError):
            known, baseline = {}, True
        new = [] if baseline else [d for k, d in by_dev.items() if k not in known]
        for k, d in by_dev.items():
            entry = known.setdefault(k, {"first_seen": now, "baseline": baseline})
            entry.update(last_seen=now, device=d["device"], ip=d["ip"],
                         ports=sorted({describe(m) for m in d["mappings"]}))
        self.path.write_text(json.dumps(known, indent=1))

        return {
            "enabled": enabled,
            "mappings": mappings,
            "exposed_devices": sorted(d["device"] for d in by_dev.values()),
            "new_devices": new,
            "baseline": baseline or None,
        }


def check_and_record(base: Path, out: str, ip_mac: dict[str, str], names: dict[str, str]) -> dict:
    """UpnpWatch.check() plus one `upnp_new_device` router event per new device."""
    from .events import append_router_event

    result = UpnpWatch(base).check(out, ip_mac, names)
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    for d in result["new_devices"]:
        append_router_event(base, {
            "ts": ts, "event": "upnp_new_device", "device": d["device"], "ip": d["ip"], "mac": d["mac"],
            "ports": [describe(m) for m in d["mappings"]],
        })
    return result
