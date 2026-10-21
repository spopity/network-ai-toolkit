import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .collector import (
    CONNMON_CMD, CUSTOM_CLIENTLIST_CMD, FIREWALL_DROPS_CMD, MERLIN_CHECK_CMD, MESH_CLIENTLIST_CMD, MESH_NODES_CMD,
    NETWORKMAP_CMD, SKYNET_SETS_CMD, SPEEDTEST_CMD, SYSLOG_TAIL_CMD,
)
from .summarize import summarize_text

RAW_SYSLOG_LINES = 200  # raw tail kept in the snapshot for humans (dashboard, Tshoot)


def _out(results: List[Dict], cmd: str) -> str:
    for r in results:
        if r["cmd"] == cmd:
            return r["out"].strip()
    return ""


def _mem_value(meminfo: str, key: str) -> int:
    m = re.search(rf"^{key}:\s*(\d+)", meminfo, re.MULTILINE)
    return int(m.group(1)) if m else 0


def _firmware_label(variant: str, firmver: str, buildno: str, extendno: str) -> str:
    if variant == "merlin":
        # Merlin's versioning: firmver 3.0.0.6 + buildno 102.9 -> "3006.102.9"
        label = f"Asuswrt-Merlin {firmver.replace('.', '')}.{buildno}"
        return label if extendno in ("", "0") else f"{label}_{extendno}"
    label = f"{firmver}.{buildno}"
    return f"{label}_{extendno}" if extendno else label


def _temp_c(raw: str) -> Optional[float]:
    # thermal_zone reports millidegrees ("66956"); wl phy_tempsense reports "54 (0x36)"
    m = re.match(r"\s*(\d+)", raw)
    if not m:
        return None
    v = int(m.group(1))
    return round(v / 1000, 1) if v > 1000 else float(v)


def _parse_system(results: List[Dict]) -> Dict:
    meminfo = _out(results, "cat /proc/meminfo")
    uptime_raw = _out(results, "cat /proc/uptime")
    loadavg = _out(results, "cat /proc/loadavg")
    uptime_seconds = float(uptime_raw.split()[0]) if uptime_raw else None
    firmver = _out(results, "nvram get firmver")
    buildno = _out(results, "nvram get buildno")
    extendno = _out(results, "nvram get extendno")
    variant = _out(results, MERLIN_CHECK_CMD) or "stock"
    return {
        "productid": _out(results, "nvram get productid"),
        "firmver": firmver,
        "buildno": buildno,
        "extendno": extendno,
        "firmware_variant": variant,
        "firmware": _firmware_label(variant, firmver, buildno, extendno),
        "jffs_scripts_enabled": _out(results, "nvram get jffs2_scripts") == "1",
        "temps_c": {
            "cpu": _temp_c(_out(results, "cat /sys/class/thermal/thermal_zone0/temp")),
            "radio_2g": _temp_c(_out(results, "wl -i eth6 phy_tempsense")),
            "radio_5g": _temp_c(_out(results, "wl -i eth7 phy_tempsense")),
        },
        "uptime_seconds": uptime_seconds,
        "mem_total_kb": _mem_value(meminfo, "MemTotal"),
        "mem_free_kb": _mem_value(meminfo, "MemFree"),
        # MemFree excludes reclaimable page cache; MemAvailable is what's actually usable
        "mem_available_kb": _mem_value(meminfo, "MemAvailable"),
        "loadavg": loadavg.split()[:3] if loadavg else [],
    }


def _num(v: str):
    try:
        return float(v) if v not in ("", None) else None
    except ValueError:
        return None


def _parse_connmon(raw: str) -> Optional[Dict]:
    """connmon aggregates: line 1 = last 24h, line 2 = 7-day baseline."""
    lines = raw.splitlines()
    if not lines or not lines[0].strip():
        return None
    count, ping, ping_max, jitter, jitter_max, quality_min, degraded = (lines[0].split("|") + [""] * 7)[:7]
    base = (lines[1].split("|") if len(lines) > 1 else []) + ["", ""]
    return {
        "tests_24h": int(_num(count) or 0),
        "ping_ms_avg": _num(ping),
        "ping_ms_max": _num(ping_max),
        "jitter_ms_avg": _num(jitter),
        "jitter_ms_max": _num(jitter_max),
        "line_quality_min_pct": _num(quality_min),  # 100 = no packet loss during the 30 s test
        "tests_with_loss_24h": int(_num(degraded) or 0),
        "ping_ms_avg_7d": _num(base[0]),
        "jitter_ms_avg_7d": _num(base[1]),
    }


def _parse_speedtest(raw: str) -> Optional[Dict]:
    """spdMerlin: line 1 = latest test, line 2 = 7-day count/avg/min."""
    lines = raw.splitlines()
    if not lines or not lines[0].strip():
        return None
    ts, down, up, latency, jitter, server = (lines[0].split("|", 5) + [""] * 6)[:6]
    stats = (lines[1].split("|") if len(lines) > 1 else []) + [""] * 4
    return {
        "last_at": datetime.fromtimestamp(int(ts), timezone.utc).isoformat(timespec="seconds") if ts.isdigit() else None,
        "download_mbps": _num(down),
        "upload_mbps": _num(up),
        "latency_ms": _num(latency),
        "jitter_ms": _num(jitter),
        "server": server or None,
        "tests_7d": int(_num(stats[0]) or 0),
        "download_mbps_avg_7d": _num(stats[1]),
        "download_mbps_min_7d": _num(stats[2]),
        "upload_mbps_avg_7d": _num(stats[3]),
    }


def _parse_wan(results: List[Dict]) -> Dict:
    pppd_line = _out(results, "ps w | grep pppd | grep -v grep")
    return {
        "state": _out(results, "nvram get wan0_state_t"),
        "ip": _out(results, "nvram get wan0_ipaddr"),
        "proto": _out(results, "nvram get wan0_proto"),
        "pppd_running": bool(pppd_line),
        "connmon": _parse_connmon(_out(results, CONNMON_CMD)),
        "speedtest": _parse_speedtest(_out(results, SPEEDTEST_CMD)),
    }


def _summarize_drops(raw: str, banned_raw: str = "", top: int = 8) -> Dict:
    """Aggregate firewall rows ("Mon DD HH:MM:SS|kind|src|dst|proto|dport") into counts.

    kind is "BLOCKED - INBOUND"/"BLOCKED - OUTBOUND"/... (Skynet) or "DROP" (router
    firewall). Inbound = internet -> router, aggregated by target port and source;
    outbound = a LAN device contacting a blocklisted address, by device and target.
    The top-level counts cover everything except outbound blocks.
    """
    rows = [line.split("|") for line in raw.splitlines() if line.count("|") == 5]
    kinds = Counter(kind for _, kind, *_ in rows)
    inbound = [r for r in rows if "OUTBOUND" not in r[1]]
    outbound = [r for r in rows if "OUTBOUND" in r[1]]
    ports = Counter(f"{proto}/{dport}" if dport else proto for _, _, _, _, proto, dport in inbound)
    sources = Counter(src for _, _, src, *_ in inbound)
    banned = dict(line.split("=", 1) for line in banned_raw.splitlines() if "=" in line)
    return {
        "total": len(inbound),
        "window_start": rows[0][0] if rows else None,
        "window_end": rows[-1][0] if rows else None,
        "by_kind": dict(kinds),
        "unique_sources": len(sources),
        "top_ports": [{"port": p, "count": c} for p, c in ports.most_common(top)],
        "top_sources": [{"ip": ip, "count": c} for ip, c in sources.most_common(top)],
        "outbound": {
            "total": len(outbound),
            "by_lan_device": [{"ip": ip, "count": c} for ip, c in Counter(r[2] for r in outbound).most_common(top)],
            "top_destinations": [
                {"dest": d, "count": c}
                for d, c in Counter(f"{r[3]}:{r[5]}" if r[5] else r[3] for r in outbound).most_common(top)
            ],
        },
        "skynet_banned": {k.replace("Skynet-", "").lower(): int(v) for k, v in banned.items() if v.isdigit()} or None,
    }


def _parse_security(results: List[Dict]) -> Dict:
    syslog = _out(results, SYSLOG_TAIL_CMD)
    security_log = _out(results, "tail -n 200 /jffs/security_recored.log")
    aae_log = _out(results, "tail -n 100 /jffs/aae.log")
    return {
        "syslog_tail": "\n".join(syslog.splitlines()[-RAW_SYSLOG_LINES:]),
        "syslog_summary": summarize_text(syslog, top=40),
        "security_log_summary": summarize_text(security_log, top=8),
        "aae_log_summary": summarize_text(aae_log, top=6),
        "firewall_drop_logging": _out(results, "nvram get fw_log_x"),
        "firewall_drops": _summarize_drops(_out(results, FIREWALL_DROPS_CMD), _out(results, SKYNET_SETS_CMD)),
        "security_log_tail": security_log,
        "aae_log_tail": aae_log,
        "aiprotection_enabled": _out(results, "nvram get wrs_protect_enable") == "1",
        "malware_block_enabled": _out(results, "nvram get wrs_mals_enable") == "1",
    }


def wifi_client_macs(wifi: Dict) -> List[str]:
    return wifi.get("clients_2g", []) + wifi.get("clients_5g", []) + wifi.get("clients_6g", [])


def _parse_mesh_nodes(raw: str) -> List[Dict]:
    # "<TUF-AX6000>192.168.1.2>AA:BB:CC:00:00:02>0<RT-AX88U_Pro>192.168.1.1>AA:BB:CC:00:00:01>1..."
    nodes = []
    for entry in raw.split("<"):
        parts = entry.split(">")
        if len(parts) >= 4 and parts[2]:
            nodes.append({"mac": parts[2].upper(), "model": parts[0], "ip": parts[1], "is_main": parts[3] == "1"})
    return sorted(nodes, key=lambda n: (not n["is_main"], n["model"]))


def _band(key: str) -> Optional[str]:
    # clientlist.json band keys: "2G", "5G", "5G1", "6G", with "_N" suffixes for guest/SDN networks
    return {"2": "2g", "5": "5g", "6": "6g"}.get(key[:1]) if key != "wired_mac" else None


# networkmap placeholders that say nothing about the device (Tuya/ESP chips report "wlan0"/"lwip0")
_GENERIC_NAMES = re.compile(r"^(\*|wlan\d*|lwip\d*|eth\d*|localhost|unknown)?$", re.IGNORECASE)
# networkmap falls back to the DHCP vendor-class string when the OUI lookup fails
_NOT_A_VENDOR = re.compile(r"^(dhcpcd|android-dhcp|udhcp|MSFT \d)", re.IGNORECASE)
_CORP_SUFFIX = re.compile(r"[\s,.]+(co\.?,?\s*ltd|ltd|inc|incorporated|gmbh|llc|limited|corp(oration)?)\.?$", re.IGNORECASE)


def _client_names(results: List[Dict]) -> Dict[str, Dict]:
    """{MAC: {"name", "vendor"}} -- the router-UI name wins, then networkmap's learned name."""
    try:
        nmp = json.loads(_out(results, NETWORKMAP_CMD) or "{}")
    except ValueError:
        nmp = {}
    names: Dict[str, Dict] = {}
    for mac, info in (nmp if isinstance(nmp, dict) else {}).items():
        if not isinstance(info, dict):
            continue
        name, vendor = (info.get("name") or "").strip(), (info.get("vendor") or "").strip()
        vendor = "" if _NOT_A_VENDOR.match(vendor) else _CORP_SUFFIX.sub("", vendor)
        if name and vendor and (info.get("vendor") or "").startswith(name):  # name is a truncated vendor
            name = ""
        names[mac.upper()] = {
            "name": None if _GENERIC_NAMES.match(name) else name,
            "vendor": vendor or None,
        }
    for entry in _out(results, CUSTOM_CLIENTLIST_CMD).split("<"):
        parts = entry.split(">")
        if len(parts) >= 2 and parts[0].strip() and parts[1]:
            names.setdefault(parts[1].upper(), {"vendor": None})["name"] = parts[0].strip()
    return names


def _parse_wifi(results: List[Dict]) -> Dict:
    def macs(band_out: str) -> List[str]:
        return [m.upper() for m in re.findall(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", band_out)]

    nodes = _parse_mesh_nodes(_out(results, MESH_NODES_CMD))
    main_mac = next((n["mac"] for n in nodes if n["is_main"]), None)
    try:
        mesh = json.loads(_out(results, MESH_CLIENTLIST_CMD) or "{}")
    except ValueError:
        mesh = {}

    # every wireless client on every mesh node; a client roaming mid-refresh can be
    # listed under two nodes -- keep the stronger signal
    clients: Dict[str, Dict] = {}
    for node_mac, bands in (mesh if isinstance(mesh, dict) else {}).items():
        for key, entries in (bands or {}).items():
            band = _band(key)
            if not band or not isinstance(entries, dict):
                continue
            for mac, info in entries.items():
                info = info if isinstance(info, dict) else {}
                rssi = int(info["rssi"]) if re.fullmatch(r"-?\d+", str(info.get("rssi", ""))) else None
                prev = clients.get(mac.upper())
                if prev and (prev["rssi"] or -999) >= (rssi or -999):
                    continue
                clients[mac.upper()] = {
                    "mac": mac.upper(), "node": node_mac.upper(), "band": band, "iface": key,
                    "ip": info.get("ip") or None, "rssi": rssi,
                }

    # live assoclist on the main router's primary radios: catches anything clientlist.json
    # hasn't picked up yet, and is the only source on a router without AiMesh
    for band, cmd in (("2g", "wl -i eth6 assoclist"), ("5g", "wl -i eth7 assoclist")):
        for mac in macs(_out(results, cmd)):
            clients.setdefault(mac, {"mac": mac, "node": main_mac, "band": band, "iface": band.upper(), "ip": None, "rssi": None})

    names = _client_names(results)
    for c in clients.values():
        c.update({"name": None, "vendor": None, **names.get(c["mac"], {})})

    client_list = sorted(
        clients.values(),
        key=lambda c: (c["node"] != main_mac, c["node"] or "", c["band"], c["name"] is None, (c["name"] or c["mac"]).lower()),
    )
    for n in nodes:
        mine = [c for c in client_list if c["node"] == n["mac"]]
        n["clients_2g"] = sum(c["band"] == "2g" for c in mine)
        n["clients_5g"] = sum(c["band"] == "5g" for c in mine)
        n["clients_6g"] = sum(c["band"] == "6g" for c in mine)
        n["client_count"] = len(mine)

    by_band = lambda b: [c["mac"] for c in client_list if c["band"] == b]  # noqa: E731
    return {
        "ssid_2g": _out(results, "nvram get wl0_ssid"),
        "ssid_5g": _out(results, "nvram get wl1_ssid"),
        "clients_2g": by_band("2g"),
        "clients_5g": by_band("5g"),
        "clients_6g": by_band("6g"),
        "client_count": len(client_list),
        "clients": client_list,
        "nodes": nodes,
    }


def build_snapshot(router_name: str, host: str, grouped_results: Dict[str, List[Dict]]) -> Dict:
    return {
        "router": router_name,
        "host": host,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "system": _parse_system(grouped_results.get("system", [])),
        "wan": _parse_wan(grouped_results.get("wan", [])),
        "security": _parse_security(grouped_results.get("security", [])),
        "wifi": _parse_wifi(grouped_results.get("wifi", [])),
    }
