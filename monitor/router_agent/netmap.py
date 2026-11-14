"""Network map: every device on the network, the mesh node it hangs off, its room.

Two halves:

* collection (every 5-minute check): `lan_snapshot()` keeps what the map needs from the
  raw router output that the rest of the snapshot discards -- which node each *wired*
  device sits behind, the backhaul between mesh nodes, and the DHCP/ARP host table --
  and `parse_services()` records what runs on the router. Both land in the snapshot.
* rendering (`/api/network-map`): `build_map()` turns a snapshot into rooms, devices,
  links and the service legend. Device type, brand and room are guessed from names
  (most names carry their room: "kitchen_Google-Home-Mini"); `network_map.rooms` in
  config.yml overrides any of them.

Wired topology: AiMesh's /tmp/clientlist.json lists, per node, every MAC learned on
that node's ethernet ports ("wired_mac") -- i.e. everything *downstream* of it. The
main router's list holds the whole wired network; a satellite's only what is cabled
behind it. So a device is cabled to the node with the *smallest* list containing it.
"""
import json
import re
from datetime import UTC, datetime

from .collector import ARP_CMD, LEASES_CMD, MESH_CLIENTLIST_CMD, SERVICES_CMD
from .snapshot import _client_names, _out

_MAC_RE = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
# networkmap / DHCP placeholders that say nothing about the device
_GENERIC_HOST = re.compile(r"^(\*|wlan\d*|lwip\d*|eth\d*|localhost|unknown|esp_[0-9a-f]+)?$", re.IGNORECASE)
VPN_HANDSHAKE_FRESH_S = 180  # WireGuard re-handshakes every 2 min while a peer is active


# ------------------------------------------------------------------ collection

def _wired_sets(mesh: dict) -> dict[str, dict[str, str]]:
    """{node_mac: {mac: ip}} from clientlist.json's wired_mac entries."""
    out = {}
    for node, bands in (mesh if isinstance(mesh, dict) else {}).items():
        wired = (bands or {}).get("wired_mac") if isinstance(bands, dict) else None
        out[node.upper()] = {m.upper(): ((v or {}).get("ip") or "") for m, v in (wired or {}).items()} \
            if isinstance(wired, dict) else {}
    return out


def _parent(mac: str, wired: dict[str, dict[str, str]]) -> str | None:
    """The node `mac` is cabled to: the node with the smallest wired list holding it."""
    holders = [n for n, macs in wired.items() if mac in macs and n != mac]
    return min(holders, key=lambda n: len(wired[n])) if holders else None


def lan_snapshot(grouped: dict[str, list[dict]], snapshot: dict) -> dict:
    """{"wired": [...], "backhaul": {node: {"to", "kind"}}, "hosts": [...]} for the map."""
    wifi_results = grouped.get("wifi", [])
    try:
        mesh = json.loads(_out(wifi_results, MESH_CLIENTLIST_CMD) or "{}")
    except ValueError:
        mesh = {}
    wired = _wired_sets(mesh)
    wifi = snapshot.get("wifi") or {}
    nodes = [n["mac"] for n in wifi.get("nodes") or []]
    main = next((n["mac"] for n in wifi.get("nodes") or [] if n.get("is_main")), None)
    wireless = {c["mac"] for c in wifi.get("clients") or []}

    # backhaul: a satellite in some node's wired list is cabled to it, otherwise it meshes over the air
    backhaul = {}
    for n in nodes:
        if n == main:
            continue
        up = _parent(n, wired)
        backhaul[n] = {"to": up, "kind": "wired"} if up else {"to": main, "kind": "wireless"}

    names = _client_names(wifi_results)
    hosts: dict[str, dict] = {}
    for line in _out(wifi_results, LEASES_CMD).splitlines():
        p = line.split()
        if len(p) >= 4 and ":" in p[1]:
            hosts[p[1].upper()] = {"mac": p[1].upper(), "ip": p[2], "host": None if _GENERIC_HOST.match(p[3]) else p[3],
                                   "lease": True, "arp": False}
    for line in _out(wifi_results, ARP_CMD).splitlines()[1:]:
        p = line.split()
        if len(p) >= 6 and _MAC_RE.match(p[3].upper()) and p[3] != "00:00:00:00:00:00" and p[5].startswith("br"):
            h = hosts.setdefault(p[3].upper(), {"mac": p[3].upper(), "ip": p[0], "host": None, "lease": False, "arp": False})
            h["ip"] = p[0]
            h["arp"] = p[2] == "0x2"  # 0x2 = answered recently; 0x0 = incomplete (gone)
    for mac, h in hosts.items():
        h.update({k: v for k, v in (names.get(mac) or {}).items() if v})

    wired_devices = []
    for mac in sorted(set().union(*wired.values()) if wired else set()):
        if mac in wireless or mac in nodes:
            continue
        ip = next((w[mac] for w in wired.values() if w.get(mac)), None) or (hosts.get(mac) or {}).get("ip")
        wired_devices.append({"mac": mac, "ip": ip, "node": _parent(mac, wired) or main,
                              **{k: v for k, v in (names.get(mac) or {}).items() if v}})
    return {"wired": wired_devices, "backhaul": backhaul, "hosts": sorted(hosts.values(), key=lambda h: h["ip"])}


def parse_services(grouped: dict[str, list[dict]]) -> dict:
    """SERVICES_CMD's key=value lines -> {"proc": {...}, "nvram": {...}, "cron": [...], "wireguard": [...], ...}."""
    raw = _out(grouped.get("services", []), SERVICES_CMD)
    out: dict = {"proc": {}, "nvram": {}, "cron": [], "wireguard": []}
    handshakes = {}
    for line in raw.splitlines():
        key, _, val = line.partition("=")
        if key.startswith("proc_"):
            out["proc"][key[5:]] = val == "1"
        elif key.startswith("nv_"):
            out["nvram"][key[3:]] = val
        elif key == "cron":
            out["cron"] = [j for j in val.split(",") if j]
        elif key == "wgpeer":
            p = val.split("|")
            if len(p) >= 4:
                out["wireguard"].append({"name": p[1], "addr": p[2].split("/")[0], "enabled": p[3] == "1",
                                         "_pub": p[4] if len(p) > 4 else ""})
        elif key == "wgdump":
            allowed, hs, endpoint, rx, tx, pub = (val.split("|") + [""] * 5)[:6]
            ep = endpoint.rsplit(":", 1)[0].strip("[]") if endpoint not in ("", "(none)") else None
            rec = (int(hs) if hs.isdigit() else 0, ep, int(rx) if rx.isdigit() else None,
                   int(tx) if tx.isdigit() else None)
            if pub:
                handshakes["pub:" + pub] = rec
            for a in allowed.split(","):
                handshakes.setdefault(a.split("/")[0], rec)
        elif key in ("now", "dnsmasq", "ntp_main", "ntp_sdn", "skynet"):
            out[key] = int(val) if val.isdigit() else 0
    now = out.get("now") or 0
    for peer in out["wireguard"]:
        pub = peer.pop("_pub", "")  # join key only, not kept in the snapshot
        hs, endpoint, rx, tx = (handshakes.get("pub:" + pub) if pub else None) or handshakes.get(peer["addr"]) \
            or (0, None, None, None)
        peer.update(handshake_ts=hs or None, endpoint=endpoint, rx=rx, tx=tx)
        peer["last_handshake_s"] = (now - hs) if hs and now else None
        peer["connected"] = bool(hs and now and now - hs < VPN_HANDSHAKE_FRESH_S)
    return out


# ------------------------------------------------------------------ classification

# (type, pattern over "name host vendor"), first match wins -- order matters:
# "Reolink Garden" is a camera, "backyard_Garden_light" a light, "Samsung TV" a TV
_TYPES = [
    ("camera", r"reolink|camera|\bcam\b|doorbell|ipcam"),
    ("nas", r"synology|diskstation|\bnas\b"),
    ("server", r"proxmox|\blxc\b|server|network-ai|ollama|timescale|coach|\bpve\b"),
    ("tv", r"(^|[\s_-])tv\b|_tv|tizen|apple.?tv|bravia|webos"),
    ("display", r"google.?hub|nest.?hub|echo.?show"),
    ("speaker", r"nest.?mini|home.?mini|google.?home|\becho\b|sonos|speaker|audio|denon|homepod"),
    ("phone", r"iphone|android|pixel|galaxy|phone"),
    ("tablet", r"tablet|ipad"),
    ("laptop", r"laptop|macbook|\bmac\b|thinkpad|notebook|\bzen\b"),
    ("computer", r"\bpc\b|desktop|workstation|imac"),
    ("dishwasher", r"dishwasher"),
    ("washer", r"washer|washing"),
    ("dryer", r"dryer"),
    ("purifier", r"purifier|zhimi"),
    ("vacuum", r"irobot|roomba|vacuum|roborock"),
    ("heating", r"heating|viessmann|boiler|thermostat|sauna"),
    ("appliance", r"digestor|hisense|oven|fridge|microwave|coffee"),
    ("light", r"lamp|bulb|light|\bled\b|_led|wiz_|\bwiz\b|hue"),
    ("plug", r"plug|shelly|socket|power"),
    ("garden", r"gardena|sprinkler|irrigation|mower"),
    ("vpn", r"vpn|wireguard"),
]
_TYPES = [(t, re.compile(p, re.IGNORECASE)) for t, p in _TYPES]

# (brand slug, pattern over "name host vendor" + MAC prefixes); the frontend has a logo for most
_BRANDS = [
    ("apple", r"apple|iphone|ipad|macbook|\bmac\b|homepod"),
    ("samsung", r"samsung|sjit|samjin|tizen"),
    ("google", r"google|\bnest\b|chromecast"),
    ("reolink", r"reolink"),
    ("bosch", r"bosch|\bbsh\b"),
    ("xiaomi", r"xiaomi|zhimi|\bmi\b"),
    ("irobot", r"irobot|roomba"),
    ("shelly", r"shelly"),
    ("meross", r"meross"),
    ("tuya", r"tuya"),
    ("viessmann", r"viessmann"),
    ("hisense", r"hisense"),
    ("gardena", r"gardena"),
    ("wiz", r"wiz_|\bwiz\b"),
    ("denon", r"d&m holdings|denon|marantz"),
    ("synology", r"synology"),
    ("proxmox", r"proxmox"),
    ("asus", r"asus"),
    ("espressif", r"espressif|^esp_"),
]
_BRANDS = [(b, re.compile(p, re.IGNORECASE)) for b, p in _BRANDS]
_MAC_BRANDS = {"BC:24:11": "proxmox", "00:11:32": "synology", "00:05:CD": "denon", "94:BB:AE": "gardena",
               "EC:71:DB": "reolink"}

# room keyword in a device name -> room
_ROOMS = [
    (r"bed.?room", "Bedroom"), (r"kitchen", "Kitchen"), (r"living.?room|\bliving\b", "Living room"),
    (r"office", "Office"), (r"\bshed\b", "Shed"), (r"terrace", "Terrace"),
    (r"backyard|garden", "Garden"), (r"entrance|doorbell|front.?gate|\bfront\b", "Entrance"),
    (r"hallway|\bhall\b", "Hallway"), (r"sauna", "Sauna"), (r"bath.?room", "Bathroom"),
    (r"garage", "Garage"), (r"laundry|utility", "Utility"),
]
_ROOMS = [(re.compile(p, re.IGNORECASE), r) for p, r in _ROOMS]
# rooms for devices whose name doesn't say (all marked as guesses on the map)
_TYPE_ROOMS = {"phone": "Mobile", "tablet": "Mobile", "laptop": "Mobile", "server": "Server", "nas": "Server",
               "washer": "Utility", "dryer": "Utility", "heating": "Utility", "vpn": "Remote"}
# fixed rooms go last, in this order; named rooms are sorted by size before them
_TAIL_ROOMS = ["Utility", "Server", "Mobile", "Remote", "Unassigned"]


def _words(*parts) -> str:
    # "livingroom_Air-Purifier" -> "livingroom Air-Purifier": \b works on underscores-turned-spaces
    return " ".join(str(p) for p in parts if p).replace("_", " ")


def classify_type(name: str, host: str | None, vendor: str | None, mac: str = "") -> str:
    text = _words(name, host, vendor)
    if mac[:8] == "BC:24:11":  # Proxmox's virtual NIC prefix: a VM/container
        return "server"
    return next((t for t, p in _TYPES if p.search(text)), "iot" if re.search(r"espressif|tuya", text, re.IGNORECASE) else "device")


def classify_brand(name: str, host: str | None, vendor: str | None, mac: str = "") -> str | None:
    if mac[:8] in _MAC_BRANDS:
        return _MAC_BRANDS[mac[:8]]
    text = _words(name, host, vendor)
    return next((b for b, p in _BRANDS if p.search(text)), None)


def room_from_name(name: str) -> str | None:
    text = _words(name)
    return next((r for p, r in _ROOMS if p.search(text)), None)


def _override(overrides: dict, *keys) -> str | None:
    low = {str(k).strip().lower(): v for k, v in (overrides or {}).items()}
    return next((low[k.lower()] for k in keys if k and k.lower() in low), None)


# ------------------------------------------------------------------ rendering

def _network(ip: str | None, networks: dict) -> str:
    if not ip:
        return "Unknown"
    return next((n for prefix, n in (networks or {}).items() if ip.startswith(prefix)), "Other")


def _services(snap: dict) -> list[dict]:
    """The router's services for the legend: {id, name, status ok|warn|down|off, detail}."""
    sv = snap.get("services") or {}
    proc, nv, cron = sv.get("proc") or {}, sv.get("nvram") or {}, set(sv.get("cron") or [])
    have = bool(sv)
    wan, sec = snap.get("wan") or {}, snap.get("security") or {}
    out = []

    def add(id_, name, status, detail="", brand=None):
        out.append({"id": id_, "name": name, "status": status, "detail": detail, "brand": brand})

    cm = wan.get("connmon") or {}
    add("wan", f"Internet ({(wan.get('proto') or 'WAN').upper()})", "ok" if wan.get("state") == "2" else "down",
        " · ".join(x for x in [wan.get("ip"), f"ping {cm['ping_ms_avg']} ms" if cm.get("ping_ms_avg") else ""] if x))
    fd = sec.get("firewall_drops") or {}
    banned = fd.get("skynet_banned") or {}
    add("skynet", "Skynet firewall", "ok" if sv.get("skynet") else ("down" if have else "off"),
        f"{banned.get('blacklist', 0):,} IPs + {banned.get('blockedranges', 0):,} ranges blocked" if banned else "IP blocklists")
    dh = snap.get("dns_health") or {}
    dns = snap.get("dns") or {}
    add("adguard", "AdGuardHome", {"ok": "ok", "unfiltered": "warn", "down": "down"}.get(dh.get("state"), "off"),
        (f"{dns.get('queries', 0)} lookups, {dns.get('blocked', 0)} blocked last check" if dns else "DNS filtering")
        + (f" · {'; '.join(dh['problems'])}" if dh.get("problems") else ""), "adguard")
    add("dnsmasq", "DHCP + local DNS (dnsmasq)", "ok" if sv.get("dnsmasq") else ("down" if have else "off"),
        f"{(sv.get('dnsmasq') or 0) // 2} networks (LAN, Guest, IoT)")
    if have:
        add("ntp", "NTP time server", "ok" if sv.get("ntp_main") and sv.get("ntp_sdn") else
            ("warn" if sv.get("ntp_main") or sv.get("ntp_sdn") else "down"),
            "main LAN + Guest/IoT (ntp-sdn), intercepts hard-coded NTP")
        peers = sv.get("wireguard") or []
        if nv.get("wgs_enable") == "1":
            add("wireguard", "WireGuard VPN server", "ok",
                f"{sum(p['connected'] for p in peers)} of {len(peers)} peers connected", "wireguard")
        add("aiprotection", "AiProtection (Trend Micro)",
            "ok" if nv.get("wrs_protect_enable") == "1" else "off",
            "malicious-site blocking" + (" + infected-device blocking" if nv.get("wrs_mals_enable") == "1" else ""))
        add("qos", "Adaptive QoS + Traffic Analyzer", "ok" if nv.get("bwdpi_db_enable") == "1" else "off",
            "per-device internet usage")
        add("connmon", "connmon", "ok" if "connmon_generate" in cron else "off",
            f"ping test every 5 min · line quality {cm.get('line_quality_min_pct', '?')}% min" if cm else "ping test every 5 min")
        st = wan.get("speedtest") or {}
        add("spdmerlin", "spdMerlin", "ok" if "spdMerlin_generate" in cron else "off",
            f"↓ {st['download_mbps']:.0f} / ↑ {st['upload_mbps']:.0f} Mbps (daily)" if st.get("download_mbps") else "daily speedtest")
        add("scribe", "scribe (syslog-ng)", "ok" if proc.get("syslog-ng") else "down", "logs on the USB stick")
        add("letsencrypt", "Let's Encrypt + HTTPS UI", "ok" if nv.get("le_enable") == "1" and proc.get("httpds") else "off",
            "router web UI certificate", "letsencrypt")
        add("ssh", "SSH (dropbear)", "ok" if proc.get("dropbear") else "down", "this monitor collects over SSH")
        add("samba", "Samba file sharing", "ok" if proc.get("smbd") else "off", "USB stick share")
        add("minidlna", "Media server (DLNA)", "ok" if proc.get("minidlna") else "off", "")
        add("avahi", "mDNS (Avahi)", "ok" if proc.get("avahi-daemon") else "off", "Bonjour / .local names")
    return out


def build_map(snap: dict | None, known: dict | None, cfg: dict | None) -> dict:
    snap, known, cfg = snap or {}, known or {}, cfg or {}
    mcfg = cfg.get("network_map") or {}
    overrides = mcfg.get("rooms") or {}
    adg = cfg.get("adguard") or {}
    networks, aliases = adg.get("networks") or {}, adg.get("aliases") or {}
    wifi, lan, sv = snap.get("wifi") or {}, snap.get("lan") or {}, snap.get("services") or {}
    hosts = {h["mac"]: h for h in lan.get("hosts") or []}
    node_list = wifi.get("nodes") or []
    node_macs = {n["mac"] for n in node_list}
    main = next((n["mac"] for n in node_list if n.get("is_main")), None)

    devices: dict[str, dict] = {}

    def add(mac, ip, name, vendor, host, link, online):
        h = hosts.get(mac) or {}
        ip = ip or h.get("ip")
        host = host or h.get("host")
        name = aliases.get(ip) or name or host or (known.get(mac) or {}).get("name")
        vendor = vendor or h.get("vendor") or (known.get(mac) or {}).get("vendor")
        label = name or (f"{vendor} device" if vendor else "Unknown device")
        dtype = classify_type(label, host, vendor, mac)
        named_room = room_from_name(name or "")
        room = _override(overrides, mac, ip, label) or named_room
        guessed = room is None
        room = room or _TYPE_ROOMS.get(dtype) or "Unassigned"
        devices[mac] = {
            "id": mac, "mac": mac, "ip": ip, "name": label, "host": host, "vendor": vendor,
            "type": dtype, "brand": classify_brand(label, host, vendor, mac),
            "network": _network(ip, networks), "room": room, "room_guessed": guessed and room != "Unassigned",
            "online": online, "link": link, "last_seen": (known.get(mac) or {}).get("last_seen"),
        }

    for c in wifi.get("clients") or []:
        add(c["mac"], c.get("ip"), c.get("name"), c.get("vendor"), None,
            {"to": c.get("node") or main, "kind": "wifi", "band": c.get("band"), "rssi": c.get("rssi")}, True)
    for w in lan.get("wired") or []:
        add(w["mac"], w.get("ip"), w.get("name"), w.get("vendor"), None, {"to": w.get("node") or main, "kind": "wired"}, True)
    # Proxmox guests share their host's cable: a guest missing from the wired lists sits
    # behind the same node as the other guests
    vm_nodes = [w.get("node") for w in lan.get("wired") or [] if w["mac"][:8] == "BC:24:11" and w.get("node")]
    vm_node = max(set(vm_nodes), key=vm_nodes.count) if vm_nodes else None
    # answered ARP recently but on no node's list (e.g. a wired IoT port): online, link unknown
    for mac, h in hosts.items():
        if mac not in devices and mac not in node_macs and h.get("arp"):
            link = {"to": vm_node, "kind": "wired", "inferred": True} if vm_node and mac[:8] == "BC:24:11" \
                else {"to": main, "kind": "seen"}
            add(mac, h.get("ip"), h.get("name"), h.get("vendor"), h.get("host"), link, True)
    # offline: remembered wifi clients and DHCP leases that aren't around right now
    for mac, k in known.items():
        if mac not in devices and mac not in node_macs:
            add(mac, None, k.get("name"), k.get("vendor"), None, None, False)
    for mac, h in hosts.items():
        if mac not in devices and mac not in node_macs and h.get("lease"):
            add(mac, h.get("ip"), h.get("name"), h.get("vendor"), h.get("host"), None, False)
    # VPN peers: a fresh WireGuard handshake = connected through the router
    for p in sv.get("wireguard") or []:
        vid = f"wg:{p['name']}"
        devices[vid] = {
            "id": vid, "mac": None, "ip": p["addr"], "name": p["name"], "host": None, "vendor": "WireGuard peer",
            "type": "vpn", "brand": "wireguard", "network": _network(p["addr"], networks) if networks else "VPN",
            "room": _override(overrides, p["name"], p["addr"]) or "Remote", "room_guessed": False,
            "online": p["connected"], "link": {"to": main, "kind": "vpn"} if p["connected"] else None,
            "last_handshake_s": p.get("last_handshake_s"),
        }

    # mesh nodes: room by override, else the most common named room among the devices behind them
    backhaul = lan.get("backhaul") or {}
    nodes = []
    for n in node_list:
        mine = [d for d in devices.values() if (d.get("link") or {}).get("to") == n["mac"]]
        rooms = [d["room"] for d in mine if d["room"] not in ("Unassigned", "Mobile", "Remote") and not d["room_guessed"]]
        rooms = rooms or [d["room"] for d in mine if d["room"] not in ("Unassigned", "Mobile", "Remote")]
        voted = max(set(rooms), key=rooms.count) if rooms else None
        room = _override(overrides, n["mac"], n["ip"], n["model"])
        nodes.append({
            "id": n["mac"], "mac": n["mac"], "ip": n["ip"], "model": n["model"].replace("_", " "),
            "is_main": n.get("is_main", False), "room": room or voted or "Unassigned", "room_guessed": room is None,
            "uplink": None if n.get("is_main") else backhaul.get(n["mac"], {"to": main, "kind": "wireless"}),
            "clients": sum(1 for d in mine if d["online"]), "brand": "asus",
        })

    sizes: dict[str, int] = {}
    for d in [*devices.values(), *nodes]:
        sizes[d["room"]] = sizes.get(d["room"], 0) + (1 if d.get("online", True) else 0)
    main_room = next((n["room"] for n in nodes if n["is_main"]), None)
    rooms = sorted((r for r in sizes if r not in _TAIL_ROOMS), key=lambda r: (r != main_room, -sizes[r], r))
    rooms += [r for r in _TAIL_ROOMS if r in sizes]

    order = {"camera": 0}
    dev_list = sorted(devices.values(), key=lambda d: (not d["online"], order.get(d["type"], 1), d["type"], d["name"].lower()))
    return {
        "collected_at": snap.get("collected_at"),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "router": {"name": snap.get("router"), "firmware": (snap.get("system") or {}).get("firmware")},
        "wan": {"ip": (snap.get("wan") or {}).get("ip"), "up": (snap.get("wan") or {}).get("state") == "2",
                "proto": (snap.get("wan") or {}).get("proto")},
        "rooms": rooms,
        "nodes": nodes,
        "devices": dev_list,
        "services": _services(snap),
        "has_topology": bool(lan),
    }
