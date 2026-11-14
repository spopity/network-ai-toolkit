"""Remote access watch: WireGuard server sessions and the DDNS name that points at it.

The router's WireGuard server (wgs1) is the one service open to the internet. Every
5-minute check already reads its peers (`snapshot.services.wireguard`: name, address,
last handshake, endpoint, rx/tx bytes, see netmap.parse_services). From that this
module derives sessions and DDNS health and emits router events (Events card,
Postgres, Telegram):

  vpn_new_peer    a peer config appeared on the router that was not there before
                  (`vpn`, major)
  vpn_connect     a session started: a fresh handshake (< FRESH_S) after none. With
                  the source IP's network (ISP / ASN) and country from the offline
                  DB-IP database (router_agent/geoip.py). `new_network` when this peer
                  never connected from that ASN before -> `vpn` (major); every
                  session -> `vpn_sessions` (opt-in). Roaming to a new network during
                  a session (wifi -> mobile) is reported the same way.
  vpn_disconnect  no handshake for END_S (WireGuard re-handshakes every 2 min while
                  traffic flows): duration and traffic of the session (`vpn_sessions`)
  ddns_mismatch   the router's DDNS name (ddns_hostname_x) resolves to something else
                  than the WAN IP on MISMATCH_CHECKS checks in a row (`vpn`); `ddns_ok`
                  once it matches again. Resolved over DNS-over-HTTPS (Cloudflare,
                  Google) so no local cache can hide a stale record. Skipped while the
                  WAN has no public IP.

Sessions are seen at check granularity: a connect is reported up to 5 minutes late and
a session shorter than one check interval may be missed. The first run (no state file)
is a silent baseline for peers: whatever is live then is recorded without alerting (a
DDNS mismatch is reported even then, after MISMATCH_CHECKS). State: logs/.vpn_state.json. No LLM.
"""
import ipaddress
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import requests

from . import geoip

logger = logging.getLogger(__name__)

STATE_FILE = ".vpn_state.json"
FRESH_S = 180          # handshake younger than this = a live session
END_S = 600            # no handshake for this long = the session ended
MISMATCH_CHECKS = 2    # DDNS must be wrong this many checks in a row (the router updates within a minute)
DOH = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")


def _ts(epoch: float | None) -> str | None:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds") if epoch else None


def resolve_a(host: str, timeout: float = 5) -> list[str] | None:
    """A records over DNS-over-HTTPS (JSON API); None when no resolver answered."""
    for url in DOH:
        try:
            r = requests.get(url, params={"name": host, "type": "A"},
                             headers={"accept": "application/dns-json"}, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            if data.get("Status") not in (0, 3):  # NOERROR / NXDOMAIN are real answers
                continue
            return sorted({a["data"] for a in data.get("Answer") or [] if a.get("type") == 1})
        except Exception as e:
            logger.info("DoH %s failed for %s: %s", url, host, e)
    return None


# a WAN address in these can't be what a DDNS name points at (no public IP / CGNAT)
NON_PUBLIC = tuple(ipaddress.ip_network(n) for n in
                   ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                    "172.16.0.0/12", "192.168.0.0/16"))


def _public(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return addr.version == 4 and not any(addr in n for n in NON_PUBLIC)


class VpnWatch:
    def __init__(self, base: Path, cfg: dict | None = None, lookup=geoip.lookup, resolver=resolve_a):
        self.path = Path(base) / STATE_FILE
        self.cfg = cfg if isinstance(cfg, dict) else {}
        self.lookup = lookup
        self.resolver = resolver

    def _load(self) -> tuple[dict, bool]:
        try:
            return json.loads(self.path.read_text()), False
        except (OSError, ValueError):
            return {}, True

    # ------------------------------------------------------------- sessions

    def _peers(self, state: dict, services: dict, baseline: bool) -> tuple[list[dict], list[dict]]:
        events, summary = [], []
        now = services.get("now") or 0
        if not now or (services.get("nvram") or {}).get("wgs_enable") != "1":
            return events, summary
        known = state.setdefault("peers", {})
        for p in services.get("wireguard") or []:
            name = p.get("name") or p.get("addr") or "?"
            st = known.get(name)
            first_sight = st is None
            if first_sight:
                st = known[name] = {"addr": p.get("addr"), "first_seen": _ts(now), "networks": {}, "session": None}
                if not baseline:
                    events.append({"event": "vpn_new_peer", "peer": name, "addr": p.get("addr"),
                                   "enabled": p.get("enabled")})
            quiet = baseline  # a peer added later is announced by vpn_new_peer, its sessions count
            hs = p.get("handshake_ts") or 0
            age = now - hs if hs else None
            ep = p.get("endpoint")
            info = self.lookup(ep) if ep else {}
            net = geoip.network_key(info)
            sess = st.get("session")
            live = age is not None and age < FRESH_S

            if sess is None and live:
                new_net = bool(net and net not in st["networks"] and st["networks"])
                if net:
                    st["networks"].setdefault(net, _ts(now))
                st["session"] = sess = {"start": _ts(hs), "endpoint": ep, "network": net, "rx0": p.get("rx"),
                                        "tx0": p.get("tx"), "last_hs": hs, "silent": quiet}
                if not quiet:
                    events.append({"event": "vpn_connect", "peer": name, "endpoint": ep, **info,
                                   "new_network": new_net})
            elif sess is not None and age is not None and age < END_S:
                sess["last_hs"] = hs
                if live and ep and ep != sess.get("endpoint"):
                    new_net = bool(net and net not in st["networks"])
                    if net:
                        st["networks"].setdefault(net, _ts(now))
                    sess.update(endpoint=ep, network=net)
                    if new_net and not quiet:
                        events.append({"event": "vpn_connect", "peer": name, "endpoint": ep, **info,
                                       "new_network": True, "roamed": True})
            elif sess is not None:
                last = sess.get("last_hs") or hs
                rx, tx = p.get("rx"), p.get("tx")
                d_rx = (rx - sess["rx0"]) if rx is not None and sess.get("rx0") is not None and rx >= sess["rx0"] else rx
                d_tx = (tx - sess["tx0"]) if tx is not None and sess.get("tx0") is not None and tx >= sess["tx0"] else tx
                start = datetime.fromisoformat(sess["start"]).timestamp() if sess.get("start") else last
                if not sess.get("silent"):
                    events.append({"event": "vpn_disconnect", "peer": name, "endpoint": sess.get("endpoint"),
                                   "start": sess.get("start"), "end": _ts(last),
                                   "duration_s": max(0, int(last - start)), "rx": d_rx, "tx": d_tx})
                st["session"] = sess = None
            st["addr"] = p.get("addr")
            summary.append({"peer": name, "enabled": p.get("enabled"), "connected": sess is not None,
                            "since": sess.get("start") if sess else None, "endpoint": ep if sess else None,
                            "network": geoip.describe(info) if sess and info else None,
                            "last_handshake": _ts(hs)})
        return events, summary

    # ------------------------------------------------------------- DDNS

    def _ddns(self, state: dict, services: dict, wan_ip: str | None) -> tuple[list[dict], dict | None]:
        nv = services.get("nvram") or {}
        host = self.cfg.get("ddns_host") or (nv.get("ddns_hostname_x") if nv.get("ddns_enable_x") == "1" else None)
        if not host or not _public(wan_ip):
            return [], None
        resolved = self.resolver(host)
        if resolved is None:
            return [], {"host": host, "wan_ip": wan_ip, "resolved": None, "ok": None}
        ok = wan_ip in resolved
        d = state.setdefault("ddns", {"bad": 0, "alerted": False})
        events = []
        if ok:
            if d.get("alerted"):
                events.append({"event": "ddns_ok", "host": host, "ip": wan_ip, "since": d.get("since")})
            state["ddns"] = {"bad": 0, "alerted": False}
        else:
            d["bad"] = d.get("bad", 0) + 1
            d.setdefault("since", datetime.now(UTC).isoformat(timespec="seconds"))
            if d["bad"] >= MISMATCH_CHECKS and not d.get("alerted"):
                d["alerted"] = True
                events.append({"event": "ddns_mismatch", "host": host, "resolved": resolved, "wan_ip": wan_ip,
                               "since": d["since"]})
        return events, {"host": host, "wan_ip": wan_ip, "resolved": resolved, "ok": ok}

    def check(self, services: dict, wan_ip: str | None) -> tuple[dict, list[dict]]:
        state, baseline = self._load()
        ev_peers, peers = self._peers(state, services or {}, baseline)
        ev_ddns, ddns = self._ddns(state, services or {}, wan_ip)
        self.path.write_text(json.dumps(state, indent=1))
        return {"peers": peers, "ddns": ddns, "baseline": baseline or None}, ev_peers + ev_ddns


def check_and_record(base: Path, cfg, services: dict, wan_ip: str | None) -> dict | None:
    """VpnWatch.check() plus its router events. Never raises."""
    from .events import append_router_event

    try:
        summary, events = VpnWatch(base, cfg).check(services, wan_ip)
    except Exception as e:
        logger.warning("vpn check failed: %s", e)
        return None
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    for e in events:
        append_router_event(base, {"ts": ts, **e})
    return summary
