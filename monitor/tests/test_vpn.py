"""Remote access: WireGuard sessions, new peers/networks, DDNS vs WAN IP, and their alerts."""
from router_agent import geoip, notify
from router_agent.netmap import parse_services
from router_agent.notify import Notifier
from router_agent.vpn import END_S, VpnWatch

T0 = 1_800_000_000
NETS = {"203.0.113.10": {"country": "RO", "asn": 64500, "as_org": "Home ISP"},
        "203.0.113.20": {"country": "RO", "asn": 64501, "as_org": "Mobile Carrier"},
        "198.51.100.5": {"country": "DE", "asn": 64502, "as_org": "Hotel Wifi"}}


def services(now, peers, wgs="1", ddns_host="home.example.net"):
    return {"now": now, "nvram": {"wgs_enable": wgs, "ddns_enable_x": "1", "ddns_hostname_x": ddns_host},
            "wireguard": [{"name": n, "addr": f"10.6.0.{i + 2}", "enabled": True, "handshake_ts": hs,
                           "endpoint": ep, "rx": rx, "tx": tx} for i, (n, hs, ep, rx, tx) in enumerate(peers)]}


def watch(tmp_path, resolved=("192.0.2.1",)):
    return VpnWatch(tmp_path, {}, lookup=lambda ip: NETS.get(ip, {}), resolver=lambda host: list(resolved))


def kinds(events):
    return [e["event"] for e in events]


def test_parse_services_joins_peers_on_public_key():
    # the firmware's allowed-ips (10.6.0.2) differ from the peer's configured address (10.6.0.3)
    raw = ("now=1800000100\nwgpeer=1|phone|10.6.0.3/32|1|PUBKEYphone=\n"
           "wgdump=10.6.0.2/32|1800000050|203.0.113.10:37466|1000|2000|PUBKEYphone=\n")
    from router_agent.netmap import SERVICES_CMD
    (phone,) = parse_services({"services": [{"cmd": SERVICES_CMD, "out": raw}]})["wireguard"]
    assert phone["connected"] is True and phone["endpoint"] == "203.0.113.10" and "_pub" not in phone


def test_parse_services_reads_endpoint_and_bytes():
    raw = ("now=1800000100\nnv_wgs_enable=1\nwgpeer=1|phone|10.6.0.2/32|1\nwgpeer=2|laptop|10.6.0.3/32|1\n"
           "wgdump=10.6.0.2/32|1800000050|203.0.113.10:37466|1000|2000\nwgdump=10.6.0.3/32|0|(none)|0|0\n")
    from router_agent.netmap import SERVICES_CMD
    sv = parse_services({"services": [{"cmd": SERVICES_CMD, "out": raw}]})
    phone, laptop = sv["wireguard"]
    assert phone["endpoint"] == "203.0.113.10" and phone["rx"] == 1000 and phone["tx"] == 2000
    assert phone["connected"] is True and phone["last_handshake_s"] == 50
    assert laptop["endpoint"] is None and laptop["handshake_ts"] is None and laptop["connected"] is False


def test_baseline_is_silent_then_sessions_alert(tmp_path):
    w = watch(tmp_path)
    # first run: phone already connected -> recorded, no events
    _, ev = w.check(services(T0, [("phone", T0 - 30, "203.0.113.10", 100, 200)]), "192.0.2.1")
    assert ev == []
    # session ends silently (it started during the baseline)
    _, ev = w.check(services(T0 + END_S + 60, [("phone", T0 - 30, "203.0.113.10", 100, 200)]), "192.0.2.1")
    assert ev == []
    # a new session from the known home network: plain connect, not new_network
    t = T0 + 5000
    summary, ev = w.check(services(t, [("phone", t - 20, "203.0.113.10", 1000, 2000)]), "192.0.2.1")
    assert kinds(ev) == ["vpn_connect"] and ev[0]["new_network"] is False and ev[0]["as_org"] == "Home ISP"
    assert summary["peers"][0]["connected"] and "Home ISP" in summary["peers"][0]["network"]
    # still active (handshake refreshed): nothing
    _, ev = w.check(services(t + 300, [("phone", t + 280, "203.0.113.10", 5000, 9000)]), "192.0.2.1")
    assert ev == []
    # idle but inside END_S: still the same session
    _, ev = w.check(services(t + 600, [("phone", t + 280, "203.0.113.10", 5000, 9000)]), "192.0.2.1")
    assert ev == []
    # gone: one disconnect with this session's traffic only
    _, ev = w.check(services(t + 280 + END_S + 1, [("phone", t + 280, "203.0.113.10", 5000, 9000)]), "192.0.2.1")
    assert kinds(ev) == ["vpn_disconnect"]
    assert ev[0]["rx"] == 4000 and ev[0]["tx"] == 7000 and ev[0]["duration_s"] == 300


def test_new_network_and_roaming(tmp_path):
    w = watch(tmp_path)
    w.check(services(T0, [("phone", T0 - 30, "203.0.113.10", 0, 0)]), "192.0.2.1")  # baseline: home ISP known
    w.check(services(T0 + 2000, [("phone", T0 - 30, "203.0.113.10", 0, 0)]), "192.0.2.1")  # ends
    t = T0 + 9000
    _, ev = w.check(services(t, [("phone", t - 10, "198.51.100.5", 0, 0)]), "192.0.2.1")
    assert kinds(ev) == ["vpn_connect"] and ev[0]["new_network"] is True and ev[0]["country"] == "DE"
    # roams to a mobile carrier mid-session: new network again, flagged as roamed
    _, ev = w.check(services(t + 300, [("phone", t + 290, "203.0.113.20", 0, 0)]), "192.0.2.1")
    assert kinds(ev) == ["vpn_connect"] and ev[0]["roamed"] is True
    # roams back to a known network: quiet
    _, ev = w.check(services(t + 600, [("phone", t + 590, "198.51.100.5", 0, 0)]), "192.0.2.1")
    assert ev == []


def test_new_peer_and_wireguard_off(tmp_path):
    w = watch(tmp_path)
    w.check(services(T0, [("phone", 0, None, None, None)]), "192.0.2.1")
    _, ev = w.check(services(T0 + 300, [("phone", 0, None, None, None), ("stranger", T0 + 290, "198.51.100.5", 0, 0)]),
                    "192.0.2.1")
    assert kinds(ev) == ["vpn_new_peer", "vpn_connect"] and ev[0]["peer"] == "stranger"
    summary, ev = w.check(services(T0 + 600, [("phone", 0, None, None, None)], wgs="0"), "192.0.2.1")
    assert ev == [] and summary["peers"] == []


def test_ddns_mismatch_after_two_checks_then_ok(tmp_path):
    sv = services(T0, [])
    ok = watch(tmp_path, resolved=["192.0.2.1"])
    bad = watch(tmp_path, resolved=["192.0.2.99"])
    assert ok.check(sv, "192.0.2.1")[1] == []
    assert bad.check(sv, "192.0.2.1")[1] == []  # one wrong check: the router may be mid-update
    _, ev = bad.check(sv, "192.0.2.1")
    assert kinds(ev) == ["ddns_mismatch"] and ev[0]["resolved"] == ["192.0.2.99"]
    assert bad.check(sv, "192.0.2.1")[1] == []  # once
    _, ev = ok.check(sv, "192.0.2.1")
    assert kinds(ev) == ["ddns_ok"]


def test_ddns_skipped_without_public_wan_or_answer(tmp_path):
    sv = services(T0, [])
    summary, ev = watch(tmp_path, resolved=["192.0.2.99"]).check(sv, "")
    assert summary["ddns"] is None and ev == []
    summary, _ = VpnWatch(tmp_path, {}, lookup=lambda ip: {}, resolver=lambda h: None).check(sv, "192.0.2.1")
    assert summary["ddns"]["ok"] is None


def _notifier(tmp_path, monkeypatch, events):
    n = Notifier("token", "1", tmp_path, events=events)
    sent = []
    monkeypatch.setattr(n, "send", sent.append)
    return n, sent


def test_alert_routing(tmp_path, monkeypatch):
    connect = {"event": "vpn_connect", "peer": "phone", "endpoint": "203.0.113.10", **NETS["203.0.113.10"],
               "new_network": False}
    new_net = {**connect, "new_network": True}
    disc = {"event": "vpn_disconnect", "peer": "phone", "duration_s": 3600, "rx": 2_000_000, "tx": 50_000_000}
    ddns = {"event": "ddns_mismatch", "host": "home.example.net", "resolved": ["192.0.2.99"], "wan_ip": "192.0.2.1"}

    n, sent = _notifier(tmp_path, monkeypatch, notify.DEFAULT_EVENTS)  # vpn on, sessions off
    for e in (connect, new_net, disc, ddns, {"event": "vpn_new_peer", "peer": "x", "addr": "10.6.0.9"}):
        n.router_event(e)
    assert len(sent) == 3
    assert "new network" in sent[0] and "Home ISP (AS64500), RO" in sent[0]
    assert "DDNS out of date" in sent[1] and "VPN peer added" in sent[2]

    n, sent = _notifier(tmp_path, monkeypatch, ("vpn_sessions",))
    for e in (connect, disc, ddns):
        n.router_event(e)
    assert len(sent) == 2 and "phone connected" in sent[0]
    assert "1 h" in sent[1] or "60 min" in sent[1] or "1h" in sent[1]
    assert "50 MB to it" in sent[1] and "2 MB from it" in sent[1]

    n, sent = _notifier(tmp_path, monkeypatch, ("wan",))
    for e in (connect, new_net, disc, ddns):
        n.router_event(e)
    assert sent == []


def test_geoip_without_database_or_private_ip(tmp_path):
    assert geoip.lookup("192.168.1.10", tmp_path) == {}
    assert geoip.lookup("not-an-ip", tmp_path) == {}
    assert geoip.lookup("203.0.113.10", tmp_path) == {}  # documentation range: not global
    assert geoip.network_key({}) is None and geoip.network_key({"asn": 1}) == "AS1"
    assert geoip.describe({"asn": 64500, "as_org": "X", "country": "RO"}) == "X (AS64500), RO"
