"""UPnP exposure watch: alert once per new device, never for known devices re-opening ports."""
import json

from router_agent import notify, upnp
from router_agent.notify import Notifier
from router_agent.upnp import UpnpWatch, check_and_record, describe, parse

NAS, PHONE, CONSOLE = "02:00:00:00:00:10", "02:00:00:00:00:56", "02:00:00:00:00:77"
IP_MAC = {"192.0.2.10": NAS, "192.0.2.56": PHONE, "192.0.2.77": CONSOLE}
NAMES = {NAS: "NAS", PHONE: "Phone", CONSOLE: "Console"}

NAS_OPEN = "TCP:65280:192.0.2.10:5001:0:upnpclient\nTCP:63851:192.0.2.10:6690:0:upnpclient\n"
TAILSCALE = "UDP:41642:192.0.2.56:41641:7200:tailscale-portmap\n"
ENABLED = "upnp_enable=1\n"


def test_parse_leases():
    maps, enabled = parse(NAS_OPEN + TAILSCALE + "garbage\nTCP:x:1:2:3:y\n" + ENABLED)
    assert enabled is True
    assert len(maps) == 3
    assert maps[0] == {"proto": "TCP", "ext_port": 65280, "ip": "192.0.2.10", "port": 5001,
                       "permanent": True, "description": "upnpclient"}
    assert maps[2]["permanent"] is False
    assert parse("")[1] is None and parse("upnp_enable=0")[1] is False


def test_description_keeps_colons():
    maps, _ = parse("UDP:41641:192.0.2.5:41641:0:NAT-PMP 41641 UDP: extra")
    assert maps[0]["description"] == "NAT-PMP 41641 UDP: extra"
    assert describe(maps[0]) == "UDP 41641 → 41641 (permanent, NAT-PMP 41641 UDP: extra)"


def test_first_run_is_a_silent_baseline(tmp_path):
    r = UpnpWatch(tmp_path).check(NAS_OPEN + ENABLED, IP_MAC, NAMES)
    assert r["new_devices"] == [] and r["baseline"] is True
    assert r["exposed_devices"] == ["NAS"]
    known = json.loads((tmp_path / ".upnp_known.json").read_text())
    assert known[NAS]["baseline"] is True


def test_new_device_alerts_once_and_known_device_reopening_stays_quiet(tmp_path):
    w = UpnpWatch(tmp_path)
    w.check(NAS_OPEN, IP_MAC, NAMES)                       # baseline: NAS known
    assert w.check("", IP_MAC, NAMES)["new_devices"] == []  # NAS closes its ports
    assert w.check(NAS_OPEN, IP_MAC, NAMES)["new_devices"] == []  # ... and re-opens: quiet
    assert w.check("TCP:8443:192.0.2.10:443:0:x", IP_MAC, NAMES)["new_devices"] == []  # other port: quiet

    console = "TCP:3074:192.0.2.77:3074:3600:game\n"
    new = w.check(NAS_OPEN + console, IP_MAC, NAMES)["new_devices"]
    assert [d["device"] for d in new] == ["Console"]
    assert w.check(NAS_OPEN + console, IP_MAC, NAMES)["new_devices"] == []  # only once


def test_short_lived_udp_never_alerts(tmp_path):
    w = UpnpWatch(tmp_path)
    w.check("", IP_MAC, NAMES)
    r = w.check(TAILSCALE, IP_MAC, NAMES)
    assert r["new_devices"] == [] and r["exposed_devices"] == []
    assert len(r["mappings"]) == 1  # still listed in the snapshot


def test_device_without_known_mac_is_keyed_by_ip(tmp_path):
    w = UpnpWatch(tmp_path)
    w.check("", {}, {})
    new = w.check("TCP:80:192.0.2.200:80:0:x", {}, {})["new_devices"]
    assert new[0]["key"] == "ip:192.0.2.200" and new[0]["device"] == "192.0.2.200"


def test_check_and_record_emits_event_and_telegram(tmp_path, monkeypatch):
    sent = []
    n = Notifier("token", "1", tmp_path)
    monkeypatch.setattr(n, "send", sent.append)
    monkeypatch.setattr(notify, "_notifier", n)

    check_and_record(tmp_path, "", IP_MAC, NAMES)
    check_and_record(tmp_path, NAS_OPEN, IP_MAC, NAMES)
    events = [json.loads(line) for line in (tmp_path / "router_events.log").read_text().splitlines()]
    assert [e["event"] for e in events] == ["upnp_new_device"]
    assert events[0]["device"] == "NAS" and events[0]["ports"][0] == "TCP 65280 → 5001 (permanent, upnpclient)"
    assert len(sent) == 1
    assert "NAS opened a port to the internet" in sent[0] and "TCP 65280 → 5001" in sent[0]

    check_and_record(tmp_path, "", IP_MAC, NAMES)
    check_and_record(tmp_path, NAS_OPEN, IP_MAC, NAMES)
    assert len(sent) == 1


def test_upnp_alerts_can_be_switched_off(tmp_path, monkeypatch):
    n = Notifier("token", "1", tmp_path, events=("wan",))
    sent = []
    monkeypatch.setattr(n, "send", sent.append)
    n.router_event({"event": "upnp_new_device", "device": "NAS", "ports": ["TCP 1 → 1"]})
    assert sent == []


def test_command_is_collected():
    from router_agent.collector import COMMAND_GROUPS
    assert upnp.UPNP_CMD in COMMAND_GROUPS["services"]
