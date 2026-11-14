"""Device naming (devices.py) and network-map classification (netmap.py)."""
import json

import pytest

from router_agent.devices import device_names, label, name_analysis, name_macs
from router_agent.netmap import build_map, classify_brand, classify_type, room_from_name

MAC = "02:00:00:00:00:01"


def test_label_never_empty():
    assert label({"name": "TV"}) == "TV"
    assert label({"vendor": "Acme"}) == "unnamed Acme device"
    assert label(None) == "unnamed device"


def test_name_macs_is_idempotent_and_handles_parentheses():
    names = {MAC: "Kitchen Plug"}
    once = name_macs(f"traffic from {MAC.lower()} and ({MAC})", names)
    assert once == f"traffic from Kitchen Plug ({MAC}) and (Kitchen Plug, {MAC})"
    assert name_macs(once, names) == once
    assert name_macs("02-00-00-00-00-02 seen", {}) == "unnamed device (02:00:00:00:00:02) seen"


def test_name_analysis_only_touches_string_sections():
    a = {"sections": {"wifi": f"new {MAC}", "score": 3}, "source": "claude"}
    out = name_analysis(a, {MAC: "Phone"})
    assert out["sections"] == {"wifi": f"new Phone ({MAC})", "score": 3}
    assert a["sections"]["wifi"] == f"new {MAC}"  # original untouched
    assert name_analysis(None, {}) is None


def test_device_names_snapshot_overrides_known_but_not_with_unnamed(tmp_path):
    (tmp_path / "known_clients.json").write_text(json.dumps({
        MAC.lower(): {"name": "Old Name"},
        "02:00:00:00:00:02": {"name": "Keeps Name"},
    }))
    snap = {"wifi": {"clients": [{"mac": MAC, "name": "New Name"}, {"mac": "02:00:00:00:00:02"}]}}
    assert device_names(tmp_path, snap) == {MAC: "New Name", "02:00:00:00:00:02": "Keeps Name"}
    assert device_names(tmp_path / "missing") == {}


@pytest.mark.parametrize(("name", "vendor", "mac", "expected"), [
    ("Front Gate", "Reolink", "", "camera"),
    ("DiskStation", None, "", "nas"),
    ("anything", None, "BC:24:11:00:00:01", "server"),     # Proxmox virtual NIC
    ("Living room TV", "Samsung", "", "tv"),
    ("Work iPhone", "Apple", "", "phone"),
    ("esp_1a2b", "Espressif", "", "iot"),
    ("mystery", None, "", "device"),
])
def test_classify_type(name, vendor, mac, expected):
    assert classify_type(name, None, vendor, mac) == expected


def test_classify_brand_prefers_mac_prefix():
    assert classify_brand("box", None, None, "00:11:32:AA:BB:CC") == "synology"
    assert classify_brand("Kitchen_Shelly", None, None) == "shelly"
    assert classify_brand("box", None, None) is None


@pytest.mark.parametrize(("name", "room"), [
    ("livingroom_Air-Purifier", "Living room"),
    ("Bedroom lamp", "Bedroom"),
    ("Front Gate", "Entrance"),
    ("Mystery", None),
])
def test_room_from_name(name, room):
    assert room_from_name(name) == room


def test_build_map_tolerates_empty_input():
    out = build_map(None, None, None)
    assert isinstance(out, dict)
