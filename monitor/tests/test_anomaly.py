"""Unusual appliance behaviour: new-site bursts and upload bursts vs the device's own baseline."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from router_agent import anomaly, db, notify
from router_agent.anomaly import (
    DEFAULTS,
    base_domain,
    find_new_domain_bursts,
    find_upload_bursts,
    is_appliance,
)
from router_agent.notify import Notifier

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
CFG = dict(DEFAULTS)
CAM, PHONE = "02:00:00:00:00:30", "02:00:00:00:00:31"


@pytest.mark.parametrize(("domain", "base"), [
    ("cdn1.example.com", "example.com"),
    ("example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("api.service.com.au", "service.com.au"),
    ("x.y.example.de.", "example.de"),
])
def test_base_domain(domain, base):
    assert base_domain(domain) == base


@pytest.mark.parametrize(("device", "network", "expected"), [
    ("Front Gate", "IoT", True),          # camera
    ("closet_Synology", "LAN", True),     # nas
    ("Kitchen_Shelly", "IoT", True),      # plug
    ("iPhone_A", "LAN", False),           # phone
    ("laptop_Work", "LAN", False),
    ("tablet_Kids", "LAN", False),
    ("Front Gate", "Guest", False),       # guest network skipped
    ("Muted Cam", "IoT", False),          # ignore_devices
])
def test_is_appliance(device, network, expected):
    assert is_appliance(device, network, None, ["muted cam"]) is expected


def _first(domain, minutes_ago, device="Front Gate", key=CAM, network="IoT", watched_days=10):
    return {"device_key": key, "domain": domain, "first_seen": NOW - timedelta(minutes=minutes_ago),
            "device": device, "network": network, "mac": key, "watched_since": NOW - timedelta(days=watched_days)}


def test_new_domain_burst_counts_base_domains_only():
    recent = [_first(f"s{i}.newsite{i}.example", 10) for i in range(3)]          # 3 new bases
    recent += [_first(f"cdn{i}.vendor.com", 5) for i in range(10)]               # known base
    found = find_new_domain_bursts(recent, {CAM: ["api.vendor.com"]}, NOW, CFG)
    assert found == []                                                           # 3 < 4
    recent.append(_first("evil.example", 2))
    found = find_new_domain_bursts(recent, {CAM: ["api.vendor.com"]}, NOW, CFG)
    assert len(found) == 1 and found[0]["kind"] == "new_domains"
    assert found[0]["domains"] == ["newsite0.example", "newsite1.example", "newsite2.example", "evil.example"]


def test_new_domain_burst_needs_baseline_and_skips_browsing_devices():
    burst = [_first(f"site{i}.example", 5, watched_days=1) for i in range(8)]       # watched only 1 day
    assert find_new_domain_bursts(burst, {}, NOW, CFG) == []
    phone = [_first(f"site{i}.example", 5, device="iPhone_A", key=PHONE, network="LAN") for i in range(30)]
    assert find_new_domain_bursts(phone, {}, NOW, CFG) == []


def _hours(mac, device, n, tx, network="IoT", end=NOW - timedelta(hours=4)):
    return [{"mac": mac, "device": device, "network": network, "hour": end - timedelta(hours=i), "tx": tx}
            for i in range(n)][::-1]


def test_upload_burst_needs_floor_and_factor():
    base = _hours(CAM, "Front Gate", 100, 400_000)                     # 0.4 MB/h usually
    clip = base + [{"mac": CAM, "device": "Front Gate", "network": "IoT", "hour": NOW - timedelta(hours=1), "tx": 53_000_000}]
    assert find_upload_bursts(clip, NOW, CFG) == []                    # 53 MB: under the 100 MB floor
    big = base + [{"mac": CAM, "device": "Front Gate", "network": "IoT", "hour": NOW - timedelta(hours=1), "tx": 900_000_000}]
    f = find_upload_bursts(big, NOW, CFG)
    assert len(f) == 1 and f[0]["tx_mb"] == 900 and f[0]["usual_mb"] == 0.4
    busy = _hours(CAM, "Front Gate", 100, 200_000_000) + big[-1:]      # usually 200 MB/h: 900 is < 10x
    assert find_upload_bursts(busy, NOW, CFG) == []


def test_first_write_after_a_data_gap_is_not_a_burst():
    base = _hours(CAM, "Front Gate", 100, 400_000)
    lump = {"mac": CAM, "device": "Front Gate", "network": "IoT", "hour": NOW - timedelta(hours=1), "tx": 900_000_000}
    gap = {"from": int((NOW - timedelta(hours=20)).timestamp()), "to": int((NOW - timedelta(minutes=30)).timestamp())}
    assert find_upload_bursts(base + [lump], NOW, CFG, gap) == []
    assert len(find_upload_bursts(base + [lump], NOW, CFG, None)) == 1


def test_upload_burst_needs_history_and_appliance():
    short = _hours(CAM, "Front Gate", 20, 100_000) + [
        {"mac": CAM, "device": "Front Gate", "network": "IoT", "hour": NOW - timedelta(hours=1), "tx": 900_000_000}]
    assert find_upload_bursts(short, NOW, CFG) == []
    phone = _hours(PHONE, "iPhone_B", 100, 100_000, "LAN") + [
        {"mac": PHONE, "device": "iPhone_B", "network": "LAN", "hour": NOW - timedelta(hours=1), "tx": 1_600_000_000}]
    assert find_upload_bursts(phone, NOW, CFG) == []                   # photo backup: phones skipped


@pytest.fixture
def telegram(tmp_path, monkeypatch):
    sent = []
    n = Notifier("token", "1", tmp_path)
    monkeypatch.setattr(n, "send", sent.append)
    monkeypatch.setattr(notify, "_notifier", n)
    return sent


def _feed(monkeypatch, recent):
    monkeypatch.setattr(db, "get_new_domains_since", lambda since: (recent, {}))
    monkeypatch.setattr(db, "get_hourly_upload", lambda days: [])


def test_run_baseline_then_once_per_cooldown(tmp_path, monkeypatch, telegram):
    burst = [_first(f"site{i}.example", 5) for i in range(5)]
    _feed(monkeypatch, burst)
    assert anomaly.run(tmp_path, {}, now=NOW) == []                       # first run: silent baseline
    _feed(monkeypatch, [])
    anomaly.run(tmp_path, {}, now=NOW + timedelta(hours=30))              # cooldown expires
    _feed(monkeypatch, burst)
    reported = anomaly.run(tmp_path, {}, now=NOW + timedelta(hours=31))
    assert [f["device"] for f in reported] == ["Front Gate"]
    assert anomaly.run(tmp_path, {}, now=NOW + timedelta(hours=32)) == []  # within the day: quiet
    events = [json.loads(line) for line in (tmp_path / "router_events.log").read_text().splitlines()]
    assert [e["event"] for e in events] == ["anomaly"] and events[0]["kind"] == "new_domains"
    assert len(telegram) == 1 and "Unusual activity: Front Gate" in telegram[0] and "site0.example" in telegram[0]


def test_run_survives_postgres_outage(tmp_path):
    assert anomaly.run(tmp_path, {}, now=NOW) == []                       # conftest: Postgres refuses


def test_anomaly_alerts_can_be_switched_off(tmp_path, monkeypatch):
    n = Notifier("token", "1", tmp_path, events=("wan",))
    sent = []
    monkeypatch.setattr(n, "send", sent.append)
    n.router_event({"event": "anomaly", "kind": "upload", "device": "Cam", "summary": "x"})
    assert sent == []
