"""Dashboard API: router-event auth, graceful degradation without Postgres, Tshoot-facing shapes."""
import importlib.util
import json
from pathlib import Path

import dotenv
import pytest
import yaml

ROUTER_IP = "192.0.2.1"
APP_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


@pytest.fixture(scope="module")
def app_module():
    real = dotenv.load_dotenv
    dotenv.load_dotenv = lambda *a, **k: False  # never pick up the host's real .env
    try:
        spec = importlib.util.spec_from_file_location("dashboard_app", APP_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        dotenv.load_dotenv = real
    return mod


@pytest.fixture
def client(app_module, tmp_path, monkeypatch):
    cfg = tmp_path / "config.yml"
    cfg.write_text(yaml.safe_dump({"log_dir": str(tmp_path / "logs"), "routers": [{"name": "rt", "host": ROUTER_IP}]}))
    monkeypatch.setattr(app_module, "CONFIG_PATH", cfg)
    app_module.app.testing = True
    c = app_module.app.test_client()
    c.logs = tmp_path / "logs"
    return c


def test_state_with_no_data_yet(client):
    r = client.get("/api/state")
    assert r.status_code == 200
    body = r.get_json()
    assert body["snapshot"] is None and body["watchdog_events"] == []


def test_state_names_macs_in_analysis(client):
    client.get("/api/state")  # creates the log dir
    snap = {"wifi": {"clients": [{"mac": "02:00:00:00:00:01", "name": "Laptop"}]}}
    analysis = {"sections": {"wifi": "new client 02:00:00:00:00:01"}}
    (client.logs / "latest.json").write_text(json.dumps({"snapshot": snap, "analysis": analysis}))
    body = client.get("/api/state").get_json()
    assert body["analysis"]["sections"]["wifi"] == "new client Laptop (02:00:00:00:00:01)"


def test_router_event_rejects_other_hosts(client):
    r = client.post("/api/router-event", json={"event": "connected"}, environ_base={"REMOTE_ADDR": "192.0.2.77"})
    assert r.status_code == 403


def test_router_event_sanitizes_and_stores(client):
    r = client.post("/api/router-event", environ_base={"REMOTE_ADDR": ROUTER_IP},
                    json={"event": "Connected; rm -rf /", "ip": "203.0.113.4", "evil": "x"})
    assert r.status_code == 201
    stored = json.loads((client.logs / "router_events.log").read_text())
    assert stored["event"] == "router_wan_connectedrmrf"
    assert stored["ip"] == "203.0.113.4" and "evil" not in stored
    assert client.post("/api/router-event", json={}, environ_base={"REMOTE_ADDR": ROUTER_IP}).status_code == 400


@pytest.mark.parametrize(("url", "key"), [
    ("/api/history", "snapshots"),
    ("/api/dns/devices", "devices"),
    ("/api/dns/lookups?hours=999999&limit=5", "lookups"),
    ("/api/traffic/devices", "devices"),
    ("/api/traffic/detail", "apps"),
    ("/api/traffic/history?days=365&bucket=week", "series"),
    ("/api/dns/history", "devices"),
])
def test_archive_endpoints_degrade_without_postgres(client, url, key):
    r = client.get(url)
    assert r.status_code == 200
    body = r.get_json()
    assert body["available"] is False and body[key] == []


def test_dns_lookups_clamps_arguments(client, app_module, monkeypatch):
    seen = {}

    def fake(hours, **kw):
        seen.update(hours=hours, **kw)
        return []

    monkeypatch.setattr(app_module.db, "get_dns_lookups", fake)
    body = client.get("/api/dns/lookups?hours=999999&limit=99999&blocked=yes&device=%20cam%20").get_json()
    assert body["available"] is True
    assert seen["hours"] == 24 * 90 and seen["limit"] == 1000
    assert seen["blocked_only"] is True and seen["device"] == "cam" and seen["domain"] is None


def test_network_map_without_snapshot(client):
    r = client.get("/api/network-map")
    assert r.status_code == 200 and isinstance(r.get_json(), dict)


def test_history_clamps_arguments(client, app_module, monkeypatch):
    seen = {}

    def fake(days, bucket, device=None, network=None):
        seen.update(days=days, bucket=bucket, device=device, network=network)
        return {"series": [{"period": "2026-11-09T00:00:00+00:00", "rx": 1, "tx": 2, "devices": 1}], "devices": []}

    monkeypatch.setattr(app_module.db, "get_traffic_history", fake)
    body = client.get("/api/traffic/history?days=999999&bucket=year&device=%20tv%20").get_json()
    assert seen == {"days": 3650, "bucket": "day", "device": "tv", "network": None}
    assert body["available"] is True and body["bucket"] == "day" and body["series"][0]["tx"] == 2


def test_api_reports(client, app_module, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "log_dir", lambda: tmp_path)
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "week-2026-11-09.json").write_text(json.dumps({"period": "week", "start": "2026-11-09"}))
    body = client.get("/api/reports?period=bogus&limit=999").get_json()
    assert body == {"reports": [{"period": "week", "start": "2026-11-09"}]}
    assert client.get("/api/reports?period=month").get_json() == {"reports": []}
