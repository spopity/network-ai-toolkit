"""What the daily LLM prompt is built from: summaries only, devices named, rollup preferred."""

from router_agent.llm_client import build_section_data

MAC = "02:00:00:00:00:01"


def _snapshot(tail: str) -> dict:
    return {
        "security": {"syslog_tail": tail},
        "system": {"uptime_seconds": 7200, "mem_total_kb": 1000, "mem_available_kb": 400, "loadavg": ["0.1"] * 3},
        "wan": {"state": "2", "pppd_running": True},
        "wifi": {"client_count": 1, "clients": [{"mac": MAC, "name": "Laptop", "rssi": -80}], "nodes": [{}]},
    }


def test_sections_are_compact_json_with_named_devices():
    tail = "\n".join(
        f"Nov 14 09:00:0{i} RT-AX88U dropbear[{100 + i}]: Bad password attempt from 203.0.113.{i}:{4000 + i}"
        for i in range(5)
    ) + f"\nNov 14 09:01:00 wlceventd: Deauth {MAC}, reason 3"
    out = build_section_data(_snapshot(tail))
    assert set(out) == {"security", "wifi", "system"}
    assert "Laptop" in out["wifi"]
    # five near-identical lines collapse to one counted template
    assert '"count":5' in out["security"].replace(" ", "")
    assert "Bad password attempt from <IP>:N" in out["security"]
    assert '"uptime_hours":2.0' in out["system"].replace(" ", "")
    assert "weak_signal_clients_below_-75dBm" in out["wifi"]


def test_day_rollup_replaces_single_tail():
    day = {"syslog_summary": {"lines": 0, "window": None, "messages": []},
           "dns": {"queries": 3}, "peaks": {"wifi_clients_min": 1, "wifi_clients_max": 4}}
    out = build_section_data(_snapshot("Nov 14 09:00:00 RT-AX88U dropbear[1]: Bad password"), day=day)
    assert "Bad password" not in out["security"]
    assert '"queries":3' in out["security"].replace(" ", "")
    assert "[1,4]" in out["wifi"].replace(" ", "")
