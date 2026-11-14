"""Day rollup: no log line is counted twice, reboots/peaks are tracked, the reset keeps cursors."""
import json

from router_agent.collector import FIREWALL_DROPS_CMD, SYSLOG_TAIL_CMD
from router_agent.rollup import Rollup, _fold_dns, new_lines, render

from .conftest import syslog_ts


def test_new_lines_first_read_takes_everything_and_sets_cursor():
    lines = [f"{syslog_ts(3)} a: one", f"{syslog_ts(1)} a: two", "no timestamp here"]
    fresh, cur = new_lines(lines, None)
    assert fresh == lines[:2]  # undated lines are ignored
    assert cur["lines"] == [lines[1]]


def test_new_lines_overlapping_tails_are_not_double_counted():
    t_old, t_new = syslog_ts(3), syslog_ts(1)
    first = [f"{t_old} a: one", f"{t_new} a: two"]
    _, cur = new_lines(first, None)
    # next tail overlaps: same lines again plus one new line in the same second as the cursor
    second = first + [f"{t_new} a: three", f"{syslog_ts(0)} a: four"]
    fresh, cur2 = new_lines(second, cur)
    assert fresh == second[2:]
    fresh3, _ = new_lines(second, cur2)
    assert fresh3 == []


def test_new_lines_keeps_cursor_when_clock_goes_back():
    _, cur = new_lines([f"{syslog_ts(1)} a: x"], None)
    fresh, cur2 = new_lines([f"{syslog_ts(60)} a: older"], cur)
    assert fresh == []
    assert cur2 == cur


def test_new_lines_empty_input_keeps_cursor():
    cur = {"ts": "2026-11-14T09:00:00", "lines": []}
    assert new_lines([], cur) == ([], cur)


def _grouped(syslog: list[str], drops: list[str]) -> dict:
    return {"security": [
        {"cmd": SYSLOG_TAIL_CMD, "out": "\n".join(syslog)},
        {"cmd": FIREWALL_DROPS_CMD, "out": "\n".join(drops)},
    ]}


def _snap(uptime: int, clients: int = 10, pppd: bool = True) -> dict:
    return {
        "collected_at": "2026-11-14T09:00:00+00:00",
        "system": {"uptime_seconds": uptime, "loadavg": ["0.5", "0.4", "0.3"], "temps_c": {"cpu": 60.0},
                   "mem_total_kb": 1000, "mem_available_kb": 250},
        "wan": {"pppd_running": pppd},
        "wifi": {"client_count": clients},
    }


def test_update_twice_with_same_tail_counts_each_line_once(tmp_path):
    syslog = [f"{syslog_ts(2)} RT-AX88U kernel: eth0 link down", f"{syslog_ts(1)} RT-AX88U kernel: eth0 link up"]
    drops = [f"{syslog_ts(2)}|BLOCKED - INBOUND|203.0.113.5|192.0.2.1|TCP|23",
             f"{syslog_ts(1)}|BLOCKED - OUTBOUND|192.0.2.50|203.0.113.80|TCP|443"]
    r = Rollup(tmp_path)
    r.update(_grouped(syslog, drops), _snap(1000))
    roll = r.update(_grouped(syslog, drops), _snap(1300))
    assert roll["checks"] == 2
    assert roll["syslog"]["lines"] == 2
    assert roll["drops"]["rows"] == 1  # inbound only
    assert roll["drops"]["ports"] == {"TCP/23": 1}
    assert roll["drops"]["outbound_devices"] == {"192.0.2.50": 1}
    assert json.loads((tmp_path / ".log_cursor.json").read_text())["syslog"]["ts"]


def test_update_tracks_peaks_wan_down_and_reboots(tmp_path):
    r = Rollup(tmp_path)
    r.update(_grouped([], []), _snap(5000, clients=12))
    r.update(_grouped([], []), _snap(5300, clients=7, pppd=False))
    roll = r.update(_grouped([], []), _snap(60, clients=9))  # uptime went backwards: reboot
    s = roll["stats"]
    assert s["wifi_clients_max"] == 12 and s["wifi_clients_min"] == 7
    assert s["checks_with_wan_down"] == 1
    assert s["router_reboots"] == 1
    assert s["mem_used_pct_max"] == 75.0
    assert s["cpu_temp_c_max"] == 60.0


def test_reset_starts_a_new_day_but_keeps_cursor_and_uptime(tmp_path):
    r = Rollup(tmp_path)
    syslog = [f"{syslog_ts(1)} RT-AX88U kernel: eth0 link down"]
    r.update(_grouped(syslog, []), _snap(5000))
    cursor_before = (tmp_path / ".log_cursor.json").read_text()
    r.reset()
    roll = r.load()
    assert roll["checks"] == 0 and roll["syslog"]["lines"] == 0
    assert roll["stats"] == {"_last_uptime": 5000}
    assert (tmp_path / ".log_cursor.json").read_text() == cursor_before
    # the same tail after the reset must not be re-counted into the new day
    roll = r.update(_grouped(syslog, []), _snap(5300))
    assert roll["syslog"]["lines"] == 0
    assert "router_reboots" not in roll["stats"]


def test_fold_dns_counts_unavailable_checks_separately():
    base = {"checks": 0, "queries": 0, "blocked": 0, "by_network": {}, "blocked_domains": {},
            "blocked_devices": {}, "new_domains": [], "unavailable_checks": 0}
    acc = _fold_dns(base, {"status": "adguard_unreachable"})
    assert acc["unavailable_checks"] == 1 and acc["checks"] == 0
    acc = _fold_dns(acc, {"queries": 10, "blocked": 2, "by_network": {"IoT": {"queries": 10, "blocked": 2}},
                          "top_blocked_domains": {"ads.example": 2}, "top_blocked_devices": {"cam [IoT]": 2},
                          "new_domains": [{"domain": "new.example", "network": "IoT"}]})
    acc = _fold_dns(acc, {"queries": 5, "blocked": 1, "by_network": {"IoT": {"queries": 5, "blocked": 1}},
                          "top_blocked_domains": {"ads.example": 1}})
    assert acc["queries"] == 15 and acc["blocked"] == 3
    assert acc["by_network"]["IoT"] == {"queries": 15, "blocked": 3}
    assert acc["blocked_domains"] == {"ads.example": 3}
    assert base["queries"] == 0  # input not mutated
    assert _fold_dns(acc, None) is acc


def test_render_shapes_for_the_llm(tmp_path):
    r = Rollup(tmp_path)
    syslog = [f"{syslog_ts(1)} RT-AX88U dropbear[1]: Bad password attempt from 203.0.113.5:22"]
    drops = [f"{syslog_ts(1)}|BLOCKED - INBOUND|203.0.113.5|192.0.2.1|TCP|23"]
    roll = r.update(_grouped(syslog, drops), {**_snap(100), "dns_health": {"state": "ok"}})
    out = render(roll)
    assert out["checks"] == 1
    assert out["syslog_summary"]["lines"] == 1
    assert out["firewall_drops"]["total"] == 1
    assert out["firewall_drops"]["top_sources"] == [{"ip": "203.0.113.5", "count": 1}]
    assert not any(k.startswith("_") for k in out["peaks"])
    assert out["dns"] == {"filter_health_checks": {"ok": 1}}
