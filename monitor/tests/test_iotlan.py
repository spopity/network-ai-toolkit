"""IoT -> LAN attempts: parse the router's LOG lines, read each line once, alert once per target."""
import json
from datetime import UTC, datetime, timedelta

from router_agent import iotlan, notify
from router_agent.collector import COMMAND_GROUPS
from router_agent.iotlan import IOT_LAN_CMD, IotLanWatch, parse, syslog_time
from router_agent.notify import Notifier
from router_agent.selfcheck import check_iot_lan

PLUG, NAS = "02:00:00:00:00:30", "02:00:00:00:00:10"
NOW = datetime(2026, 11, 14, 11, 0, tzinfo=UTC)


def namer(ip):
    known = {"203.0.113.30": (PLUG, "Smart plug", "IoT"), "192.0.2.10": (NAS, "NAS", "LAN")}
    if ip in known:
        mac, name, net = known[ip]
        return {"key": mac, "mac": mac, "device": name, "network": net}
    return {"key": f"ip:{ip}", "mac": None, "device": ip, "network": "Other"}


def line(ts, src="203.0.113.30", dst="192.0.2.10", proto="TCP", dpt=445, spt=49154):
    return (f"{ts} RT-AX88U kernel: DROP IN=br54 OUT=br0 MAC=ff:ff:ff:ff:ff:ff:02:00:00:00:00:30:08:00 "
            f"SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO={proto} SPT={spt} DPT={dpt} "
            "WINDOW=64240 RES=0x00 SYN URGP=0")


def test_command_is_collected():
    assert IOT_LAN_CMD in COMMAND_GROUPS["services"]


def test_parse():
    out = "logging=1\n" + line("Nov 14 10:58:01") + "\ngarbage\n" + line("Nov  9 23:00:00", proto="ICMP", dpt=None).replace(" SPT=49154 DPT=None", "")
    logging_on, attempts = parse(out, NOW.replace(tzinfo=None))
    assert logging_on is True
    assert [(a["dst"], a["proto"], a["port"]) for a in attempts] == [("192.0.2.10", "ICMP", None), ("192.0.2.10", "TCP", 445)]
    assert parse("logging=0\n", NOW)[0] is False and parse("", NOW)[0] is None


def test_december_lines_read_in_january_are_last_year():
    assert syslog_time("Dec 31 23:59:59", datetime(2027, 1, 1)) == datetime(2026, 12, 31, 23, 59, 59)
    assert syslog_time("Jan  1 00:00:01", datetime(2027, 1, 1)) == datetime(2027, 1, 1, 0, 0, 1)


def test_first_run_is_a_silent_baseline_then_only_new_lines_count(tmp_path):
    w = IotLanWatch(tmp_path, {})
    old = "logging=1\n" + line("Nov 14 10:50:00")
    r = w.check(old, namer, NOW)
    assert r["baseline"] is True and r["alerts"] == [] and r["new_attempts"] == 0

    r = w.check(old, namer, NOW)  # same line again: not counted twice
    assert r["new_attempts"] == 0 and r["alerts"] == []

    # a second line in the same second as the cursor is still new
    same_second = old + "\n" + line("Nov 14 10:50:00", spt=50000)
    r = w.check(same_second, namer, NOW)
    assert r["new_attempts"] == 1
    assert [a["targets"] for a in r["alerts"]] == [["NAS (192.0.2.10) TCP/445 ×1"]]
    assert r["alerts"][0]["device"] == "Smart plug" and r["alerts"][0]["mac"] == PLUG


def test_alerts_once_per_target_within_cooldown(tmp_path):
    w = IotLanWatch(tmp_path, {})
    w.check("logging=1\n", namer, NOW)  # baseline
    r = w.check(line("Nov 14 10:51:00") + "\n" + line("Nov 14 10:51:05"), namer, NOW)
    assert r["alerts"][0]["count"] == 2 and r["attempts"][0]["count"] == 2

    later = NOW + timedelta(hours=1)
    r = w.check(line("Nov 14 11:51:00"), namer, later)
    assert r["new_attempts"] == 1 and r["alerts"] == []  # same target: quiet ...
    r = w.check(line("Nov 14 11:52:00", dpt=22), namer, later)
    assert [a["targets"] for a in r["alerts"]] == [["NAS (192.0.2.10) TCP/22 ×1"]]  # ... a new port alerts

    r = w.check(line("Nov 15 11:00:00"), namer, NOW + timedelta(hours=25))
    assert len(r["alerts"]) == 1  # cooldown over


def test_ignore_lists(tmp_path):
    w = IotLanWatch(tmp_path, {"ignore_targets": ["192.0.2.10:1883", "nas:8123"], "ignore_devices": []})
    w.check("", namer, NOW)
    r = w.check(line("Nov 14 10:51:00", dpt=1883) + "\n" + line("Nov 14 10:51:01", dpt=8123), namer, NOW)
    assert r["alerts"] == [] and r["new_attempts"] == 2
    w2 = IotLanWatch(tmp_path / "x", {"ignore_devices": ["smart plug"]})
    (tmp_path / "x").mkdir()
    w2.check("", namer, NOW)
    assert w2.check(line("Nov 14 10:52:00"), namer, NOW)["alerts"] == []


def test_event_and_telegram(tmp_path, monkeypatch):
    sent = []
    n = Notifier("t", "c", tmp_path)
    monkeypatch.setattr(n, "send", sent.append)
    monkeypatch.setattr(notify, "_notifier", n)
    (tmp_path / iotlan.STATE_FILE).write_text(json.dumps({}))  # not a baseline run
    r = iotlan.check_and_record(tmp_path, {}, line("Nov 14 10:51:00"), namer)
    assert len(r["alerts"]) == 1
    ev = [json.loads(x) for x in (tmp_path / "router_events.log").read_text().splitlines()]
    assert ev[-1]["event"] == "iot_lan" and ev[-1]["targets"] == ["NAS (192.0.2.10) TCP/445 ×1"]
    assert len(sent) == 1 and "Smart plug tried to reach the LAN" in sent[0] and "TCP/445" in sent[0]

    quiet = Notifier("t", "c", tmp_path, events=("wan",))
    monkeypatch.setattr(quiet, "send", sent.append)
    quiet.router_event(ev[-1])
    assert len(sent) == 1


def test_selfcheck_flags_missing_log_rule(tmp_path):
    assert check_iot_lan(tmp_path) is None  # no check yet
    (tmp_path / "latest.json").write_text(json.dumps({"snapshot": {"iot_lan": {"logging": False}}}))
    assert "LOG rule is missing" in check_iot_lan(tmp_path)
    (tmp_path / "latest.json").write_text(json.dumps({"snapshot": {"iot_lan": {"logging": True}}}))
    assert check_iot_lan(tmp_path) is None
