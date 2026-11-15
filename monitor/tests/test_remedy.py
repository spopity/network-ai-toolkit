"""Known fixes: which apply, auto limits, the Telegram request queue, the event and message."""
import json
from datetime import UTC, datetime, timedelta

from router_agent import notify, remedy, selfcheck
from router_agent.notify import Notifier

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def _latest(tmp_path, missing):
    (tmp_path / "latest.json").write_text(json.dumps({"snapshot": {"router_setup": {"missing": missing}}}))


def test_fixes_for_checks_and_router_setup_items(tmp_path):
    assert remedy.fixes_for("traffic", tmp_path) == ["hour_monitor"]
    assert remedy.fixes_for("disk", tmp_path) == []
    _latest(tmp_path, ["hour_monitor", "syslog_socket", "dns_redirect:br53", "ntp_redirect:br54", "cron:x"])
    assert remedy.fixes_for("router_setup", tmp_path) == ["hour_monitor", "syslog_ng", "nat_start"]
    assert all(f in remedy.FIXES for fs in remedy.CHECK_FIXES.values() for f in fs)
    assert all(f in remedy.FIXES for _, f in remedy.ITEM_FIXES)


def test_tests_never_run_a_real_fix(tmp_path):
    ev = remedy.run_fix({}, tmp_path, "dashboard", "auto")
    assert ev["ok"] is False and "disabled in tests" in ev["detail"]


def _runner(calls):
    def run(cfg, log_dir, fid, trigger, by="", check=""):
        calls.append((fid, trigger, by, check))
        state = json.loads((log_dir / remedy.STATE_FILE).read_text()) if (log_dir / remedy.STATE_FILE).exists() else {}
        state.setdefault(fid, []).append({"ts": NOW.isoformat(), "trigger": trigger, "ok": True})
        (log_dir / remedy.STATE_FILE).write_text(json.dumps(state))
        return {"fix": fid, "ok": True}
    return run


def test_auto_fix_only_alerted_auto_fixes_with_limits(tmp_path):
    calls = []
    state = {"traffic": {"alerted": True}, "iot_lan": {"alerted": True}, "dashboard": {"alerted": False}}
    remedy.auto_fix({}, tmp_path, state, NOW, runner=_runner(calls))
    assert calls == [("hour_monitor", "auto", "", "traffic")]   # firewall_start is tap-only, dashboard not alerted yet
    remedy.auto_fix({}, tmp_path, state, NOW + timedelta(minutes=5), runner=_runner(calls))
    assert len(calls) == 1                                      # too soon again
    remedy.auto_fix({}, tmp_path, state, NOW + timedelta(minutes=20), runner=_runner(calls))
    assert len(calls) == 2                                      # second attempt after the gap
    remedy.auto_fix({}, tmp_path, state, NOW + timedelta(minutes=40), runner=_runner(calls))
    assert len(calls) == 2                                      # 2 per 24 h, then only by hand


def test_auto_fix_daily_cap_and_switch_off(tmp_path):
    (tmp_path / remedy.STATE_FILE).write_text(json.dumps({"hour_monitor": [
        {"ts": (NOW - timedelta(hours=3)).isoformat(), "trigger": "auto"},
        {"ts": (NOW - timedelta(hours=1)).isoformat(), "trigger": "auto"},
        {"ts": (NOW - timedelta(minutes=1)).isoformat(), "trigger": "telegram"}]}))
    assert not remedy.auto_due(tmp_path, "hour_monitor", NOW)
    assert remedy.auto_due(tmp_path, "hour_monitor", NOW + timedelta(hours=22))
    calls = []
    remedy.auto_fix({"remedy": {"auto": False}}, tmp_path, {"watchdog": {"alerted": True}}, NOW, runner=_runner(calls))
    assert calls == []


def test_request_queue_validates_and_expires(tmp_path):
    assert remedy.request_fix(tmp_path, "hour_monitor", "telegram:me", "traffic")
    assert not remedy.request_fix(tmp_path, "rm -rf /", "telegram:me")
    with open(tmp_path / remedy.REQUESTS_FILE, "a") as f:
        f.write(json.dumps({"ts": (datetime.now(UTC) - timedelta(hours=1)).isoformat(), "fix": "watchdog", "by": "x"}) + "\n")
        f.write(json.dumps({"ts": datetime.now(UTC).isoformat(), "fix": "reboot", "by": "x"}) + "\n")
        f.write("not json\n")
    calls = []
    remedy.run_queue({}, tmp_path, runner=_runner(calls))
    assert calls == [("hour_monitor", "telegram", "telegram:me", "traffic")]
    assert (tmp_path / remedy.REQUESTS_FILE).read_text() == ""
    remedy.run_queue({}, tmp_path, runner=_runner(calls))
    assert len(calls) == 1


def test_selfcheck_problem_event_lists_fixes_and_runs_auto_fix(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(remedy, "run_fix", _runner(calls))
    (tmp_path / ".traffic_cursor.json").write_text(json.dumps({"ts": int((NOW - timedelta(hours=5)).timestamp())}))
    selfcheck.run({"traffic_analyzer": True}, tmp_path, only=("traffic",), now=NOW)
    ev = json.loads((tmp_path / "router_events.log").read_text().splitlines()[0])
    assert ev["event"] == "monitor_problem"
    assert ev["fixes"] == [{"id": "hour_monitor", "title": "Restart hour_monitor", "auto": True}]
    assert calls == [("hour_monitor", "auto", "", "traffic")]


def _notifier(tmp_path, interactive=True):
    sent = []
    n = Notifier("token", "1", tmp_path, interactive=interactive)
    n.send = lambda text, buttons=None: sent.append((text, buttons))
    return n, sent


def test_problem_alert_buttons_and_mute(tmp_path):
    n, sent = _notifier(tmp_path)
    ev = {"event": "monitor_problem", "check": "iot_lan", "title": "IoT", "problem": "rule gone", "since": NOW.isoformat(),
          "fixes": [{"id": "firewall_start", "title": "Re-run firewall-start", "auto": False}]}
    n.router_event(ev)
    _text, buttons = sent[0]
    assert ("🔧 Re-run firewall-start", "fix:firewall_start:iot_lan") in [b for row in buttons for b in row]
    assert ("🩺 Troubleshoot", "ts:iot_lan") in buttons[-1]
    (tmp_path / notify.MUTE_FILE).write_text(json.dumps({"iot_lan": (datetime.now(UTC) + timedelta(hours=1)).isoformat()}))
    n.router_event(ev)
    assert len(sent) == 1


def test_no_buttons_unless_interactive_and_remedy_messages(tmp_path):
    n, sent = _notifier(tmp_path, interactive=False)
    n.router_event({"event": "monitor_problem", "check": "traffic", "problem": "x",
                    "fixes": [{"id": "hour_monitor", "title": "Restart hour_monitor", "auto": True}]})
    assert sent[0][1] is None and "Trying automatically: Restart hour_monitor" in sent[0][0]
    n, sent = _notifier(tmp_path)
    n.router_event({"event": "remedy", "fix": "hour_monitor", "title": "Restart hour_monitor", "trigger": "auto", "ok": True})
    assert "Fixed: Restart hour_monitor" in sent[0][0] and sent[0][1] is None
    n.router_event({"event": "remedy", "fix": "syslog_ng", "title": "Restart syslog-ng", "trigger": "telegram",
                    "by": "telegram:me", "ok": False, "detail": "<boom>", "check": "router_setup"})
    assert "Fix failed" in sent[1][0] and "&lt;boom&gt;" in sent[1][0]
    assert sent[1][1] == [[("🩺 Troubleshoot", "ts:router_setup")]]
