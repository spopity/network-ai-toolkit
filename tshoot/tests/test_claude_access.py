"""Claude has the same access as Gemini: reads run, changes wait for approval, blocks stay blocked."""
import json

from tshoot import claude_agent
from tshoot.agent import Session, TshootAgent
from tshoot.audit import AuditLog
from tshoot.prompt import TOOLS
from tshoot.ssh import CommandResult


class FakeShell:
    def __init__(self):
        self.ran = []

    def run(self, command, timeout=30):
        self.ran.append(command)
        return CommandResult(command, "ok\n", 0, 5)


def _agent(tmp_path):
    cfg = {"router": {"name": "r", "host": "192.0.2.1"}, "monitor": {"latest_json": str(tmp_path / "latest.json")}}
    shell = FakeShell()
    return TshootAgent(cfg, gemini=None, shell=shell, audit=AuditLog(tmp_path / "audit.jsonl", pg_enabled=False)), shell


def _fake_claude(monkeypatch, script):
    """script(call_tool, message) -> answer text; records every Claude call's (message, tool results)."""
    calls = []

    def ask(component, system, tools, call_tool, prior, message):
        assert {t["name"] for t in tools} == {t["name"] for t in TOOLS}
        results = []
        text = script(lambda n, a: results.append(call_tool(n, a)) or results[-1], message)
        calls.append((message, results))
        return text, "claude-opus"

    monkeypatch.setattr(claude_agent, "ask_claude", ask)
    return calls


def test_allowlist_covers_all_tools():
    assert {t["name"] for t in TOOLS} <= claude_agent.ALLOWED_TOOLS


def test_reads_run_and_change_awaits_approval_then_runs(tmp_path, monkeypatch):
    agent, shell = _agent(tmp_path)
    s = Session("test0001")

    def script(call, message):
        if message.startswith("[Outcome"):
            call("run_command", {"command": "nvram get wl1_chanspec", "purpose": "verify"})
            return "Verified."
        call("run_command", {"command": "nvram get wl1_chanspec", "purpose": "check"})
        r = call("propose_change", {"command": "nvram set wl1_chanspec=36/80", "reason": "r",
                                    "expected_effect": "e", "rollback": "x"})
        assert r["status"] == "awaiting_approval"
        # a second change in the same turn is skipped, not queued
        assert call("run_command", {"command": "service restart_wireless", "purpose": "p"})["status"] == "skipped"
        return "Proposed a channel change."

    calls = _fake_claude(monkeypatch, script)
    evs = list(agent.chat(s, "fix wifi", use_claude=True))
    approval = next(e for e in evs if e.get("type") == "approval")
    final = evs[-1]
    assert final["awaiting_approval"] == approval["id"] and final["model"].startswith("claude")
    assert shell.ran == ["nvram get wl1_chanspec"] and s.pending.model == "claude"

    evs = list(agent.resume(s, approval["id"], approve=True))
    assert shell.ran == ["nvram get wl1_chanspec", "nvram set wl1_chanspec=36/80", "nvram get wl1_chanspec"]
    assert s.pending is None and evs[-1]["content"] == "Verified."
    assert "approved_and_executed" in calls[-1][0]


def test_reject_goes_back_to_claude(tmp_path, monkeypatch):
    agent, shell = _agent(tmp_path)
    s = Session("test0002")
    calls = _fake_claude(monkeypatch, lambda call, m: (
        "OK, leaving it." if "NOT applied" in m else
        call("propose_change", {"command": "service restart_wan_if 0", "reason": "r", "expected_effect": "e",
                                "rollback": "x"}) and "Proposed."))
    evs = list(agent.chat(s, "restart wan", use_claude=True))
    pid = next(e for e in evs if e.get("type") == "approval")["id"]
    evs = list(agent.resume(s, pid, approve=False, note="not now"))
    assert shell.ran == [] and s.pending is None and evs[-1]["content"] == "OK, leaving it."
    assert "not now" in calls[-1][0]


def test_blocked_stays_blocked(tmp_path, monkeypatch):
    agent, shell = _agent(tmp_path)
    s = Session("test0003")
    _fake_claude(monkeypatch, lambda call, m: json.dumps(
        [call("propose_change", {"command": c, "reason": "r", "expected_effect": "e", "rollback": "x"})["status"]
         for c in ("mtd-erase2 nvram", "nvram erase")]))
    evs = list(agent.chat(s, "reset it", use_claude=True))
    assert json.loads(evs[-1]["content"]) == ["blocked", "blocked"]
    assert shell.ran == [] and s.pending is None


def test_dns_lookups_tool_queries_monitor_api(tmp_path, monkeypatch):
    agent, shell = _agent(tmp_path)
    seen = {}

    class Resp:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def fake_get(url, params=None, timeout=None):
        seen["url"], seen["params"] = url, params
        if url.endswith("/api/dns/devices"):
            return Resp({"available": True, "hours": 24, "devices": [{"device": "cam"}] * 3})
        return Resp({"available": True, "hours": 6, "lookups": [{"device": "cam", "domain": "x.example"}]})

    import tshoot.agent as agent_mod
    monkeypatch.setattr(agent_mod.requests, "get", fake_get)

    out = agent._dns_lookups({"limit": 2})
    assert seen["url"].endswith("/api/dns/devices") and out["kind"] == "devices" and len(out["rows"]) == 2
    out = agent._dns_lookups({"device": "cam", "hours": 6, "blocked_only": True})
    assert seen["url"].endswith("/api/dns/lookups")
    assert seen["params"]["device"] == "cam" and seen["params"]["blocked"] == 1 and seen["params"]["hours"] == 6
    assert out["status"] == "ok" and out["rows"][0]["domain"] == "x.example"
    assert shell.ran == []  # no SSH
    assert "get_dns_lookups" in claude_agent.ALLOWED_TOOLS


def test_traffic_usage_tool_queries_monitor_api(tmp_path, monkeypatch):
    agent, shell = _agent(tmp_path)
    seen = {}

    class Resp:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def fake_get(url, params=None, timeout=None):
        seen["url"], seen["params"] = url, params
        if url.endswith("/api/traffic/devices"):
            return Resp({"available": True, "hours": 24, "devices": [{"device": "tv", "rx": 5, "tx": 1}] * 4})
        return Resp({"available": True, "hours": 168, "apps": [{"app": "Youtube", "rx": 9, "tx": 1}],
                     "series": [{"hour": "h1", "rx": 0, "tx": 0}, {"hour": "h2", "rx": 3, "tx": 1}]})

    import tshoot.agent as agent_mod
    monkeypatch.setattr(agent_mod.requests, "get", fake_get)

    out = agent._traffic_usage({"limit": 2})
    assert seen["url"].endswith("/api/traffic/devices") and out["kind"] == "devices"
    assert len(out["rows"]) == 2 and out["truncated"]
    out = agent._traffic_usage({"device": "tv", "hours": 168})
    assert seen["url"].endswith("/api/traffic/detail") and seen["params"]["device"] == "tv"
    assert out["apps"][0]["app"] == "Youtube" and out["hourly"] == [{"hour": "h2", "rx": 3, "tx": 1}]
    assert shell.ran == []  # no SSH
    assert "get_traffic_usage" in claude_agent.ALLOWED_TOOLS
    assert any(t["name"] == "get_traffic_usage" for t in agent_mod.TOOLS)
