from tshoot import claude_agent
from tshoot.agent import Pending, Session, TshootAgent
from tshoot.audit import AuditLog
from tshoot.prompt import READ_ONLY_TOOLS
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


def _call(agent, name, args):
    evs = list(agent._handle_call(Session("test0001"), {"name": name, "args": args}, 0, read_only=True))
    assert not any(isinstance(e, Pending) for e in evs)
    return next(e[1]["functionResponse"]["response"] for e in evs if isinstance(e, tuple))


def test_read_only_runs_reads(tmp_path):
    agent, shell = _agent(tmp_path)
    assert _call(agent, "run_command", {"command": "nvram get wl1_chanspec", "purpose": "x"})["status"] == "executed"
    assert shell.ran == ["nvram get wl1_chanspec"]


def test_read_only_refuses_writes_without_approval(tmp_path):
    agent, shell = _agent(tmp_path)
    for cmd in ("nvram set wl1_chanspec=36/80", "service restart_wireless", "reboot", "nvram get x > /tmp/y"):
        assert _call(agent, "run_command", {"command": cmd, "purpose": "x"})["status"] in ("refused", "blocked")
    assert _call(agent, "propose_change", {"command": "reboot"})["status"] == "error"
    assert shell.ran == []


def test_allowlist_matches_read_only_tools():
    assert {t["name"] for t in READ_ONLY_TOOLS} <= claude_agent.READ_ONLY_TOOLS
    assert "propose_change" not in claude_agent.READ_ONLY_TOOLS
