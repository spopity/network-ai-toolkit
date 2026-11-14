"""The WAN restart the watchdog sends must be one Merlin accepts, and a refusal must not count as success."""
import watchdog


def test_restart_command_quotes_the_action():
    # unquoted, Merlin only prints "Usage: service <action_service>" (found by the live test, 2026-11-14)
    assert watchdog.restart_command(0) == 'service "restart_wan_if 0"'
    assert watchdog.restart_command("1") == 'service "restart_wan_if 1"'


def test_restart_succeeded():
    assert watchdog.restart_succeeded({"out": "\nDone.\n", "err": ""})
    assert not watchdog.restart_succeeded({"out": "", "err": "Usage: service <action_service>\n"})
    assert not watchdog.restart_succeeded({"out": "Usage: service <action_service>", "err": ""})
    assert not watchdog.restart_succeeded({"out": "", "err": ""})


def test_restart_wan_sends_the_quoted_command(monkeypatch):
    sent = []

    class FakeCollector:
        def __init__(self, **kw):
            pass

        def run_command(self, cmd):
            sent.append(cmd)
            return {"cmd": cmd, "out": "Done.\n", "err": ""}

        def close(self):
            sent.append("closed")

    monkeypatch.setattr(watchdog, "SSHCollector", FakeCollector)
    assert watchdog.restart_succeeded(watchdog.restart_wan({"host": "192.0.2.1"}, 0))
    assert sent == ['service "restart_wan_if 0"', "closed"]
