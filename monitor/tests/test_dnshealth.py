"""DNS filter health: state decision and transition events."""
import json

import pytest

from router_agent import dnshealth
from router_agent.dnshealth import DnsHealth, evaluate, parse_router

from .conftest import FakeCollector

OK_ROUTER = {"owners_53": ["AdGuardHome"], "agh_pid": "123", "monitors": 1}
OK_API = {"running": True, "protection_enabled": True}
OK_PROBE = {"ok": True, "ms": 5}


def test_parse_router_output():
    out = "1234 AdGuardHome\n1234 AdGuardHome\n999 dnsmasq\nagh_pid=1234\nmonitors=1\n"
    assert parse_router(out) == {"owners_53": ["AdGuardHome", "dnsmasq"], "agh_pid": "1234", "monitors": 1}
    assert parse_router("agh_pid=\nmonitors=x") == {"owners_53": [], "agh_pid": None, "monitors": None}


@pytest.mark.parametrize(("router", "api", "blocking", "probe", "state"), [
    (OK_ROUTER, OK_API, True, OK_PROBE, "ok"),
    (OK_ROUTER, OK_API, True, {"ok": False, "error": "timeout"}, "down"),
    ({**OK_ROUTER, "owners_53": ["dnsmasq"]}, OK_API, True, OK_PROBE, "unfiltered"),     # AGH fallback
    ({**OK_ROUTER, "owners_53": ["AdGuardHome", "dnsmasq"]}, OK_API, True, OK_PROBE, "unfiltered"),
    (OK_ROUTER, None, None, OK_PROBE, "unfiltered"),                                      # API unreachable
    (OK_ROUTER, {**OK_API, "protection_enabled": False}, True, OK_PROBE, "unfiltered"),
    (OK_ROUTER, OK_API, False, OK_PROBE, "unfiltered"),                                   # blocklists off
    (None, OK_API, True, OK_PROBE, "ok"),                                                 # SSH failed: no verdict on port 53
])
def test_evaluate_states(router, api, blocking, probe, state):
    assert evaluate(router, api, blocking, probe)["state"] == state


def test_missing_supervisor_is_reported_but_not_unhealthy():
    r = evaluate({**OK_ROUTER, "monitors": 0}, OK_API, True, OK_PROBE)
    assert r["state"] == "ok"
    assert any("supervisor" in p for p in r["problems"])


class StubAgh:
    def __init__(self, status, reason="FilteredBlackList"):
        self.status, self.reason = status, reason

    def _get(self, path, **params):
        if self.status is None:
            raise ConnectionError("down")
        return self.status if path == "status" else {"reason": self.reason}


def _check(tmp_path, monkeypatch, agh, router_out="1 AdGuardHome\nagh_pid=1\nmonitors=1"):
    monkeypatch.setattr(dnshealth, "dns_probe", lambda ip: OK_PROBE)
    return DnsHealth(tmp_path, "192.0.2.1", agh).check(FakeCollector(router_out))


def _events(tmp_path):
    p = tmp_path / "router_events.log"
    return [json.loads(line)["event"] for line in p.read_text().splitlines()] if p.exists() else []


def test_events_only_on_state_change(tmp_path, monkeypatch):
    r = _check(tmp_path, monkeypatch, StubAgh(OK_API))
    assert r["state"] == "ok" and _events(tmp_path) == []  # first check healthy: nothing to report
    _check(tmp_path, monkeypatch, StubAgh(None))
    _check(tmp_path, monkeypatch, StubAgh(None))
    assert _events(tmp_path) == ["dns_unfiltered"]
    r = _check(tmp_path, monkeypatch, StubAgh(OK_API))
    assert _events(tmp_path) == ["dns_unfiltered", "dns_ok"]
    assert r["since"] == r["checked_at"]


def test_blocking_test_uses_check_host_reason(tmp_path, monkeypatch):
    r = _check(tmp_path, monkeypatch, StubAgh(OK_API, reason="NotFilteredNotFound"))
    assert r["blocking_test"] is False and r["state"] == "unfiltered"
