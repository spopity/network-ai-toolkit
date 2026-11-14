"""Who may approve Tshoot router changes, and the dashboard paths that enforce it."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from router_agent import identity
from router_agent.identity import VIA_TAILSCALE, MarkTailscale, can_approve, identify

from .test_dashboard import ROUTER_IP, app_module  # noqa: F401 -- fixture reused

LOGIN = "owner@example.com"
APPROVERS = {"logins": [LOGIN], "devices": ["laptop", "phone"]}
WHOIS = {
    "100.64.0.1": {"Node": {"ComputedName": "laptop", "Tags": None}, "UserProfile": {"LoginName": LOGIN}},
    "100.64.0.2": {"Node": {"ComputedName": "server", "Tags": None}, "UserProfile": {"LoginName": LOGIN}},
    "100.64.0.3": {"Node": {"ComputedName": "tagged-box", "Tags": ["tag:server"]}, "UserProfile": {"LoginName": "tagged-devices"}},
}


@pytest.fixture(autouse=True)
def fake_whois(monkeypatch):
    identity._whois_cache.clear()

    def run(cmd, **kw):
        ip = cmd[-1]
        if ip not in WHOIS:
            raise subprocess.CalledProcessError(1, cmd)
        return SimpleNamespace(stdout=json.dumps(WHOIS[ip]))

    monkeypatch.setattr(identity.subprocess, "run", run)


def _ts(ip, login=LOGIN):
    return identify({VIA_TAILSCALE: True}, {"Tailscale-User-Login": login, "X-Forwarded-For": ip})


def test_identify_only_trusts_headers_from_the_tailscale_listener():
    assert identify({}, {"Tailscale-User-Login": LOGIN, "X-Forwarded-For": "100.64.0.1"}) == {"via_tailscale": False}
    ident = _ts("100.64.0.1")
    assert ident["login"] == LOGIN and ident["device"] == "laptop" and ident["tagged"] is False


@pytest.mark.parametrize(("ident", "ok", "why"), [
    (lambda: _ts("100.64.0.1"), True, ""),
    (lambda: {"via_tailscale": False}, False, "only accepted through Tailscale"),
    (lambda: _ts("100.64.0.2"), False, "not accepted from server"),          # own account, wrong device
    (lambda: _ts("100.64.0.1", "other@example.com"), False, "may not approve"),
    (lambda: _ts("100.64.0.3", None), False, "may not approve"),              # tagged device: no user
    (lambda: _ts("100.64.0.9"), False, "not accepted from 100.64.0.9"),       # whois unknown
])
def test_can_approve(ident, ok, why):
    allowed, reason = can_approve(ident(), APPROVERS)
    assert allowed is ok
    assert why in reason


def test_no_approvers_configured_means_nobody():
    assert can_approve(_ts("100.64.0.1"), None) == (False, "No approvers are configured (dashboard.approvers.logins in config.yml).")
    assert can_approve(_ts("100.64.0.2"), {"logins": [LOGIN.upper()]})[0] is True  # no device list: any device


def test_whois_is_cached(monkeypatch):
    calls = []
    real = identity.subprocess.run
    monkeypatch.setattr(identity.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or real(cmd, **kw))
    identity.whois("100.64.0.1")
    identity.whois("100.64.0.1")
    assert len(calls) == 1


def test_mark_tailscale_middleware():
    seen = {}
    MarkTailscale(lambda env, sr: seen.update(env) or [])({}, None)
    assert seen[VIA_TAILSCALE] is True


# ---- dashboard endpoints ----

@pytest.fixture
def dash(app_module, tmp_path, monkeypatch):  # noqa: F811
    import yaml

    cfg = tmp_path / "config.yml"
    cfg.write_text(yaml.safe_dump({"log_dir": str(tmp_path / "logs"), "routers": [{"name": "rt", "host": ROUTER_IP}],
                                   "dashboard": {"approvers": APPROVERS}}))
    monkeypatch.setattr(app_module, "CONFIG_PATH", cfg)
    monkeypatch.setattr(app_module, "TSHOOT_PROXY_KEY", "k")
    forwarded = []

    class Upstream:
        status_code = 200
        headers = {"Content-Type": "text/event-stream"}  # noqa: RUF012

        def iter_content(self, chunk_size=None):
            yield b"data: {}\n\n"

        def close(self):
            pass

    monkeypatch.setattr(app_module.requests, "request", lambda method, url, **kw: forwarded.append((url, kw)) or Upstream())
    c = app_module.app.test_client()
    c.forwarded = forwarded
    c.logs = tmp_path / "logs"
    return c


def _via(ip, login=LOGIN):
    return {"environ_base": {VIA_TAILSCALE: True},
            "headers": {"Tailscale-User-Login": login, "X-Forwarded-For": ip}}


def test_approve_from_allowed_device_is_forwarded_with_key_and_user(dash):
    r = dash.post("/api/tshoot/approve", json={"decision": "approve", "session_id": "abcdefgh"}, **_via("100.64.0.1"))
    assert r.status_code == 200
    _, kw = dash.forwarded[0]
    assert kw["headers"]["X-Tshoot-Proxy-Key"] == "k"
    assert kw["headers"]["X-Tshoot-User"] == f"{LOGIN} on laptop"


@pytest.mark.parametrize("kw", [
    {},                                                            # LAN/TCP listener: no identity
    {"headers": {"Tailscale-User-Login": LOGIN}},                  # forged header on the TCP listener
    "server",                                                      # own login, not an approver device
])
def test_approve_refused(dash, kw):
    kw = _via("100.64.0.2") if kw == "server" else kw
    r = dash.post("/api/tshoot/approve", json={"decision": "approve"}, **kw)
    assert r.status_code == 403 and r.get_json()["error"].startswith("Not approved:")
    assert dash.forwarded == []


def test_reject_and_chat_need_no_approver(dash):
    assert dash.post("/api/tshoot/approve", json={"decision": "reject"}).status_code == 200
    assert dash.post("/api/tshoot/chat", json={"message": "hi"}).status_code == 200
    assert all(kw["headers"]["X-Tshoot-Proxy-Key"] == "k" for _, kw in dash.forwarded)


def test_whoami(dash):
    assert dash.get("/api/whoami").get_json()["can_approve"] is False
    body = dash.get("/api/whoami", **_via("100.64.0.1")).get_json()
    assert body["can_approve"] is True and body["device"] == "laptop" and body["reason"] is None


def test_connmon_reads_the_file_written_by_the_check(dash, app_module):  # noqa: F811
    import time

    dash.get("/api/state")  # creates logs/
    now = int(time.time())
    (dash.logs / "connmon.json").write_text(json.dumps({"fetched_at": "x", "points": [
        {"ts": now - 3600, "ping": 7, "jitter": 1, "quality": 100},
        {"ts": now - 3 * 86400, "ping": 9, "jitter": 2, "quality": 100}]}))
    assert len(dash.get("/api/connmon?hours=24").get_json()["points"]) == 1
    assert len(dash.get("/api/connmon?hours=168").get_json()["points"]) == 2


def test_connmon_without_data(dash):
    body = dash.get("/api/connmon").get_json()
    assert body["available"] is False and body["points"] == []


def test_collect_now_in_systemd_mode_touches_trigger(dash, app_module, monkeypatch):  # noqa: F811
    monkeypatch.setattr(app_module, "_systemd_mode", lambda: True)
    state = {"ActiveState": "inactive"}

    def show(cmd, **kw):
        return SimpleNamespace(stdout="\n".join(f"{k}={v}" for k, v in {
            "ActiveState": state["ActiveState"], "Result": "success", "ExecMainStatus": "0",
            "ExecMainStartTimestamp": "@1700000000", "ExecMainExitTimestamp": "@1700000030"}.items()))

    monkeypatch.setattr(app_module.subprocess, "run", show)
    dash.get("/api/state")
    assert dash.post("/api/collect-now").status_code == 202
    assert (dash.logs / ".collect-request").exists()
    st = dash.get("/api/collect-status").get_json()
    assert st["running"] is True  # requested, systemd not started yet
    state["ActiveState"] = "activating"
    assert dash.post("/api/collect-now").status_code == 409
    state["ActiveState"] = "inactive"
    (dash.logs / ".collect-request").unlink()
    st = dash.get("/api/collect-status").get_json()
    assert st == {"running": False, "started_at": "2023-11-14T22:13:20+00:00",
                  "finished_at": "2023-11-14T22:13:50+00:00", "last_result": "ok"}
