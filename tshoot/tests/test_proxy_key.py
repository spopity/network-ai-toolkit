"""Tshoot only answers requests that carry the dashboard proxy's shared key."""
import os
from pathlib import Path

import pytest

if not (Path(__file__).resolve().parent.parent / "config.yml").exists():
    pytest.skip("needs a config.yml to import the app", allow_module_level=True)

os.environ.setdefault("GEMINI_API_KEY", "test-only")  # the app builds its LLM clients at import
from tshoot import app as tapp  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(tapp, "PROXY_KEY", "s3cret")
    tapp.app.testing = True
    return tapp.app.test_client()


def test_requests_without_key_are_refused(client):
    assert client.post("/api/tshoot/approve", json={"decision": "approve"}).status_code == 403
    assert client.get("/api/tshoot/audit").status_code == 403
    assert client.post("/api/tshoot/chat", json={"message": "hi"},
                       headers={"X-Tshoot-Proxy-Key": "wrong"}).status_code == 403


def test_key_lets_requests_through_and_health_stays_open(client):
    r = client.post("/api/tshoot/approve", json={"decision": "maybe"}, headers={"X-Tshoot-Proxy-Key": "s3cret"})
    assert r.status_code == 400  # reached the handler (invalid decision)
    assert client.get("/api/tshoot/health").status_code != 403


def test_no_key_configured_keeps_old_behaviour(monkeypatch):
    monkeypatch.setattr(tapp, "PROXY_KEY", "")
    c = tapp.app.test_client()
    assert c.post("/api/tshoot/approve", json={"decision": "maybe"}).status_code == 400
