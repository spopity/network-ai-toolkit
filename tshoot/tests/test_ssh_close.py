"""A failed SSH login must close the connection (dropbear holds half-open ones for 5 min)."""
import paramiko
import pytest

from tshoot import ssh


def test_failed_connect_closes_the_client(monkeypatch):
    closed = []

    class FakeClient:
        def set_missing_host_key_policy(self, _p):
            pass

        def connect(self, *a, **k):
            raise paramiko.AuthenticationException("Authentication failed.")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(ssh.paramiko, "SSHClient", FakeClient)
    shell = ssh.RouterShell("192.0.2.1", username="x")
    with pytest.raises(paramiko.AuthenticationException):
        shell._connect()
    assert closed and shell._client is None
    assert "Authentication failed" in shell.run("uptime").error
    assert len(closed) == 3  # run(): first try + the one reconnect, each closed
