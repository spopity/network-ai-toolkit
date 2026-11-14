"""Shared fixtures. Tests never touch the router, AdGuardHome or Postgres.

Test data uses documentation addresses (192.0.2.0/24, 203.0.113.0/24) and made-up
MACs so the suite can be published with the public toolkit unchanged.
"""
from datetime import datetime, timedelta

import pytest

from router_agent import db


@pytest.fixture(autouse=True)
def no_postgres(monkeypatch):
    """Any Postgres access fails, like an unreachable archive. Tests that need the
    archive to succeed patch the specific db.* function they exercise."""

    def refuse():
        raise RuntimeError("Postgres is disabled in tests")

    monkeypatch.setattr(db, "_connect", refuse)
    monkeypatch.setattr(db, "_SCHEMA_READY", False)


def syslog_ts(minutes_ago: float = 0, now: datetime | None = None) -> str:
    """A syslog-style timestamp ("Nov 14 09:35:51") relative to now."""
    t = (now or datetime.now()) - timedelta(minutes=minutes_ago)
    return t.strftime("%b %d %H:%M:%S")


class FakeNamer:
    """Stands in for dnslog.Namer: {ip: mac} and {mac: name} without router output."""

    def __init__(self, ip_mac: dict[str, str] | None = None, names: dict[str, str] | None = None):
        self.ip_mac = ip_mac or {}
        self.names = names or {}

    def __call__(self, ip: str, agh_name: str = "") -> dict:
        mac = self.ip_mac.get(ip)
        if mac:
            return {"key": mac, "mac": mac, "device": self.names.get(mac, "unnamed device"), "network": "LAN"}
        return {"key": f"ip:{ip}", "mac": None, "device": agh_name or ip, "network": "Other"}


class FakeCollector:
    """SSHCollector stand-in: returns canned output for run_command()."""

    def __init__(self, out: str = "", exc: Exception | None = None):
        self.out, self.exc = out, exc
        self.commands: list[str] = []
        self.closed = False

    def run_command(self, cmd: str, timeout: int = 30) -> dict:
        self.commands.append(cmd)
        if self.exc:
            raise self.exc
        return {"cmd": cmd, "out": self.out}

    def close(self):
        self.closed = True
