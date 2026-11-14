"""Merlin needs `service "action arg"` quoted; the quoted form must get the same risk as the bare one."""
import pytest

from tshoot.policy import WRITE, classify


@pytest.mark.parametrize("bare,quoted", [
    ("service restart_wan_if 0", 'service "restart_wan_if 0"'),
    ("service restart_wan_if 0", "service 'restart_wan_if 0'"),
    ("service restart_wireless", 'service "restart_wireless"'),
    ("service restart_dnsmasq", 'service "restart_dnsmasq"'),
    ("service restart_lan", 'service "restart_lan"'),
])
def test_quoted_service_has_the_same_risk(bare, quoted):
    b, q = classify(bare), classify(quoted)
    assert q.kind == WRITE and (q.risk, q.warnings) == (b.risk, b.warnings)


def test_quoted_wan_restart_is_high_risk():
    v = classify('service "restart_wan_if 0"')
    assert v.risk == "high" and any("WAN" in w for w in v.warnings)


def test_prompt_teaches_the_quoted_form():
    from pathlib import Path

    from tshoot import prompt

    text = Path(prompt.__file__).read_text()
    assert 'service \\"restart_wan_if 0\\"' in text or 'service "restart_wan_if 0"' in text
