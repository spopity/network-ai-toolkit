"""Router setup drift: learned items, silent baseline, alert only on something that vanished."""
import json
from datetime import UTC, datetime, timedelta

from router_agent import routersetup, selfcheck
from router_agent.routersetup import SETUP_CMD, SetupWatch, describe_missing, parse

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)

FULL = """jffs_scripts=1
entware=1
swap=1
skynet_ipsets=12
skynet_rules=8
ntp_sdn=1
syslog_ng=1
root_ssh_keys=1
dns_redirect:br54=1
dns_redirect:br53=1
ntp_redirect:br53=1
sdn_accept:br0>br54=1
dhcp_ntp:dnsmasq=1
cron:ntp-sdn=1
cron:Skynet_rules=1
cron:WGC_CHK_EP=1
script:nat-start=1
script:firewall-start=1
router_setup_end=1
"""


def _drop(out: str, *names: str) -> str:
    return "".join(line + "\n" for line in out.splitlines() if line.split("=")[0] not in names)


def test_parse_values_and_incomplete_output():
    items = parse(FULL)
    assert items["skynet_ipsets"] is True and items["dns_redirect:br53"] is True
    assert parse(FULL.replace("swap=1", "swap=0"))["swap"] is False
    assert parse(FULL.replace("jffs_scripts=1", "jffs_scripts="))["jffs_scripts"] is False
    # no end marker: SSH dropped mid-command -> unknown, never "everything missing"
    assert parse(_drop(FULL, "router_setup_end")) is None
    assert parse("") is None


def test_baseline_silent_then_vanished_items_reported(tmp_path):
    w = SetupWatch(tmp_path)
    first = w.check(FULL, NOW)
    assert first["missing"] == [] and first["baseline"] is True
    assert w.check(FULL, NOW)["baseline"] is None

    # a cron job vanished (absent), Skynet's rules gone (count 0), a redirect gone
    out = _drop(FULL, "cron:ntp-sdn", "dns_redirect:br54").replace("skynet_rules=8", "skynet_rules=0")
    assert w.check(out, NOW)["missing"] == ["cron:ntp-sdn", "dns_redirect:br54", "skynet_rules"]
    # back again -> nothing missing
    assert w.check(FULL, NOW)["missing"] == []


def test_items_never_seen_ok_are_not_reported(tmp_path):
    w = SetupWatch(tmp_path)
    w.check(FULL.replace("swap=1", "swap=0"), NOW)  # this router has no swap
    assert w.check(FULL.replace("swap=1", "swap=0"), NOW)["missing"] == []


def test_failed_command_keeps_state(tmp_path):
    w = SetupWatch(tmp_path)
    w.check(FULL, NOW)
    before = (tmp_path / routersetup.STATE_FILE).read_text()
    assert w.check("", NOW) is None
    assert (tmp_path / routersetup.STATE_FILE).read_text() == before


def test_ignore_patterns_and_firmware_default(tmp_path):
    SetupWatch(tmp_path).check(FULL, NOW)
    out = _drop(FULL, "cron:Skynet_rules", "cron:WGC_CHK_EP", "script:nat-start")
    assert SetupWatch(tmp_path).check(out, NOW)["missing"] == ["cron:Skynet_rules", "script:nat-start"]
    w = SetupWatch(tmp_path, {"ignore": ["cron:Skynet_*"]})
    assert w.check(out, NOW)["missing"] == ["script:nat-start"]


def test_describe_groups_by_hook():
    text = describe_missing(["dns_redirect:br53", "ntp_redirect:br54", "skynet_rules", "mystery"])
    assert text == "dns_redirect:br53, ntp_redirect:br54 (nat-start); skynet_rules (firewall-start (Skynet)); mystery"


def test_check_never_raises(tmp_path):
    assert routersetup.check(tmp_path / "missing-dir", None, FULL) is None


def test_selfcheck_alerts_after_grace_once_and_recovers(tmp_path):
    def latest(missing):
        (tmp_path / "latest.json").write_text(json.dumps({"snapshot": {"router_setup": {"missing": missing}}}))

    latest(["dns_redirect:br53"])
    assert "dns_redirect:br53 (nat-start)" in selfcheck.check_router_setup(tmp_path)
    state: dict = {}
    res = {"router_setup": selfcheck.check_router_setup(tmp_path)}
    assert selfcheck.update_state(state, res, NOW) == []  # inside the 15 min grace (reboot hook order)
    ev = selfcheck.update_state(state, res, NOW + timedelta(minutes=16))
    assert [e["event"] for e in ev] == ["monitor_problem"] and ev[0]["title"] == "router setup"
    assert selfcheck.update_state(state, res, NOW + timedelta(minutes=21)) == []
    latest([])
    ev = selfcheck.update_state(state, {"router_setup": selfcheck.check_router_setup(tmp_path)}, NOW + timedelta(minutes=26))
    assert [e["event"] for e in ev] == ["monitor_ok"]


def test_selfcheck_off_and_unknown(tmp_path):
    (tmp_path / "latest.json").write_text(json.dumps({"snapshot": {"router_setup": None}}))
    assert selfcheck.check_router_setup(tmp_path) is None
    res = selfcheck.gather({"router_setup": False}, tmp_path, NOW, only=("router_setup",))
    assert res == {"router_setup": None}


def test_command_is_collected():
    from router_agent.collector import COMMAND_GROUPS
    assert SETUP_CMD in COMMAND_GROUPS["services"]
    assert SETUP_CMD.rstrip().endswith(f'echo "{routersetup.END_MARK}=1"')
