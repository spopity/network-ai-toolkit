"""Router setup drift: is everything the hook scripts and add-ons put in place still there?

Much of this setup lives in memory and is rebuilt by Merlin hook scripts: Skynet's
ipsets and iptables rules (firewall-start), the Guest/IoT DNS and NTP redirects
(nat-start), the LAN -> IoT accept rule (firewall-start), ntp-sdn and root's SSH keys
(services-start), Entware, swap, scribe's syslog-ng (and that it still owns /dev/log) and the add-on cron jobs (post-mount
on the USB stick), the DHCP NTP option (dnsmasq*.postconf). When a hook silently fails
(after a reboot, a firmware update, `service restart_firewall`, a USB stick that did not
mount) nothing breaks loudly: data just gets quieter, or a network loses filtering.

Every 5-minute check runs SETUP_CMD (read-only, a few iptables/ipset/cru reads) and
gets `item=value` lines. Items are learned, not configured: every item that has been
OK once is remembered in logs/.router_setup.json, and an item that was OK before but
is now missing (value 0, or absent: a cron job, rule or script that vanished) is
reported in `snapshot.router_setup.missing`. Items this router never had are never
reported, so the first run is a silent baseline and other setups work unchanged.

Alerting goes through the self-check (`router_setup`, 15 min grace so a reboot's hook
order or Skynet's periodic ipset refresh stays quiet): one `monitor_problem` when items
go missing, one `monitor_ok` when they are back. Something removed on purpose: add it to
`router_setup.ignore` (fnmatch patterns such as "cron:spdMerlin_*"), or delete the file
to re-learn. No LLM, nothing here writes to the router.
"""
import fnmatch
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_FILE = ".router_setup.json"
# firmware-managed cron jobs that come and go on their own (WireGuard client endpoint check)
DEFAULT_IGNORE = ("cron:WGC_CHK_EP",)
END_MARK = "router_setup_end"

# BusyBox sh. Fixed probes print "name=<number>" (> 0 means OK); enumerated items print
# "prefix:name=1" only when present, so a vanished one simply stops being listed.
SETUP_CMD = "; ".join([
    'echo "jffs_scripts=$(nvram get jffs2_scripts)"',
    'echo "entware=$([ -x /opt/bin/opkg ] && echo 1 || echo 0)"',
    "echo \"swap=$(awk 'NR>1' /proc/swaps 2>/dev/null | wc -l)\"",
    "echo \"skynet_ipsets=$(ipset list -n 2>/dev/null | grep -c '^Skynet-')\"",
    'echo "skynet_rules=$(iptables -t raw -S 2>/dev/null | grep -c Skynet)"',
    'echo "ntp_sdn=$(kill -0 "$(cat /var/run/ntp-sdn.pid 2>/dev/null)" 2>/dev/null && echo 1 || echo 0)"',
    'echo "syslog_ng=$(pidof syslog-ng >/dev/null && echo 1 || echo 0)"',
    # syslog-ng still owns /dev/log? If something recreates the socket later (a firmware
    # service restart did, 2026-11-14), syslog-ng keeps reading the deleted one and all
    # userspace logging is silently lost. OK = /dev/log no newer than syslog-ng + 60 s.
    ('bt=$(awk \'/^btime/{print $2}\' /proc/stat); st=0; for p in $(pidof syslog-ng); do'
     ' s=$(awk \'{print $22}\' /proc/$p/stat 2>/dev/null); [ "${s:-0}" -gt "$st" ] && st=$s; done;'
     ' dl=$(date -r /dev/log +%s 2>/dev/null || echo 0);'
     ' echo "syslog_socket=$([ "$st" -gt 0 ] && [ "$dl" -gt 0 ] && [ $((dl - bt - st / 100)) -le 60 ]'
     ' && echo 1 || echo 0)"'),
    'echo "root_ssh_keys=$([ -s /home/root/.ssh/authorized_keys ] && echo 1 || echo 0)"',
    "iptables -t nat -S DNSFILTER 2>/dev/null | sed -n 's/^-A DNSFILTER -i \\([^ ]*\\) -j REDIRECT$/dns_redirect:\\1=1/p'",
    ("iptables -t nat -S PREROUTING 2>/dev/null"
     " | sed -n 's/^-A PREROUTING -i \\([^ ]*\\) -p udp -m udp --dport 123 -j REDIRECT.*/ntp_redirect:\\1=1/p'"),
    "iptables -S SDN_IA 2>/dev/null | sed -n 's/^-A SDN_IA -i \\([^ ]*\\) -o \\([^ ]*\\) -j ACCEPT$/sdn_accept:\\1>\\2=1/p'",
    "grep -l 'option:ntp-server' /etc/dnsmasq*.conf 2>/dev/null | sed 's|.*/\\(.*\\)\\.conf$|dhcp_ntp:\\1=1|'",
    "cru l 2>/dev/null | sed -n 's/.*#\\([^#]*\\)#$/cron:\\1=1/p'",
    ('for f in /jffs/scripts/*; do case "$f" in *.bak*|*.old|*~) continue;; esac;'
     ' [ -f "$f" ] && [ -x "$f" ] && echo "script:${f##*/}=1"; done'),
    f'echo "{END_MARK}=1"',
])

# where a missing item comes from, so the alert says what to look at
HINTS = (
    ("dns_redirect:", "nat-start"), ("ntp_redirect:", "nat-start"),
    ("sdn_accept:", "firewall-start"), ("skynet_", "firewall-start (Skynet)"),
    ("ntp_sdn", "services-start"), ("root_ssh_keys", "services-start"),
    ("entware", "post-mount (USB stick)"), ("swap", "post-mount (USB stick)"),
    ("syslog_ng", "Entware (scribe)"),
    ("syslog_socket", "syslog-ng lost /dev/log, logs are dropped: /opt/etc/init.d/S01syslog-ng restart"), ("cron:", "the add-on's startup"),
    ("dhcp_ntp:", "dnsmasq*.postconf"), ("script:", "/jffs/scripts (restore from a backup)"),
    ("jffs_scripts", "Administration > System > custom scripts"),
)


def parse(out: str) -> dict[str, bool] | None:
    """SETUP_CMD output -> {item: ok}; None when the command did not run to the end."""
    items: dict[str, bool] = {}
    complete = False
    for line in (out or "").splitlines():
        name, sep, val = line.strip().partition("=")
        if not sep or not name:
            continue
        if name == END_MARK:
            complete = True
            continue
        try:
            items[name] = int(val.strip() or 0) > 0
        except ValueError:
            items[name] = False
    return items if complete else None


def hint(item: str) -> str | None:
    return next((h for prefix, h in HINTS if item.startswith(prefix)), None)


def describe_missing(missing: list[str]) -> str:
    """'skynet_ipsets, skynet_rules (firewall-start (Skynet)); cron:ntp-sdn (...)' grouped by hint."""
    groups: dict[str, list[str]] = {}
    for m in missing:
        groups.setdefault(hint(m) or "", []).append(m)
    return "; ".join(", ".join(items) + (f" ({h})" if h else "") for h, items in groups.items())


class SetupWatch:
    def __init__(self, base: Path, cfg: dict | None = None):
        self.path = Path(base) / STATE_FILE
        self.ignore = [*DEFAULT_IGNORE, *(((cfg or {}).get("ignore")) or [])]

    def ignored(self, item: str) -> bool:
        return any(fnmatch.fnmatchcase(item, p) for p in self.ignore)

    def check(self, out: str, now: datetime | None = None) -> dict | None:
        items = parse(out)
        if items is None:
            return None  # SSH/command failure: unknown, not "everything missing"
        ts = (now or datetime.now(UTC)).isoformat(timespec="seconds")
        try:
            known = json.loads(self.path.read_text())
            baseline = False
        except (OSError, ValueError):
            known, baseline = {}, True
        for name, ok in items.items():
            if ok:
                known.setdefault(name, {"first_ok": ts})["last_ok"] = ts
        missing = sorted(n for n in known if not items.get(n) and not self.ignored(n))
        self.path.write_text(json.dumps(known, indent=1, sort_keys=True))
        return {
            "checked": len(known),
            "missing": missing,
            "baseline": baseline or None,
        }


def check(base: Path, cfg: dict | None, out: str) -> dict | None:
    """SetupWatch.check() for the 5-minute check. Never raises."""
    try:
        return SetupWatch(base, cfg).check(out)
    except Exception as e:
        logger.warning("router setup check failed: %s", e)
        return None
