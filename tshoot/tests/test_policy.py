import pytest

from tshoot.policy import BLOCKED, READ, REFUSED, WRITE, classify
from tshoot.redact import MASK, redact


@pytest.mark.parametrize("cmd", [
    "uptime",
    "cat /proc/loadavg",
    "cat /proc/mtd",
    "tail -n 100 /tmp/syslog.log | grep -i pppd",
    "grep -i 'restore_defaults' /jffs/syslog.log",
    "nvram get wan0_state_t",
    "nvram show | grep ^wl0_ | sort",
    "wl -i eth6 assoclist",
    "wl -i eth7 sta_info AA:BB:CC:DD:EE:FF",
    "wl -i eth7 chanspec",
    "wl -i eth7 chanim_stats",
    "ip addr show br0",
    "ip -4 route",
    "ip route get 1.1.1.1",
    "iptables -nvL",
    "iptables -t nat -nvL --line-numbers",
    "iptables -S",
    "ping -c 4 1.1.1.1",
    "ping -c4 -I ppp0 8.8.8.8",
    "top -b -n 1",
    "ifconfig",
    "ifconfig ppp0",
    "brctl showmacs br0",
    "arp -an",
    "cat /var/lib/misc/dnsmasq.leases; cat /etc/dnsmasq.conf",
    "dmesg | tail -n 50",
    "ps w | grep -v grep | grep pppd",
    "cru l",
    "fc status",
    "netstat -an | wc -l",
    "cat /proc/net/nf_conntrack 2>/dev/null | wc -l",
    "find /jffs -name '*.log'",
    "awk '{print $1}' /proc/net/dev",
    "sed -n '1,20p' /etc/dnsmasq.conf",
    "nslookup google.com 127.0.0.1",
    # Merlin
    "cat /jffs/scripts/wan-event",
    "ls -la /jffs/scripts /jffs/configs",
    "cat /jffs/syslog.log-1 /jffs/syslog.log | grep -v 'DROP IN=' | tail -n 50",
    "conntrack -L -p tcp",
    "conntrack -S",
    "conntrack -C",
    "ipset list",
    "wg show",
    "opkg list-installed",
    "sqlite3 /jffs/addons/connmon.d/connstats.db \"SELECT * FROM connstats ORDER BY StatID DESC LIMIT 5\"",
    "sqlite3 -separator ',' /jffs/addons/spdmerlin.d/spdstats.db '.tables'",
])
def test_read(cmd):
    assert classify(cmd).kind == READ, classify(cmd)


@pytest.mark.parametrize("cmd", [
    "nvram set wl1_chanspec=36/80",
    "nvram commit",
    "service restart_wireless",
    "service restart_wan_if 0",
    "reboot",
    "wl -i eth7 chanspec 36/80",
    "wl -i eth7 down",
    "ifconfig br0 down",
    "ip route add 10.0.0.0/8 via 192.168.1.2",
    "iptables -A INPUT -j DROP",
    "iptables -F",
    "echo hi > /jffs/test",
    "echo hi >> /jffs/test",
    "cat /tmp/x | sh",
    "sh -c 'uptime'",
    "killall dnsmasq",
    "rm /tmp/foo",
    "sed -i 's/a/b/' /etc/hosts",
    "find /tmp -name x -delete",
    "find / -exec rm {} \\;",
    "awk 'BEGIN{system(\"reboot\")}'",
    "cat $(echo /etc/passwd)",
    "uptime `reboot`",
    "uptime & reboot",
    "cru a job '* * * * * reboot'",
    "unknownbinary --foo",
    "wget -O /tmp/x http://example.com",
    "tcpdump -c 10 -w /tmp/cap.pcap",
    # Merlin
    "chmod 755 /jffs/scripts/firewall-start",
    "cp /tmp/x /jffs/configs/dnsmasq.conf.add",
    "conntrack -F",
    "conntrack -D -s 1.2.3.4",
    "ipset add Blacklist 1.2.3.4",
    "wg set wgc1 peer abc remove",
    "opkg install tcpdump",
    "nvram set jffs2_scripts=0",
    "sqlite3 /jffs/addons/connmon.d/connstats.db \"DELETE FROM connstats\"",
    "sqlite3 /jffs/addons/connmon.d/connstats.db \"SELECT 1; DROP TABLE connstats\"",
    "sqlite3 /jffs/addons/connmon.d/connstats.db",
])
def test_write(cmd):
    assert classify(cmd).kind == WRITE, classify(cmd)


@pytest.mark.parametrize("cmd", [
    "nvram erase",
    "nvram restore /tmp/x",
    "mtd-erase2 nvram",
    "mtd-write -i fw.trx -d linux",
    "hnd-write /tmp/fw.w",
    "dd if=/dev/zero of=/dev/mtd0",
    "cat /tmp/x > /dev/mtdblock2",
    "nvram set restore_defaults=1",
    "nvram set jffs2_format=1",
    "service restore",
    "service start_webs_upgrade",
    "rm -rf /jffs",
    "rm -rf /jffs/scripts",
    "rm -rf /",
    "halt",
    "poweroff",
    "uptime; nvram erase",
    "mkfs.ext4 /dev/sda1",
])
def test_blocked(cmd):
    assert classify(cmd).kind == BLOCKED, classify(cmd)


@pytest.mark.parametrize("cmd", ["ping 1.1.1.1", "top", "tcpdump -i ppp0", "sleep 60", "ip monitor", "",
                                 "amtm", "vi /jffs/scripts/wan-event", "conntrack -E"])
def test_refused(cmd):
    assert classify(cmd).kind == REFUSED, classify(cmd)


def test_warnings_and_risk():
    v = classify("service restart_wan_if 0")
    assert v.risk == "high" and any("WAN" in w for w in v.warnings)
    v = classify("reboot")
    assert v.risk == "high"
    v = classify("service restart_wireless")
    assert v.risk == "medium"
    v = classify("nvram set wl1_txpower=80")
    assert v.risk == "low" and not v.warnings
    v = classify("chmod 755 /jffs/scripts/firewall-start")
    assert v.risk == "high" and any("/jffs" in w for w in v.warnings)
    v = classify("nvram set jffs2_scripts=0")
    assert v.risk == "high"


def test_redact():
    out = "wl0_wpa_psk=hunter22\nwl0_ssid=Home\nhttp_passwd=abc\nwan0_pppoe_passwd=xyz\n"
    r = redact("nvram show", out)
    assert "hunter22" not in r and "abc" not in r and "xyz" not in r
    assert "wl0_ssid=Home" in r
    assert redact("nvram get wl1_wpa_psk", "secret123\n") == MASK
    assert redact("nvram get wl1_ssid", "Home\n") == "Home\n"
