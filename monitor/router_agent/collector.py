
import paramiko

from .iotlan import IOT_LAN_CMD
from .routersetup import SETUP_CMD
from .upnp import UPNP_CMD

# Log layout. With scribe (syslog-ng on the USB stick) the main log is
# /opt/var/log/messages (/jffs/syslog.log symlinks to it), firewall drops and
# Skynet blocks go to skynet-0.log and wlceventd chatter to wlceventd.log.
# Without scribe, Merlin's syslogd writes everything to /jffs/syslog.log and
# rotates it at 256 KB into syslog.log-1. Each command picks whichever layout is
# present. Firewall lines are never part of the syslog tail -- they are parsed
# into compact rows and aggregated (snapshot.py), and the rest of the log is
# templated down there too, before anything reaches an LLM.
_HAS_SCRIBE = "[ -f /opt/var/log/messages ]"
SYSLOG_TAIL_CMD = (
    f"{{ if {_HAS_SCRIBE}; then tail -n 3000 /opt/var/log/messages; tail -n 500 /opt/var/log/wlceventd.log; "
    "else cat /jffs/syslog.log-1 /jffs/syslog.log; fi; } 2>/dev/null "
    "| grep -v -e 'DROP IN=' -e 'BLOCKED - ' | tail -n 3500"
)
# -> "Mon DD HH:MM:SS|BLOCKED - INBOUND|src|dst|proto|dport" (kind is "DROP" for the router's own firewall)
FIREWALL_DROPS_CMD = (
    f"{{ if {_HAS_SCRIBE}; then tail -n 30000 /opt/var/log/skynet-0.log; tail -n 3000 /opt/var/log/messages; "
    "else cat /jffs/syslog.log-1 /jffs/syslog.log; fi; } 2>/dev/null "
    r"""| sed -n -E 's/^(... .. ..:..:..) .*[[ ](BLOCKED - [A-Z]+|DROP)\]? IN=[^ ]* .* SRC=([^ ]*) DST=([^ ]*) .* PROTO=([A-Z0-9]+)( .* DPT=([0-9]+))?.*/\1|\2|\3|\4|\5|\7/p'"""
)
SKYNET_SETS_CMD = (
    "for s in Skynet-Blacklist Skynet-BlockedRanges; do "
    "ipset list $s -t 2>/dev/null | sed -n \"s/^Number of entries: /$s=/p\"; done"
)
# connmon (ping/jitter/line quality every 5 min) and spdMerlin (daily speedtest)
# keep SQLite databases; aggregate on the router so only a few numbers come back.
CONNMON_DB = "/jffs/addons/connmon.d/connstats.db"
# the last 7 days of connmon points for the dashboard's chart (logs/connmon.json, written by each check)
CONNMON_POINTS_CMD = (
    f"[ -f {CONNMON_DB} ] && sqlite3 -separator '|' {CONNMON_DB} \""
    "SELECT Timestamp, Ping, Jitter, LineQuality FROM connstats "
    "WHERE Timestamp > strftime('%s','now','-7 days') ORDER BY Timestamp\""
)
CONNMON_CMD = (
    f"[ -f {CONNMON_DB} ] && sqlite3 -separator '|' {CONNMON_DB} \""
    "SELECT COUNT(*), ROUND(AVG(Ping),2), ROUND(MAX(Ping),2), ROUND(AVG(Jitter),2), ROUND(MAX(Jitter),2), "
    "ROUND(MIN(LineQuality),1), SUM(LineQuality<100) FROM connstats WHERE Timestamp > strftime('%s','now','-1 day'); "
    "SELECT ROUND(AVG(Ping),2), ROUND(AVG(Jitter),2) FROM connstats WHERE Timestamp > strftime('%s','now','-7 days');\""
)
SPDMERLIN_DB = "/jffs/addons/spdmerlin.d/spdstats.db"
SPEEDTEST_CMD = (
    f"[ -f {SPDMERLIN_DB} ] && sqlite3 -separator '|' {SPDMERLIN_DB} \""
    "SELECT Timestamp, ROUND(Download,1), ROUND(Upload,1), Latency, Jitter, ServerName FROM spdstats_WAN "
    "ORDER BY Timestamp DESC LIMIT 1; "
    "SELECT COUNT(*), ROUND(AVG(Download),1), ROUND(MIN(Download),1), ROUND(AVG(Upload),1) FROM spdstats_WAN "
    "WHERE Timestamp > strftime('%s','now','-7 days');\""
)
MERLIN_CHECK_CMD = "[ -x /usr/sbin/amtm ] && echo merlin || echo stock"
# AiMesh: cfg_server on the main router keeps every node's wireless clients in
# /tmp/clientlist.json ({node_mac: {"2G"|"5G_2"|...: {client_mac: {ip, rssi}}, "wired_mac": ...}})
# and the node roster in cfg_device_list ("<model>ip>mac>is_main" per node).
# wl assoclist only sees the main router's own primary radios.
MESH_CLIENTLIST_CMD = "cat /tmp/clientlist.json 2>/dev/null"
MESH_NODES_CMD = "nvram get cfg_device_list"
# client names: the ones the owner set in the router UI ("<name>mac>..." per client), and
# networkmap's cache ({mac: {name, vendor, ...}}, names learned from DHCP/mDNS/NetBIOS)
CUSTOM_CLIENTLIST_CMD = "nvram get custom_clientlist"
NETWORKMAP_CMD = "cat /jffs/nmp_cl_json.js 2>/dev/null"
# IP -> MAC for every network (LAN/Guest/IoT dnsmasq instances), used to name AdGuardHome clients
ARP_CMD = "cat /proc/net/arp"
LEASES_CMD = "cat /var/lib/misc/dnsmasq*.leases 2>/dev/null"
# what runs on the router, for the network map's service legend: one "key=value" per line
# (proc_* = process alive, nv_* = firmware setting, cron = amtm add-on jobs, wg = WireGuard
# server peers as "wgpeer=<n>|<name>|<addr>" and "wgdump=<allowed-ips>|<last handshake epoch>")
SERVICES_CMD = (
    "for p in AdGuardHome syslog-ng minidlna smbd avahi-daemon pppd dropbear httpds; do "
    'pidof $p >/dev/null && echo "proc_$p=1" || echo "proc_$p=0"; done; '
    'echo "now=$(date +%s)"; '
    'echo "dnsmasq=$(pidof dnsmasq | wc -w)"; '
    "echo \"ntp_main=$(ps w | grep -c '[n]tp -t')\"; "
    "echo \"ntp_sdn=$(ps w | grep -c '[n]tpd -w -l')\"; "
    'echo "skynet=$(iptables -t raw -S PREROUTING 2>/dev/null | grep -c Skynet)"; '
    "echo \"cron=$(cru l | sed -n 's/.*#\\(.*\\)#$/\\1/p' | tr '\\n' ',')\"; "
    "for k in wgs_enable ntpd_enable le_enable bwdpi_db_enable wrs_protect_enable wrs_mals_enable "
    'enable_samba dms_enable qos_enable qos_type; do echo "nv_$k=$(nvram get $k)"; done; '
    "for i in 1 2 3 4 5 6 7 8 9 10; do n=$(nvram get wgs1_c${i}_name); "
    '[ -n "$n" ] && echo "wgpeer=$i|$n|$(nvram get wgs1_c${i}_addr)|$(nvram get wgs1_c${i}_enable)"; done; '
    "wg show wgs1 dump 2>/dev/null | tail -n +2 | awk '{print \"wgdump=\"$4\"|\"$5}'"
)

COMMAND_GROUPS: dict[str, list[str]] = {
    "system": [
        "nvram get productid",
        "nvram get firmver",
        "nvram get buildno",
        "nvram get extendno",
        MERLIN_CHECK_CMD,
        "nvram get jffs2_scripts",
        "cat /proc/uptime",
        "cat /proc/meminfo",
        "cat /proc/loadavg",
        "cat /sys/class/thermal/thermal_zone0/temp",
        "wl -i eth6 phy_tempsense",
        "wl -i eth7 phy_tempsense",
    ],
    "wan": [
        "nvram get wan0_state_t",
        "nvram get wan0_ipaddr",
        "nvram get wan0_proto",
        "ps w | grep pppd | grep -v grep",
        CONNMON_CMD,
        SPEEDTEST_CMD,
    ],
    "security": [
        SYSLOG_TAIL_CMD,
        FIREWALL_DROPS_CMD,
        SKYNET_SETS_CMD,
        "nvram get fw_log_x",
        "tail -n 200 /jffs/security_recored.log",
        "tail -n 100 /jffs/aae.log",
        "nvram get wrs_protect_enable",
        "nvram get wrs_mals_enable",
    ],
    "wifi": [
        "nvram get wl0_ssid",
        "nvram get wl1_ssid",
        "wl -i eth6 assoclist",
        "wl -i eth7 assoclist",
        MESH_CLIENTLIST_CMD,
        MESH_NODES_CMD,
        CUSTOM_CLIENTLIST_CMD,
        NETWORKMAP_CMD,
        ARP_CMD,
        LEASES_CMD,
    ],
    "services": [
        SERVICES_CMD,
        UPNP_CMD,  # port mappings devices opened via UPnP / NAT-PMP (router_agent/upnp.py)
        IOT_LAN_CMD,  # blocked IoT -> LAN connection attempts (router_agent/iotlan.py)
        SETUP_CMD,  # is what the hook scripts set up still in place? (router_agent/routersetup.py)
    ],
}


class SSHCollector:
    def __init__(self, host: str, port: int = 22, username: str | None = None, password: str | None = None, key_filename: str | None = None, timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, port=self.port, username=self.username, password=self.password, key_filename=self.key_filename, timeout=self.timeout)

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    def run_command(self, cmd: str, timeout: int = 30) -> dict:
        if not self.client:
            self.connect()
        _stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        return {"cmd": cmd, "out": out, "err": err}

    def collect_grouped(self, command_groups: dict[str, list[str]] | None = None) -> dict[str, list[dict]]:
        groups = command_groups or COMMAND_GROUPS
        results: dict[str, list[dict]] = {}
        try:
            for category, commands in groups.items():
                category_results = []
                for c in commands:
                    try:
                        category_results.append(self.run_command(c))
                    except Exception as e:
                        category_results.append({"cmd": c, "out": "", "err": f"exception: {e}"})
                results[category] = category_results
        finally:
            self.close()
        return results
