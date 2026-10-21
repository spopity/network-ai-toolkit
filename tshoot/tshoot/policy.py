"""Command safety policy for Tshoot.

Every command the agent wants to run on the router is classified here, never
by the LLM itself:

- ``read``    -- known diagnostic command; runs automatically.
- ``write``   -- anything that changes state, or anything not positively
                 recognised as read-only; needs explicit user approval.
- ``blocked`` -- can brick the router or wipe its config; never runs.
- ``refused`` -- would be read-only but is malformed for unattended use
                 (e.g. ``ping`` without ``-c``); the agent gets the reason back.

The read side is a strict allowlist: an unknown binary or subcommand falls
through to ``write`` so a human sees it before it runs.
"""
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional

READ, WRITE, BLOCKED, REFUSED = "read", "write", "blocked", "refused"


@dataclass
class Verdict:
    kind: str
    reason: str = ""
    warnings: List[str] = field(default_factory=list)
    risk: str = "low"  # low | medium | high (only meaningful for write)
    opaque: bool = False  # write only because the syntax can't be verified (substitution, redirection...)


# ---------------------------------------------------------------- blocked

# Checked against the raw command text, before any parsing.
_BLOCKED_RAW = [
    (r"\bnvram\s+(erase|restore|loadfile)\b", "wipes or replaces the whole NVRAM (factory reset)"),
    (r"\b(mtd|mtd-write|mtd-erase|mtd-erase2|mtd_erase|mtd_write|mtd-unlock)\b", "raw flash access"),
    (r"\b(flash_erase\w*|flashcp|hnd-write|hnd-erase|bcm_flasher|nandwrite|ubiformat|ubidetach|ubirmvol)\b", "raw flash access"),
    (r"\bmkfs(\.\w+)?\b", "formats a filesystem"),
    (r"jffs2?_format", "formats /jffs (deletes scripts and the SSH key Tshoot depends on)"),
    (r"restore_defaults", "factory reset"),
    (r"\bservice\s+\S*(restore|factory|upgrade|firmware)\S*", "factory reset / firmware upgrade"),
    (r"\b(rc_service|rc)\b.*\b(restore|upgrade)\b", "factory reset / firmware upgrade"),
    (r"\b(webs_upgrade|firmware_upgrade|fwupgrade|start_upgrade)\b", "firmware upgrade"),
    (r">\s*/dev/(?!null\b)", "writes to a raw device"),
    (r":\(\)\s*\{", "fork bomb"),
]

# Command words that are never allowed regardless of arguments.
_BLOCKED_CMDS = {
    "dd": "raw block copy (can overwrite flash)",
    "halt": "powers the router off (needs physical access to recover)",
    "poweroff": "powers the router off (needs physical access to recover)",
}

_RM_PROTECTED = re.compile(r"^/(\*|jffs/?\*?|jffs/scripts/?\*?|jffs/\.ssh/?\*?|etc/?|bin/?|sbin/?|usr/?|lib/?|)$")


# ---------------------------------------------------------------- disruption hints

_WARNINGS = [
    (r"\breboot\b", "high",
     "The router reboots: all networking is down for ~2-3 minutes and Tshoot loses the router until it is back."),
    (r"\bservice\s+(restart|stop)_(wan\w*|net\w*|allnet\w*)|\bifconfig\s+ppp\d+\s+down|\bkillall\s+pppd\b", "high",
     "Internet (WAN) drops briefly. Tshoot needs the internet to reach Gemini, so it may go quiet until WAN is back."),
    (r"\bservice\s+(restart|stop)_(lan|net_and_phy|allnet)\b|\bifconfig\s+br\d+\b", "high",
     "The LAN bridge restarts: every wired and wireless client (and this dashboard's SSH link) briefly drops."),
    (r"\bservice\s+(restart|stop)_(wireless|wl\w*)|\bwl\b.*\b(down|radio\s+off)\b", "medium",
     "Wi-Fi restarts: wireless clients disconnect and reconnect."),
    (r"\bservice\s+(restart|stop)_(sshd|dropbear)|\bkillall\s+dropbear\b|\bsshd_(enable|port)\b", "high",
     "Touches the SSH server Tshoot (and the analyzer) uses -- risk of locking yourself out of CLI access."),
    (r"\bservice\s+(restart|stop)_(dnsmasq|firewall|httpd)\b", "medium",
     "Briefly interrupts DNS/DHCP, firewall or the web UI."),
    (r"\b(iptables|ip6tables)\b.*\s-(F|X)\b", "high",
     "Flushes firewall rules -- the router may be exposed to the internet until the firewall restarts."),
    (r"/jffs/(scripts|configs)\b", "high",
     "Changes a Merlin custom script/config under /jffs: it re-runs on every boot or service restart, so a "
     "mistake persists. /jffs/scripts/services-start and wan-event belong to the network-ai monitor."),
    (r"\bnvram\s+set\s+jffs2_(scripts|enable)=", "high",
     "Toggles /jffs or custom-script support: disables the monitor's SSH-key persistence and wan-event hook."),
    (r"\bopkg\s+(install|remove|upgrade)\b", "medium",
     "Installs/removes Entware packages (lives on USB storage, may start new services)."),
    (r"\bnvram\s+commit\b", "medium",
     "Makes NVRAM changes permanent (they survive a reboot)."),
    (r"\brm\b", "medium", "Deletes files."),
]


# ---------------------------------------------------------------- read allowlist

_TEXT_TOOLS = {
    "cat", "tail", "head", "grep", "egrep", "fgrep", "wc", "sort", "uniq", "cut", "tr",
    "echo", "printf", "ls", "stat", "md5sum", "sha256sum", "strings", "hexdump", "od",
    "basename", "dirname", "true", "column",
}
_SIMPLE_READ = {
    "ps", "free", "df", "du", "uptime", "uname", "date", "dmesg", "netstat", "pidof", "which",
    "id", "whoami", "hostname", "lsmod", "nslookup", "traceroute", "traceroute6",
    "iptables-save", "ip6tables-save", "env", "printenv", "pwd", "cpuinfo", "lsusb", "robocfg",
}


def _read_if(cond: bool, why: str = "") -> Verdict:
    return Verdict(READ) if cond else Verdict(WRITE, why or "state-changing arguments")


def _check_ip(args: List[str]) -> Verdict:
    words = [a for a in args if not a.startswith("-")]
    if not words:
        return Verdict(READ)
    obj = words[0]
    if obj in ("monitor",):
        return Verdict(REFUSED, "`ip monitor` never exits; use a one-shot `ip ... show` instead")
    if len(words) > 1 and words[1] in {
        "add", "del", "delete", "change", "replace", "flush", "set", "append", "prepend",
        "save", "restore", "update", "up", "down",
    }:
        return Verdict(WRITE, f"`ip {obj} {words[1]}` changes network state")
    return Verdict(READ)


_IPT_READ_LONG = {"--list", "--list-rules", "--numeric", "--verbose", "--exact", "--line-numbers", "--table"}


def _check_iptables(args: List[str]) -> Verdict:
    listing = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-t", "--table"):
            i += 2
            continue
        if a.startswith("--"):
            if a not in _IPT_READ_LONG:
                return Verdict(WRITE, "iptables rule change")
            listing |= a in ("--list", "--list-rules")
        elif a.startswith("-"):
            letters = set(a[1:])
            if not letters <= set("LSnvx"):
                return Verdict(WRITE, "iptables rule change")
            listing |= bool(letters & {"L", "S"})
        i += 1
    return _read_if(listing, "iptables without -L/-S modifies rules")


_NVRAM_READ = {"get", "show", "getall", "dump"}


def _check_nvram(args: List[str]) -> Verdict:
    if not args:
        return Verdict(READ)
    return _read_if(args[0] in _NVRAM_READ, f"`nvram {args[0]}` changes NVRAM")


# wl subcommands that only read, whatever their arguments.
_WL_READ_ANY = {
    "assoclist", "authe_sta_list", "autho_sta_list", "sta_info", "rssi", "status", "chanspecs",
    "counters", "chanim_stats", "chan_info", "dump", "ver", "revinfo", "cap", "bw_cap",
    "scanresults", "dfs_status", "dfs_status_all", "pktq_stats", "phy_tempsense", "noise",
    "isup", "bssid", "curpower", "txpwr_target_max", "phy_rssi_ant", "wme_counters",
    "if_counters", "bs_data", "cca_get_stats", "dump_txbf", "ssid_status", "per_chan_info",
}
# wl subcommands that read when given no value (with a value they set it).
_WL_READ_NOARGS = {
    "channel", "chanspec", "ssid", "country", "band", "txpwr1", "rate", "nrate", "ap", "infra",
    "spect", "maclist", "macmode", "radio", "bi", "dtim", "txchain", "rxchain", "wme",
    "frameburst", "ampdu", "mimo_bw_cap", "obss_coex", "he", "rxchain_pwrsave_enable",
    "radarthrs", "mode", "phytype", "interference", "interference_override", "roam_trigger",
    "assoc_info", "amsdu", "mu_features", "txbf", "txbf_bfr_cap", "txbf_bfe_cap", "pm", "mbss",
    "bss_maxassoc", "maxassoc", "wds", "lazywds", "keys", "wpa_auth", "wsec", "auth",
}


def _check_wl(args: List[str]) -> Verdict:
    rest = list(args)
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in ("-i", "-a") else rest[1:]
    if not rest:
        return Verdict(READ)
    sub, extra = rest[0], rest[1:]
    if sub in _WL_READ_ANY:
        return Verdict(READ)
    if sub in _WL_READ_NOARGS and not extra:
        return Verdict(READ)
    if sub == "scan":
        return Verdict(WRITE, "`wl scan` briefly takes the radio off-channel")
    return Verdict(WRITE, f"`wl {sub}` with arguments changes radio settings")


def _check_ping(args: List[str]) -> Verdict:
    if "-c" not in args and not any(re.fullmatch(r"-c\d+", a) for a in args):
        return Verdict(REFUSED, "ping needs a count (e.g. `ping -c 4 1.1.1.1`) or it never exits")
    return Verdict(READ)


def _check_top(args: List[str]) -> Verdict:
    flags = "".join(a[1:] for a in args if a.startswith("-"))
    if "b" not in flags or "n" not in flags:
        return Verdict(REFUSED, "top must run in batch mode with an iteration count, e.g. `top -b -n 1`")
    return Verdict(READ)


def _check_tcpdump(args: List[str]) -> Verdict:
    if any(a == "-w" or a.startswith("-w") for a in args):
        return Verdict(WRITE, "tcpdump -w writes a capture file")
    if "-c" not in args and not any(re.fullmatch(r"-c\d+", a) for a in args):
        return Verdict(REFUSED, "tcpdump needs a packet count, e.g. `tcpdump -n -c 50 -i ppp0`")
    return Verdict(READ)


def _check_find(args: List[str]) -> Verdict:
    bad = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls"}
    return _read_if(not (bad & set(args)), "find with -exec/-delete")


def _check_awk(args: List[str]) -> Verdict:
    prog = " ".join(a for a in args if not a.startswith("-"))
    return _read_if(not re.search(r"system\s*\(|\|\s*\"|>\s*\"|getline", prog), "awk program runs commands or writes files")


def _check_sed(args: List[str]) -> Verdict:
    if any(a.startswith("-i") or a == "--in-place" for a in args):
        return Verdict(WRITE, "sed -i edits files in place")
    for a in args:
        if a.startswith("-"):
            continue
        # sed's `e` (execute) and `w` (write file) commands/flags
        if re.search(r"(^|[;{}\s])[ew]\s|/[gpIi0-9]*[ew](\s|;|$)", a):
            return Verdict(WRITE, "sed script executes commands or writes files")
    return Verdict(READ)


def _check_arp(args: List[str]) -> Verdict:
    return _read_if(all(a in ("-a", "-n", "-an", "-na", "-v") or not a.startswith("-") for a in args)
                    and not any(a in ("-d", "-s") for a in args), "arp table change")


def _check_brctl(args: List[str]) -> Verdict:
    return _read_if(not args or args[0] in ("show", "showmacs", "showstp"), "bridge change")


def _check_cru(args: List[str]) -> Verdict:
    return _read_if(args[:1] == ["l"], "cron change")


def _check_ifconfig(args: List[str]) -> Verdict:
    opts = [a for a in args if a != "-a"]
    return _read_if(len(opts) <= 1, "ifconfig with arguments changes an interface")


def _check_route(args: List[str]) -> Verdict:
    return _read_if(all(a in ("-n", "-e", "-ee", "-A", "inet", "inet6") for a in args), "routing table change")


def _check_mount(args: List[str]) -> Verdict:
    return _read_if(not args, "mount with arguments")


def _check_sleep(args: List[str]) -> Verdict:
    try:
        ok = len(args) == 1 and float(args[0]) <= 10
    except ValueError:
        ok = False
    return Verdict(READ) if ok else Verdict(REFUSED, "sleep is limited to 10 seconds")


def _check_fc(args: List[str]) -> Verdict:
    return _read_if(args[:1] == ["status"], "flow cache change")


def _check_ethctl(args: List[str]) -> Verdict:
    return _read_if(len(args) == 2 and args[1] in ("media-type", "phy-power"), "ethernet PHY change")


def _check_arping(args: List[str]) -> Verdict:
    return _check_ping(args)


def _check_conntrack(args: List[str]) -> Verdict:
    if any(a in ("-E", "--event") for a in args):
        return Verdict(REFUSED, "`conntrack -E` never exits; use `conntrack -L` or `conntrack -S`")
    flags = [a for a in args if a.startswith("-")]
    ok = bool(flags) and all(a in ("-L", "--dump", "-S", "--stats", "-C", "--count", "-p", "-s", "-d",
                                   "--sport", "--dport", "-f", "-o", "--orig-src", "--orig-dst") for a in flags)
    return _read_if(ok, "conntrack with -D/-F/-U changes connection tracking")


def _check_ipset(args: List[str]) -> Verdict:
    return _read_if(bool(args) and args[0] in ("list", "-L", "save", "-S", "test", "-T", "-n", "-t", "version"),
                    "ipset change")


def _check_wg(args: List[str]) -> Verdict:
    return _read_if(not args or args[0] in ("show", "showconf"), "WireGuard change")


def _check_sqlite3(args: List[str]) -> Verdict:
    # read-only: a single SELECT (or .tables/.schema) passed on the command line
    sql, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-cmd", "--cmd", "-init", "--init"):
            return Verdict(WRITE, f"sqlite3 {a} runs extra commands")
        if a in ("-separator", "-newline", "-nullvalue", "--separator", "--newline", "--nullvalue"):
            i += 2
            continue
        if not a.startswith("-") and not a.endswith(".db"):
            sql.append(a)
        i += 1
    if len(sql) != 1:
        return Verdict(WRITE, "sqlite3 without a single inline query")
    q = sql[0].strip().rstrip(";")
    if re.match(r"(?is)^\.(tables|schema)\b[^;]*$", q):
        return Verdict(READ)
    stmts = [x for x in q.split(";") if x.strip()]
    ok = all(re.match(r"(?is)^\s*select\b", x) for x in stmts) and not re.search(
        r"(?i)\b(insert|update|delete|drop|alter|create|attach|replace|pragma|vacuum)\b|load_extension|writefile", q)
    return _read_if(ok, "sqlite3 statement that isn't a plain SELECT")


def _check_opkg(args: List[str]) -> Verdict:
    words = [a for a in args if not a.startswith("-")]
    return _read_if(bool(words) and words[0] in (
        "list", "list-installed", "list-upgradable", "info", "status", "files", "search", "find",
        "whatprovides", "depends", "print-architecture",
    ), "opkg package change")


# Merlin add-on / amtm menus are interactive TUIs: they'd hang until the SSH timeout.
_INTERACTIVE = {
    "amtm": "`amtm` is an interactive menu; use the web UI or ask the user to run it from a terminal",
    "vi": "interactive editor",
    "nano": "interactive editor",
    "less": "interactive pager; use `cat`/`tail`/`head`",
    "more": "interactive pager; use `cat`/`tail`/`head`",
}


_READ_CHECKS = {
    "ip": _check_ip,
    "iptables": _check_iptables,
    "ip6tables": _check_iptables,
    "nvram": _check_nvram,
    "wl": _check_wl,
    "ping": _check_ping,
    "ping6": _check_ping,
    "arping": _check_arping,
    "top": _check_top,
    "tcpdump": _check_tcpdump,
    "find": _check_find,
    "awk": _check_awk,
    "sed": _check_sed,
    "arp": _check_arp,
    "brctl": _check_brctl,
    "cru": _check_cru,
    "ifconfig": _check_ifconfig,
    "route": _check_route,
    "mount": _check_mount,
    "sleep": _check_sleep,
    "fc": _check_fc,
    "ethctl": _check_ethctl,
    "conntrack": _check_conntrack,
    "ipset": _check_ipset,
    "wg": _check_wg,
    "opkg": _check_opkg,
    "sqlite3": _check_sqlite3,
}


# ---------------------------------------------------------------- parsing

_SEPARATORS = {"|", "||", "&&", ";", "\n"}
_SAFE_REDIRECTS = re.compile(r"\s*(\d?>>?\s*/dev/null|\d?>&\d|<\s*/dev/null)")


def _split_segments(command: str) -> Optional[List[List[str]]]:
    """Split a shell command into pipeline/list segments of argv tokens.

    Returns None if it can't be parsed confidently (caller treats as write).
    """
    cleaned = _SAFE_REDIRECTS.sub(" ", command)
    lexer = shlex.shlex(cleaned, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    segments, cur = [], []
    for t in tokens:
        if t in _SEPARATORS:
            segments.append(cur)
            cur = []
        elif t and set(t) <= set(";&|<>"):
            return None  # '>', '>>', '&', '<' and other unexpected operators
        else:
            cur.append(t)
    segments.append(cur)
    return [s for s in segments if s]


def _segment_verdict(argv: List[str]) -> Verdict:
    # leading VAR=value assignments
    while argv and re.fullmatch(r"[A-Za-z_]\w*=.*", argv[0]):
        argv = argv[1:]
    if not argv:
        return Verdict(WRITE, "bare variable assignment")
    name, args = argv[0].rsplit("/", 1)[-1], argv[1:]

    if name in _BLOCKED_CMDS:
        return Verdict(BLOCKED, _BLOCKED_CMDS[name])
    if name == "rm" and any(a.startswith("-") and "r" in a.lower() for a in args):
        targets = [a for a in args if not a.startswith("-")]
        if any(_RM_PROTECTED.match(t.rstrip() or "/") for t in targets):
            return Verdict(BLOCKED, "recursive delete of a system or /jffs directory")
    if name in _INTERACTIVE:
        return Verdict(REFUSED, _INTERACTIVE[name])
    if name in _TEXT_TOOLS:
        return Verdict(READ)
    if name in _SIMPLE_READ:
        return Verdict(READ)
    check = _READ_CHECKS.get(name)
    if check:
        return check(args)
    return Verdict(WRITE, f"`{name}` is not on the read-only allowlist")


def classify(command: str) -> Verdict:
    cmd = (command or "").strip()
    if not cmd:
        return Verdict(REFUSED, "empty command")
    if len(cmd) > 2000:
        return Verdict(REFUSED, "command too long")

    for pattern, why in _BLOCKED_RAW:
        if re.search(pattern, cmd, re.IGNORECASE):
            # a pure text search (grep/cat/tail...) mentioning a scary word is fine
            segs = _split_segments(cmd)
            if segs and all(s[0].rsplit("/", 1)[-1] in _TEXT_TOOLS for s in segs) and ">" not in pattern:
                continue
            return Verdict(BLOCKED, why)

    if re.search(r"`|\$\(|<\(|<<", cmd):
        verdict = Verdict(WRITE, "uses command substitution / here-doc, can't be verified as read-only", opaque=True)
    else:
        segs = _split_segments(cmd)
        if segs is None:
            verdict = Verdict(WRITE, "uses output redirection, background jobs or unparsable syntax", opaque=True)
        else:
            verdicts = [_segment_verdict(s) for s in segs]
            for kind in (BLOCKED, REFUSED, WRITE):
                hit = next((v for v in verdicts if v.kind == kind), None)
                if hit:
                    verdict = hit
                    break
            else:
                verdict = Verdict(READ)

    if verdict.kind == WRITE:
        verdict.risk = "low"
        rank = {"low": 0, "medium": 1, "high": 2}
        for pattern, risk, text in _WARNINGS:
            if re.search(pattern, cmd):
                verdict.warnings.append(text)
                if rank[risk] > rank[verdict.risk]:
                    verdict.risk = risk
    return verdict
