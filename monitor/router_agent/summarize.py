"""Compress raw router logs into small structured summaries before they reach an LLM.

Each log line is reduced to a *template* -- the message with its variable parts
(IPs, MACs, numbers, hashes, JSON blobs) replaced by placeholders -- and lines
sharing a template are counted together. A few hundred lines typically collapse
into 10-20 templates, each with a count, first/last time, one example and a
sample of the distinct IPs/MACs it mentioned. Templates whose wording suggests a
problem (fail, error, timeout, down...) are flagged and sorted first so they
survive the top-N cut.
"""
import re
from collections import OrderedDict
from typing import Dict, Iterable, List

# "Oct 11 20:05:09 proc[123]: msg" (syslogd) / "Oct 11 20:05:09 RT-AX88U proc[123]: msg" (syslog-ng/scribe)
_SYSLOG_LINE = re.compile(
    r"^(?P<ts>\w{3} [ \d]\d \d\d:\d\d:\d\d) (?:[\w.-]+ (?=[^:\s]+(?:\[\d+\])?: ))?(?P<proc>[^:\[\s]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def _ts_key(ts: str):
    # "Oct 11 20:05:09" -> sortable (month, day, time); logs here never span a year boundary in practice
    return (_MONTHS.get(ts[:3], 0), int(ts[4:6]), ts[7:])
# "Sun Oct 11 12:58:55 2026  [info] [mastiff][2961]][fn:(954)] msg"  (security_recored.log / aae.log)
_ASUS_LINE = re.compile(
    r"^\w{3} (?P<ts>\w{3} [ \d]\d \d\d:\d\d:\d\d) \d{4}\s+\[(?P<level>\w+)\]\s*(?:\[(?P<proc>[\w-]+)\](?:\[\d+\]\])?)?(?:\[[\w:() ]*\])?\s*(?P<msg>.*)$"
)

_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_JSON = re.compile(r"\{.*\}")
_HEX = re.compile(r"\b0x[0-9A-Fa-f]+\b")
_TOKEN = re.compile(r"\b(?=[A-Za-z0-9+/=_-]*\d)[A-Za-z0-9+/=_-]{16,}\b")  # hashes, key fingerprints, ids
_NUM = re.compile(r"\d+")

NOTABLE = re.compile(
    r"(?i)\b(err(or)?|fail(ed|ure)?|denied|invalid|time[d ]?out|timeout|(?<!shutting )down|disconnect\w*|lost|"
    r"unreachable|refused|warn\w*|critical|panic|oops|segfault|radar|attack|blocked|blocking|malware|brute|"
    r"reject\w*|lcp|padi|padt|no response|reset)\b"
)


# Broadcom daemons prefix messages with their C function: "wlceventd_proc_event(645): wl0.1: ..."
_FUNC_PREFIX = re.compile(r"^\w+\(\d+\):\s*")


def _template(msg: str) -> str:
    t = _JSON.sub("{…}", msg)
    t = _MAC.sub("<MAC>", t)
    t = _IP.sub("<IP>", t)
    t = _HEX.sub("<HEX>", t)
    t = _TOKEN.sub("<ID>", t)
    t = _NUM.sub("N", t)
    return t[:140]


def _parse(line: str):
    m = _SYSLOG_LINE.match(line)
    if m:
        return m["ts"], m["proc"], m["msg"]
    m = _ASUS_LINE.match(line)
    if m:
        return m["ts"], m["proc"] or m["level"], m["msg"]
    return None, None, line


def summarize_lines(lines: Iterable[str], top: int = 15, example_len: int = 140, values: int = 4) -> Dict:
    return render_groups(group_lines(lines, example_len, values), top=top)


def group_lines(lines: Iterable[str], example_len: int = 140, values: int = 4) -> Dict:
    """Template-count lines without truncating: {"lines", "window", "groups": [...]}.
    Group lists from successive log windows can be merged (merge_groups) and rendered later."""
    groups: "OrderedDict[tuple, Dict]" = OrderedDict()
    total = 0
    first_ts = last_ts = None
    for raw in lines:
        raw = raw.rstrip()
        if not raw.strip():
            continue
        total += 1
        ts, proc, msg = _parse(raw)
        msg = _FUNC_PREFIX.sub("", msg)
        if ts:  # input may be several files concatenated, so track min/max, not first/last
            if first_ts is None or _ts_key(ts) < _ts_key(first_ts):
                first_ts = ts
            if last_ts is None or _ts_key(ts) > _ts_key(last_ts):
                last_ts = ts
        key = (proc or "-", _template(msg))
        g = groups.get(key)
        if g is None:
            ex = _JSON.sub("{…}", msg)
            g = groups[key] = {
                "source": proc or "-",
                "template": key[1],
                "count": 0,
                "first": ts,
                "last": ts,
                "example": ex[:example_len] + ("…" if len(ex) > example_len else ""),
                "notable": bool(NOTABLE.search(msg)),  # dropped from the output when False
                "_vals": OrderedDict(),
            }
        g["count"] += 1
        g["last"] = ts or g["last"]
        for v in _IP.findall(msg) + _MAC.findall(msg):
            if len(g["_vals"]) < values:
                g["_vals"][v] = None

    out = []
    for g in groups.values():
        g = dict(g)
        g["values"] = list(g.pop("_vals"))
        out.append(g)
    return {"lines": total, "window": [first_ts, last_ts] if first_ts else None, "groups": out}


def _earlier(a, b):
    if a is None or b is None:
        return a or b
    return a if _ts_key(a) <= _ts_key(b) else b


def _later(a, b):
    if a is None or b is None:
        return a or b
    return a if _ts_key(a) >= _ts_key(b) else b


def merge_groups(acc: Dict, new: Dict, values: int = 4, max_groups: int = 600) -> Dict:
    """Fold one group_lines() result into an accumulated one (same shape)."""
    by_key = {(g["source"], g["template"]): g for g in acc.get("groups", [])}
    for g in new.get("groups", []):
        cur = by_key.get((g["source"], g["template"]))
        if cur is None:
            by_key[(g["source"], g["template"])] = dict(g)
            continue
        cur["count"] += g["count"]
        cur["first"] = _earlier(cur["first"], g["first"])
        cur["last"] = _later(cur["last"], g["last"])
        cur["values"] = list(dict.fromkeys(cur["values"] + g["values"]))[:values]
    merged = sorted(by_key.values(), key=lambda g: (not g["notable"], -g["count"]))
    if len(merged) > max_groups:  # bound the rollup: drop the rarest non-notable templates
        merged = merged[:max_groups]
    aw, nw = acc.get("window"), new.get("window")
    window = [_earlier(aw[0], nw[0]), _later(aw[1], nw[1])] if aw and nw else (aw or nw)
    return {"lines": acc.get("lines", 0) + new.get("lines", 0), "window": window, "groups": merged}


def render_groups(grouped: Dict, top: int = 15) -> Dict:
    """Ranked, truncated LLM-ready summary of a group_lines()/merge_groups() result."""
    groups = grouped.get("groups", [])
    ranked = sorted(groups, key=lambda g: (not g["notable"], -g["count"]))
    notable_lines = sum(g["count"] for g in groups if g["notable"])
    out: List[Dict] = []
    for g in ranked[:top]:
        g = dict(g)
        vals = g.pop("values")
        if not g["notable"]:
            g.pop("notable")
        if vals:
            g["values"] = vals
        # keep one wording: the concrete example for one-offs, the template (+ values) for repeats
        if g["count"] == 1:
            g["at"] = g.pop("first")
            g.pop("last")
            g.pop("template")
            g["message"] = g.pop("example")
            g.pop("count")
            g.pop("values", None)
        else:
            g.pop("example")
            if g["first"] == g["last"]:
                g.pop("last")
        out.append(g)
    rest = ranked[top:]
    return {
        "lines": grouped.get("lines", 0),
        "window": grouped.get("window"),
        "distinct_messages": len(groups),
        "notable_lines": notable_lines,
        "messages": out,
        **({"omitted": {"messages": len(rest), "lines": sum(g["count"] for g in rest)}} if rest else {}),
    }


def summarize_text(text: str, **kw) -> Dict:
    return summarize_lines((text or "").splitlines(), **kw)


# Which LLM section a syslog message belongs to, by the process that logged it.
WIFI_SOURCES = {"roamast", "wlceventd", "hostapd", "eapd", "acsd", "acsd2", "wpa_supplicant", "bsd", "cfg_server"}
SECURITY_SOURCES = {"dropbear", "sshd", "HTTPD", "httpd", "LOGIN", "BWDPI", "bwdpi", "AiProtection", "Remote_access",
                    "custom_script", "openvpn", "ovpn-server1", "ovpn-server2", "charon", "wireguard"}


def split_by_section(summary: Dict, per_section: int = 10) -> Dict[str, Dict]:
    """Split a syslog summary's messages into {"security", "wifi", "system"} sub-summaries."""
    out = {name: [] for name in ("security", "wifi", "system")}
    for m in summary.get("messages", []):
        src = m.get("source", "")
        name = "wifi" if src in WIFI_SOURCES else "security" if src in SECURITY_SOURCES else "system"
        out[name].append(m)
    return {
        name: {
            "window": summary.get("window"),
            "messages": msgs[:per_section],
            **({"omitted_messages": len(msgs) - per_section} if len(msgs) > per_section else {}),
        }
        for name, msgs in out.items()
    }
