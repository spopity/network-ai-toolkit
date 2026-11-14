"""IoT devices trying to reach the main LAN. No LLM.

The router's guest-network (SDN) firewall already blocks the IoT network (br54,
192.168.107.x) from opening connections to the LAN (br0): the SDN_IA chain drops
everything br+ -> br+ except LAN -> IoT. Merlin's `logdrop` drops without logging,
so `router/firewall-start` adds a rate-limited LOG rule (prefix "DROP ") in front of
it for br54 -> br0 only. Scribe routes "DROP IN=" lines to skynet-0.log (without
scribe: the syslog), where every 5-minute check reads them:

    Nov 14 11:59:30 RT-AX88U kernel: DROP IN=br54 OUT=br0 MAC=... SRC=192.168.107.30
        DST=192.168.1.10 ... PROTO=TCP SPT=49154 DPT=445 ...

Replies to connections the LAN started are ESTABLISHED and never reach that rule,
and broadcast/multicast discovery isn't forwarded, so every line is a real attempt
by an IoT device to open something on the LAN: worth knowing (compromised camera
scanning, a plug talking to a LAN MQTT broker that should be on the IoT side, ...).

Only lines newer than the cursor (logs/.iot_lan_state.json) are read; the first run
records the cursor silently. Attempts are grouped per IoT device; a (device, target,
port) alerts at most once per `cooldown_hours` (24) as one `iot_lan` router event per
device and check -> Events card, Postgres, Telegram (`iot_lan`). Expected traffic:
`iot_lan.ignore_devices` (IoT side) / `iot_lan.ignore_targets` ("ip", "ip:port" or
"name:port", LAN side). The snapshot's `iot_lan.logging` says whether the LOG rule is
installed (the self-check alerts when it disappears, e.g. after a firewall restart
that skipped firewall-start).
"""
import hashlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_FILE = ".iot_lan_state.json"
DEFAULTS = {"cooldown_hours": 24, "ignore_devices": [], "ignore_targets": []}
MAX_LINES = 2000  # per check; the LOG rule is rate-limited to 10/min, so this is ~3 h of attempts


def command(iot_bridge: str = "br54", lan_bridge: str = "br0") -> str:
    """BusyBox sh: 'logging=<n>' (LOG rules for the path) then the matching log lines."""
    pat = f"DROP IN={iot_bridge} OUT={lan_bridge} "
    return (
        f"echo \"logging=$(iptables -S SDN_IA 2>/dev/null | grep -c -- '-i {iot_bridge} -o {lan_bridge} .*-j LOG')\"; "
        "{ if [ -f /opt/var/log/messages ]; then tail -n 30000 /opt/var/log/skynet-0.log; "
        "else cat /jffs/syslog.log-1 /jffs/syslog.log; fi; } 2>/dev/null "
        f"| grep -F '{pat}' | tail -n {MAX_LINES}"
    )


IOT_LAN_CMD = command()

_LINE = re.compile(r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) .*?DROP IN=(?P<inp>\S+) OUT=(?P<out>\S+) .*?"
                   r"SRC=(?P<src>[\d.]+) DST=(?P<dst>[\d.]+) .*?PROTO=(?P<proto>[A-Z0-9]+)(?:.*? DPT=(?P<dpt>\d+))?")
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def syslog_time(ts: str, now: datetime) -> datetime:
    """'Nov 14 11:59:30' (router local time, no year) -> naive datetime in the most
    recent year that isn't in the future (a December line read in January)."""
    mon, day, hms = ts.split()
    h, m, s = (int(x) for x in hms.split(":"))
    year = now.year - (1 if _MONTHS[mon] > now.month else 0)
    return datetime(year, _MONTHS[mon], int(day), h, m, s)


def parse(out: str, now: datetime) -> tuple[bool | None, list[dict]]:
    """-> (LOG rule installed?, attempts oldest first). Unparseable lines are skipped."""
    logging_on, attempts = None, []
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("logging="):
            v = line.split("=", 1)[1]
            logging_on = int(v) > 0 if v.isdigit() else None
            continue
        m = _LINE.match(line)
        if not m:
            continue
        try:
            t = syslog_time(m["ts"], now)
        except (KeyError, ValueError):
            continue
        attempts.append({"t": t, "src": m["src"], "dst": m["dst"], "proto": m["proto"],
                         "port": int(m["dpt"]) if m["dpt"] else None,
                         "id": hashlib.sha1(line.encode()).hexdigest()[:16]})
    attempts.sort(key=lambda a: a["t"])
    return logging_on, attempts


def _service(proto: str, port: int | None) -> str:
    return f"{proto}/{port}" if port is not None else proto


class IotLanWatch:
    def __init__(self, base: Path, cfg: dict | None = None):
        self.path = Path(base) / STATE_FILE
        self.cfg = {**DEFAULTS, **(cfg if isinstance(cfg, dict) else {})}

    def _load(self) -> dict | None:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None

    def _ignored_target(self, ip: str, name: str, port: int | None) -> bool:
        keys = {ip.lower(), name.lower()}
        if port is not None:
            keys |= {f"{ip}:{port}", f"{name.lower()}:{port}"}
        return bool(keys & {str(x).lower() for x in self.cfg["ignore_targets"] or []})

    def check(self, out: str, namer, now: datetime | None = None) -> dict:
        """Parse the router output, advance the cursor and return the snapshot's `iot_lan`
        summary; `alerts` lists one entry per IoT device to report."""
        now = now or datetime.now(UTC)
        # log times are the router's local time; `now` only picks their year, so the zone doesn't matter
        logging_on, attempts = parse(out, now.replace(tzinfo=None))
        state = self._load()
        baseline = state is None
        state = state or {}

        cur_t = state.get("cursor_t")
        cur_ids = set(state.get("cursor_ids") or [])
        if cur_t:
            cur = datetime.fromisoformat(cur_t)
            new = [a for a in attempts if a["t"] > cur or (a["t"] == cur and a["id"] not in cur_ids)]
        else:
            new = attempts
        if attempts:
            last_t = attempts[-1]["t"]
            ids = {a["id"] for a in attempts if a["t"] == last_t}
            if cur_t and datetime.fromisoformat(cur_t) == last_t:
                ids |= cur_ids
            state["cursor_t"], state["cursor_ids"] = last_t.isoformat(), sorted(ids)

        # group this check's new attempts per IoT device and LAN target
        ignore_dev = {str(x).lower() for x in self.cfg["ignore_devices"] or []}
        groups: dict[tuple, dict] = {}
        for a in [] if baseline else new:
            src, dst = namer(a["src"]), namer(a["dst"])
            if {src["device"].lower(), a["src"], (src["mac"] or "").lower()} & ignore_dev:
                continue
            if self._ignored_target(a["dst"], dst["device"], a["port"]):
                continue
            k = (src["key"], a["dst"], a["proto"], a["port"])
            g = groups.setdefault(k, {"device": src["device"], "ip": a["src"], "mac": src["mac"], "key": src["key"],
                                      "target": dst["device"], "target_ip": a["dst"],
                                      "service": _service(a["proto"], a["port"]), "count": 0})
            g["count"] += 1
            g["last"] = a["t"].isoformat(sep=" ")  # router local time

        alerted = state.setdefault("alerted", {})
        cooldown = timedelta(hours=self.cfg["cooldown_hours"])
        per_device: dict[str, dict] = {}
        for k, g in groups.items():
            ak = "|".join(str(x) for x in k)
            last = alerted.get(ak)
            if last and now - datetime.fromisoformat(last) < cooldown:
                continue
            alerted[ak] = now.isoformat(timespec="seconds")
            d = per_device.setdefault(g["key"], {"device": g["device"], "ip": g["ip"], "mac": g["mac"],
                                                 "targets": [], "count": 0})
            d["targets"].append(f"{g['target']} ({g['target_ip']}) {g['service']} ×{g['count']}"
                                if g["target"] != g["target_ip"] else f"{g['target_ip']} {g['service']} ×{g['count']}")
            d["count"] += g["count"]
        # forget alert times past the cooldown so the file stays small
        state["alerted"] = {k: v for k, v in alerted.items() if now - datetime.fromisoformat(v) < cooldown}
        self.path.write_text(json.dumps(state, indent=1))

        top = sorted(groups.values(), key=lambda g: -g["count"])[:20]
        return {
            "logging": logging_on,
            "new_attempts": 0 if baseline else len(new),
            "attempts": [{k: g[k] for k in ("device", "ip", "target", "target_ip", "service", "count", "last")}
                         for g in top],
            "alerts": list(per_device.values()),
            "baseline": baseline or None,
        }


def check_and_record(base: Path, cfg: dict | None, out: str, namer) -> dict:
    """IotLanWatch.check() plus one `iot_lan` router event per IoT device to report."""
    from .events import append_router_event

    result = IotLanWatch(base, cfg).check(out, namer)
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    for d in result["alerts"]:
        append_router_event(base, {"ts": ts, "event": "iot_lan", "device": d["device"], "ip": d["ip"],
                                   "mac": d["mac"], "count": d["count"], "targets": d["targets"][:10]})
    return result
