"""Push notifications to a Telegram bot (no SMTP needed, one HTTPS POST per message).

What is sent (each can be switched off with `notify.events` in config.yml):

  wan         internet back after an outage the watchdog measured (with downtime and
              whether it auto-restarted the WAN). Sent on recovery: while the WAN is
              down Telegram is unreachable anyway.
  dns         DNS health changes (dns_ok / dns_unfiltered / dns_down router events)
  new_device  a wifi client seen for the first time
  firmware    the router's scheduled firmware check found a new release
              (router/update-notification posts it to /api/router-event)
  monitor     network-ai itself is unhealthy / healthy again: stale checks, failed daily
              analysis, old backup, Postgres/dashboard down, low disk, watchdog dead
              (router_agent/selfcheck.py), and the result of every fix tried for it
              (`remedy` events, router_agent/remedy.py). With `notify.telegram.interactive:
              true` problem alerts carry [Fix] / [Troubleshoot] / [Mute 24 h] buttons that
              router_agent/telegram_bot.py answers; a muted check (logs/.notify_mute.json)
              is still recorded and auto-fixed, just not sent
  anomaly     an appliance behaves unusually: many new sites in an hour or an upload far
              above its own baseline (router_agent/anomaly.py; phones/computers skipped)
  upnp        a device opened a port to the internet via UPnP for the first time
              (router_agent/upnp.py; known devices re-opening ports stay quiet)
  vpn         remote access: a WireGuard peer added on the router, a peer connecting from
              a network (ISP/ASN) it never used, the DDNS name not matching the WAN IP
              (router_agent/vpn.py)
  vpn_sessions  every WireGuard session start (source IP, network, country) and end
              (duration, traffic); opt-in
  daily       the daily LLM briefing's one-line overall summary (opt-in: not in the default list)
  report      the weekly / monthly network report: key numbers + AI summary (opt-in;
              router_agent/report.py)

Best-effort like the Postgres archive: sending never raises, so a Telegram outage
can't fail a check, the watchdog or an API call. Messages that could not be
delivered because of the network (or a Telegram 5xx/429) are queued in
logs/.notify_queue.jsonl and delivered, marked as delayed, by the next send or
flush() -- the watchdog flushes every loop, so the queue empties as soon as the
WAN is back. Messages with a permanent error (bad token or chat id) are dropped.

The bot token is a secret: TELEGRAM_BOT_TOKEN in .env. The chat id goes in config.yml.

  python -m router_agent.notify --config config.yml --chat-id   # find your chat id
  python -m router_agent.notify --config config.yml --test      # send a test message
  python -m router_agent.notify --config config.yml --send TEXT # send any text (deploy.sh)
"""
import argparse
import fcntl
import html
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

API = "https://api.telegram.org/bot{token}/{method}"
QUEUE_FILE = ".notify_queue.jsonl"
MUTE_FILE = ".notify_mute.json"   # {check: until-ISO}, written by the Telegram bot
LOCK_FILE = ".notify.lock"
QUEUE_MAX = 50                       # oldest dropped beyond this
QUEUE_MAX_AGE = timedelta(days=2)    # older undelivered messages are dropped, not sent
TIMEOUT = 10
ALL_EVENTS = ("wan", "dns", "new_device", "firmware", "upnp", "monitor", "anomaly", "iot_lan", "vpn", "vpn_sessions",
              "daily", "report")
DEFAULT_EVENTS = ("wan", "dns", "new_device", "firmware", "upnp", "monitor", "anomaly", "iot_lan", "vpn")  # major only

_notifier = None  # set by configure(); every hook is a no-op without it


class Notifier:
    def __init__(self, token: str, chat_id: str, log_dir: Path, events=DEFAULT_EVENTS,
                 tz: str | None = None, dashboard_url: str | None = None,
                 wan_min_downtime_seconds: float = 60, interactive: bool = False):
        self.token = token
        self.chat_id = str(chat_id)
        self.base = Path(log_dir)
        self.events = set(events)
        self.tz = ZoneInfo(tz) if tz else None
        self.dashboard_url = (dashboard_url or "").rstrip("/") or None
        self.wan_min_downtime = wan_min_downtime_seconds
        self.interactive = interactive  # buttons only make sense while telegram_bot.py answers them

    @classmethod
    def from_config(cls, cfg: dict, log_dir) -> "Notifier | None":
        ncfg = (cfg or {}).get("notify") or {}
        tg = ncfg.get("telegram") or {}
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not tg.get("chat_id") or not token:
            return None
        events = ncfg.get("events") or DEFAULT_EVENTS
        unknown = set(events) - set(ALL_EVENTS)
        if unknown:
            print(f"warning: unknown notify.events {sorted(unknown)} ignored", file=sys.stderr)
        return cls(token, tg["chat_id"], log_dir, events=events, tz=ncfg.get("timezone"),
                   dashboard_url=ncfg.get("dashboard_url"),
                   wan_min_downtime_seconds=ncfg.get("wan_min_downtime_seconds", 60),
                   interactive=bool(tg.get("interactive")))

    # ---- formatting helpers ----

    def local(self, ts: str | datetime | None = None) -> datetime:
        t = datetime.fromisoformat(ts) if isinstance(ts, str) else (ts or datetime.now(UTC))
        if t.tzinfo is None:
            t = t.replace(tzinfo=UTC)
        return t.astimezone(self.tz) if self.tz else t.astimezone()

    def hhmm(self, ts=None) -> str:
        t, now = self.local(ts), self.local()
        return t.strftime("%H:%M") if t.date() == now.date() else t.strftime("%b %d %H:%M")

    # ---- delivery ----

    def _post(self, text: str, buttons: list | None = None) -> str:
        """-> "ok" | "retry" (network / 5xx / 429: queue it) | "drop" (permanent error).
        `buttons`: rows of (label, callback_data) for an inline keyboard."""
        body = {"chat_id": self.chat_id, "text": text[:4000], "parse_mode": "HTML", "disable_web_page_preview": True}
        if buttons:
            body["reply_markup"] = keyboard(buttons)
        try:
            r = requests.post(API.format(token=self.token, method="sendMessage"), timeout=TIMEOUT, json=body)
        except requests.RequestException as e:
            print(f"notify: telegram unreachable, queued ({e.__class__.__name__})", file=sys.stderr)
            return "retry"
        if r.ok:
            return "ok"
        detail = r.text[:200].replace(self.token, "<token>")
        if r.status_code == 429 or r.status_code >= 500:
            print(f"notify: telegram {r.status_code}, queued: {detail}", file=sys.stderr)
            return "retry"
        print(f"notify: telegram rejected the message ({r.status_code}): {detail}", file=sys.stderr)
        return "drop"

    def _locked(self):
        f = open(self.base / LOCK_FILE, "w")  # noqa: SIM115 -- closed by the caller's with-block
        fcntl.flock(f, fcntl.LOCK_EX)
        return f

    def _read_queue(self) -> list[dict]:
        try:
            lines = (self.base / QUEUE_FILE).read_text().splitlines()
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def _write_queue(self, items: list[dict]) -> None:
        path = self.base / QUEUE_FILE
        if not items:
            path.unlink(missing_ok=True)
            return
        path.write_text("".join(json.dumps(i) + "\n" for i in items[-QUEUE_MAX:]))

    def _flush_locked(self) -> bool:
        """Deliver queued messages in order. -> True when the queue is empty afterwards."""
        queue = self._read_queue()
        if not queue:
            return True
        cutoff = datetime.now(UTC) - QUEUE_MAX_AGE
        remaining = []
        for i, item in enumerate(queue):
            if datetime.fromisoformat(item["ts"]) < cutoff:
                continue
            res = self._post(f"<i>⏱ delayed, from {self.hhmm(item['ts'])}</i>\n{item['text']}", item.get("buttons"))
            if res == "retry":
                remaining = [q for q in queue[i:] if datetime.fromisoformat(q["ts"]) >= cutoff]
                break
        self._write_queue(remaining)
        return not remaining

    def send(self, text: str, buttons: list | None = None) -> bool:
        """Send now (after anything still queued, to keep the order). Never raises.
        -> True if delivered. Buttons are dropped unless notify.telegram.interactive is on."""
        buttons = buttons if self.interactive else None
        try:
            with self._locked():
                if self._flush_locked():
                    res = self._post(text, buttons)
                    if res != "retry":
                        return res == "ok"
                queue = self._read_queue()
                item = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "text": text}
                if buttons:
                    item["buttons"] = buttons
                queue.append(item)
                self._write_queue(queue)
                return False
        except Exception as e:  # notifications are best-effort
            print(f"notify: send failed: {e}", file=sys.stderr)
            return False

    def flush(self) -> None:
        if not (self.base / QUEUE_FILE).exists():
            return
        try:
            with self._locked():
                self._flush_locked()
        except Exception as e:
            print(f"notify: flush failed: {e}", file=sys.stderr)

    def _send(self, text: str, buttons: list | None) -> None:
        """send() with buttons only when the bot answers them (keeps send(text) for everything else)."""
        if self.interactive and buttons:
            self.send(text, buttons)
        else:
            self.send(text)

    def muted(self, check: str) -> bool:
        try:
            until = json.loads((self.base / MUTE_FILE).read_text()).get(check)
            return bool(until) and datetime.fromisoformat(until) > datetime.now(UTC)
        except (OSError, ValueError, TypeError):
            return False

    def _footer(self) -> str:
        return f'\n<a href="{html.escape(self.dashboard_url)}">Dashboard</a>' if self.dashboard_url else ""

    # ---- the notifications ----

    def wan_recovered(self, down_since: str | None, downtime_s: float, restarts: int = 0, dry_run: bool = False) -> None:
        if "wan" not in self.events or downtime_s < self.wan_min_downtime:
            return
        lines = [f"🟢 <b>Internet is back</b> after {duration(downtime_s)} down"
                 + (f" (since {self.hhmm(down_since)})" if down_since else "") + "."]
        if restarts:
            what = "would have restarted" if dry_run else "restarted"
            lines.append(f"The watchdog {what} the WAN {restarts}×.")
        self.send("\n".join(lines) + self._footer())

    def router_event(self, event: dict) -> None:
        kind = event.get("event", "")
        if kind.startswith("dns_") and "dns" in self.events:
            state = kind[4:]
            head = {
                "ok": "🟢 <b>DNS is healthy again</b> (filtered by AdGuardHome)",
                "unfiltered": "🟠 <b>DNS works but is not filtered</b>",
                "down": "🔴 <b>Router DNS is down</b>",
            }.get(state, f"DNS state: {html.escape(state)}")
            lines = [head]
            if event.get("previous") and event.get("since"):
                lines.append(f"Was {html.escape(event['previous'])} since {self.hhmm(event['since'])}.")
            lines += [f"• {html.escape(p)}" for p in event.get("problems") or []]
            self.send("\n".join(lines) + self._footer())
        elif kind == "router_firmware_available" and "firmware" in self.events:
            model = html.escape(event.get("model") or "router")
            self.send(
                f"⬆️ <b>New firmware for {model}</b>: {html.escape(event.get('new') or '?')}\n"
                f"Installed: {html.escape(event.get('current') or '?')}\n"
                "Nothing was downloaded or installed. "
                '<a href="https://www.asuswrt-merlin.net/changelog">Changelog</a>'
            )
        elif kind == "monitor_problem" and "monitor" in self.events:
            check = event.get("check") or "?"
            if self.muted(check):
                return
            fixes = event.get("fixes") or []
            auto = [f["title"] for f in fixes if f.get("auto")]
            text = (f"⚠️ <b>network-ai: {html.escape(event.get('title') or check)} problem</b>\n"
                    f"{html.escape(event.get('problem') or '')}\nSince {self.hhmm(event.get('since'))}.")
            if auto:
                text += "\n🔧 Trying automatically: " + html.escape(", ".join(auto)) + "…"
            buttons = [[(f"🔧 {f['title']}", f"fix:{f['id']}:{check}")] for f in fixes if not f.get("auto")]
            buttons.append([("🩺 Troubleshoot", f"ts:{check}"), ("🔕 Mute 24 h", f"mute:{check}")])
            self._send(text + self._footer(), buttons)
        elif kind == "remedy" and "monitor" in self.events:
            self._remedy(event)
        elif kind == "monitor_ok" and "monitor" in self.events:
            since = f" (failing since {self.hhmm(event['since'])})" if event.get("since") else ""
            self.send(f"✅ <b>network-ai: {html.escape(event.get('title') or event.get('check') or '?')} OK again</b>{since}."
                      + self._footer())
        elif kind == "anomaly" and "anomaly" in self.events:
            who = html.escape(event.get("device") or event.get("mac") or "?")
            net = f" [{html.escape(event['network'])}]" if event.get("network") else ""
            lines = [f"🕵️ <b>Unusual activity: {who}</b>{net}", html.escape(event.get("summary") or "")]
            if event.get("domains"):
                lines.append("New: " + ", ".join(html.escape(d) for d in event["domains"][:12])
                             + (" …" if len(event["domains"]) > 12 else ""))
            lines.append("Check it in the dashboard (DNS / Internet usage). Expected? Add the device to "
                         "anomaly.ignore_devices.")
            self.send("\n".join(lines) + self._footer())
        elif kind == "iot_lan" and "iot_lan" in self.events:
            who = html.escape(event.get("device") or event.get("ip") or "?")
            where = ", ".join(html.escape(x) for x in (event.get("ip"), event.get("mac")) if x and x != event.get("device"))
            n = event.get("count") or 0
            lines = [f"🚧 <b>IoT device {who} tried to reach the LAN</b>" + (f" ({where})" if where else ""),
                     f"Blocked {n} connection attempt{'s' if n != 1 else ''}:"]
            lines += [f"• {html.escape(t)}" for t in (event.get("targets") or [])[:10]]
            lines.append("The firewall blocked it. Expected (e.g. a LAN MQTT broker)? Add it to "
                         "iot_lan.ignore_targets; otherwise check the device.")
            self.send("\n".join(lines) + self._footer())
        elif ((kind == "vpn_new_peer" or kind == "ddns_mismatch" or kind == "ddns_ok") and "vpn" in self.events) \
                or (kind == "vpn_connect" and event.get("new_network") and "vpn" in self.events) \
                or ((kind == "vpn_connect" or kind == "vpn_disconnect") and "vpn_sessions" in self.events):
            self._vpn_event(event, kind)
        elif kind == "upnp_new_device" and "upnp" in self.events:
            who = html.escape(event.get("device") or event.get("ip") or "?")
            where = ", ".join(html.escape(x) for x in (event.get("ip"), event.get("mac")) if x and x != event.get("device"))
            lines = [f"🔓 <b>{who} opened a port to the internet</b>" + (f" ({where})" if where else "")]
            lines += [f"• {html.escape(p)}" for p in (event.get("ports") or [])[:10]]
            lines.append("First time for this device (via UPnP). If unexpected, turn it off in the "
                         "device's settings or disable UPnP on the router.")
            self.send("\n".join(lines) + self._footer())

    def _remedy(self, event: dict) -> None:
        how = {"auto": "automatic", "telegram": f"asked by {event.get('by') or 'you'} in Telegram",
               "cli": "run by hand"}.get(event.get("trigger"), event.get("trigger") or "")
        title = html.escape(event.get("title") or event.get("fix") or "?")
        lines = [f"{'🛠️' if event.get('ok') else '❌'} <b>{'Fixed' if event.get('ok') else 'Fix failed'}: {title}</b>"
                 + (f" ({html.escape(how)})" if how else "")]
        if event.get("note"):
            lines.append(html.escape(event["note"]))
        if not event.get("ok") and event.get("detail"):
            lines.append(f"<code>{html.escape(event['detail'][-300:])}</code>")
        if event.get("ok"):
            lines.append("The next check confirms it (✅ OK again).")
        check = event.get("check") or ""
        buttons = None if event.get("ok") else [[("🩺 Troubleshoot", f"ts:{check}" if check else f"tsfix:{event.get('fix')}")]]
        self._send("\n".join(lines) + self._footer(), buttons)

    def _vpn_event(self, event: dict, kind: str) -> None:
        from .geoip import describe

        peer = html.escape(event.get("peer") or "?")
        if kind == "vpn_new_peer":
            self.send(f"🆕 <b>VPN peer added on the router: {peer}</b> ({html.escape(event.get('addr') or '?')})\n"
                      "Not you? Remove it in VPN > VPN Server > WireGuard." + self._footer())
        elif kind == "vpn_connect":
            where = html.escape(describe(event)) or "unknown network"
            src = html.escape(event.get("endpoint") or "?")
            if event.get("new_network"):
                verb = "moved to" if event.get("roamed") else "connected from"
                self.send(f"⚠️ <b>VPN: {peer} {verb} a new network</b>\n{src} · {where}\n"
                          "First time from this network. Not you? Remove the peer on the router and "
                          "make new keys." + self._footer())
            else:
                self.send(f"🔐 <b>VPN: {peer} connected</b>\n{src} · {where}" + self._footer())
        elif kind == "vpn_disconnect":
            traffic = ", ".join(f"{mb(v)} {d}" for v, d in ((event.get("tx"), "to it"), (event.get("rx"), "from it"))
                                if v is not None)
            self.send(f"🔒 <b>VPN: {peer} disconnected</b> after {duration(event.get('duration_s') or 0)}"
                      + (f"\n{traffic}" if traffic else "") + self._footer())
        elif kind == "ddns_mismatch":
            self.send(f"🌐 <b>DDNS out of date: {html.escape(event.get('host') or '?')}</b>\n"
                      f"Resolves to {html.escape(', '.join(event.get('resolved') or []) or 'nothing')}, "
                      f"WAN IP is {html.escape(event.get('wan_ip') or '?')}.\n"
                      "VPN/remote access by name fails until the router updates it (WAN > DDNS, "
                      "/jffs/scripts/ddns-start)." + self._footer())
        elif kind == "ddns_ok":
            self.send(f"🌐 <b>DDNS OK again: {html.escape(event.get('host') or '?')}</b> → "
                      f"{html.escape(event.get('ip') or '?')}"
                      + (f" (wrong since {self.hhmm(event['since'])})" if event.get("since") else "") + self._footer())

    def new_devices(self, clients: list[dict]) -> None:
        if "new_device" not in self.events or not clients:
            return
        from .devices import label

        head = "🆕 <b>New device on the network</b>" if len(clients) == 1 else f"🆕 <b>{len(clients)} new devices on the network</b>"
        lines = [head]
        for c in clients[:15]:
            where = ", ".join(x for x in (c.get("ip"), {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}.get(c.get("band"), c.get("band")))
                              if x)
            lines.append(f"• {html.escape(label(c))} <code>{html.escape(c.get('mac') or '')}</code>"
                         + (f" ({html.escape(where)})" if where else ""))
        if len(clients) > 15:
            lines.append(f"… and {len(clients) - 15} more")
        self.send("\n".join(lines) + self._footer())

    def daily(self, analysis: dict) -> None:
        if "daily" not in self.events:
            return
        overall = (analysis.get("sections") or {}).get("overall")
        if overall:
            text = f"📋 <b>Daily router briefing</b>\n{html.escape(overall)}"
        else:
            text = f"⚠️ <b>Daily router briefing failed</b>\n{html.escape((analysis.get('error') or 'no analysis')[:500])}"
        self.send(text + self._footer())

    def report(self, record: dict) -> None:
        if "report" not in self.events:
            return
        title = "Weekly" if record.get("period") == "week" else "Monthly"
        lines = [(f"📊 <b>{title} network report</b> "
                 f"({html.escape(str(record.get('start')))} – {html.escape(str(record.get('end')))})")]
        lines += [html.escape(x) for x in record.get("headline") or []]
        if record.get("summary"):
            lines += ["", html.escape(record["summary"][:2500])]
        else:
            lines += ["", f"(no AI summary: {html.escape((record.get('error') or 'no LLM answered')[:300])})"]
        self.send("\n".join(lines) + self._footer())


def keyboard(rows: list) -> dict:
    """[[(label, callback_data), ...], ...] -> Telegram inline keyboard (data max 64 bytes)."""
    return {"inline_keyboard": [[{"text": label, "callback_data": data[:64]} for label, data in row] for row in rows]}


def mb(n: float) -> str:
    """Bytes -> '512 KB' / '45 MB' / '1.2 GB'."""
    if n < 1e6:
        return f"{n / 1e3:.0f} KB"
    return f"{n / 1e6:.0f} MB" if n < 1e9 else f"{n / 1e9:.1f} GB"


def duration(seconds: float) -> str:
    s = round(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {s % 3600 // 60:02d}m"


# ---- module-level hooks: configure once per process, then call from anywhere ----

def configure(cfg: dict, log_dir) -> "Notifier | None":
    global _notifier
    _notifier = Notifier.from_config(cfg, log_dir)
    return _notifier


def get() -> "Notifier | None":
    return _notifier


def router_event(event: dict) -> None:
    if _notifier:
        _notifier.router_event(event)


# ---- setup CLI ----

def main():
    import yaml
    from dotenv import load_dotenv

    load_dotenv()
    p = argparse.ArgumentParser(description="Telegram notifications: setup helpers")
    p.add_argument("--config", default=os.getenv("NETWORK_AI_CONFIG", "config.yml"))
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--chat-id", action="store_true", help="list chats that messaged the bot (send it /start first)")
    g.add_argument("--test", action="store_true", help="send a test message")
    g.add_argument("--flush", action="store_true", help="deliver queued messages now")
    g.add_argument("--send", metavar="TEXT", help="send TEXT (HTML-escaped) right away, e.g. from deploy.sh")
    args = p.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN is not set in .env")
    if args.chat_id:
        r = requests.get(API.format(token=token, method="getUpdates"), timeout=TIMEOUT)
        if not r.ok:
            raise SystemExit(f"getUpdates failed ({r.status_code}): {r.text[:200].replace(token, '<token>')}")
        chats = {}
        for u in r.json().get("result", []):
            chat = (u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}).get("chat") or {}
            if chat.get("id"):
                chats[chat["id"]] = chat.get("username") or chat.get("title") or chat.get("first_name") or ""
        if not chats:
            raise SystemExit("No chats yet: open the bot in Telegram, send it /start, then run this again.")
        for cid, who in chats.items():
            print(f"chat_id: {cid}  ({who})")
        return

    n = Notifier.from_config(cfg, Path(cfg.get("log_dir", "logs")))
    if not n:
        raise SystemExit("notify.telegram.chat_id is not set in config.yml")
    if args.flush:
        n.flush()
        print("queue empty" if not (n.base / QUEUE_FILE).exists() else "some messages are still queued")
        return
    if args.send:
        raise SystemExit(0 if n.send(html.escape(args.send) + n._footer()) else "message not delivered")
    ok = n.send(f"✅ <b>network-ai test</b>\nTelegram notifications work. Sending: {', '.join(sorted(n.events))}."
                + n._footer())
    raise SystemExit(0 if ok else "test message not delivered (see the error above)")


if __name__ == "__main__":
    main()
