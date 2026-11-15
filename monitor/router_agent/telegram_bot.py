"""Telegram bot: answer alerts with fixes, talk to Tshoot, approve its changes.

Runs as network-ai-telegram.service (user netai, like the dashboard: no root, no SSH).
It long-polls Telegram's getUpdates, so nothing listens on this host. Only messages and
button taps from the configured chat (`notify.telegram.chat_id`) AND from a Telegram user
in `notify.telegram.allowed_users` (default: the chat id, i.e. your private chat) are
answered; everything else is ignored and logged.

  buttons under alerts (router_agent/notify.py, notify.telegram.interactive: true)
    fix:<fix>:<check>  queue a fix from router_agent/remedy.py FIXES -> network-ai-remedy.path
                       runs it as root; the result comes back as a `remedy` message
    ts:<check>         new Tshoot session seeded with the self-check problem
    tsfix:<fix>        new Tshoot session about a fix that failed
    mute:<check>       no Telegram for that check's problems for 24 h (logs/.notify_mute.json)
    ap:<id> / rj:<id>  approve / reject the change Tshoot proposed
  text                 goes to Tshoot (current session); /new starts a fresh one
  /status /fixes /unmute /new /cancel /help

Tshoot (/opt/tshoot, 127.0.0.1:8090) is called directly with TSHOOT_PROXY_KEY, like the
dashboard's proxy; the bot is the approver check here (chat + user allowlist instead of
dashboard.approvers) and sends X-Tshoot-User "telegram:<user>" for Tshoot's audit log.
Changes Tshoot rates high risk (reboot, WAN/LAN/Wi-Fi/SSH restarts, ...) need
TELEGRAM_APPROVAL_PIN from .env as a reply (3 tries, 2 minutes, the reply is deleted);
without a PIN configured they cannot be approved from Telegram at all.
"""
import argparse
import hmac
import html
import json
import logging
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

from . import remedy
from .notify import API, MUTE_FILE, keyboard

logger = logging.getLogger("telegram_bot")

STATE_FILE = ".telegram_bot.json"
POLL_TIMEOUT = 50
PIN_TTL = timedelta(minutes=2)
PIN_TRIES = 3
MUTE_FOR = timedelta(hours=24)
MAX_MSG = 3900
TROUBLESHOOT_PROMPT = ("The monitor raised an alert: {title}: {problem}\n"
                       "Find the cause on the router and propose a fix if one is needed. "
                       "I am reading this on my phone in Telegram: keep the answer short.")


def md_to_html(text: str) -> str:
    """Tshoot answers in Markdown; Telegram gets the small HTML subset it understands."""
    out, parts = [], re.split(r"```(?:\w+)?\n?(.*?)```", text or "", flags=re.DOTALL)
    for i, part in enumerate(parts):
        if i % 2:
            out.append(f"<pre>{html.escape(part.strip())}</pre>")
            continue
        t = html.escape(part)
        t = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", t)
        t = re.sub(r"\*\*([^*\n]+)\*\*", r"<b>\1</b>", t)
        t = re.sub(r"(?m)^#{1,6} +(.+)$", r"<b>\1</b>", t)
        out.append(t)
    return "".join(out).strip()


def chunks(text: str, size: int = MAX_MSG) -> list[str]:
    out = []
    while len(text) > size:
        cut = text.rfind("\n", 0, size)
        cut = cut if cut > size // 2 else size
        out.append(text[:cut])
        text = text[cut:].lstrip("\n")
    return [*out, text] if text else out


class Bot:
    def __init__(self, token: str, chat_id: str, log_dir: Path, allowed_users=None, pin: str = "",
                 tshoot_url: str = "http://127.0.0.1:8090", proxy_key: str = "", model: str = "claude"):
        self.token = token
        self.chat_id = str(chat_id)
        self.allowed = {str(u) for u in (allowed_users or [chat_id])}
        self.base = Path(log_dir)
        self.pin = pin
        self.tshoot = tshoot_url.rstrip("/")
        self.proxy_key = proxy_key
        self.model = model
        self.lock = threading.Lock()
        self.worker = ThreadPoolExecutor(max_workers=1)  # Tshoot turns run one at a time, polling goes on
        self.state = self._load()

    # ------------------------------------------------------------ state

    def _load(self) -> dict:
        try:
            return json.loads((self.base / STATE_FILE).read_text())
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        (self.base / STATE_FILE).write_text(json.dumps(self.state, indent=1))

    def _read(self, name: str) -> dict:
        try:
            return json.loads((self.base / name).read_text())
        except (OSError, ValueError):
            return {}

    def session(self, new: bool = False) -> str:
        with self.lock:
            if new or not self.state.get("session"):
                self.state["session"] = f"tg-{secrets.token_hex(8)}"
                self.state.pop("approval", None)
                self.state.pop("pin", None)
                self._save()
            return self.state["session"]

    # ------------------------------------------------------------ Telegram API

    def api(self, method: str, timeout: float = 15, **body):
        try:
            r = requests.post(API.format(token=self.token, method=method), json=body, timeout=timeout)
            data = r.json()
            if not data.get("ok"):
                logger.warning("telegram %s failed: %s", method, str(data)[:200])
            return data.get("result")
        except (requests.RequestException, ValueError) as e:
            logger.warning("telegram %s: %s", method, type(e).__name__)
            return None

    def say(self, text: str, buttons: list | None = None, html_text: bool = True) -> None:
        parts = chunks(text if html_text else html.escape(text)) or ["…"]
        for i, part in enumerate(parts):
            body = {"chat_id": self.chat_id, "text": part, "parse_mode": "HTML", "disable_web_page_preview": True}
            if buttons and i == len(parts) - 1:
                body["reply_markup"] = keyboard(buttons)
            self.api("sendMessage", **body)

    # ------------------------------------------------------------ dispatch

    def authorized(self, chat: dict, user: dict) -> bool:
        return str(chat.get("id")) == self.chat_id and str(user.get("id")) in self.allowed

    @staticmethod
    def who(user: dict) -> str:
        return f"telegram:{user.get('username') or user.get('id')}"

    def handle(self, update: dict) -> None:
        if "callback_query" in update:
            q = update["callback_query"]
            msg = q.get("message") or {}
            if not self.authorized(msg.get("chat") or {}, q.get("from") or {}):
                logger.warning("ignored button from user %s", (q.get("from") or {}).get("id"))
                self.api("answerCallbackQuery", callback_query_id=q["id"], text="Not allowed")
                return
            self.on_button(q, msg)
        elif "message" in update:
            m = update["message"]
            if not self.authorized(m.get("chat") or {}, m.get("from") or {}):
                logger.warning("ignored message from chat %s user %s", (m.get("chat") or {}).get("id"),
                               (m.get("from") or {}).get("id"))
                return
            self.on_text(m)

    def on_text(self, m: dict) -> None:
        text = (m.get("text") or "").strip()
        user = m.get("from") or {}
        if not text:
            return
        with self.lock:
            pin = self.state.get("pin")
        if pin and not text.startswith("/cancel"):
            self.api("deleteMessage", chat_id=self.chat_id, message_id=m.get("message_id"))
            self.pin_attempt(text, user)
            return
        cmd = text.split()[0].split("@")[0].lower() if text.startswith("/") else ""
        logger.info("message: %s", cmd or f"text for Tshoot ({len(text)} chars)")  # never the text itself
        if cmd in ("/start", "/help"):
            self.say(HELP)
        elif cmd == "/new":
            self.session(new=True)
            self.say("🆕 New Tshoot conversation. What should I look at?")
        elif cmd == "/cancel":
            with self.lock:
                self.state.pop("pin", None)
                self._save()
            self.say("Cancelled. The change is still waiting: tap Approve or Reject.")
        elif cmd == "/status":
            self.say(self.status_text())
        elif cmd == "/fixes":
            self.say("Known fixes (tap to run; 🤖 = also runs automatically when its problem is alerted):",
                     [[(f"{'🤖' if f.auto else '🔧'} {f.title}", f"fix:{f.id}:")] for f in remedy.FIXES.values()])
        elif cmd == "/unmute":
            (self.base / MUTE_FILE).unlink(missing_ok=True)
            self.say("🔔 All monitor alerts are on again.")
        elif cmd:
            self.say("Unknown command. /help lists them; plain text goes to Tshoot.")
        else:
            sid = self.session()
            with self.lock:  # Tshoot treats a pending change as rejected when you write instead of deciding
                self.state.pop("approval", None)
                self._save()
            self.worker.submit(self.tshoot_turn, "chat", {"session_id": sid, "message": text, "model": self.model}, user)

    def on_button(self, q: dict, msg: dict) -> None:
        data, user = q.get("data") or "", q.get("from") or {}
        logger.info("button: %s", data)
        kind, _, rest = data.partition(":")
        answer = ""
        if kind == "fix":
            fid, _, check = rest.partition(":")
            if remedy.request_fix(self.base, fid, self.who(user), check):
                answer = "Queued"
                self.say(f"🔧 Running <b>{html.escape(remedy.FIXES[fid].title)}</b>… the result follows.")
            else:
                answer = "Unknown fix"
        elif kind in ("ts", "tsfix"):
            answer = "Starting Tshoot"
            sid = self.session(new=True)
            self.say("🩺 Tshoot is looking into it (a minute or two)…")
            self.worker.submit(self.tshoot_turn, "chat",
                               {"session_id": sid, "message": self.troubleshoot_prompt(kind, rest), "model": self.model},
                               user)
        elif kind == "mute":
            mutes = self._read(MUTE_FILE)
            mutes[rest] = (datetime.now(UTC) + MUTE_FOR).isoformat(timespec="seconds")
            (self.base / MUTE_FILE).write_text(json.dumps(mutes, indent=1))
            answer = "Muted for 24 h"
            self.say(f"🔕 <b>{html.escape(rest)}</b> alerts muted for 24 h (auto-fixes still run). /unmute to undo.")
        elif kind in ("ap", "rj"):
            answer = self.decide(rest, kind == "ap", user, msg)
        self.api("answerCallbackQuery", callback_query_id=q["id"], text=answer[:180])

    def troubleshoot_prompt(self, kind: str, arg: str) -> str:
        if kind == "tsfix":
            fix = remedy.FIXES.get(arg)
            title = fix.title if fix else arg
            return TROUBLESHOOT_PROMPT.format(title=f"the automatic fix '{title}'", problem="it failed")
        cur = self._read(".selfcheck.json").get(arg) or {}
        problem = cur.get("problem") or "the problem has cleared since the alert; check that it really is OK"
        return TROUBLESHOOT_PROMPT.format(title=arg, problem=problem)

    def status_text(self) -> str:
        problems = self._read(".selfcheck.json")
        latest = (self._read("latest.json").get("snapshot") or {}).get("collected_at")
        lines = ["📋 <b>network-ai status</b>"]
        if latest:
            lines.append(f"Last check: {html.escape(str(latest))}")
        if not problems:
            lines.append("✅ No open problems.")
        for name, cur in problems.items():
            lines.append(f"⚠️ <b>{html.escape(name)}</b> since {html.escape(cur.get('since', '?'))}: "
                         f"{html.escape(cur.get('problem', ''))}")
        mutes = {k: v for k, v in self._read(MUTE_FILE).items() if v > datetime.now(UTC).isoformat()}
        if mutes:
            lines.append("🔕 Muted: " + ", ".join(html.escape(k) for k in mutes))
        return "\n".join(lines)

    # ------------------------------------------------------------ approvals

    def decide(self, approval_id: str, approve: bool, user: dict, msg: dict) -> str:
        with self.lock:
            ap = self.state.get("approval") or {}
        if ap.get("id") != approval_id:
            return "That change is no longer pending"
        if msg.get("message_id"):  # no double taps
            self.api("editMessageReplyMarkup", chat_id=self.chat_id, message_id=msg["message_id"],
                     reply_markup={"inline_keyboard": []})
        if approve and ap.get("risk") == "high":
            if not self.pin:
                self.say("🔐 High-risk change: approving it from Telegram needs TELEGRAM_APPROVAL_PIN in .env. "
                         "Approve it on the dashboard, or Reject it here.",
                         [[("❌ Reject", f"rj:{approval_id}")]])
                return "PIN not configured"
            with self.lock:
                self.state["pin"] = {"id": approval_id, "tries": 0,
                                     "until": (datetime.now(UTC) + PIN_TTL).isoformat(timespec="seconds")}
                self._save()
            self.say("🔐 High-risk change. Reply with your PIN within 2 minutes (the reply is deleted). /cancel to stop.")
            return "PIN needed"
        self.send_decision(approval_id, approve, user)
        return "Approved" if approve else "Rejected"

    def pin_attempt(self, text: str, user: dict) -> None:
        with self.lock:
            pin = self.state.get("pin") or {}
            expired = not pin or datetime.fromisoformat(pin["until"]) < datetime.now(UTC)
            ok = not expired and hmac.compare_digest(text.encode(), self.pin.encode())
            if not ok and not expired:
                pin["tries"] = pin.get("tries", 0) + 1
            give_up = expired or ok or pin.get("tries", 0) >= PIN_TRIES
            if give_up:
                self.state.pop("pin", None)
            self._save()
        if ok:
            self.send_decision(pin["id"], True, user)
        elif expired:
            self.say("⌛ PIN request expired. The change was rejected.")
            self.send_decision(pin.get("id", ""), False, user, note="PIN not given in time")
        elif give_up:
            self.say("⛔ Wrong PIN 3 times. The change was rejected.")
            self.send_decision(pin["id"], False, user, note="wrong PIN")
        else:
            self.say(f"Wrong PIN ({pin['tries']}/{PIN_TRIES}). Try again or /cancel.")

    def send_decision(self, approval_id: str, approve: bool, user: dict, note: str = "") -> None:
        with self.lock:
            sid = self.state.get("session")
            self.state.pop("approval", None)
            self._save()
        if not sid or not approval_id:
            return
        self.say("✅ Approved, running it…" if approve else "❌ Rejected. Telling Tshoot…")
        self.worker.submit(self.tshoot_turn, "approve",
                           {"session_id": sid, "approval_id": approval_id,
                            "decision": "approve" if approve else "reject", "note": note or "via Telegram"}, user)

    # ------------------------------------------------------------ Tshoot

    def tshoot_turn(self, endpoint: str, body: dict, user: dict) -> None:
        """One streamed Tshoot turn -> Telegram messages. Runs in the worker thread."""
        headers = {"Content-Type": "application/json", "X-Tshoot-User": self.who(user)}
        if self.proxy_key:
            headers["X-Tshoot-Proxy-Key"] = self.proxy_key
        self.api("sendChatAction", chat_id=self.chat_id, action="typing")
        commands, approval, final, errors = [], None, None, []
        try:
            with requests.post(f"{self.tshoot}/api/tshoot/{endpoint}", json=body, headers=headers,
                               stream=True, timeout=(5, 600)) as r:
                if not r.ok:
                    self.say(f"⚠️ Tshoot answered {r.status_code}: {html.escape(r.text[:300])}")
                    return
                last_typing = time.monotonic()
                for line in r.iter_lines(decode_unicode=True):
                    if not line or not line.startswith("data: "):
                        continue
                    ev = json.loads(line[6:])
                    t = ev.get("type")
                    if t == "command":
                        commands.append(ev.get("command") or "")
                    elif t == "approval":
                        approval = ev
                    elif t == "final":
                        final = ev
                    elif t == "error":
                        errors.append(ev.get("content") or "")
                    if time.monotonic() - last_typing > 4:
                        self.api("sendChatAction", chat_id=self.chat_id, action="typing")
                        last_typing = time.monotonic()
        except (requests.RequestException, ValueError) as e:
            logger.warning("tshoot %s failed: %r", endpoint, e)
            self.say(f"⚠️ Tshoot is unreachable ({html.escape(type(e).__name__)}). Is tshoot.service running?")
            return
        self.render(commands, approval, final, errors)

    def render(self, commands: list, approval: dict | None, final: dict | None, errors: list) -> None:
        cmds = list(dict.fromkeys(c for c in commands if c))
        head = ""
        if cmds:
            shown = "\n".join(f"• <code>{html.escape(c[:120])}</code>" for c in cmds[:6])
            more = f"\n… and {len(cmds) - 6} more" if len(cmds) > 6 else ""
            head = f"<i>Ran {len(cmds)} command{'s' if len(cmds) != 1 else ''}:</i>\n{shown}{more}\n\n"
        body = md_to_html((final or {}).get("content") or "") or "\n".join(html.escape(e) for e in errors) or "(no answer)"
        model = (final or {}).get("model")
        self.say(head + body + (f"\n<i>— {html.escape(model)}</i>" if model else ""))
        if approval:
            with self.lock:
                self.state["approval"] = {"id": approval["id"], "risk": approval.get("risk", "low"),
                                          "command": approval.get("command")}
                self._save()
            self.say(approval_card(approval, pin_needed=approval.get("risk") == "high"),
                     [[("✅ Approve", f"ap:{approval['id']}"), ("❌ Reject", f"rj:{approval['id']}")]])

    # ------------------------------------------------------------ loop

    def poll_once(self) -> None:
        offset = self.state.get("offset")
        try:
            r = requests.post(API.format(token=self.token, method="getUpdates"), timeout=POLL_TIMEOUT + 10, json={
                "offset": offset, "timeout": POLL_TIMEOUT, "allowed_updates": ["message", "callback_query"]})
            data = r.json()
            if not data.get("ok"):  # e.g. 409: another process polls this bot token
                logger.warning("getUpdates: %s", str(data)[:200])
                time.sleep(10)
                return
            updates = data.get("result") or []
        except (requests.RequestException, ValueError) as e:
            logger.warning("getUpdates: %s", type(e).__name__)
            time.sleep(10)
            return
        for u in updates:
            with self.lock:
                self.state["offset"] = u["update_id"] + 1
                self._save()
            try:
                self.handle(u)
            except Exception:
                logger.exception("update %s failed", u.get("update_id"))

    def run(self) -> None:
        logger.info("telegram bot polling (chat %s, users %s, PIN %s)", self.chat_id, sorted(self.allowed),
                    "set" if self.pin else "not set")
        while True:
            self.poll_once()


def approval_card(ap: dict, pin_needed: bool) -> str:
    risk = ap.get("risk", "low")
    icon = {"high": "🔴", "medium": "🟠"}.get(risk, "🟢")
    lines = ["🛠️ <b>Tshoot wants to make a change</b>", f"<pre>{html.escape(ap.get('command') or '')}</pre>",
             f"{icon} Risk: <b>{html.escape(risk)}</b>"]
    if ap.get("reason"):
        lines.append(f"Why: {html.escape(ap['reason'])}")
    lines += [f"⚠️ {html.escape(w)}" for w in ap.get("warnings") or []]
    if pin_needed:
        lines.append("🔐 Approving asks for your PIN.")
    return "\n".join(lines)


HELP = ("🤖 <b>network-ai bot</b>\n"
        "Write anything: Tshoot (the router troubleshooting agent) answers and asks before changing anything.\n"
        "/status open problems · /fixes run a known fix · /new new Tshoot conversation · /unmute alerts · "
        "/cancel a PIN request\n"
        "Alert buttons: 🔧 run that fix · 🩺 let Tshoot investigate · 🔕 mute 24 h")


def from_config(cfg: dict, log_dir: Path) -> Bot:
    tg = ((cfg or {}).get("notify") or {}).get("telegram") or {}
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token or not tg.get("chat_id"):
        raise SystemExit("TELEGRAM_BOT_TOKEN (.env) and notify.telegram.chat_id (config.yml) are required")
    return Bot(token, tg["chat_id"], log_dir, allowed_users=tg.get("allowed_users"),
               pin=os.getenv("TELEGRAM_APPROVAL_PIN", "").strip(),
               tshoot_url=os.getenv("TSHOOT_URL", "http://127.0.0.1:8090"),
               proxy_key=os.getenv("TSHOOT_PROXY_KEY", ""), model=tg.get("tshoot_model", "claude"))


def main():
    import yaml
    from dotenv import load_dotenv

    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--config", default=os.getenv("NETWORK_AI_CONFIG", "config.yml"))
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    root = Path(args.config).resolve().parent
    if os.access(root / ".env", os.R_OK):  # root-only (0600): under systemd EnvironmentFile already set it
        load_dotenv(root / ".env")
    cfg = yaml.safe_load(Path(args.config).read_text()) or {}
    from_config(cfg, root / cfg.get("log_dir", "logs")).run()


if __name__ == "__main__":
    main()
