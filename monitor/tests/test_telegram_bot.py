"""Telegram bot: who may talk to it, buttons, Tshoot relay, the PIN for high-risk changes."""
import json

import pytest

from router_agent import remedy, telegram_bot
from router_agent.telegram_bot import Bot, chunks, md_to_html

ME = {"id": 111, "username": "me"}
CHAT = {"id": 111}


class FakeResp:
    def __init__(self, events, ok=True):
        self.ok, self.status_code, self.text = ok, 200 if ok else 500, ""
        self.lines = [f"data: {json.dumps(e)}" for e in events]

    def iter_lines(self, decode_unicode=True):
        yield from self.lines

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def bot(tmp_path, monkeypatch):
    b = Bot("token", "111", tmp_path, pin="4321", proxy_key="k")
    b.api_calls, b.said, b.tshoot_calls, b.tshoot_reply = [], [], [], []
    b.api = lambda method, timeout=15, **body: b.api_calls.append((method, body))
    b.say = lambda text, buttons=None, html_text=True: b.said.append((text, buttons))

    class Inline:  # run Tshoot turns synchronously
        def submit(self, fn, *a):
            fn(*a)
    b.worker = Inline()

    def post(url, json=None, headers=None, stream=False, timeout=None):
        b.tshoot_calls.append((url.rsplit("/", 1)[-1], json, headers))
        return FakeResp(b.tshoot_reply)
    monkeypatch.setattr(telegram_bot.requests, "post", post)
    return b


def msg(text, user=ME, chat=CHAT, mid=5):
    return {"message": {"message_id": mid, "text": text, "from": user, "chat": chat}}


def tap(data, user=ME, chat=CHAT):
    return {"callback_query": {"id": "q", "data": data, "from": user, "message": {"message_id": 9, "chat": chat}}}


def test_strangers_are_ignored(bot):
    bot.handle(msg("hi", user={"id": 999}))
    bot.handle(msg("hi", chat={"id": -100}))
    bot.handle(tap("fix:watchdog:", user={"id": 999}))
    assert bot.said == [] and bot.tshoot_calls == []
    assert not (bot.base / remedy.REQUESTS_FILE).exists()


def test_text_goes_to_tshoot_with_proxy_key_and_user(bot):
    bot.tshoot_reply = [{"type": "command", "command": "nvram get x"}, {"type": "final", "content": "All **good**",
                                                                        "model": "claude-opus"}]
    bot.handle(msg("is the wifi ok?"))
    endpoint, body, headers = bot.tshoot_calls[0]
    assert endpoint == "chat" and body["message"] == "is the wifi ok?" and body["session_id"].startswith("tg-")
    assert headers["X-Tshoot-Proxy-Key"] == "k" and headers["X-Tshoot-User"] == "telegram:me"
    assert "<code>nvram get x</code>" in bot.said[0][0] and "All <b>good</b>" in bot.said[0][0]


def test_fix_button_queues_a_known_fix_only(bot):
    bot.handle(tap("fix:hour_monitor:traffic"))
    req = json.loads((bot.base / remedy.REQUESTS_FILE).read_text())
    assert req["fix"] == "hour_monitor" and req["by"] == "telegram:me" and req["check"] == "traffic"
    bot.handle(tap("fix:reboot:"))
    assert len((bot.base / remedy.REQUESTS_FILE).read_text().splitlines()) == 1


def test_troubleshoot_button_seeds_a_new_session(bot):
    (bot.base / ".selfcheck.json").write_text(json.dumps({"traffic": {"problem": "no rows for 3 h"}}))
    bot.tshoot_reply = [{"type": "final", "content": "hour_monitor is dead"}]
    bot.handle(tap("ts:traffic"))
    assert "no rows for 3 h" in bot.tshoot_calls[0][1]["message"]


def _propose(bot, risk):
    bot.tshoot_reply = [{"type": "approval", "id": "ap1", "command": "service restart_wan", "risk": risk,
                         "warnings": ["drops the internet"], "reason": "WAN stuck"},
                        {"type": "final", "content": "Please approve", "awaiting_approval": "ap1"}]
    bot.handle(msg("fix the wan"))
    card, buttons = bot.said[-1]
    assert "service restart_wan" in card and buttons == [[("✅ Approve", "ap:ap1"), ("❌ Reject", "rj:ap1")]]
    bot.tshoot_reply = [{"type": "final", "content": "done"}]


def test_low_risk_approve_is_one_tap(bot):
    _propose(bot, "low")
    bot.handle(tap("ap:ap1"))
    endpoint, body, _ = bot.tshoot_calls[-1]
    assert endpoint == "approve" and body["decision"] == "approve" and body["approval_id"] == "ap1"
    bot.handle(tap("ap:ap1"))  # double tap: no longer pending
    assert sum(1 for c in bot.tshoot_calls if c[0] == "approve") == 1


def test_high_risk_needs_the_pin(bot):
    _propose(bot, "high")
    bot.handle(tap("ap:ap1"))
    assert not any(c[0] == "approve" for c in bot.tshoot_calls) and "PIN" in bot.said[-1][0]
    bot.handle(msg("0000", mid=77))
    assert ("deleteMessage", {"chat_id": "111", "message_id": 77}) in bot.api_calls
    assert not any(c[0] == "approve" for c in bot.tshoot_calls)
    bot.handle(msg("4321"))
    assert [c[1]["decision"] for c in bot.tshoot_calls if c[0] == "approve"] == ["approve"]


def test_wrong_pin_three_times_rejects(bot):
    _propose(bot, "high")
    bot.handle(tap("ap:ap1"))
    for _ in range(3):
        bot.handle(msg("1"))
    assert [c[1]["decision"] for c in bot.tshoot_calls if c[0] == "approve"] == ["reject"]


def test_high_risk_without_pin_cannot_be_approved(bot):
    bot.pin = ""
    _propose(bot, "high")
    bot.handle(tap("ap:ap1"))
    assert not any(c[0] == "approve" for c in bot.tshoot_calls)
    bot.handle(tap("rj:ap1"))
    assert [c[1]["decision"] for c in bot.tshoot_calls if c[0] == "approve"] == ["reject"]


def test_mute_and_status(bot):
    bot.handle(tap("mute:traffic"))
    assert "traffic" in json.loads((bot.base / ".notify_mute.json").read_text())
    (bot.base / ".selfcheck.json").write_text(json.dumps({"traffic": {"since": "x", "problem": "stale"}}))
    bot.handle(msg("/status"))
    assert "stale" in bot.said[-1][0] and "Muted: traffic" in bot.said[-1][0]
    bot.handle(msg("/unmute"))
    assert not (bot.base / ".notify_mute.json").exists()


def test_formatting_helpers():
    assert md_to_html("a <b> `x<y>`\n```\nls -l\n```") == "a &lt;b&gt; <code>x&lt;y&gt;</code>\n<pre>ls -l</pre>"
    parts = chunks("line\n" * 2000)
    assert all(len(p) <= telegram_bot.MAX_MSG for p in parts) and len(parts) > 1
