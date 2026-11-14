"""Tshoot HTTP API (Server-Sent Events, same wire format as the AI Coach chat).

Listens on localhost only; the network-ai dashboard proxies /api/tshoot/* here.
With Tailscale in userspace mode every 127.0.0.1 port is reachable from the tailnet, so
when TSHOOT_PROXY_KEY is set (.env, same value as in network-ai's .env) only requests
carrying it -- i.e. coming through the dashboard proxy, which also enforces who may
approve changes -- are answered.
"""
import hmac
import json
import logging
import os
import re
from pathlib import Path

import yaml
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, stream_with_context

from . import claude_agent
from .agent import SessionStore, TshootAgent
from .audit import AuditLog
from .gemini import Gemini
from .ssh import RouterShell

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

CONFIG_PATH = Path(os.getenv("TSHOOT_CONFIG", BASE_DIR / "config.yml"))
CFG = yaml.safe_load(CONFIG_PATH.read_text())

_log_dir = Path(CFG.get("log_dir", "logs"))
LOG_DIR = _log_dir if _log_dir.is_absolute() else BASE_DIR / _log_dir

_router = CFG["router"]
SHELL = RouterShell(_router["host"], port=_router.get("port", 22), username=_router["username"],
                    key_filename=_router["key_filename"])
GEMINI = Gemini(os.getenv("GEMINI_API_KEY"), CFG.get("llm", {}).get("model") or os.getenv("GEMINI_MODEL", "models/gemini-pro-latest"),
                timeout=int(CFG.get("llm", {}).get("timeout", 120)))
AUDIT = AuditLog(LOG_DIR / "audit.jsonl", pg_enabled=CFG.get("audit", {}).get("postgres", True))
AGENT = TshootAgent(CFG, GEMINI, SHELL, AUDIT)
SESSIONS = SessionStore()

app = Flask(__name__)
_SID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
PROXY_KEY = os.getenv("TSHOOT_PROXY_KEY", "")


@app.before_request
def _require_proxy_key():
    if PROXY_KEY and request.path != "/api/tshoot/health" and not hmac.compare_digest(
            request.headers.get("X-Tshoot-Proxy-Key", ""), PROXY_KEY):
        return jsonify({"error": "forbidden: use the network-ai dashboard"}), 403
    return None


def _sse(gen):
    def stream():
        try:
            for ev in gen:
                yield f"data: {json.dumps(ev)}\n\n"
        except Exception as e:  # never leave the browser hanging without a final event
            log.exception("tshoot turn failed")
            yield f"data: {json.dumps({'type': 'final', 'agent': 'error', 'content': f'Tshoot crashed: {e}'})}\n\n"
    return Response(stream_with_context(stream()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _locked_turn(session, gen_factory):
    """Hold the session lock for the whole streamed turn; release even if the client disconnects.

    The lock is taken inside the generator so a request dropped before
    streaming starts can't leak it.
    """
    def gen():
        if not session.lock.acquire(blocking=False):
            yield {"type": "final", "agent": "error",
                   "content": "Tshoot is still working on the previous request in this conversation."}
            return
        try:
            yield from gen_factory()
        finally:
            session.lock.release()
    return gen()


def _session_from(body):
    sid = str(body.get("session_id") or "")
    if not _SID.match(sid):
        return None, (jsonify({"error": "invalid session_id"}), 400)
    return SESSIONS.get(sid, body.get("history")), None


@app.post("/api/tshoot/chat")
def chat():
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    if not message:
        return jsonify({"error": "empty message"}), 400
    session, err = _session_from(body)
    if err:
        return err
    # Claude is the default (same tools and approvals as Gemini); without a token the chat silently stays on Gemini
    use_claude = body.get("model", "claude") == "claude" and claude_agent.configured()
    return _sse(_locked_turn(session, lambda: AGENT.chat(session, message[:4000], use_claude)))


@app.post("/api/tshoot/approve")
def approve():
    body = request.get_json(silent=True) or {}
    decision = body.get("decision")
    if decision not in ("approve", "reject"):
        return jsonify({"error": "decision must be approve or reject"}), 400
    session, err = _session_from(body)
    if err:
        return err
    # who decided, as identified by the dashboard (Tailscale login + device)
    AUDIT.record("decision", session.id, decision=decision, approval_id=str(body.get("approval_id") or ""),
                 user=request.headers.get("X-Tshoot-User") or "unknown")
    return _sse(_locked_turn(session, lambda: AGENT.resume(
        session, str(body.get("approval_id") or ""), decision == "approve", (body.get("note") or "")[:500])))


@app.post("/api/tshoot/reset")
def reset():
    body = request.get_json(silent=True) or {}
    sid = str(body.get("session_id") or "")
    s = SESSIONS.peek(sid)
    if s and s.pending:
        AUDIT.record("rejected", sid, s.pending.command, "write", decision="rejected", note="conversation reset")
    SESSIONS.drop(sid)
    return jsonify({"ok": True})


@app.get("/api/tshoot/health")
def health():
    return jsonify({"ok": True, "router": _router.get("name"), "host": _router["host"],
                    "model": GEMINI.model.replace("models/", ""),
                    "claude": claude_agent.configured(), "claude_model": claude_agent.model_name()})


@app.get("/api/tshoot/audit")
def audit():
    return jsonify({"entries": AUDIT.recent(min(request.args.get("limit", 100, type=int), 500))})


def main():
    srv = CFG.get("server", {})
    app.run(host=srv.get("host", "127.0.0.1"), port=int(srv.get("port", 8090)), threaded=True)


if __name__ == "__main__":
    main()
