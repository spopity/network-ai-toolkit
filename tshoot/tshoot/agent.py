"""The Tshoot agent loop.

A turn is a generator of UI events (dicts). It alternates Gemini calls and tool
executions until Gemini answers in plain text, or until a state-changing
command needs the user's approval -- then the turn ends and the session keeps
the pending call. ``resume()`` runs (or rejects) it and continues the loop.

With ``use_claude`` a chat turn goes to Claude instead, with the same tools and
the same approval flow: a state-changing call becomes the session's pending
change and Claude ends its turn; after the user decides, the outcome is sent to
Claude as the next message. If Claude fails, Gemini answers the turn.
"""
import json
import logging
import queue
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import requests

from . import claude_agent, policy
from .audit import AuditLog
from .gemini import Gemini, GeminiError
from .prompt import CLAUDE_APPROVAL_NOTE, FIX_STEP, POLICY_RULE, SYSTEM_PROMPT, TOOLS
from .redact import redact
from .ssh import CommandResult, RouterShell

MAX_STEPS = 20              # Gemini calls per turn
MODEL_OUTPUT_CHARS = 12_000  # per command, sent to Gemini
UI_OUTPUT_CHARS = 64_000     # per command, sent to the browser
MAX_CONTENTS = 80            # history entries kept per session
SESSION_TTL = 6 * 3600

logger = logging.getLogger(__name__)


@dataclass
class Pending:
    id: str
    command: str
    call: dict                 # the functionCall part
    responses: list            # functionResponse parts for the same model turn, None at this call's slot
    slot: int
    details: dict
    model: str = "gemini"      # who proposed it, and so who continues once the user decides


@dataclass
class Session:
    id: str
    contents: list = field(default_factory=list)
    pending: Pending | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    touched: float = field(default_factory=time.time)


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str, seed_history: list | None = None) -> Session:
        with self._lock:
            now = time.time()
            for sid in [s for s, v in self._sessions.items() if now - v.touched > SESSION_TTL]:
                del self._sessions[sid]
            s = self._sessions.get(session_id)
            if s is None:
                s = Session(session_id)
                # server restarted / session expired: rebuild plain-text context from the browser's copy
                for m in (seed_history or [])[-12:]:
                    text = (m.get("content") or "").strip()
                    if text and m.get("role") in ("user", "assistant"):
                        s.contents.append({"role": "user" if m["role"] == "user" else "model",
                                           "parts": [{"text": text}]})
                self._sessions[session_id] = s
            s.touched = now
            return s

    def peek(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def drop(self, session_id: str):
        with self._lock:
            self._sessions.pop(session_id, None)


def _clip_for_model(text: str) -> str:
    if len(text) <= MODEL_OUTPUT_CHARS:
        return text
    half = MODEL_OUTPUT_CHARS // 2
    return f"{text[:half]}\n... [{len(text) - MODEL_OUTPUT_CHARS} chars omitted] ...\n{text[-half:]}"


def _fn_response(call: dict, payload: dict) -> dict:
    resp = {"name": call["name"], "response": payload}
    if call.get("id"):
        resp["id"] = call["id"]
    return {"functionResponse": resp}


def _run_with_heartbeat(fn: Callable, label: str, every: float = 8.0, events: queue.Queue | None = None) -> Iterator:
    """Run ``fn`` in a thread, yielding status events while it works; the last item is ('result', value).

    ``fn`` may put ("event", dict) items on ``events`` to have them yielded as they happen.
    """
    q: queue.Queue = events or queue.Queue()

    def worker():
        try:
            q.put(("ok", fn()))
        except Exception as e:  # surfaced to the caller below
            q.put(("err", e))

    threading.Thread(target=worker, daemon=True).start()
    start = time.monotonic()
    while True:
        try:
            status, value = q.get(timeout=every)
        except queue.Empty:
            yield {"type": "status", "content": f"{label} ({int(time.monotonic() - start)}s)"}
            continue
        if status != "event":
            break
        yield value
    if status == "err":
        raise value
    yield ("result", value)


class TshootAgent:
    def __init__(self, cfg: dict, gemini: Gemini, shell: RouterShell, audit: AuditLog):
        self.cfg = cfg
        self.gemini = gemini
        self.shell = shell
        self.audit = audit
        self.cmd_timeout = int(cfg.get("limits", {}).get("command_timeout_seconds", 30))
        self.change_timeout = int(cfg.get("limits", {}).get("change_timeout_seconds", 90))
        router = cfg["router"]
        fmt = {"router_name": router.get("name", "router"), "router_host": router["host"], "cmd_timeout": self.cmd_timeout}
        self.system = SYSTEM_PROMPT.format(fix_step=FIX_STEP, policy_rule=POLICY_RULE, **fmt)
        self.system_claude = self.system + CLAUDE_APPROVAL_NOTE
        mon = cfg.get("monitor", {})
        self.latest_path = Path(mon.get("latest_json", "/opt/network-ai/logs/latest.json"))
        self.watchdog_path = Path(mon.get("watchdog_status_json", "/opt/network-ai/logs/watchdog_status.json"))
        self.monitor_api = mon.get("api_url", "http://127.0.0.1:8080").rstrip("/")

    # ------------------------------------------------------------ public API

    def chat(self, session: Session, message: str, use_claude: bool = False) -> Iterator[dict]:
        self._repair(session)
        parts = []
        if session.pending:
            # user moved on without deciding: treat the pending change as rejected
            p = session.pending
            parts += self._reject_parts(session, p, "User sent a new message instead of approving.")
            yield {"type": "approval_update", "id": p.id, "status": "superseded"}
        prior = self._text_history(session)
        parts.append({"text": message})
        session.contents.append({"role": "user", "parts": parts})
        if use_claude:
            yield from self._claude_turn(session, prior, message)
        else:
            yield from self._loop(session)

    def resume(self, session: Session, approval_id: str, approve: bool, note: str = "") -> Iterator[dict]:
        p = session.pending
        if not p or p.id != approval_id:
            yield {"type": "approval_update", "id": approval_id, "status": "expired"}
            yield {"type": "error", "content": "That approval is no longer pending (it expired or was superseded)."}
            return
        if not approve:
            parts = self._reject_parts(session, p, note or "Rejected by user.")
            yield {"type": "approval_update", "id": p.id, "status": "rejected"}
            if p.model == "claude":
                yield from self._claude_continue(session, parts[0]["text"])
                return
            session.contents.append({"role": "user", "parts": parts})
            yield from self._loop(session)
            return

        session.pending = None
        verdict = policy.classify(p.command)
        if verdict.kind == policy.BLOCKED:  # defence in depth; can't normally happen
            payload = {"status": "blocked", "reason": verdict.reason}
            yield {"type": "approval_update", "id": p.id, "status": "blocked"}
        else:
            yield {"type": "approval_update", "id": p.id, "status": "approved"}
            self.audit.record("approved", session.id, p.command, policy.WRITE, decision="approved", note=note)
            result = None
            for ev in self._execute(session, p.command, policy.WRITE, p.details.get("reason", ""), self.change_timeout):
                if isinstance(ev, tuple):
                    result = ev[1]
                else:
                    yield ev
            payload = {"status": "approved_and_executed", **self._result_payload(p.command, result)}
            if note:
                payload["user_note"] = note
        if p.model == "claude":
            yield from self._claude_continue(session, (
                f"[Outcome of the proposed change `{p.command}`: "
                f"{json.dumps(payload, ensure_ascii=False, default=str)}]\nContinue: verify the result."))
            return
        responses = list(p.responses)
        responses[p.slot] = _fn_response(p.call, payload)
        session.contents.append({"role": "user", "parts": responses})
        yield from self._loop(session)

    # ------------------------------------------------------------ loop

    def _claude_continue(self, session: Session, outcome: str) -> Iterator[dict]:
        """After the user decided on a change Claude proposed: hand Claude the outcome."""
        prior = self._text_history(session)
        session.contents.append({"role": "user", "parts": [{"text": outcome}]})
        yield from self._claude_turn(session, prior, outcome)

    def _claude_turn(self, session: Session, prior: list, message: str) -> Iterator[dict]:
        yield {"type": "status", "content": "Engaging Claude…"}
        events: queue.Queue = queue.Queue()

        def call_tool(name: str, args: dict) -> dict:
            # runs on Claude's tool thread; UI events are relayed through the queue
            if session.pending and name in ("run_command", "propose_change") and \
                    policy.classify((args.get("command") or "").strip()).kind == policy.WRITE:
                return {"status": "skipped", "reason": "Another change is already awaiting the user's approval; "
                                                       "end your reply now and wait for the decision."}
            payload = None
            for ev in self._handle_call(session, {"name": name, "args": args}, 0):
                if isinstance(ev, Pending):
                    ev.model = "claude"
                    session.pending = ev
                    payload = {"status": "awaiting_approval", "approval_id": ev.id,
                               "note": "Not run yet. The user is shown an Approve/Reject card. Make no more tool "
                                       "calls; end your reply now. The decision and result arrive as the next message."}
                elif isinstance(ev, tuple):
                    payload = ev[1]["functionResponse"]["response"]
                elif isinstance(ev, dict):
                    events.put(("event", ev))
            return payload

        answer = None
        try:
            for ev in _run_with_heartbeat(
                    lambda: claude_agent.ask_claude("tshoot_chat", self.system_claude, TOOLS, call_tool,
                                                    prior, message), "Claude is thinking", events=events):
                if isinstance(ev, tuple):
                    answer = ev[1]
                else:
                    yield ev
        except Exception as e:
            logger.warning("Claude unavailable, Gemini answers instead: %s", e)
            if session.pending and session.pending.model == "claude":  # proposed, but the turn never finished
                p, session.pending = session.pending, None
                self.audit.record("rejected", session.id, p.command, policy.WRITE, decision="dropped",
                                  note="Claude failed before the proposal was shown")
            yield from self._loop(session, prefix=claude_agent.FALLBACK_NOTE)
            return
        text, model = answer
        model = model if model.startswith("claude") else f"claude-{model}"
        session.contents.append({"role": "model", "parts": [{"text": text}]})  # keeps context if the user switches to Gemini
        p = session.pending
        if p and p.model == "claude":
            yield {"type": "approval", "id": p.id, "command": p.command, **p.details}
            yield self._final(text or "I'd like to make a change -- please review it below.", model=model,
                              awaiting_approval=p.id)
            return
        yield self._final(text, model=model)

    def _loop(self, session: Session, prefix: str = "") -> Iterator[dict]:
        system, tools = self.system, TOOLS
        for step in range(MAX_STEPS):
            self._trim(session)
            yield {"type": "status", "content": "Tshoot is analyzing…" if step == 0 else "Reviewing results…"}
            content = None
            try:
                for ev in _run_with_heartbeat(
                        lambda: self.gemini.generate(session.contents, system, tools), "Thinking"):
                    if isinstance(ev, tuple):
                        content = ev[1]
                    else:
                        yield ev
            except GeminiError as e:
                yield {"type": "final", "agent": "error", "content": f"Gemini call failed: {e}"}
                return
            session.contents.append(content)

            text = "\n".join(p["text"] for p in content["parts"] if p.get("text") and not p.get("thought")).strip()
            calls = [p["functionCall"] for p in content["parts"] if "functionCall" in p]
            if not calls:
                yield self._final(prefix + (text or "(no answer)"))
                return

            if text:
                yield {"type": "note", "content": text}

            responses: list = []
            pending: Pending | None = None
            for call in calls:
                if pending:
                    responses.append(_fn_response(call, {
                        "status": "skipped",
                        "reason": "Another change is already awaiting the user's approval; propose one change at a time."}))
                    continue
                result_part = None
                for ev in self._handle_call(session, call, len(responses)):
                    if isinstance(ev, Pending):
                        pending = ev
                    elif isinstance(ev, tuple):
                        result_part = ev[1]
                    else:
                        yield ev
                responses.append(result_part)  # None at the pending slot

            if pending:
                pending.responses = responses
                session.pending = pending
                yield {"type": "approval", "id": pending.id, "command": pending.command, **pending.details}
                yield self._final(text or "I'd like to make a change -- please review it below.",
                                  awaiting_approval=pending.id)
                return
            session.contents.append({"role": "user", "parts": responses})

        yield self._final(prefix + f"I've used {MAX_STEPS} reasoning steps on this without finishing. "
                          "Tell me to continue, or narrow the question.")

    def _handle_call(self, session: Session, call: dict, slot: int) -> Iterator:
        name = call.get("name")
        args = call.get("args") or {}

        if name == "get_monitor_snapshot":
            yield ("result", _fn_response(call, self._monitor_snapshot()))
            return

        if name == "get_dns_lookups":
            yield ("result", _fn_response(call, self._dns_lookups(args)))
            return

        if name == "get_traffic_usage":
            yield ("result", _fn_response(call, self._traffic_usage(args)))
            return

        if name not in ("run_command", "propose_change"):
            yield ("result", _fn_response(call, {"status": "error", "reason": f"unknown tool {name}"}))
            return

        command = (args.get("command") or "").strip()
        verdict = policy.classify(command)
        purpose = args.get("purpose") or args.get("reason") or ""

        if verdict.kind in (policy.BLOCKED, policy.REFUSED):
            self.audit.record(verdict.kind, session.id, command, verdict.kind, reason=verdict.reason)
            yield {"type": "command", "id": uuid.uuid4().hex[:10], "command": command, "kind": verdict.kind,
                   "purpose": purpose, "status": verdict.kind, "reason": verdict.reason}
            yield ("result", _fn_response(call, {"status": verdict.kind, "reason": verdict.reason}))
            return

        if name == "run_command" and verdict.kind == policy.WRITE and verdict.opaque:
            reason = (f"Not run: {verdict.reason}. Rewrite it with literal values (look them up with a separate "
                      "command first) and without $(...), backticks, '>' redirection or '&'. If you really intend "
                      "a change, use propose_change.")
            yield {"type": "command", "id": uuid.uuid4().hex[:10], "command": command, "kind": policy.REFUSED,
                   "purpose": purpose, "status": policy.REFUSED, "reason": verdict.reason}
            yield ("result", _fn_response(call, {"status": policy.REFUSED, "reason": reason}))
            return

        if verdict.kind == policy.READ:
            result = None
            for ev in self._execute(session, command, policy.READ, purpose, self.cmd_timeout):
                if isinstance(ev, tuple):
                    result = ev[1]
                else:
                    yield ev
            yield ("result", _fn_response(call, {"status": "executed", **self._result_payload(command, result)}))
            return

        # state-changing -> approval
        details = {
            "reason": args.get("reason") or purpose or "",
            "expected_effect": args.get("expected_effect") or "",
            "rollback": args.get("rollback") or "",
            "risk": verdict.risk,
            "warnings": verdict.warnings,
            "policy_reason": verdict.reason,
        }
        p = Pending(id=uuid.uuid4().hex[:12], command=command, call=call, responses=[], slot=slot, details=details)
        self.audit.record("proposed", session.id, command, policy.WRITE, risk=verdict.risk, **{
            k: details[k] for k in ("reason", "expected_effect", "rollback")})
        yield p

    def _execute(self, session: Session, command: str, kind: str, purpose: str, timeout: int) -> Iterator:
        cid = uuid.uuid4().hex[:10]
        yield {"type": "command", "id": cid, "command": command, "kind": kind, "purpose": purpose, "status": "running"}
        result: CommandResult = None
        try:
            for ev in _run_with_heartbeat(lambda: self.shell.run(command, timeout=timeout), f"Running `{command[:60]}`"):
                if isinstance(ev, tuple):
                    result = ev[1]
                else:
                    yield ev
        except Exception as e:
            result = CommandResult(command, "", None, 0, error=str(e))
        result.output = redact(command, result.output)
        self.audit.record("executed", session.id, command, kind, exit_code=result.exit_code,
                          duration_ms=result.duration_ms, timed_out=result.timed_out, error=result.error,
                          output=result.output[:20_000])
        yield {"type": "command_result", "id": cid, "exit_code": result.exit_code, "duration_ms": result.duration_ms,
               "output": result.output[-UI_OUTPUT_CHARS:], "timed_out": result.timed_out,
               "truncated": result.truncated or len(result.output) > UI_OUTPUT_CHARS, "error": result.error}
        yield ("result", result)

    # ------------------------------------------------------------ helpers

    def _result_payload(self, command: str, r: CommandResult) -> dict:
        out = {"exit_code": r.exit_code, "duration_ms": r.duration_ms, "output": _clip_for_model(r.output)}
        if r.timed_out:
            out["note"] = f"timed out and was killed after {r.duration_ms // 1000}s"
        if r.truncated:
            out["note"] = "output exceeded the size cap and was cut"
        if r.error:
            out["error"] = r.error
            if "reboot" in command:
                out["note"] = "connection loss is expected after a reboot; wait ~3 min before checking again"
        return out

    def _reject_parts(self, session: Session, p: Pending, note: str) -> list:
        session.pending = None
        self.audit.record("rejected", session.id, p.command, policy.WRITE, decision="rejected", note=note)
        if p.model == "claude":  # Claude's history is plain text, not function calls
            return [{"text": f"[The proposed change `{p.command}` was NOT applied -- rejected by the user: {note}]"}]
        responses = list(p.responses)
        responses[p.slot] = _fn_response(p.call, {"status": "rejected_by_user", "note": note})
        return responses

    def _final(self, text: str, model: str | None = None, **extra) -> dict:
        model = model or (self.gemini.last_model_version or self.gemini.model).replace("models/", "")
        return {"type": "final", "agent": "tshoot", "model": model, "content": text, **extra}

    def _text_history(self, session: Session) -> list:
        """Plain-text turns of the conversation (no tool calls or results), for Claude's prompt."""
        out = []
        for c in session.contents:
            text = "\n".join(p["text"] for p in c["parts"] if p.get("text") and not p.get("thought")).strip()
            if text:
                out.append({"role": "user" if c["role"] == "user" else "assistant", "content": text})
        return out[-24:]

    def _repair(self, session: Session):
        """A stream aborted mid-turn can leave unanswered function calls; answer them so history stays valid."""
        if session.pending or not session.contents:
            return
        last = session.contents[-1]
        if last.get("role") == "model":
            calls = [p["functionCall"] for p in last["parts"] if "functionCall" in p]
            if calls:
                session.contents.append({"role": "user", "parts": [
                    _fn_response(c, {"status": "cancelled", "reason": "user stopped the turn"}) for c in calls]})

    def _trim(self, session: Session):
        c = session.contents
        if len(c) <= MAX_CONTENTS:
            return
        cut = len(c) - MAX_CONTENTS
        # restart history at a plain user message so no functionResponse is orphaned
        while cut < len(c) - 1 and not (c[cut]["role"] == "user" and any("text" in p for p in c[cut]["parts"])
                                        and not any("functionResponse" in p for p in c[cut]["parts"])):
            cut += 1
        del c[:cut]

    def _dns_lookups(self, args: dict) -> dict:
        """Read-only query of network-ai's AdGuardHome archive (its /api/dns/* endpoints)."""
        params = {"hours": int(args.get("hours") or 24)}
        for k in ("device", "domain", "network"):
            if (args.get(k) or "").strip():
                params[k] = args[k].strip()
        filtered = any(k in params for k in ("device", "domain")) or args.get("blocked_only") or args.get("new_only")
        if args.get("blocked_only"):
            params["blocked"] = 1
        if args.get("new_only"):
            params["new"] = 1
        params["limit"] = max(1, min(int(args.get("limit") or 100), 500))
        path = "/api/dns/lookups" if filtered else "/api/dns/devices"
        try:
            r = requests.get(self.monitor_api + path, params=params, timeout=15)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            return {"status": "unavailable", "reason": f"network-ai DNS archive unreachable: {e}"}
        if not data.get("available"):
            return {"status": "unavailable", "reason": data.get("error", "archive unavailable")}
        rows = data.get("lookups") if filtered else data.get("devices")
        if not filtered:
            rows = rows[:params["limit"]]
        return {"status": "ok", "hours": data.get("hours"), "kind": "lookups" if filtered else "devices",
                "rows": rows, "truncated": len(rows) >= params["limit"]}

    def _traffic_usage(self, args: dict) -> dict:
        """Read-only query of network-ai's Traffic Analyzer archive (its /api/traffic/* endpoints)."""
        limit = max(1, min(int(args.get("limit") or 30), 200))
        params = {"hours": int(args.get("hours") or 24), "limit": limit}
        for k in ("device", "network"):
            if (args.get(k) or "").strip():
                params[k] = args[k].strip()
        per_device = "device" in params
        path = "/api/traffic/detail" if per_device else "/api/traffic/devices"
        try:
            r = requests.get(self.monitor_api + path, params=params, timeout=15)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            return {"status": "unavailable", "reason": f"network-ai traffic archive unreachable: {e}"}
        if not data.get("available"):
            return {"status": "unavailable", "reason": data.get("error", "archive unavailable")}
        if per_device:
            # drop empty hours so a quiet device doesn't cost hundreds of zero rows
            series = [s for s in data.get("series") or [] if s.get("rx") or s.get("tx")]
            return {"status": "ok", "hours": data.get("hours"), "kind": "device", "units": "bytes",
                    "apps": data.get("apps") or [], "hourly": series}
        rows = (data.get("devices") or [])[:limit]
        return {"status": "ok", "hours": data.get("hours"), "kind": "devices", "units": "bytes",
                "rows": rows, "truncated": len(data.get("devices") or []) > limit}

    def _monitor_snapshot(self) -> dict:
        def load(p: Path):
            try:
                return json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                return None

        latest = load(self.latest_path) or {}
        snap = dict(latest.get("snapshot") or {})
        sec = dict(snap.get("security") or {})
        for k in ("syslog_tail", "security_log_tail", "aae_log_tail"):
            summary_key = k.replace("_tail", "_summary")
            if sec.get(summary_key):
                sec.pop(k, None)  # the monitor's templated summary replaces raw lines; run_command for raw logs
            elif isinstance(sec.get(k), str):
                sec[k] = "\n".join(sec[k].splitlines()[-25:])
        if sec:
            snap["security"] = sec
        wd = load(self.watchdog_path) or {}
        if isinstance(wd.get("history"), list):
            wd["history"] = wd["history"][-30:]
        if not snap and not wd:
            return {"status": "unavailable", "reason": "monitor has not produced a snapshot yet"}
        # live WAN transitions pushed by the router's Merlin wan-event hook (JSONL, newest last)
        router_events = []
        try:
            for line in (self.latest_path.parent / "router_events.log").read_text().splitlines()[-20:]:
                router_events.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
        return {"status": "ok", "snapshot": snap, "analysis": latest.get("analysis"), "watchdog": wd,
                "router_wan_events": router_events}
