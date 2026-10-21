"""The Tshoot agent loop.

A turn is a generator of UI events (dicts). It alternates Gemini calls and tool
executions until Gemini answers in plain text, or until a state-changing
command needs the user's approval -- then the turn ends and the session keeps
the pending call. ``resume()`` runs (or rejects) it and continues the loop.
"""
import json
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from . import policy
from .audit import AuditLog
from .gemini import Gemini, GeminiError
from .prompt import SYSTEM_PROMPT, TOOLS
from .redact import redact
from .ssh import CommandResult, RouterShell

MAX_STEPS = 20              # Gemini calls per turn
MODEL_OUTPUT_CHARS = 12_000  # per command, sent to Gemini
UI_OUTPUT_CHARS = 64_000     # per command, sent to the browser
MAX_CONTENTS = 80            # history entries kept per session
SESSION_TTL = 6 * 3600


@dataclass
class Pending:
    id: str
    command: str
    call: dict                 # the functionCall part
    responses: list            # functionResponse parts for the same model turn, None at this call's slot
    slot: int
    details: dict


@dataclass
class Session:
    id: str
    contents: list = field(default_factory=list)
    pending: Optional[Pending] = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    touched: float = field(default_factory=time.time)


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str, seed_history: list = None) -> Session:
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

    def peek(self, session_id: str) -> Optional[Session]:
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


def _run_with_heartbeat(fn: Callable, label: str, every: float = 8.0) -> Iterator:
    """Run ``fn`` in a thread, yielding status events while it works; the last item is ('result', value)."""
    q: queue.Queue = queue.Queue()

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
            break
        except queue.Empty:
            yield {"type": "status", "content": f"{label} ({int(time.monotonic() - start)}s)"}
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
        self.system = SYSTEM_PROMPT.format(router_name=router.get("name", "router"),
                                           router_host=router["host"], cmd_timeout=self.cmd_timeout)
        mon = cfg.get("monitor", {})
        self.latest_path = Path(mon.get("latest_json", "/opt/network-ai/logs/latest.json"))
        self.watchdog_path = Path(mon.get("watchdog_status_json", "/opt/network-ai/logs/watchdog_status.json"))

    # ------------------------------------------------------------ public API

    def chat(self, session: Session, message: str) -> Iterator[dict]:
        self._repair(session)
        parts = []
        if session.pending:
            # user moved on without deciding: treat the pending change as rejected
            p = session.pending
            parts += self._reject_parts(session, p, "User sent a new message instead of approving.")
            yield {"type": "approval_update", "id": p.id, "status": "superseded"}
        parts.append({"text": message})
        session.contents.append({"role": "user", "parts": parts})
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
        responses = list(p.responses)
        responses[p.slot] = _fn_response(p.call, payload)
        session.contents.append({"role": "user", "parts": responses})
        yield from self._loop(session)

    # ------------------------------------------------------------ loop

    def _loop(self, session: Session) -> Iterator[dict]:
        for step in range(MAX_STEPS):
            self._trim(session)
            yield {"type": "status", "content": "Tshoot is analyzing…" if step == 0 else "Reviewing results…"}
            content = None
            try:
                for ev in _run_with_heartbeat(
                        lambda: self.gemini.generate(session.contents, self.system, TOOLS), "Thinking"):
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
                yield self._final(text or "(no answer)")
                return

            if text:
                yield {"type": "note", "content": text}

            responses: list = []
            pending: Optional[Pending] = None
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

        yield self._final(f"I've used {MAX_STEPS} reasoning steps on this without finishing. "
                          "Tell me to continue, or narrow the question.")

    def _handle_call(self, session: Session, call: dict, slot: int) -> Iterator:
        name = call.get("name")
        args = call.get("args") or {}

        if name == "get_monitor_snapshot":
            yield ("result", _fn_response(call, self._monitor_snapshot()))
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
        responses = list(p.responses)
        responses[p.slot] = _fn_response(p.call, {"status": "rejected_by_user", "note": note})
        return responses

    def _final(self, text: str, **extra) -> dict:
        model = (self.gemini.last_model_version or self.gemini.model).replace("models/", "")
        return {"type": "final", "agent": "tshoot", "model": model, "content": text, **extra}

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
