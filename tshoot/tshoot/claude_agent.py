"""Read-only chat answers from Claude (Claude Code via the Claude Agent SDK, on the user's subscription).

Claude gets none of Claude Code's built-in tools -- only Tshoot's read-only
tools, served from an in-process MCP server. Tool names are checked against a
hard-coded allowlist, so a state-changing tool can never be handed to Claude by
accident. Without ``CLAUDE_CODE_OAUTH_TOKEN`` in .env the chat stays on Gemini.
"""
import asyncio
import json
import logging
import os
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from claude_agent_sdk import (AssistantMessage, CanUseToolShadowedWarning, ClaudeAgentOptions, PermissionResultAllow,
                              PermissionResultDeny, ResultMessage, create_sdk_mcp_server, query, tool)

logger = logging.getLogger(__name__)
warnings.simplefilter("ignore", CanUseToolShadowedWarning)  # allowed tools skip can_use_tool; that's intended

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
CLAUDE_HOME = STATE_DIR / "claude"        # CLAUDE_CONFIG_DIR and HOME; never the interactive ~/.claude
EMPTY_CWD = STATE_DIR / "claude-empty"
SERVER = "tshoot"
MAX_TURNS = 25

# Tools Claude may ever see. run_command is Tshoot's read-only variant: the agent
# refuses anything the policy doesn't classify as read (see TshootAgent._handle_call).
READ_ONLY_TOOLS = {"run_command", "get_monitor_snapshot"}

FALLBACK_NOTE = "_Claude was unavailable, so Gemini answered this one._\n\n"


class ClaudeError(RuntimeError):
    pass


def configured() -> bool:
    return bool(os.getenv("CLAUDE_CODE_OAUTH_TOKEN", "").strip())


def model_name() -> str:
    return os.getenv("CLAUDE_CHAT_MODEL", "").strip() or "opus"


def _sdk_tool(decl: dict, call_tool: Callable[[str, dict], dict]):
    schema = {k: v for k, v in (decl.get("parameters") or {"type": "object", "properties": {}}).items() if k != "title"}

    @tool(decl["name"], decl["description"], schema)
    async def handler(args):
        try:
            out = await asyncio.to_thread(call_tool, decl["name"], args or {})
        except Exception as e:
            logger.warning("claude tool %s failed: %s", decl["name"], e)
            return {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "is_error": True}
        return {"content": [{"type": "text", "text": json.dumps(out, default=str)}]}

    return handler


def _prompt(prior_messages: list, question: str) -> str:
    lines = []
    for m in prior_messages:
        text = (m.get("content") or "").strip()
        if text:
            lines.append(f"{'User' if m.get('role') == 'user' else 'Assistant'}: {text}")
    if not lines:
        return question
    return "Conversation so far (oldest first):\n" + "\n\n".join(lines) + f"\n\nNew message from the user:\n{question}"


async def _ask(component: str, system_prompt: str, tools: list, call_tool, prior_messages: list, question: str):
    decls = []
    for d in tools:
        if d["name"] in READ_ONLY_TOOLS:
            decls.append(d)
        else:
            logger.warning("claude: dropping tool %s (not on the read-only allowlist)", d["name"])
    allowed = [f"mcp__{SERVER}__{d['name']}" for d in decls]

    async def can_use_tool(name, _input, _context):
        if name in allowed:
            return PermissionResultAllow()
        logger.warning("claude: denied tool %s", name)
        return PermissionResultDeny(message="Not available: Tshoot's Claude mode is read-only.")

    async def stream():
        yield {"type": "user", "message": {"role": "user", "content": _prompt(prior_messages, question)}}

    for d in (CLAUDE_HOME, EMPTY_CWD):
        d.mkdir(parents=True, exist_ok=True)
    env = {
        "CLAUDE_CONFIG_DIR": str(CLAUDE_HOME),
        "HOME": str(CLAUDE_HOME),
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }
    if configured():
        env["CLAUDE_CODE_OAUTH_TOKEN"] = os.environ["CLAUDE_CODE_OAUTH_TOKEN"].strip()
    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        tools=[],
        mcp_servers={SERVER: create_sdk_mcp_server(name=SERVER, tools=[_sdk_tool(d, call_tool) for d in decls])},
        allowed_tools=allowed,
        strict_mcp_config=True,
        setting_sources=[],
        can_use_tool=can_use_tool,
        cwd=str(EMPTY_CWD),
        env=env,
        model=model_name(),
        max_turns=MAX_TURNS,
    )

    start = time.monotonic()
    result, used_model = None, None
    async for msg in query(prompt=stream(), options=options):
        if isinstance(msg, AssistantMessage):
            used_model = msg.model or used_model
        elif isinstance(msg, ResultMessage):
            result = msg
    if result is None:
        raise ClaudeError("no result from Claude")
    if result.is_error or not result.result:
        raise ClaudeError(f"Claude failed ({result.subtype}): {(result.result or result.errors or '')!s:.300}")

    u = result.usage or {}
    logger.info("llm service=claude component=%s model=%s duration_ms=%d turns=%s input_tokens=%d output_tokens=%d cost=0",
                component, used_model or model_name(), (time.monotonic() - start) * 1000, result.num_turns,
                u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0),
                u.get("output_tokens", 0))
    return result.result, used_model or model_name()


def ask_claude(component: str, system_prompt: str, tools: list, call_tool: Callable[[str, dict], dict],
               prior_messages: list, question: str) -> tuple[str, str]:
    """Blocking. Returns (answer, model); raises on any failure so the caller can fall back to Gemini.

    ``tools`` are Gemini-style declarations; ``call_tool(name, args)`` runs one and returns a JSON-able dict.
    """
    coro = _ask(component, system_prompt, tools, call_tool, prior_messages, question)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()
