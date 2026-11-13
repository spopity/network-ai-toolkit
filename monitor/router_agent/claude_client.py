"""Claude for the daily analysis (Claude Code via the Claude Agent SDK, on the user's
subscription, the same way Tshoot's chat uses it).

One prompt in, plain text out: no tools at all, one turn, no settings or CLAUDE.md
picked up from disk, and a private config dir so it never touches the interactive
~/.claude. Needs CLAUDE_CODE_OAUTH_TOKEN in .env (from `claude setup-token`);
without it the client reports itself unconfigured and the router skips it.
"""
import asyncio
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
CLAUDE_HOME = STATE_DIR / "claude"        # CLAUDE_CONFIG_DIR and HOME
EMPTY_CWD = STATE_DIR / "claude-empty"


class ClaudeClient:
    def __init__(self, model: str = "opus", timeout: int = 180):
        self.model = model
        self.timeout = timeout

    @staticmethod
    def configured() -> bool:
        return bool(os.getenv("CLAUDE_CODE_OAUTH_TOKEN", "").strip())

    def analyze(self, prompt: str) -> str:
        if not self.configured():
            raise RuntimeError("CLAUDE_CODE_OAUTH_TOKEN not configured")
        return asyncio.run(asyncio.wait_for(self._ask(prompt), self.timeout))

    async def _ask(self, prompt: str) -> str:
        from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

        for d in (CLAUDE_HOME, EMPTY_CWD):
            d.mkdir(parents=True, exist_ok=True)
        options = ClaudeAgentOptions(
            tools=[],
            allowed_tools=[],
            setting_sources=[],
            strict_mcp_config=True,
            cwd=str(EMPTY_CWD),
            env={
                "CLAUDE_CONFIG_DIR": str(CLAUDE_HOME),
                "HOME": str(CLAUDE_HOME),
                "DISABLE_AUTOUPDATER": "1",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_OAUTH_TOKEN": os.environ["CLAUDE_CODE_OAUTH_TOKEN"].strip(),
            },
            model=self.model,
            max_turns=1,
        )
        start = time.monotonic()
        result = None
        async for msg in query(prompt=prompt, options=options):
            if isinstance(msg, ResultMessage):
                result = msg
        if result is None:
            raise RuntimeError("no result from Claude")
        if result.is_error or not result.result:
            raise RuntimeError(f"Claude failed ({result.subtype}): {(result.result or result.errors or '')!s:.300}")
        u = result.usage or {}
        logger.info("llm service=claude model=%s duration_ms=%d input_tokens=%d output_tokens=%d",
                    self.model, (time.monotonic() - start) * 1000,
                    u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0),
                    u.get("output_tokens", 0))
        return result.result
