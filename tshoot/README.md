# Tshoot — ASUS router troubleshooting agent

Chat-driven troubleshooting for the ASUS RT-AX88U Pro (Asuswrt-Merlin). Tshoot
is a function-calling agent that diagnoses and fixes issues over the router's
SSH CLI. Claude answers by default, read-only; Gemini can also apply fixes
(see [Chat model](#chat-model)). You talk to it from the **Tshoot** tab of the network-ai
dashboard (`http://<dashboard-host>:8080/#/tshoot`).

Tshoot is a separate project from the network-ai analyzer. It has its own venv,
config, `.env` and service, and imports nothing from `/opt/network-ai`. Its
only links to network-ai are:
- it **reads** the analyzer's `logs/latest.json` / `watchdog_status.json`
  (`get_monitor_snapshot` tool),
- the dashboard's Flask app proxies `/api/tshoot/*` → `127.0.0.1:8090`,
- the chat UI lives in `network-ai/dashboard/frontend/src/tshoot/`.

## Safety model

Commands are classified by `tshoot/policy.py`, never by the LLM:

| kind      | what                                                               | behaviour |
|-----------|--------------------------------------------------------------------|-----------|
| `read`    | allowlisted diagnostics (`nvram get`, `wl … status`, `cat`, `iptables -nvL`, `ping -c`…) | runs immediately |
| `write`   | anything else: `nvram set/commit`, `service …`, `reboot`, redirection, unknown binaries | Approve/Reject card in the chat |
| `blocked` | factory reset, NVRAM erase/restore, mtd/flash/firmware writes, `dd`, `halt`, `rm -rf /jffs` | never runs |
| `refused` | read-only but never-ending (`ping` without `-c`, `top` without `-b -n`) | bounced back to the agent |

Unknown commands fall through to `write`, so a person always sees them first.
Disruptive changes (WAN/LAN/Wi-Fi/SSH restarts, reboot, firewall flush) come
with a risk level and warnings on the approval card. Secrets (PSKs,
passwords, private keys) are masked before output reaches Gemini, the UI or
the audit log. Commands time out after 30 s (90 s for approved changes), and
output is capped.

Every command, proposal, approval, rejection and block is written to
`logs/audit.jsonl` and, best-effort, to the `tshoot_audit` table in the
`network_ai` Postgres database.

## Chat model

The chat header has a **Claude / Gemini** selector (remembered per browser,
Claude by default).

- **Claude** (Claude Code via the Claude Agent SDK, on the Claude
  subscription) is **read-only**. It gets only `get_monitor_snapshot` and a
  `run_command` that runs policy-`read` commands; anything else is refused
  unrun, never turned into an approval. There's no `propose_change`, and none
  of Claude Code's built-in tools (Bash, files, web). Asked for a change, it
  recommends the command and rollback and tells you to switch to Gemini.
  `tshoot/claude_agent.py` enforces this with a hard-coded tool allowlist,
  an in-process MCP server, `strict_mcp_config`, no settings sources and a
  deny-by-default `can_use_tool`.
- **Gemini** works as before: diagnostics plus Approve/Reject changes.
- **Fallback:** if Claude fails (expired token, outage...), Gemini answers that
  message in the same read-only mode, prefixed with *"Claude was unavailable,
  so Gemini answered this one."*; the answer's model badge then shows Gemini.
- **No token = Gemini:** without `CLAUDE_CODE_OAUTH_TOKEN` in `.env` the chat
  silently uses Gemini.

Setup: run `.venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude setup-token`
(browser sign-in), put the `sk-ant-oat...` token in `.env` as
`CLAUDE_CODE_OAUTH_TOKEN`, optionally set `CLAUDE_CHAT_MODEL` (default `opus`),
and restart `tshoot.service`. The CLI's config lives in `state/claude`
(git-ignored), never in `~/.claude`. Each Claude call is logged to the journal
(`llm service=claude ...`, tokens, `cost=0` because it's a flat-rate subscription).

## Layout

- `tshoot/policy.py` — command classifier (tests in `tests/`)
- `tshoot/agent.py` — agent loop, sessions, approval pause/resume
- `tshoot/prompt.py` — system prompt (ASUSWRT expertise) + tool declarations
- `tshoot/gemini.py` — Gemini `generateContent` client (keeps thought signatures)
- `tshoot/claude_agent.py` — read-only Claude answers via the Claude Agent SDK
- `tshoot/ssh.py` — persistent SSH shell with timeouts/output caps
- `tshoot/redact.py` — secret masking
- `tshoot/audit.py` — JSONL + Postgres audit trail
- `tshoot/app.py` — Flask SSE API on `127.0.0.1:8090`

API (same SSE wire format as the AI Coach chat — `data: {json}\n\n`):
`POST /api/tshoot/chat` (`model`: `claude` | `gemini`), `POST /api/tshoot/approve`, `POST /api/tshoot/reset`,
`GET /api/tshoot/health`, `GET /api/tshoot/audit`.

## Setup / running

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yml config.yml && cp .env.example .env   # fill in
.venv/bin/python -m pytest            # policy, redaction + read-only mode tests
.venv/bin/python -m tshoot.app        # foreground

sudo cp systemd/tshoot.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tshoot.service
```

Conversations live in memory (6 h idle TTL), and the browser keeps its own
copy. After a restart, a conversation continues from the browser's text
history, but a pending approval expires.
