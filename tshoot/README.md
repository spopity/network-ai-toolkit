# Tshoot — ASUS router troubleshooting agent

Chat-driven troubleshooting for the ASUS RT-AX88U Pro (Asuswrt-Merlin). Tshoot
is a Gemini function-calling agent that diagnoses and fixes issues over the
router's SSH CLI. You talk to it from the **Tshoot** tab of the network-ai
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

## Layout

- `tshoot/policy.py` — command classifier (tests in `tests/`)
- `tshoot/agent.py` — agent loop, sessions, approval pause/resume
- `tshoot/prompt.py` — system prompt (ASUSWRT expertise) + tool declarations
- `tshoot/gemini.py` — Gemini `generateContent` client (keeps thought signatures)
- `tshoot/ssh.py` — persistent SSH shell with timeouts/output caps
- `tshoot/redact.py` — secret masking
- `tshoot/audit.py` — JSONL + Postgres audit trail
- `tshoot/app.py` — Flask SSE API on `127.0.0.1:8090`

API (same SSE wire format as the AI Coach chat — `data: {json}\n\n`):
`POST /api/tshoot/chat`, `POST /api/tshoot/approve`, `POST /api/tshoot/reset`,
`GET /api/tshoot/health`, `GET /api/tshoot/audit`.

## Setup / running

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yml config.yml && cp .env.example .env   # fill in
.venv/bin/python -m pytest            # policy + redaction tests
.venv/bin/python -m tshoot.app        # foreground

sudo cp systemd/tshoot.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tshoot.service
```

Conversations live in memory (6 h idle TTL), and the browser keeps its own
copy. After a restart, a conversation continues from the browser's text
history, but a pending approval expires.
