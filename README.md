# Network AI — ASUS router monitoring + AI troubleshooting

A self-hosted toolkit for an ASUS router running Asuswrt-Merlin (developed against an
RT-AX88U Pro with an AiMesh setup). Two cooperating projects:

| Folder | What it does |
|---|---|
| [`monitor/`](monitor/) | SSH collector, log summarizer, PPPoE watchdog, Postgres archive and a React/TypeScript dashboard. Checks run every 5 minutes with no LLM; one Gemini (or local Ollama) analysis runs per day over a compressed 24 h rollup. |
| [`tshoot/`](tshoot/) | "Tshoot", a Gemini function-calling agent that troubleshoots the router over SSH from a chat tab in the dashboard. Read-only diagnostics run freely, changes need an explicit Approve/Reject, and destructive commands (factory reset, flash writes…) are always blocked. A rule-based policy does the classification, not the LLM. |

## Highlights

- **Token-frugal LLM use**: logs are turned into message templates with counts before an LLM sees them, so no raw log line is sent.
- **Safety-first agent**: allowlist command policy, secret redaction (PSKs, passwords, keys) before output reaches the LLM/UI, and an audit trail in JSONL and Postgres.
- **Router-pushed events**: a Merlin `wan-event` hook reports WAN state changes to the dashboard.
- **Mobile-friendly dashboard**: React + Tailwind v4, served as static files by Flask (no Node process in production).

## Getting started

Each folder has its own README with setup steps. In short:

1. Copy `config.example.yml` → `config.yml` and `.env.example` → `.env` in each project, then fill in your router IP, SSH key path, Gemini API key and (optionally) Postgres credentials.
2. Use SSH **key** auth to the router; never commit `config.yml` or `.env` (both are git-ignored).
3. The systemd units assume the projects live in `/opt/network-ai` (contents of `monitor/`) and `/opt/tshoot`. Adjust the paths if you install elsewhere.

## Stack

Python 3 · Paramiko · Flask (SSE) · Gemini API / Ollama · PostgreSQL · React · TypeScript · Vite · Tailwind CSS · systemd
