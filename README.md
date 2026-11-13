# Network AI — ASUS router monitoring + AI troubleshooting

A self-hosted toolkit for an ASUS router running Asuswrt-Merlin (developed against an
RT-AX88U Pro with an AiMesh setup). Two cooperating projects:

| Folder | What it does |
|---|---|
| [`monitor/`](monitor/) | SSH collector, log summarizer, PPPoE watchdog, Postgres archive and a React/TypeScript dashboard. Checks run every 5 minutes with no LLM; one LLM analysis runs per day over a compressed 24 h rollup, trying Claude, Gemini and local Ollama in a configurable order. Also: AdGuardHome query log per device, per-device internet usage from the firmware's Traffic Analyzer, a DNS filtering health check, a local NTP server for every network, and daily router backups. |
| [`tshoot/`](tshoot/) | "Tshoot", a function-calling agent that troubleshoots the router over SSH from a chat tab in the dashboard. Claude (via the Claude Agent SDK) answers read-only by default, with Gemini as a selectable model and automatic fallback. Read-only diagnostics run freely, changes need an explicit Approve/Reject, and destructive commands (factory reset, flash writes…) are always blocked. A rule-based policy does the classification, not the LLM. |

## Highlights

- **Token-frugal LLM use**: logs are turned into message templates with counts before an LLM sees them, so no raw log line is sent.
- **Safety-first agent**: allowlist command policy, secret redaction (PSKs, passwords, keys) before output reaches the LLM/UI, and an audit trail in JSONL and Postgres.
- **Router-pushed events**: a Merlin `wan-event` hook reports WAN state changes to the dashboard.
- **DNS and usage visibility**: per-device DNS lookups from AdGuardHome and per-device/per-app internet usage from the Traffic Analyzer, archived in Postgres, with a hide list for domains/apps you never want stored.
- **DNS health check**: every 5 minutes, checks that DNS answers and is actually filtered by AdGuardHome (not the unfiltered dnsmasq fallback), and logs state changes.
- **Local NTP for all networks**: Guest and IoT (SDN) networks get time from the router too, via `router/ntp-sdn`, a NAT redirect and DHCP option 42.
- **Mobile-friendly dashboard**: React + Tailwind v4, served as static files by Flask (no Node process in production).

## Getting started

Each folder has its own README with setup steps. In short:

1. Copy `config.example.yml` → `config.yml` and `.env.example` → `.env` in each project, then fill in your router IP, SSH key path, a Claude token (`claude setup-token`) and/or Gemini API key, and (optionally) Postgres credentials.
2. Use SSH **key** auth to the router; never commit `config.yml` or `.env` (both are git-ignored).
3. The systemd units assume the projects live in `/opt/network-ai` (contents of `monitor/`) and `/opt/tshoot`. Adjust the paths if you install elsewhere.

## Stack

Python 3 · Paramiko · Flask (SSE) · Claude Agent SDK · Gemini API / Ollama · PostgreSQL · React · TypeScript · Vite · Tailwind CSS · systemd
