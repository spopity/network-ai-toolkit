# Network AI — Router Monitoring + PPPoE Watchdog

Monitors an ASUS RT-AX88U Pro (Asuswrt-Merlin since 2026-10-11) over SSH, analyzes logs with an
LLM (Gemini primary, local Ollama fallback), serves a React/TypeScript
dashboard, archives history to Postgres, and auto-restarts the PPPoE
connection after a sustained outage.

## Components

- `router_agent/collector.py` — SSH into the router, run grouped diagnostic commands. The syslog tail excludes firewall `DROP` lines (they're ~97% of the log); those are aggregated into `security.firewall_drops` (top ports/sources) instead.
- `router_agent/snapshot.py` — turn raw command output into a structured snapshot (system/wan/security/wifi).
- `router_agent/summarize.py` — compresses logs before any LLM sees them: each line becomes a message template (IPs/MACs/numbers/JSON → placeholders), repeats are counted with first/last time and sample values, error-like wording is flagged and ranked first. Snapshots store these summaries (`*_summary`) next to a short raw tail for humans; syslog messages are routed to the security/wifi/system prompts by the process that logged them. No raw log line is sent to the LLM.
- `router_agent/llm_client.py` — `GeminiClient`, `OllamaClient`, and `LLMRouter` (tries Gemini, falls back to Ollama per-run if it fails).
- `router_agent/storage.py` — writes timestamped snapshots + `logs/latest.json` (the fast, dependency-free live-state source), prunes old files, and best-effort archives to Postgres.
- `router_agent/db.py` — Postgres archive layer (`network_ai` database). Best-effort only: never blocks or fails a collection/watchdog cycle if Postgres is unreachable.
- `router_agent/events.py` + `router/wan-event` — the router pushes its own WAN state changes: `router/wan-event` is installed on the router as the Merlin hook `/jffs/scripts/wan-event` and POSTs to the dashboard's `/api/router-event` (accepted only from the configured router IPs). Events land in `logs/router_events.log` and the Postgres `watchdog_events` table as `router_wan_<event>`, show up in the dashboard's events table, and the last 24h are fed to the LLM's system analysis.
- `collect_and_analyze.py` — one-shot, two modes. `--mode check` (default; every 5 minutes via `network-ai-check.timer`, and the dashboard's "Check now" button): collect → summarize → track wifi clients → fold into the 24h rollup → store. **Never calls an LLM.** `--mode daily` (once a day via `network-ai-collect.timer`, 03:00 UTC — this machine's timezone is `Etc/UTC`; edit the timer's `OnCalendar=` if that's not your night): the same check, then the **only** LLM pass of the day, over the rollup, then a fresh rollup starts. Runs are serialized with `logs/.run.lock`; check records carry the last daily analysis forward in `latest.json`.
- `router_agent/rollup.py` — day-long aggregation of the checks (`logs/rollup.json`). Each check keeps only the log lines newer than the previous check (timestamp cursor in `logs/.log_cursor.json`, so overlapping tails are never double-counted) and merges their syslog templates and firewall-drop counters, plus peaks/minimums (load, memory, temperatures, wifi clients, WAN-down checks, router reboots). The daily analysis renders it into the LLM's input (`day_summary` in the daily record).
- Storage: daily records `logs/<router>-<ts>.json` (kept `retention_days`), checks gzipped in `logs/checks/` (kept `check_retention_hours`, ~9 KB each). Postgres gets every check too (`kind='check'`, raw log tails stripped); `/api/history` thins checks to ~hourly beyond 2 days. New wifi clients come from `logs/known_clients.json` (a client counts as new for 24 h after it first appears; devices unseen for `retention_days` are forgotten).
- `watchdog.py` — continuous connectivity monitor; restarts WAN (`service restart_wan_if <unit>`) after `down_threshold_seconds` of outage, with a cooldown between attempts. Supports `--dry-run` and `--max-iterations` for safe testing.
- `dashboard/app.py` — Flask backend: serves the built React app as static files, `/api/state` (live), `/api/history` (Postgres-backed trends), `/api/collect-now` + `/api/collect-status` (on-demand trigger).
- `dashboard/app.py` also proxies `/api/tshoot/*` to the separate **Tshoot** troubleshooting agent (`/opt/tshoot`, `127.0.0.1:8090`); its chat UI is the dashboard's Tshoot tab (`dashboard/frontend/src/tshoot/`). See [`../tshoot/README.md`](../tshoot/README.md).
- `dashboard/frontend/` — Vite + React + TypeScript dashboard. `npm run build` outputs static assets Flask serves directly; no Node process runs in production.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yml config.yml   # edit host/credentials
cp .env.example .env               # fill in GEMINI_API_KEY, PG* vars, etc.

cd dashboard/frontend
npm install
npm run build
```

`config.yml` expects SSH key auth (`key_filename`), not a password. The
router-side key persistence (needed because `authorized_keys` lives under a
RAM-backed path on ASUSWRT) is handled by `/jffs/scripts/services-start`
on the router itself, reading the key from `/jffs/network-ai/authorized_keys`.

Postgres is a dedicated, isolated database/role (`network_ai` /
`network_ai_app`) on the existing TimescaleDB-in-Docker instance — it does not
touch any other database there. It's purely an archive: the dashboard's live
state always comes from `logs/latest.json`, so the site keeps working even if
Postgres is briefly unreachable (`/api/history` degrades to an empty-but-valid
payload in that case).

### Router USB stick / amtm add-ons (installed 2026-10-11)

An 8 GB stick (ext4, label `entware`, mounted at `/tmp/mnt/entware`) holds Entware, a 2 GB swap file and:

- **scribe** (syslog-ng + logrotate): main log `/opt/var/log/messages` (`/jffs/syslog.log` symlinks to it), firewall/Skynet lines in `skynet-0.log`, wlceventd in `wlceventd.log`. The collector reads this layout and falls back to `/jffs/syslog.log(-1)` if scribe is absent.
- **Skynet**: IP-blocklist firewall. `security.firewall_drops` aggregates its `[BLOCKED - INBOUND/OUTBOUND]` lines (outbound = a LAN device contacted a blocklisted address) plus blocklist sizes from `ipset`.
- **connmon**: 30 s ping test to 8.8.8.8 every 5 min, SQLite on `/jffs`; `wan.connmon` = 24h aggregates + 7-day baseline, computed on the router.
- **spdMerlin**: speedtest once a day at 04:12 (each test ≈ 2.3 GB; the add-on's default of every 30 min was changed in `/jffs/addons/spdmerlin.d/config` + cron); `wan.speedtest` = latest + 7-day stats.

Entware starts at boot via `/jffs/scripts/post-mount` (amtm's `mount-entware.mod`). Manage add-ons interactively with `amtm` on the router.

### Router-side hook (Asuswrt-Merlin)

Requires Administration → System → "Enable JFFS custom scripts and configs". Install/update:

```bash
ssh admin@192.168.1.1 'cat > /jffs/scripts/wan-event && chmod 755 /jffs/scripts/wan-event' < router/wan-event
```

## Running

```bash
.venv/bin/python3 collect_and_analyze.py --config config.yml   # one collection+analysis cycle
.venv/bin/python3 watchdog.py --config config.yml              # connectivity watchdog (foreground)
.venv/bin/python3 dashboard/app.py                             # dashboard on :8080
```

Frontend development (hot reload, proxies `/api` to Flask on :8080):

```bash
cd dashboard/frontend
npm run dev
```

### Installing as systemd services

```bash
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now network-ai-watchdog.service
sudo systemctl enable --now network-ai-dashboard.service
sudo systemctl enable --now network-ai-collect.timer   # daily LLM analysis
sudo systemctl enable --now network-ai-check.timer     # 5-minute checks, no LLM
```

After changing the frontend, rebuild (`npm run build` in `dashboard/frontend`)
and `sudo systemctl restart network-ai-dashboard.service` — the dashboard
serves whatever is currently in `dashboard/frontend/dist`.

## Known follow-ups (intentionally not done automatically)

- **Router reboot test**: the `/jffs/scripts/services-start` key-persistence fix hasn't been validated against an actual reboot yet — rebooting the router is disruptive and wasn't done without explicit go-ahead.
- **Live PPPoE restart test**: the watchdog's restart trigger logic was dry-run tested (`--dry-run`) against simulated downtime, but a real `service restart_wan_if 0` against the live router hasn't been fired yet — do that deliberately once, at a convenient time, before trusting the 5-minute auto-restart in production.
