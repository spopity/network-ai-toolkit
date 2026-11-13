# Network AI — Router Monitoring + PPPoE Watchdog

Monitors an ASUS RT-AX88U Pro (Asuswrt-Merlin since 2026-10-11) over SSH, analyzes logs with an
LLM (Claude, Gemini and local Ollama, tried in the order set by `llm.order`), serves a React/TypeScript
dashboard, archives history to Postgres, and auto-restarts the PPPoE
connection after a sustained outage.

## Components

- `router_agent/collector.py` — SSH into the router, run grouped diagnostic commands. The syslog tail excludes firewall `DROP` lines (they're ~97% of the log); those are aggregated into `security.firewall_drops` (top ports/sources) instead.
- `router_agent/snapshot.py` — turn raw command output into a structured snapshot (system/wan/security/wifi).
- `router_agent/summarize.py` — compresses logs before any LLM sees them: each line becomes a message template (IPs/MACs/numbers/JSON → placeholders), repeats are counted with first/last time and sample values, error-like wording is flagged and ranked first. Snapshots store these summaries (`*_summary`) next to a short raw tail for humans; syslog messages are routed to the security/wifi/system prompts by the process that logged them. No raw log line is sent to the LLM.
- `router_agent/llm_client.py` — `GeminiClient`, `OllamaClient`, and `LLMRouter` (tries the backends in `llm.order`; the first one that answers every prompt writes the whole analysis, and `fallback_reason` records any that failed).
- `router_agent/claude_client.py` — `ClaudeClient`: Claude Code on the user's subscription via the Claude Agent SDK, same as Tshoot's chat. No tools, one turn, private config dir under `state/claude`. Needs `CLAUDE_CODE_OAUTH_TOKEN` in `.env` (`claude setup-token`) and is skipped without it.
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
cp .env.example .env               # fill in CLAUDE_CODE_OAUTH_TOKEN and/or GEMINI_API_KEY, PG* vars, etc.

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

### Firmware update emails (notify only)

`router/update-notification` is installed as the Merlin hook
`/jffs/scripts/update-notification`. The router's own scheduled firmware check
(Administration → Firmware Upgrade → "Scheduled new firmware check", nvram
`firmware_check_enable=1`) calls it when a newer Merlin release is out, and it
**only sends an email** (once per version) -- nothing is downloaded or flashed.
MerlinAU was deliberately not used: it has no notify-only mode and flashes on its
own after its postponement period (max 199 days).

Mail goes through amtm's email settings (`amtm` → `em`); without them the hook
only logs to syslog (`update-notification: new firmware ...`). Install/update and test:

```bash
ssh admin@192.168.1.1 'cat > /jffs/scripts/update-notification && chmod 755 /jffs/scripts/update-notification' < router/update-notification
ssh admin@192.168.1.1 /jffs/scripts/update-notification --test   # sends a test email
```

### Local NTP server (all networks)

Set up 2026-11-13. Every client gets its time from the router, including IoT
devices with hard-coded NTP servers:

- **Main LAN (br0)**: firmware feature, Administration → System → "Enable local
  NTP server" + "Intercept NTP client requests" (nvram `ntpd_enable=1`,
  `ntpd_server_redir=1`). The firmware runs BusyBox `ntpd -l -I br0`, so it only
  answers on br0.
- **Guest (br53) / IoT (br54)**: `router/ntp-sdn` → `/jffs/scripts/ntp-sdn`, a
  second BusyBox ntpd (`-w -l`, never sets the clock) that answers on every other
  interface. Started from `services-start`, watched by the cron job `ntp-sdn`
  (every 10 min, restarts it if it died). `nat-start` REDIRECTs udp/123 from
  br53/br54 to it.
- **DHCP option 42** (NTP server = router) is added on all three networks by
  `dnsmasq.postconf` / `dnsmasq-sdn.postconf`.

Install/update and check:

```bash
ssh admin@192.168.1.1 'cat > /jffs/scripts/ntp-sdn && chmod 755 /jffs/scripts/ntp-sdn' < router/ntp-sdn
ssh admin@192.168.1.1 '/jffs/scripts/ntp-sdn status; iptables -t nat -L PREROUTING -v -n | grep 123'
```

To undo: turn the two firmware options off, `ntp-sdn stop`, and remove the NTP
lines from `services-start`, `nat-start` and both dnsmasq postconf scripts.

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
sudo systemctl enable --now router-backup.timer        # daily router backup, see below
```

After changing the frontend, rebuild (`npm run build` in `dashboard/frontend`)
and `sudo systemctl restart network-ai-dashboard.service` — the dashboard
serves whatever is currently in `dashboard/frontend/dist`.

### Router backups

`router/backup.sh` (run daily at 03:40 UTC by `router-backup.timer`) pulls a
backup over SSH into `/var/backups/router/<UTC timestamp>/` and keeps the
newest 14 (~33 MB each). Nothing is installed on the router. Each backup has
`jffs.tar.gz` (custom scripts, amtm add-ons and their databases), `usb.tar.gz`
(the USB stick's `entware/` and `skynet/`, without the 2 GB swap file),
`nvram.txt.gz` (`nvram show`) and a `MANIFEST` with firmware and sha256 sums.
**They contain secrets** (Wi-Fi keys, passwords), so the folder is root-only.
Run one now with `sudo systemctl start router-backup.service`; settings via
env vars at the top of the script (`BACKUP_KEEP`, `MIN_FREE_MB`, ...).

Restoring (from this machine, router reachable over SSH):

```bash
B=/var/backups/router/<timestamp>
# USB stick replaced: format it ext4 labelled "entware" (amtm -> fd), then
ssh admin@192.168.1.1 'cd /tmp/mnt/entware && tar -xzf -' < $B/usb.tar.gz
# swap file is not backed up: recreate it with amtm -> sw, or Skynet's installer
ssh admin@192.168.1.1 'tar -xzf - -C /' < $B/jffs.tar.gz   # /jffs (after a factory reset)
ssh admin@192.168.1.1 reboot
```

NVRAM is a reference copy, not a one-shot restore: after a factory reset,
reconfigure in the web UI and look values up with `gzip -dc $B/nvram.txt.gz | grep <key>`
(blindly re-applying every `nvram set` can break a newer firmware).

## DNS lookups (AdGuardHome)

Every 5-minute check (`router_agent/dnslog.py`, enabled by the `adguard:` block in `config.yml`) reads the AdGuardHome query-log entries that are new since the last check (nanosecond cursor in `logs/.dns_cursor.json`) and names each client: IP -> MAC from the router's DHCP leases (all three dnsmasq instances) and ARP table, MAC -> name the same way as the Wi-Fi card (router UI name, networkmap, DHCP hostname); `adguard.aliases` overrides by IP. The lookups are archived in Postgres:

- `dns_lookups` -- one row per (hour, device, domain, blocked) with a count and the blocking rule
- `dns_devices` -- when each device was first/last seen
- `dns_first_seen` -- each device's first-ever lookup of each domain. A domain counts as **new** only once the device has been watched for 24 h.

The cursor only advances after Postgres accepted the batch, so a database outage is caught up on the next check. AdGuardHome keeps 90 days of log; one check reads at most 100k entries.

- **Dashboard:** "DNS lookups" card on Monitor (per-network filter, devices by volume, domains per device with blocked/new filters, "Ask Tshoot"). API: `/api/dns/devices?hours=&network=` and `/api/dns/lookups?hours=&device=&domain=&network=&blocked=1&new=1&limit=`.
- **Tshoot:** `get_dns_lookups` tool (reads the API above; no SSH).
- **Daily AI briefing:** the 24 h DNS rollup (totals per network, top blocked domains/devices, new domains with IoT/Guest first) is part of the security section's data. It adds no extra LLM call.

### DNS health check

Every 5-minute check (`router_agent/dnshealth.py`) also answers "is DNS working, and
is it filtered?": which process owns udp/53 on the router (the AdGuardHome add-on hands
:53 back to dnsmasq while AdGuardHome is down, so DNS keeps working **unfiltered**),
AdGuardHome's `/control/status` (running, protection on), `/control/filtering/check_host`
for `doubleclick.net` (blocklists active; no DNS query, nothing in the query log) and a
real `example.com` query from this host to the router. Result `snapshot.dns_health`:
`ok` / `unfiltered` / `down` plus the reasons (a missing add-on supervisor is reported
as a problem while the state stays `ok`). State changes are written as router events
(`dns_ok`, `dns_unfiltered`, `dns_down`; last state in `logs/.dns_health.json`), the DNS
card shows a status pill and a banner when not ok, the daily rollup counts checks per
state (`filter_health_checks`, mentioned by the AI if any were unhealthy), and Tshoot
sees it via `get_monitor_snapshot`.

## Internet usage per device (Traffic Analyzer)

The firmware's Traffic Analyzer (Adaptive QoS → Traffic Analyzer → Statistic, nvram
`bwdpi_db_enable=1`) writes per-device, per-app WAN bytes to
`/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db` about once an hour and keeps ~2 weeks.
Every 5-minute check (`router_agent/traffic.py`, enabled by `traffic_analyzer: true`
in `config.yml`) reads only rows newer than the last archived one (cursor in
`logs/.traffic_cursor.json`; rows from the last 30 s wait for the next check), names
MACs like the DNS archive (reusing `adguard.networks`/`aliases`) and adds them to
Postgres `traffic_usage` (one row per hour/MAC/app, rx = download, tx = upload). The
first run backfilled the router's whole history (13 days, 66k rows).

- API: `/api/traffic/devices?hours=24&network=IoT` (per-device totals + top 3 apps),
  `/api/traffic/detail?hours=24&device=<mac|ip|name>` (apps + hourly series; no device =
  whole network).
- Dashboard: "Internet usage" card on Monitor (24h/7d/14d, per network, per device).
- Tshoot: `get_traffic_usage` tool.
- Not sent to the daily LLM analysis (no extra tokens).

Only internet traffic is measured, not traffic between devices at home.

## Known follow-ups (intentionally not done automatically)

- **Router reboot test**: the `/jffs/scripts/services-start` key-persistence fix hasn't been validated against an actual reboot yet — rebooting the router is disruptive and wasn't done without explicit go-ahead.
- **Live PPPoE restart test**: the watchdog's restart trigger logic was dry-run tested (`--dry-run`) against simulated downtime, but a real `service restart_wan_if 0` against the live router hasn't been fired yet — do that deliberately once, at a convenient time, before trusting the 5-minute auto-restart in production.
- **Firmware update emails need amtm email set up** (noted 2026-11-11): the `update-notification` hook is installed, but amtm email isn't configured yet, so new-firmware alerts only go to syslog. To do: SSH to the router, run `amtm` → `em`, enter the SMTP details (Gmail: `smtp.gmail.com`, port 465, an app password), then send a test with `ssh admin@192.168.1.1 /jffs/scripts/update-notification --test`.
- **AdGuardHome (installed 2026-11-12)**: release v0.107.80 via the jumpsmm7 installer (amtm `ag`), web UI http://192.168.1.1:3000 (login in `/root/.config/adguardhome.cred` on the backup host). AdGuardHome owns port 53; dnsmasq moved to 553 (local names/PTR forwarded there). Upstreams: Cloudflare + Quad9 DoH in parallel, bootstrap 9.9.9.9/1.1.1.1. Lists: AdGuard DNS filter + OISD Small. Installer set DHCP option 6 to the router on LAN/Guest/IoT (dnsmasq postconf hooks) and DNSFilter=Router; firmware exempts SDN bridges from DNSFilter, so `/jffs/scripts/nat-start` inserts REDIRECTs for br53/br54 (survives `service restart_firewall`, checked 2026-11-13; not yet validated across a reboot). Its query log is wired into network-ai and Tshoot (see "DNS lookups (AdGuardHome)").
