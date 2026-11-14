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
- Storage: daily records `logs/<router>-<ts>.json` (kept `retention_days`), checks gzipped in `logs/checks/` (kept `check_retention_hours`, ~9 KB each). Postgres gets every check too (`kind='check'`, raw log tails stripped); `/api/history` thins checks to ~hourly beyond 2 days. **Postgres retention**: the daily run deletes 5-minute snapshots, `dns_lookups` and `traffic_usage` rows older than `db_retention_days` (default 90; 0 = keep forever; values under 7 are refused), via `db.prune_old()` / `RETENTION_TABLES`. Kept forever: daily analyses, `watchdog_events`, `dns_devices`/`dns_first_seen` (the "new domain" detection needs every domain a device ever used) and Tshoot's `tshoot_audit`. Works on any Postgres (plain `DELETE`). **With TimescaleDB** (installed in the `network_ai` database since 2026-11-14) the daily run's `db.ensure_timescale()` also sets up, once and idempotently: `dns_lookups` and `traffic_usage` as hypertables (7-day chunks, compressed once 14 days old, because the Traffic Analyzer catch-up writes up to 2 weeks back), retention by whole chunks (`drop_chunks`, never inside the 30-day summary refresh window), and the daily per-device summaries `traffic_daily` (rx/tx) and `dns_daily` (queries/blocked), refreshed hourly and **kept forever**. The summaries deliberately carry no domain or app names, so the hidden list can't outlive a purge in them. Long-range API: `/api/traffic/history` and `/api/dns/history` (`?days=365&bucket=day|week|month&device=&network=`, totals per period + top devices; on plain Postgres they read the raw tables instead). `snapshots` stays a plain table: its daily rows (the LLM analyses) must survive while check rows are deleted. New wifi clients come from `logs/known_clients.json` (a client counts as new for 24 h after it first appears; devices unseen for `retention_days` are forgotten).
- `router_agent/notify.py` — Telegram push notifications (see "Telegram notifications").
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

### Firmware update notifications (notify only)

`router/update-notification` is installed as the Merlin hook
`/jffs/scripts/update-notification`. The router's own scheduled firmware check
(Administration → Firmware Upgrade → "Scheduled new firmware check", nvram
`firmware_check_enable=1`) calls it when a newer Merlin release is out, and it
**only reports it** -- nothing is downloaded or flashed. It POSTs
`{"type": "firmware", ...}` to the dashboard's `/api/router-event`, which records a
`router_firmware_available` event (Events card) and pushes it to Telegram. Each version
is reported once; if the dashboard was unreachable it retries on the next scheduled
check. MerlinAU was deliberately not used: it has no notify-only mode and flashes on its
own after its postponement period (max 199 days). (It used to email via amtm; replaced
2026-11-14 by Telegram, so amtm email/SMTP is not needed.)

```bash
ssh admin@192.168.1.1 'cat > /jffs/scripts/update-notification && chmod 755 /jffs/scripts/update-notification' < router/update-notification
ssh admin@192.168.1.1 /jffs/scripts/update-notification --test   # sends a TEST firmware notification
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
.venv/bin/python3 dashboard/app.py                             # dashboard (waitress; listeners from dashboard: in config.yml)
.venv/bin/python3 dashboard/app.py --dev                       # Flask development server instead
```

Frontend development (hot reload, proxies `/api` to Flask on :8080):

```bash
cd dashboard/frontend
npm run dev
```

### Dashboard access (Tailscale only) and who may approve Tshoot changes

The dashboard runs as the unprivileged user `netai` under waitress
(`systemd/network-ai-dashboard.service`, sandboxed: read-only system, writes only
`logs/`, no capabilities). It has two listeners (`dashboard/serve.py`):

| Listener | Used by | Identity |
|---|---|---|
| `dashboard.unix_socket` (`/run/network-ai/dashboard.sock`) | `tailscale serve`: https://<host>.<tailnet>.ts.net and http://<host>.<tailnet>.ts.net:8080 | trusted: serve adds `Tailscale-User-Login` + `X-Forwarded-For` and strips forged copies |
| `dashboard.host:port` = `192.168.1.10:8080` (LAN address only) | the router's `wan-event` / `update-notification` hooks, Tshoot's API calls | none: can never approve |

Never bind it to `0.0.0.0` or `127.0.0.1`: Tailscale runs in userspace mode here, so
every `127.0.0.1` port is reachable from the tailnet and would bypass the identity check.

**Approvals.** A Tshoot "Approve & run" is only forwarded when the request came through
`tailscale serve` from a login in `dashboard.approvers.logins` **and** a device in
`dashboard.approvers.devices` (looked up with `tailscale whois`; e.g. only your laptop and phone, so servers that
run under the same account can't approve). Rejecting and chatting need no approver. The
Tshoot card shows why when the current device can't approve; `/api/whoami` returns what
the dashboard sees. Tshoot itself only answers requests carrying `TSHOOT_PROXY_KEY`
(same value in both `.env` files), so its own `127.0.0.1:8090` is useless from the
tailnet, and it records who decided each approval (`decision` rows in its audit log).

**Without root.** "Check now" writes `logs/.collect-request`; `network-ai-check.path`
starts the normal (root) check unit, and `/api/collect-status` reads that unit's state.
The connection-quality chart reads `logs/connmon.json`, which every check writes, so
the dashboard never SSHes to the router. `logs/` is group `netai` (setgid, the root
units run with `UMask=0007`); `config.yml` is `0640 root:netai`; `.env` stays root-only
and reaches the dashboard via `EnvironmentFile=`.

Setup (once):

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netai
sudo chgrp -R netai logs && sudo chmod -R g+rwX,o-rwx logs && sudo find logs -type d -exec chmod g+s {} +
sudo chgrp netai config.yml && sudo chmod 640 config.yml
echo "TSHOOT_PROXY_KEY=$(openssl rand -hex 32)"   # add the same line to .env and /opt/tshoot/.env
sudo cp systemd/network-ai-*.service systemd/network-ai-check.path /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now network-ai-check.path && sudo systemctl restart network-ai-dashboard network-ai-watchdog tshoot
sudo tailscale serve reset
sudo tailscale serve --bg --https=443 unix:/run/network-ai/dashboard.sock
sudo tailscale serve --bg --http=8080 unix:/run/network-ai/dashboard.sock
```

`nftables/dashboard.nft` additionally limits TCP 8080 to localhost and the router:

```bash
sudo mkdir -p /etc/nftables.d && sudo cp nftables/dashboard.nft /etc/nftables.d/
grep -q nftables.d /etc/nftables.conf || echo 'include "/etc/nftables.d/*.nft"' | sudo tee -a /etc/nftables.conf
sudo nft -f /etc/nftables.d/dashboard.nft      # undo: sudo nft delete table inet dashboard
```

### Deploying a change (`deploy.sh`)

This host is production: code is edited in place in `/opt/network-ai`. After a change run

```bash
./deploy.sh              # verify, build, restart what's stale, health check
./deploy.sh --dry-run    # only show what it would do
./deploy.sh --fast       # skip pytest
./deploy.sh --force      # restart the watchdog even while it tracks a WAN outage
```

It stops before restarting anything if py_compile or pytest fails (running services keep
the old code; ruff only warns), runs `pip install` when `requirements.txt` changed and
`npm ci`/`npm run build` when frontend sources are newer than `dist/`, then restarts
`network-ai-dashboard` / `network-ai-watchdog` only if code, `config.yml` or `.env` is
newer than the running process. The dashboard restart waits for `logs/.run.lock` (a
"Check now" run would be killed with it); the watchdog is not restarted while it is
tracking an outage. Then `/api/state` must answer 200. Failures are pushed to Telegram.
Finally it lists what is never done automatically: changed `router/` scripts (reinstall
on the router), `systemd/` units that differ from `/etc/systemd/system`, and a changed
`config.example.yml` (new keys for `config.yml`). State: `logs/.deploy.json`.

There is deliberately no CD from GitHub: development happens on this host, so CI
(GitHub Actions) checks what was pushed and `deploy.sh` makes it live here.

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

## Telegram notifications

`router_agent/notify.py` pushes to a Telegram bot (one HTTPS POST per message, no SMTP):

| `notify.events` | When | From |
|---|---|---|
| `wan` | internet back after an outage of at least `wan_min_downtime_seconds` (default 60), with the downtime and whether the watchdog restarted the WAN | `watchdog.py` |
| `dns` | DNS health changes to unfiltered / down / ok again | `dnshealth.py` via `events.append_router_event` |
| `new_device` | a wifi client seen for the first time (known_clients.json; devices forgotten after `retention_days` count as new again) | 5-minute check |
| `firmware` | new Merlin release (`router/update-notification`) | `/api/router-event` |
| `monitor` | network-ai itself is unhealthy, and again when fixed (see "Monitoring the monitor") | watchdog / 5-minute check |
| `anomaly` | an appliance contacts many new sites in an hour or uploads far more than usual (see "Unusual device behaviour") | 5-minute check |
| `upnp` | a device opens a port to the internet via UPnP **for the first time** (see "UPnP port mappings") | 5-minute check |
| `report` | the weekly (Mondays) / monthly (1st) network report: key numbers + AI summary; opt-in (`router_agent/report.py`, `network-ai-report-{weekly,monthly}.timer`, Report card on Monitor, `/api/reports`) | report timer |
| `iot_lan` | an IoT device tries to open a connection to a LAN device (blocked by the firewall; see "IoT devices reaching for the LAN") | 5-minute check |
| `vpn` | remote access: a WireGuard peer added on the router, a peer connecting from a network (ISP) it never used, the DDNS name not matching the WAN IP (and OK again) (see "Remote access (WireGuard + DDNS)") | 5-minute check |
| `vpn_sessions` | opt-in: every WireGuard session start (source IP, ISP, country) and end (duration, traffic) | 5-minute check |
| `daily` | opt-in (not sent unless listed): the daily LLM briefing's one-line overall summary (or that it failed) | `--mode daily` |

WAN down is not pushed while it happens -- Telegram is unreachable then; the
"back up" message covers it. Router-reported `router_wan_*` events are not pushed (the
watchdog's view is the one that matters). Sending is best-effort and never fails a
check, the watchdog or an API call: messages that hit a network error or a Telegram
5xx/429 are queued in `logs/.notify_queue.jsonl` and delivered (marked "delayed") by
the next send, the watchdog's next loop or the next check; messages older than 2 days
are dropped. A bad token/chat id is logged to the unit's journal and the message dropped.

Setup:

1. In Telegram, talk to @BotFather → `/newbot`; put the token in `.env` as `TELEGRAM_BOT_TOKEN=`.
2. Open your new bot and send it `/start`.
3. `.venv/bin/python3 -m router_agent.notify --chat-id` prints your chat id; add the
   `notify:` block from `config.example.yml` to `config.yml` with it.
4. `.venv/bin/python3 -m router_agent.notify --test` sends a test message.
5. `sudo systemctl restart network-ai-watchdog.service network-ai-dashboard.service`
   (the 5-minute check picks the config up on its own).

## Monitoring the monitor

`router_agent/selfcheck.py` checks that network-ai itself is working. The watchdog runs it
every 5 minutes; the 5-minute check watches the watchdog, so each guards the other.

| Check | Problem when | Grace |
|---|---|---|
| checks | no successful 5-minute check for 20 min (timer stopped, router SSH failing, check crashing) | 10 min |
| daily | no daily analysis for 26 h, or the last one failed (no LLM answered) | — |
| backup | newest `/var/backups/router/<ts>` older than 26 h | — |
| postgres | `SELECT 1` fails (only when `PGHOST` is set) | 15 min |
| dashboard | `http://127.0.0.1:<port>/api/state` does not answer | 10 min |
| disk | under 10 % free on the disk holding `logs/` | — |
| watchdog | `logs/watchdog_status.json` older than 5 min (checked by the 5-minute check) | — |
| traffic | no new Traffic Analyzer rows for 3 h (when `traffic_analyzer:` is on) | — |
| iot_lan | the router's IoT → LAN LOG rule is missing (when `iot_lan:` is on; see "IoT devices reaching for the LAN") | — |
| router_setup | something the router's hook scripts/add-ons set up, and that was there before, is missing (see "Router setup drift") | 15 min |

A problem that outlasts its grace records one `monitor_problem` event (Events card,
Postgres, Telegram `monitor`); when it clears, one `monitor_ok`. Short blips inside
the grace period stay silent. State: `logs/.selfcheck.json`. Thresholds: `monitor:` in
`config.example.yml`.

Nothing on this host can report the host itself being off (power, Proxmox, the LXC
crashing). For that, set `monitor.heartbeat_url` to an external dead-man's switch,
e.g. a free https://healthchecks.io check (period 5 min, grace 15 min, its own
Telegram/email integration): the watchdog pings it every 5 minutes while the checks
are fresh, and the service alerts when the pings stop. Not configured as of 2026-11-14.

## Router setup drift

A lot of the router's setup is rebuilt in memory by Merlin hook scripts and add-ons, and
a hook that silently fails (reboot, firmware update, `service restart_firewall`, a USB
stick that didn't mount) just makes things quieter. Every 5-minute check
(`router_agent/routersetup.py`, read-only, part of the `services` command group) lists:

| Item | Put there by |
|---|---|
| `skynet_ipsets`, `skynet_rules` (raw table) | `firewall-start` (Skynet) |
| `sdn_accept:br0>br54` (LAN → IoT allowed) | `firewall-start` |
| `dns_redirect:<bridge>` (Guest/IoT DNS → AdGuardHome), `ntp_redirect:<bridge>` | `nat-start` |
| `ntp_sdn` (process), `root_ssh_keys` | `services-start` |
| `entware`, `swap`, `syslog_ng` (scribe), most `cron:<tag>` jobs | `post-mount` / the add-ons on the USB stick |
| `syslog_socket`: syslog-ng still owns `/dev/log` (a firmware service restart can recreate the socket; syslog-ng then silently drops all userspace logs until `/opt/etc/init.d/S01syslog-ng restart`) | scribe |
| `dhcp_ntp:<dnsmasq conf>` (DHCP option 42) | `dnsmasq*.postconf` |
| `script:<name>` (every executable in `/jffs/scripts`, `*.bak*` skipped), `jffs_scripts` | `/jffs` + the custom-scripts setting |

Nothing is configured per item: every item that has been OK once is remembered in
`logs/.router_setup.json`, and one that later goes missing shows up in
`snapshot.router_setup.missing`. Items the router never had are never reported, so the
first run is a silent baseline. The self-check turns it into one `monitor_problem`
(Telegram `monitor`, listing the missing items with the hook that creates them) after a
15-minute grace, and one `monitor_ok` when everything is back. A further item going
missing while the alert is open does not alert again (`/api/state` /
`logs/latest.json` show the current list). Firmware-managed `cron:WGC_CHK_EP` is ignored.

Removed something on purpose: add it to `router_setup.ignore` (fnmatch patterns, e.g.
`"cron:spdMerlin_*"`), or `rm logs/.router_setup.json` to re-learn from the next check.
`router_setup: false` turns the feature off.

## Remote access (WireGuard + DDNS)

The router's WireGuard server is the one service reachable from the internet, through
the DDNS name (DuckDNS via `/jffs/scripts/ddns-start`). Every 5-minute check reads the
peers (`wg show wgs1 dump` in the `services` group: last handshake, endpoint, bytes) and
`router_agent/vpn.py` turns that into sessions and events:

| Event | When | Telegram |
|---|---|---|
| `vpn_new_peer` | a peer config appears on the router that wasn't there before | `vpn` |
| `vpn_connect` | a session starts (handshake < 3 min old after none), with source IP, ISP/ASN and country | `vpn_sessions`; `vpn` too when `new_network` |
| `vpn_connect` + `new_network` | the peer connects (or roams mid-session) from an ISP/ASN it never used before | `vpn` |
| `vpn_disconnect` | no handshake for 10 min: duration and traffic of the session | `vpn_sessions` |
| `ddns_mismatch` / `ddns_ok` | the DDNS name resolves to something other than the WAN IP on 2 checks in a row (resolved over DNS-over-HTTPS, Cloudflare then Google, so no cache hides it) / matches again | `vpn` |

Sessions are seen at check granularity: a connect arrives up to 5 minutes late, a
session shorter than one check may be missed. The first run is a silent baseline for
peers (whatever is live is recorded); known networks per peer and open sessions live in
`logs/.vpn_state.json`. `snapshot.vpn` has the per-peer state and the DDNS check;
DDNS is skipped while the WAN has no public IP.

Network and country come from the offline **DB-IP Lite** databases (IP Geolocation by
[DB-IP](https://db-ip.com), CC BY 4.0) in `state/geoip/`, so peers' IPs never leave this
host: the daily run downloads them when missing or older than 32 days;
`.venv/bin/python3 -m router_agent.geoip --update` does it by hand and
`... -m router_agent.geoip <ip>` looks one up. Without them sessions are still reported,
just without network/country and without new-network detection.

`vpn: false` turns it off; `vpn.ddns_host` checks another name than the router's
`ddns_hostname_x`.

**DuckDNS updater** (`router/ddns-start`, Merlin hook for WAN > DDNS = Custom): updates
the name set in WAN > DDNS > Host Name with the WAN IP the firmware passes in, verifies
TLS, logs the result (`ddns-start` tag) and reports it back to the web UI. The token is
not in the script but in a root-only file on the router. Install / test:

```bash
ssh admin@192.168.1.1 'mkdir -p /jffs/addons/duckdns.d && umask 077 && cat > /jffs/addons/duckdns.d/token'   # paste the token, Ctrl-D
ssh admin@192.168.1.1 'cat > /jffs/scripts/ddns-start && chmod 755 /jffs/scripts/ddns-start' < router/ddns-start
ssh admin@192.168.1.1 '/jffs/scripts/ddns-start "$(nvram get wan0_ipaddr)"; nvram get ddns_status'   # 1 = OK
```

## Unusual device behaviour

`router_agent/anomaly.py` compares every **appliance** (cameras, plugs, TVs, speakers,
NAS, servers: anything `netmap.classify_type` doesn't call a phone, tablet or computer;
the Guest network is skipped) with its own history in Postgres, every 5-minute check,
without an LLM:

| Kind | Alert when | Why this threshold (measured 2026-11-14) |
|---|---|---|
| `new_domains` | 4+ new **base** domains (`example.com`, subdomains don't count) within an hour | appliances never exceeded 2/h; phones and laptops reach 30-50/h, hence skipped |
| `upload` | an hour with 100 MB+ uploaded **and** 10x the device's usual peak (95th percentile of its hourly uploads, 14 days) | a Reolink clip burst (53 MB vs 0.4 MB usual) stays below the floor |

A device is judged only after 72 h of baseline. Each (kind, device) alerts at most once
a day as an `anomaly` event (Events card, Postgres, Telegram `anomaly`); the first run
records what is going on silently. Thresholds and `ignore_devices` (names or MACs that
may do this): `anomaly:` in `config.example.yml`. State: `logs/.anomaly_state.json`.
The baseline needs the DNS archive (AdGuardHome) and/or the Traffic Analyzer archive.

## IoT devices reaching for the LAN

The router's SDN firewall already blocks the IoT network (`br54`, 192.168.107.x) from
opening connections to the LAN (`br0`): chain `SDN_IA` drops `br+ -> br+` except
LAN -> IoT (re-inserted by `firewall-start`). Merlin's `logdrop` drops silently, so
`router/firewall-start` also inserts a **rate-limited LOG rule** (10/min, burst 30,
prefix `DROP `) for `br54 -> br0` in front of it. Scribe files those lines with the other
firewall drops in `skynet-0.log`; they never enter the syslog the LLM sees. Replies to
connections the LAN opened are ESTABLISHED and never logged, and broadcast/multicast
discovery isn't forwarded, so each line is a real attempt by an IoT device to reach a
LAN device.

Every 5-minute check (`router_agent/iotlan.py`, on when `iot_lan:` is in config.yml)
reads only the lines past its cursor (`logs/.iot_lan_state.json`; the first run sets
the cursor silently), names both ends like the rest of the dashboard and puts the
check's attempts in `snapshot.iot_lan` (plus `logging`: is the LOG rule installed?).
Each (IoT device, LAN target, port) alerts at most once a day: one `iot_lan` event per
device (Events card, Postgres, Telegram `iot_lan`). Expected traffic (a plug talking to a
LAN MQTT broker, say) goes in `iot_lan.ignore_targets` / `ignore_devices`. If a firewall
rebuild drops the LOG rule without running `firewall-start`, the self-check reports
`IoT → LAN logging` as a `monitor` problem.

Install / update the hook (file write only; applying the two LOG lines by hand avoids
re-running Skynet's `firewall start`):

```bash
ssh admin@192.168.1.1 'cat > /jffs/scripts/firewall-start && chmod 755 /jffs/scripts/firewall-start' < router/firewall-start
ssh admin@192.168.1.1 'iptables -D SDN_IA -i br54 -o br0 -m limit --limit 10/min --limit-burst 30 -j LOG --log-prefix "DROP " 2>/dev/null;
  iptables -I SDN_IA 1 -i br54 -o br0 -m limit --limit 10/min --limit-burst 30 -j LOG --log-prefix "DROP "'
ssh admin@192.168.1.1 'iptables -vnL SDN_IA'   # the LOG rule's counter = attempts seen
```

Only IoT -> LAN is watched: IoT devices hitting the router's own LAN address (e.g.
ASUS port 18018 discovery) and Guest -> LAN are dropped by other rules and not logged.

## UPnP port mappings (internet exposure)

Every 5-minute check reads the router's miniupnpd leases (`/tmp/upnp.leases`, plus
`nvram get upnp_enable`) into `snapshot.upnp`: every port a LAN device opened to the
internet via UPnP / NAT-PMP, named like the rest of the dashboard
(`router_agent/upnp.py`). A mapping counts as **exposing** when it is TCP or permanent
(lifetime 0), e.g. a NAS opening its login page; short-lived UDP mappings (Tailscale's
2-hour NAT-PMP ones, consoles, VoIP) are listed but never alerted on.

Alerts are per device and only once: `logs/.upnp_known.json` remembers every device
that ever held an exposing mapping. A device not on that list opening one records an
`upnp_new_device` event (Events card, Postgres) and a Telegram message (`upnp` in
`notify.events`). A known device closing and re-opening its ports, or opening more,
stays quiet. The first run records whatever was open as known, silently. To be alerted
about a device again, delete its entry from `logs/.upnp_known.json`.

Started 2026-11-14 with nothing exposed (the Synology's DSM "Router Configuration"
mappings for 5000/5001/6690 had just been removed; QuickConnect now uses Synology's relay),
so the Synology re-opening them would alert once.

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

## Network map (Map tab)

Every device on the network, in its room, linked to the mesh node it is connected to.
Each 5-minute check also stores `snapshot.lan` (`router_agent/netmap.py`): which node each
**wired** device sits behind (AiMesh's `/tmp/clientlist.json` lists per node every MAC on
its ethernet ports, i.e. everything downstream, so the node with the smallest list holding a
MAC is the one it is cabled to), the backhaul between nodes, and the DHCP/ARP host table;
and `snapshot.services` (what runs on the router: Skynet, AdGuardHome, dnsmasq, NTP,
WireGuard peers, AiProtection, QoS, connmon, spdMerlin, scribe, ...). Neither is sent to the LLM.

- API: `/api/network-map` (built from `logs/latest.json` + `known_clients.json`, no SSH).
- Rooms come from device names (`livingroom_Lamp` -> Living room); devices without one go
  to Mobile / Server / Utility / Unassigned and are marked as guessed. Mesh nodes take the
  room most of their devices are in. Override with `network_map.rooms` in `config.yml`
  (by name, IP or MAC).
- Device type and brand are guessed from name, DHCP hostname, vendor and MAC prefix;
  logos come from `simple-icons` (Reolink, Tuya, Meross, Viessmann, Gardena, WiZ have none
  and show only the type icon).
- Links: Wi-Fi (band + signal), cable, VPN (WireGuard handshake < 3 min), "seen" (answers
  ARP but on no node's list). Proxmox guests missing from the wired lists are drawn behind
  the same node as the other guests ("inferred").

## Weekly and monthly reports

`router_agent/report.py` writes a short report about the last full week (Monday to Sunday,
UTC; `network-ai-report-weekly.timer`, Mondays 04:30 UTC) and the last calendar month
(`network-ai-report-monthly.timer`, the 1st at 05:00 UTC), both after the 03:00 daily run.
Each is **one** LLM call (same `llm.order` fallback as the daily analysis) over compact
facts with the previous period for comparison:

- internet: WAN-up share of the 5-minute checks, outages the watchdog measured, auto-restarts,
  router reboots; spdMerlin speedtests and connmon ping/jitter
- traffic and DNS totals per day and the top devices (from the daily summaries, so they work
  after the raw rows are pruned); new devices from `known_clients.json`; notable router
  events (anomaly, UPnP, IoT→LAN, monitor problems, DNS down, firmware)

Per device only: no domain or app names, so the hidden list can't end up in a report.
Saved as `logs/reports/<week|month>-<start>.json`, shown in the **Report** card on Monitor
(Week/Month switch, `/api/reports?period=week&limit=1`) and pushed to Telegram as `report`
(opt-in: add it to `notify.events`). Missing Postgres → those facts are listed as missing;
no LLM → the report keeps the numbers.

```bash
.venv/bin/python3 -m router_agent.report --period week --dry-run   # facts only: no LLM, nothing saved
.venv/bin/python3 -m router_agent.report --period week --no-send   # write it, don't push to Telegram
sudo cp systemd/network-ai-report@.service systemd/network-ai-report-*.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now network-ai-report-weekly.timer network-ai-report-monthly.timer
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest            # offline: the router, AdGuardHome and Postgres are faked
ruff check .
```

GitHub Actions (`.github/workflows/ci.yml`) runs these plus the dashboard's
`npm run lint` and `npm run build` on every push to `main`.

## Known follow-ups (intentionally not done automatically)

- **Router reboot test**: the `/jffs/scripts/services-start` key-persistence fix hasn't been validated against an actual reboot yet — rebooting the router is disruptive and wasn't done without explicit go-ahead.
- **Live PPPoE restart test**: the watchdog's restart trigger logic was dry-run tested (`--dry-run`) against simulated downtime, but a real `service restart_wan_if 0` against the live router hasn't been fired yet — do that deliberately once, at a convenient time, before trusting the 5-minute auto-restart in production.
- **AdGuardHome (installed 2026-11-12)**: release v0.107.80 via the jumpsmm7 installer (amtm `ag`), web UI http://192.168.1.1:3000 (login in `/root/.config/adguardhome.cred` on the backup host). AdGuardHome owns port 53; dnsmasq moved to 553 (local names/PTR forwarded there). Upstreams: Cloudflare + Quad9 DoH in parallel, bootstrap 9.9.9.9/1.1.1.1. Lists: AdGuard DNS filter + OISD Small. Installer set DHCP option 6 to the router on LAN/Guest/IoT (dnsmasq postconf hooks) and DNSFilter=Router; firmware exempts SDN bridges from DNSFilter, so `/jffs/scripts/nat-start` inserts REDIRECTs for br53/br54 (survives `service restart_firewall`, checked 2026-11-13; not yet validated across a reboot). Its query log is wired into network-ai and Tshoot (see "DNS lookups (AdGuardHome)").
