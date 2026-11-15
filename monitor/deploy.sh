#!/usr/bin/env bash
# Put the code in /opt/network-ai live after an edit. This host IS production (code is
# edited in place), so "deploying" means: verify, rebuild what changed, restart what
# runs stale code, check it came back.
#
#   ./deploy.sh              verify + build + restart + health check
#   ./deploy.sh --dry-run    only report what would be done
#   ./deploy.sh --fast       skip pytest (py_compile still runs)
#   ./deploy.sh --force      restart the watchdog even while it is tracking a WAN outage
#
# Steps:
#   1. preflight: py_compile every Python file, pytest, ruff (ruff only warns). A failure
#      stops here, before anything is restarted -- running services keep the old code.
#   2. pip install -r requirements.txt if it changed since the last deploy
#   3. npm ci (lockfile changed) + npm run build if frontend sources are newer than dist/
#      (Flask reads dist/ from disk: no restart needed for the frontend)
#   4. restart network-ai-dashboard / network-ai-watchdog (/ network-ai-telegram if enabled) only if code, config.yml or
#      .env is newer than the running process. Waits for logs/.run.lock first: a
#      dashboard "Check now" runs in the dashboard's cgroup and would be killed. The
#      5-minute check and the daily run start fresh processes and need no restart.
#   5. health: /api/state answers, both services active
#   6. reminders for what is never deployed automatically: router/ scripts (installed on
#      the router by hand), systemd/ units, new config keys in config.example.yml
# Failures are pushed to Telegram (notify:), success is not. State: logs/.deploy.json
set -uo pipefail

cd "$(dirname "$(readlink -f "$0")")"
PY=.venv/bin/python3
DRY=false FAST=false FORCE=false
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=true ;;
        --fast) FAST=true ;;
        --force) FORCE=true ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

# log_dir and the dashboard's TCP listener from config.yml (bound to the LAN address in production)
read -r LOG_DIR HOST PORT < <($PY -c '
import yaml; c = yaml.safe_load(open("config.yml")) or {}
d = c.get("dashboard") or {}
h = d.get("host") or "127.0.0.1"
print(c.get("log_dir", "logs"), "127.0.0.1" if h == "0.0.0.0" else h, d.get("port", 8080))')
STATE="$LOG_DIR/.deploy.json"
WARNINGS=()

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf '   ok: %s\n' "$*"; }
warn() { printf '   \033[33mwarning:\033[0m %s\n' "$*"; WARNINGS+=("$*"); }
fail() {
    printf '\n\033[31mDEPLOY FAILED:\033[0m %s\n' "$1" >&2
    $DRY || $PY -m router_agent.notify --send "❌ network-ai deploy failed: $1" >/dev/null 2>&1 || true
    exit 1
}
run() { if $DRY; then echo "   would run: $*"; else "$@"; fi; }

exec 9>"$LOG_DIR/.deploy.lock"
flock -n 9 || { echo "another deploy is running" >&2; exit 1; }

# newest mtime (epoch) among the given files
newest() { stat -c %Y "$@" 2>/dev/null | sort -n | tail -1; }
# epoch at which a systemd unit last became active (0 when not running)
started() {
    local t; t=$(systemctl show -p ActiveEnterTimestamp --value "$1")
    [ -n "$t" ] && date -d "$t" +%s || echo 0
}
state_get() { $PY -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))
except Exception: print("")' "$STATE" "$1"; }

# Python sources the services import (tracked + new untracked files, not the tests)
mapfile -t PYFILES < <(git ls-files -co --exclude-standard -- '*.py' ':!tests/*' ':!dashboard/frontend/*')
mapfile -t ALLPY < <(git ls-files -co --exclude-standard -- '*.py' ':!dashboard/frontend/*')

# ---- 1. preflight ----
step "preflight"
$PY -m py_compile "${ALLPY[@]}" || fail "Python syntax error (nothing restarted)"
ok "py_compile (${#ALLPY[@]} files)"
if $FAST; then
    echo "   skipped pytest (--fast)"
else
    $PY -m pytest -p no:cacheprovider >/tmp/network-ai-deploy-pytest.log 2>&1 \
        || { tail -25 /tmp/network-ai-deploy-pytest.log; fail "pytest failed (nothing restarted)"; }
    ok "pytest: $(grep -Eo '[0-9]+ passed.*' /tmp/network-ai-deploy-pytest.log | tail -1)"
fi
if [ -x .venv/bin/ruff ]; then
    .venv/bin/ruff check --quiet . >/dev/null 2>&1 && ok "ruff" || warn "ruff reports problems (CI will fail): .venv/bin/ruff check ."
fi

# ---- 2. Python dependencies ----
step "python dependencies"
REQ_HASH=$(sha256sum requirements.txt | cut -d' ' -f1)
if [ "$REQ_HASH" != "$(state_get requirements)" ]; then
    run .venv/bin/pip install -q -r requirements.txt || fail "pip install failed"
    $DRY || ok "installed requirements.txt"
    DEPS_CHANGED=true
else
    ok "requirements.txt unchanged"
    DEPS_CHANGED=false
fi

# ---- 3. frontend ----
step "frontend"
FE=dashboard/frontend
mapfile -t FE_SRC < <(cd $FE && git ls-files -co --exclude-standard | grep -v '^dist/' | sed "s#^#$FE/#")
if [ ! -f $FE/dist/index.html ] || [ "$(newest "${FE_SRC[@]}")" -gt "$(stat -c %Y $FE/dist/index.html)" ]; then
    if [ ! -f $FE/node_modules/.package-lock.json ] || [ $FE/package-lock.json -nt $FE/node_modules/.package-lock.json ]; then
        run npm --prefix $FE ci --no-audit --no-fund || fail "npm ci failed"
    fi
    if $DRY; then
        echo "   would run: npm --prefix $FE run build"
    else
        npm --prefix $FE run build >/tmp/network-ai-deploy-build.log 2>&1 \
            || { tail -25 /tmp/network-ai-deploy-build.log; fail "frontend build failed (dist/ may be incomplete)"; }
        touch $FE/dist/index.html
        ok "built dist/"
    fi
else
    ok "dist/ is up to date"
fi

# ---- 4. restart what runs stale code ----
step "services"
CODE_MTIME=$(newest "${PYFILES[@]}" config.yml .env)
RESTARTED=()
# the Telegram bot only where it is installed (optional: notify.telegram.interactive)
SERVICES=(network-ai-dashboard network-ai-watchdog)
systemctl is-enabled --quiet network-ai-telegram.service 2>/dev/null && SERVICES+=(network-ai-telegram)
for svc in "${SERVICES[@]}"; do
    since=$(started "$svc.service")
    if [ "$since" -ne 0 ] && [ "$CODE_MTIME" -le "$since" ] && ! $DEPS_CHANGED; then
        ok "$svc runs the current code"
        continue
    fi
    if [ "$svc" = network-ai-watchdog ] && ! $FORCE \
            && [ "$($PY -c 'import json,sys; print(json.load(open(sys.argv[1])).get("up", True))' "$LOG_DIR/watchdog_status.json" 2>/dev/null)" = False ]; then
        warn "watchdog NOT restarted: it is tracking a WAN outage right now (rerun later, or --force)"
        continue
    fi
    if $DRY; then
        echo "   would restart $svc"
        continue
    fi
    # a dashboard "Check now" run lives in the dashboard's cgroup: let it finish first
    if [ "$svc" = network-ai-dashboard ]; then
        exec 8>"$LOG_DIR/.run.lock"
        flock -w 300 8 || warn "a check held logs/.run.lock for 5 min; restarting anyway"
        sudo systemctl restart "$svc.service"
        flock -u 8
    else
        sudo systemctl restart "$svc.service"
    fi
    RESTARTED+=("$svc")
    ok "restarted $svc"
done

# ---- 5. health ----
step "health"
if ! $DRY; then
    for svc in "${SERVICES[@]}"; do
        systemctl is-active --quiet "$svc.service" || {
            journalctl -u "$svc.service" -n 20 --no-pager; fail "$svc is not running"; }
    done
    for _ in $(seq 1 20); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://$HOST:$PORT/api/state")
        [ "$code" = 200 ] && break
        sleep 1
    done
    [ "$code" = 200 ] || { journalctl -u network-ai-dashboard.service -n 20 --no-pager; fail "/api/state answered $code"; }
    ok "/api/state 200, dashboard and watchdog active"
else
    echo "   skipped (--dry-run)"
fi

# ---- 6. what is never deployed automatically ----
step "manual steps"
for u in systemd/*.service systemd/*.timer systemd/*.path; do
    cmp -s "$u" "/etc/systemd/system/$(basename "$u")" \
        || warn "$u differs from the installed unit: sudo cp $u /etc/systemd/system/ && sudo systemctl daemon-reload"
done
ROUTER_HASHES=$(sha256sum router/* | sort -k2)
PREV_ROUTER=$(state_get router)
if [ -n "$PREV_ROUTER" ]; then
    while read -r h f; do
        grep -qxF "$h  $f" <<<"$PREV_ROUTER" || {
            case "$f" in
                router/backup.sh) ;;  # runs on this host
                *) warn "$f changed: reinstall it on the router (see README)" ;;
            esac; }
    done <<<"$ROUTER_HASHES"
fi
EXAMPLE_HASH=$(sha256sum config.example.yml | cut -d' ' -f1)
PREV_EXAMPLE=$(state_get config_example)
[ -n "$PREV_EXAMPLE" ] && [ "$EXAMPLE_HASH" != "$PREV_EXAMPLE" ] \
    && warn "config.example.yml changed: check for new keys to add to config.yml (git diff config.example.yml)"
[ ${#WARNINGS[@]} -eq 0 ] && ok "nothing to do by hand"

if ! $DRY; then
    $PY - "$STATE" "$REQ_HASH" "$EXAMPLE_HASH" "$ROUTER_HASHES" "$(git rev-parse --short HEAD)" <<'EOF'
import json, sys
from datetime import UTC, datetime
path, req, example, router, head = sys.argv[1:]
json.dump({"deployed_at": datetime.now(UTC).isoformat(timespec="seconds"), "git_head": head,
           "requirements": req, "config_example": example, "router": router}, open(path, "w"), indent=1)
EOF
fi

$DRY && DONE="dry run done (nothing changed)" || DONE=deployed
printf '\n\033[32m%s\033[0m%s%s\n' "$DONE" \
    "${RESTARTED[*]:+ (restarted: ${RESTARTED[*]})}" "${WARNINGS[*]:+, ${#WARNINGS[@]} warning(s) above}"
