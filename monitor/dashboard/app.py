import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    request,
    send_from_directory,
    stream_with_context,
)

try:
    load_dotenv()
except OSError:
    pass  # under systemd .env stays root-only; the unit passes it via EnvironmentFile=

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from router_agent import db, notify, report
from router_agent.devices import device_names, name_analysis
from router_agent.events import append_router_event, read_router_events
from router_agent.identity import can_approve, identify
from router_agent.netmap import build_map

CONFIG_PATH = Path(os.getenv("NETWORK_AI_CONFIG", BASE_DIR / "config.yml"))
COLLECT_SCRIPT = BASE_DIR / "collect_and_analyze.py"
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

# Tshoot troubleshooting agent: separate service in /opt/tshoot, proxied under /api/tshoot/*
TSHOOT_URL = os.getenv("TSHOOT_URL", "http://127.0.0.1:8090")
TSHOOT_PROXY_KEY = os.getenv("TSHOOT_PROXY_KEY", "")  # shared with /opt/tshoot/.env

STALE_LOCK_SECONDS = 900  # safety net: self-heal if a watcher thread died without cleaning up

app = Flask(__name__, static_folder=None)


def load_config() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text())


def log_dir() -> Path:
    cfg = load_config()
    d = Path(cfg.get("log_dir", "logs"))
    d = d if d.is_absolute() else BASE_DIR / d
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _lock_path() -> Path:
    return log_dir() / ".collect.lock"


def _last_result_path() -> Path:
    return log_dir() / ".collect_last_result.json"


# "Check now" in production: the dashboard runs unprivileged and must not SSH to the router
# itself, so it touches a trigger file that network-ai-check.path watches; systemd then
# starts the normal check unit (as root). Without that path unit (development, other
# installs) it falls back to running the check script as a subprocess.
CHECK_UNIT = "network-ai-check.service"
TRIGGER_FILE = ".collect-request"
TRIGGER_PENDING_SECONDS = 30


def _systemd_mode() -> bool:
    try:
        r = subprocess.run(["systemctl", "is-enabled", "network-ai-check.path"], check=False, capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "enabled"
    except (OSError, subprocess.SubprocessError):
        return False


def _unit_status() -> dict:
    out = subprocess.run(
        ["systemctl", "show", CHECK_UNIT, "--timestamp=unix", "-p", "ActiveState", "-p", "Result",
         "-p", "ExecMainStartTimestamp", "-p", "ExecMainExitTimestamp", "-p", "ExecMainStatus"],
        capture_output=True, text=True, timeout=5, check=True).stdout
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    def ts(key):
        v = props.get(key, "").lstrip("@")
        return datetime.fromtimestamp(int(v), UTC) if v.isdigit() and int(v) else None

    started, finished = ts("ExecMainStartTimestamp"), ts("ExecMainExitTimestamp")
    running = props.get("ActiveState") in ("activating", "active", "reloading", "deactivating")
    trig = log_dir() / TRIGGER_FILE
    if not running and trig.exists():  # requested, systemd hasn't started it yet
        t = datetime.fromtimestamp(trig.stat().st_mtime, UTC)
        if (started is None or t > started) and (datetime.now(UTC) - t).total_seconds() < TRIGGER_PENDING_SECONDS:
            running, started = True, t
    iso = lambda t: t.isoformat(timespec="seconds") if t else None
    return {
        "running": running,
        "started_at": iso(started),
        "finished_at": None if running else iso(finished),
        "last_result": None if running else ("ok" if props.get("Result") == "success" and props.get("ExecMainStatus") == "0" else "error"),
    }


def _run_collect_background():
    lp = _lock_path()
    started_at = read_json(lp).get("started_at") if read_json(lp) else None
    try:
        proc = subprocess.run(  # noqa: PLW1510 -- returncode checked below
            [sys.executable, str(COLLECT_SCRIPT), "--config", str(CONFIG_PATH)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
        )
        result = "ok" if proc.returncode == 0 else "error"
    except Exception:
        result = "error"
    finally:
        lp.unlink(missing_ok=True)
        _last_result_path().write_text(json.dumps({
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "result": result,
        }))


# ---- static frontend (React build output) ----

@app.route("/")
@app.route("/<path:path>")
def serve_frontend(path="index.html"):
    full = FRONTEND_DIST / path
    if full.is_file():
        return send_from_directory(FRONTEND_DIST, path)
    return send_from_directory(FRONTEND_DIST, "index.html")


# ---- API ----

@app.route("/api/state")
def api_state():
    ld = log_dir()
    latest = read_json(ld / "latest.json") or {}
    watchdog_status = read_json(ld / "watchdog_status.json") or {}

    watchdog_log_path = ld / "watchdog.log"
    recent_events = []
    if watchdog_log_path.exists():
        lines = watchdog_log_path.read_text().splitlines()
        for line in lines[-20:]:
            try:
                recent_events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    events = recent_events + read_router_events(ld, limit=20)
    events.sort(key=lambda e: e.get("ts", ""), reverse=True)

    return jsonify({
        "snapshot": latest.get("snapshot"),
        # older briefings cited bare MACs: always show each device's name alongside
        "analysis": name_analysis(latest.get("analysis"), device_names(ld, latest.get("snapshot"))),
        "watchdog": watchdog_status,
        "watchdog_events": events[:30],
    })


ROUTER_EVENT_FIELDS = ("unit", "state", "sbstate", "auxstate", "ip", "gateway", "router_uptime")
FIRMWARE_EVENT_FIELDS = ("model", "current", "new")


@app.route("/api/router-event", methods=["POST"])
def api_router_event():
    """Receives events from the router's Merlin hooks: WAN state transitions
    (wan-event) and new firmware releases (update-notification, "type": "firmware").
    Only the configured routers may post (LAN-only, no other auth)."""
    cfg = load_config()
    router_hosts = {r.get("host") for r in cfg.get("routers", [])}
    if request.remote_addr not in router_hosts:
        return jsonify({"error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}
    notify.configure(cfg, log_dir())  # Telegram: dns/firmware events are pushed from append_router_event
    if body.get("type") == "firmware":
        event = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "event": "router_firmware_available",
            "source": "router",
            **{k: str(body[k])[:64] for k in FIRMWARE_EVENT_FIELDS if body.get(k)},
        }
        if not event.get("new"):
            return jsonify({"error": "missing new"}), 400
        if event["new"] == event.get("current"):  # already installed: nothing to report
            return jsonify({"status": "ignored"}), 200
        append_router_event(log_dir(), event)
        return jsonify({"status": "ok"}), 201

    kind = re.sub(r"[^a-z_]", "", str(body.get("event", "")).lower())[:32]
    if not kind:
        return jsonify({"error": "missing event"}), 400

    event = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "event": f"router_wan_{kind}",
        "source": "router",
        **{k: str(body[k])[:64] for k in ROUTER_EVENT_FIELDS if k in body},
    }
    append_router_event(log_dir(), event)
    return jsonify({"status": "ok"}), 201


@app.route("/api/history")
def api_history():
    days = request.args.get("days", default=30, type=int)
    try:
        snapshots = db.get_snapshot_history(days=days)
        watchdog_events = db.get_watchdog_event_history(days=days)
        return jsonify({"snapshots": snapshots, "watchdog_events": watchdog_events, "available": True})
    except Exception as e:
        # degrade gracefully -- history is an archival nice-to-have, not load-bearing
        return jsonify({"snapshots": [], "watchdog_events": [], "available": False, "error": str(e)})


def _dns_args():
    hours = max(1, min(request.args.get("hours", default=24, type=int), 24 * 90))
    blank = lambda k: (request.args.get(k) or "").strip() or None
    return hours, blank


@app.route("/api/dns/devices")
def api_dns_devices():
    """Per-device DNS totals from the AdGuardHome archive (?hours=24&network=IoT)."""
    hours, arg = _dns_args()
    try:
        return jsonify({"available": True, "hours": hours, "devices": db.get_dns_devices(hours, arg("network"))})
    except Exception as e:
        return jsonify({"available": False, "hours": hours, "devices": [], "error": str(e)})


@app.route("/api/dns/lookups")
def api_dns_lookups():
    """Which device looked up what (?hours=24&device=<name|ip|mac|key>&domain=<substring>
    &network=IoT&blocked=1&new=1&limit=200). Used by the dashboard and Tshoot."""
    hours, arg = _dns_args()
    flag = lambda k: request.args.get(k, "").lower() in ("1", "true", "yes")
    limit = max(1, min(request.args.get("limit", default=200, type=int), 1000))
    try:
        rows = db.get_dns_lookups(hours, device=arg("device"), domain=arg("domain"), network=arg("network"),
                                  blocked_only=flag("blocked"), new_only=flag("new"), limit=limit)
        return jsonify({"available": True, "hours": hours, "lookups": rows})
    except Exception as e:
        return jsonify({"available": False, "hours": hours, "lookups": [], "error": str(e)})


@app.route("/api/traffic/devices")
def api_traffic_devices():
    """Per-device internet usage from the Traffic Analyzer archive (?hours=24&network=IoT)."""
    hours, arg = _dns_args()
    try:
        return jsonify({"available": True, "hours": hours, "devices": db.get_traffic_devices(hours, arg("network"))})
    except Exception as e:
        return jsonify({"available": False, "hours": hours, "devices": [], "error": str(e)})


def _history_args():
    days = max(1, min(request.args.get("days", default=90, type=int), 3650))
    bucket = request.args.get("bucket", "day")
    blank = lambda k: (request.args.get(k) or "").strip() or None
    return days, (bucket if bucket in db.HISTORY_BUCKETS else "day"), blank


@app.route("/api/traffic/history")
def api_traffic_history():
    """Long-range internet usage (?days=365&bucket=day|week|month&device=&network=): totals per
    period + top devices, from the daily summaries (kept after raw rows are pruned)."""
    days, bucket, arg = _history_args()
    try:
        data = db.get_traffic_history(days, bucket, device=arg("device"), network=arg("network"))
        return jsonify({"available": True, "days": days, "bucket": bucket, **data})
    except Exception as e:
        return jsonify({"available": False, "days": days, "bucket": bucket, "series": [], "devices": [],
                        "error": str(e)})


@app.route("/api/dns/history")
def api_dns_history():
    """Long-range DNS totals (?days=365&bucket=day|week|month&device=&network=): queries/blocked
    per period + top devices. No domain names (those stay in the 90-day raw archive)."""
    days, bucket, arg = _history_args()
    try:
        data = db.get_dns_history(days, bucket, device=arg("device"), network=arg("network"))
        return jsonify({"available": True, "days": days, "bucket": bucket, **data})
    except Exception as e:
        return jsonify({"available": False, "days": days, "bucket": bucket, "series": [], "devices": [],
                        "error": str(e)})


@app.route("/api/reports")
def api_reports():
    """Saved weekly/monthly reports, newest first (?period=week|month&limit=4). Files only
    (logs/reports/), so this works without Postgres."""
    period = request.args.get("period")
    period = period if period in report.PERIODS else None
    limit = max(1, min(request.args.get("limit", default=4, type=int), 24))
    return jsonify({"reports": report.latest(log_dir(), period, limit)})


@app.route("/api/traffic/detail")
def api_traffic_detail():
    """Apps + hourly series (?hours=24&device=<mac|ip|name>&network=IoT&limit=50); no device = everything.
    Used by the dashboard and Tshoot."""
    hours, arg = _dns_args()
    limit = max(1, min(request.args.get("limit", default=50, type=int), 200))
    try:
        apps = db.get_traffic_apps(hours, device=arg("device"), network=arg("network"), limit=limit)
        series = db.get_traffic_series(min(hours, 24 * 31), device=arg("device"), network=arg("network"))
        return jsonify({"available": True, "hours": hours, "apps": apps, "series": series})
    except Exception as e:
        return jsonify({"available": False, "hours": hours, "apps": [], "series": [], "error": str(e)})


@app.route("/api/network-map")
def api_network_map():
    """Every device on the network with its room, type, brand and link to a mesh node,
    plus the router's services -- built from the latest 5-minute check (no SSH here)."""
    ld = log_dir()
    snap = (read_json(ld / "latest.json") or {}).get("snapshot")
    known = read_json(ld / "known_clients.json") or {}
    return jsonify(build_map(snap, known if isinstance(known, dict) else {}, load_config()))


@app.route("/api/connmon")
def api_connmon():
    """Ping/jitter/line-quality points from the router's connmon DB. The 5-minute check
    copies the last 7 days into logs/connmon.json, so the dashboard never SSHes itself."""
    hours = max(1, min(request.args.get("hours", default=24, type=int), 24 * 7))
    data = read_json(log_dir() / "connmon.json")
    if not data:
        return jsonify({"points": [], "available": False, "hours": hours, "error": "no connmon data yet"})
    cutoff = time.time() - hours * 3600
    points = [p for p in data.get("points", []) if p.get("ts", 0) > cutoff]
    return jsonify({"points": points, "available": True, "hours": hours, "fetched_at": data.get("fetched_at")})


@app.route("/api/collect-now", methods=["POST"])
def api_collect_now():
    if _systemd_mode():
        st = _unit_status()
        if st["running"]:
            return jsonify({"status": "already_running", "started_at": st["started_at"]}), 409
        (log_dir() / TRIGGER_FILE).write_text(datetime.now(UTC).isoformat(timespec="seconds"))
        return jsonify({"status": "started", "started_at": datetime.now(UTC).isoformat(timespec="seconds")}), 202
    lp = _lock_path()
    existing = read_json(lp)
    if existing:
        started_at = existing.get("started_at")
        age = time.time() - existing.get("started_ts", 0)
        if age < STALE_LOCK_SECONDS:
            return jsonify({"status": "already_running", "started_at": started_at}), 409
        # stale lock from a watcher thread that died (e.g. dashboard restart mid-run) -- self-heal

    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    lp.write_text(json.dumps({"pid": os.getpid(), "started_at": started_at, "started_ts": time.time()}))

    threading.Thread(target=_run_collect_background, daemon=True).start()
    return jsonify({"status": "started", "started_at": started_at}), 202


@app.route("/api/collect-status")
def api_collect_status():
    if _systemd_mode():
        try:
            return jsonify(_unit_status())
        except (OSError, subprocess.SubprocessError) as e:
            return jsonify({"running": False, "started_at": None, "finished_at": None, "last_result": "error", "error": str(e)})
    lp = _lock_path()
    lock = read_json(lp)
    last_result = read_json(_last_result_path()) or {}
    return jsonify({
        "running": lock is not None,
        "started_at": lock.get("started_at") if lock else last_result.get("started_at"),
        "finished_at": last_result.get("finished_at"),
        "last_result": last_result.get("result"),
    })


def _identity() -> dict:
    return identify(request.environ, request.headers)


@app.route("/api/whoami")
def api_whoami():
    """Who the dashboard sees (via Tailscale serve) and whether they may approve Tshoot changes."""
    ident = _identity()
    ok, why = can_approve(ident, (load_config().get("dashboard") or {}).get("approvers"))
    return jsonify({**ident, "can_approve": ok, "reason": why or None})


@app.route("/api/tshoot/<path:sub>", methods=["GET", "POST"])
def api_tshoot_proxy(sub):
    headers = {"Content-Type": request.headers.get("Content-Type", "application/json")}
    if TSHOOT_PROXY_KEY:  # Tshoot only answers requests that came through this proxy
        headers["X-Tshoot-Proxy-Key"] = TSHOOT_PROXY_KEY
    ident = _identity()
    if ident.get("login"):
        headers["X-Tshoot-User"] = f"{ident['login']} on {ident.get('device') or ident.get('ip') or '?'}"
    if sub == "approve" and request.method == "POST":
        body = request.get_json(silent=True) or {}
        if body.get("decision") == "approve":  # rejecting is always allowed
            ok, why = can_approve(ident, (load_config().get("dashboard") or {}).get("approvers"))
            if not ok:
                return jsonify({"error": f"Not approved: {why}"}), 403
    try:
        upstream = requests.request(
            request.method,
            f"{TSHOOT_URL}/api/tshoot/{sub}",
            params=request.args,
            data=request.get_data(),
            headers=headers,
            stream=True,
            timeout=(5, 600),
        )
    except requests.RequestException as e:
        return jsonify({"error": f"Tshoot service unreachable: {e}"}), 502

    def relay():
        try:
            yield from upstream.iter_content(chunk_size=None)
        finally:
            upstream.close()

    return Response(
        stream_with_context(relay()),
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type"),
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    dash_cfg = load_config().get("dashboard", {})
    if "--dev" in sys.argv:  # Flask's development server, single TCP listener
        app.run(host=dash_cfg.get("host", "127.0.0.1"), port=dash_cfg.get("port", 8080), threaded=True)
    else:
        # dashboard/serve.py; this script's directory is on sys.path
        from serve import run

        run(app, dash_cfg)
