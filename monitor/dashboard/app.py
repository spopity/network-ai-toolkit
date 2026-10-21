import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from router_agent import db
from router_agent.events import append_router_event, read_router_events
from router_agent.collector import CONNMON_DB, SSHCollector
CONFIG_PATH = Path(os.getenv("NETWORK_AI_CONFIG", BASE_DIR / "config.yml"))
COLLECT_SCRIPT = BASE_DIR / "collect_and_analyze.py"
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

# Tshoot troubleshooting agent: separate service in /opt/tshoot, proxied under /api/tshoot/*
TSHOOT_URL = os.getenv("TSHOOT_URL", "http://127.0.0.1:8090")

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


def _run_collect_background():
    lp = _lock_path()
    started_at = read_json(lp).get("started_at") if read_json(lp) else None
    try:
        proc = subprocess.run(
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
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
        "analysis": latest.get("analysis"),
        "watchdog": watchdog_status,
        "watchdog_events": events[:30],
    })


ROUTER_EVENT_FIELDS = ("unit", "state", "sbstate", "auxstate", "ip", "gateway", "router_uptime")


@app.route("/api/router-event", methods=["POST"])
def api_router_event():
    """Receives WAN state transitions from the router's Merlin wan-event hook.
    Only the configured routers may post (LAN-only, no other auth)."""
    router_hosts = {r.get("host") for r in load_config().get("routers", [])}
    if request.remote_addr not in router_hosts:
        return jsonify({"error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}
    kind = re.sub(r"[^a-z_]", "", str(body.get("event", "")).lower())[:32]
    if not kind:
        return jsonify({"error": "missing event"}), 400

    event = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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


CONNMON_CACHE_SECONDS = 120  # connmon writes a new row every 5 min; don't SSH on every page poll
_connmon_cache: dict = {}


@app.route("/api/connmon")
def api_connmon():
    """Ping/jitter/line-quality rows from the router's connmon SQLite DB (live, via SSH)."""
    hours = max(1, min(request.args.get("hours", default=24, type=int), 24 * 7))
    cached = _connmon_cache.get(hours)
    if cached and time.time() - cached[0] < CONNMON_CACHE_SECONDS:
        return jsonify(cached[1])

    r = load_config()["routers"][0]
    sql = (f"SELECT Timestamp, Ping, Jitter, LineQuality FROM connstats "
           f"WHERE Timestamp > strftime('%s','now','-{hours} hours') ORDER BY Timestamp")
    collector = SSHCollector(host=r["host"], port=r.get("port", 22), username=r.get("username"),
                             password=r.get("password"), key_filename=r.get("key_filename"))
    try:
        out = collector.run_command(f"sqlite3 -separator '|' {CONNMON_DB} \"{sql}\"", timeout=20)["out"]
    except Exception as e:
        return jsonify({"points": [], "available": False, "error": str(e)})
    finally:
        collector.close()

    points = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) == 4:
            try:
                points.append({"ts": int(float(parts[0])), "ping": float(parts[1]),
                               "jitter": float(parts[2]), "quality": float(parts[3])})
            except ValueError:
                continue
    payload = {"points": points, "available": True, "hours": hours}
    _connmon_cache[hours] = (time.time(), payload)
    return jsonify(payload)


@app.route("/api/collect-now", methods=["POST"])
def api_collect_now():
    lp = _lock_path()
    existing = read_json(lp)
    if existing:
        started_at = existing.get("started_at")
        age = time.time() - existing.get("started_ts", 0)
        if age < STALE_LOCK_SECONDS:
            return jsonify({"status": "already_running", "started_at": started_at}), 409
        # stale lock from a watcher thread that died (e.g. dashboard restart mid-run) -- self-heal

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lp.write_text(json.dumps({"pid": os.getpid(), "started_at": started_at, "started_ts": time.time()}))

    threading.Thread(target=_run_collect_background, daemon=True).start()
    return jsonify({"status": "started", "started_at": started_at}), 202


@app.route("/api/collect-status")
def api_collect_status():
    lp = _lock_path()
    lock = read_json(lp)
    last_result = read_json(_last_result_path()) or {}
    return jsonify({
        "running": lock is not None,
        "started_at": lock.get("started_at") if lock else last_result.get("started_at"),
        "finished_at": last_result.get("finished_at"),
        "last_result": last_result.get("result"),
    })


@app.route("/api/tshoot/<path:sub>", methods=["GET", "POST"])
def api_tshoot_proxy(sub):
    try:
        upstream = requests.request(
            request.method,
            f"{TSHOOT_URL}/api/tshoot/{sub}",
            params=request.args,
            data=request.get_data(),
            headers={"Content-Type": request.headers.get("Content-Type", "application/json")},
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
    cfg = load_config()
    dash_cfg = cfg.get("dashboard", {})
    app.run(host=dash_cfg.get("host", "0.0.0.0"), port=dash_cfg.get("port", 8080))
