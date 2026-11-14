"""Who is using the dashboard, and may they approve Tshoot router changes?

The dashboard has two listeners (dashboard/serve.py):

  * a Unix socket that only `tailscale serve` proxies to. Tailscale serve adds
    Tailscale-User-Login / -Name and X-Forwarded-For (the client's tailnet IP) and
    strips client-supplied copies of them (verified 2026-11-14), so on this listener
    the headers can be trusted. MarkTailscale tags those requests.
  * a TCP port on the LAN address for the router's wan-event hook and Tshoot's API
    calls. Requests there carry no identity and can never approve.

The device is looked up with `tailscale whois` on the forwarded IP, so approvals can
be limited to specific devices (e.g. your phone and laptop, not a server that also
runs under your account). Configured in config.yml:

  dashboard:
    approvers:
      logins: [you@example.com]
      devices: [laptop, phone]      # optional; empty = any device of those logins
"""
import json
import subprocess
import time

VIA_TAILSCALE = "network_ai.via_tailscale"
WHOIS_TTL = 300
_whois_cache: dict[str, tuple[float, dict | None]] = {}


class MarkTailscale:
    """WSGI middleware for the Unix-socket listener behind `tailscale serve`."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ[VIA_TAILSCALE] = True
        return self.app(environ, start_response)


def whois(ip: str) -> dict | None:
    """{"device", "login", "tags"} for a tailnet IP, cached; None when unknown."""
    hit = _whois_cache.get(ip)
    if hit and time.monotonic() - hit[0] < WHOIS_TTL:
        return hit[1]
    info = None
    try:
        out = subprocess.run(["tailscale", "whois", "--json", ip], capture_output=True, text=True, timeout=5, check=True)
        d = json.loads(out.stdout)
        node = d.get("Node") or {}
        info = {
            "device": node.get("ComputedName") or (node.get("Hostinfo") or {}).get("Hostname"),
            "login": (d.get("UserProfile") or {}).get("LoginName"),
            "tags": node.get("Tags") or [],
        }
    except (OSError, subprocess.SubprocessError, ValueError):
        info = None
    _whois_cache[ip] = (time.monotonic(), info)
    return info


def identify(environ: dict, headers) -> dict:
    if not environ.get(VIA_TAILSCALE):
        return {"via_tailscale": False}
    ip = (headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    w = whois(ip) if ip else None
    return {
        "via_tailscale": True,
        "login": headers.get("Tailscale-User-Login") or None,  # absent for tagged devices
        "name": headers.get("Tailscale-User-Name") or None,
        "ip": ip or None,
        "device": (w or {}).get("device"),
        "tagged": bool((w or {}).get("tags")),
    }


def can_approve(ident: dict, approvers: dict | None) -> tuple[bool, str]:
    """-> (allowed, reason shown to the user when not)."""
    approvers = approvers or {}
    if not ident.get("via_tailscale"):
        return False, "Approvals are only accepted through Tailscale (the https://….ts.net address)."
    logins = {x.lower() for x in approvers.get("logins") or []}
    if not logins:
        return False, "No approvers are configured (dashboard.approvers.logins in config.yml)."
    login = (ident.get("login") or "").lower()
    if ident.get("tagged") or login not in logins:
        return False, f"{ident.get('login') or 'This Tailscale identity'} may not approve router changes."
    devices = {x.lower() for x in approvers.get("devices") or []}
    if devices and (ident.get("device") or "").lower() not in devices:
        return False, (f"Approvals are not accepted from {ident.get('device') or ident.get('ip') or 'this device'}; "
                       f"use {', '.join(sorted(approvers.get('devices')))}.")
    return True, ""
