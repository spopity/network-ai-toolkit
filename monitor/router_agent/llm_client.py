import json
import os
import re
import requests

from .snapshot import wifi_client_macs
from .summarize import split_by_section, summarize_text

try:
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request as GoogleRequest
    GCP_AVAILABLE = True
except Exception:
    GCP_AVAILABLE = False


LOG_FORMAT_NOTE = (
    'Logs are pre-summarized: each "messages" entry is either a one-off {at, message} or a repeated message '
    "template (variable parts as <IP>/<MAC>/N) with count, first/last time and sample values; "
    '"notable" marks error-like wording.'
).replace("{", "{{").replace("}", "}}")  # survives the str.format() below

SECTION_PROMPTS = {
    "security": """You are analyzing a home router's security logs and settings (ASUS router running Asuswrt-Merlin). In ONE short paragraph (2-4 sentences, plain text, no markdown), flag only real issues: malware blocks, suspicious or failed logins, exposed configuration, inbound traffic that targets a port the router actually exposes. SSH logins from monitoring_host_ip are this monitoring system itself, not a person. "asus_cloud_service_log" is the router's OWN outbound connection to ASUS's cloud (remote access / ASUS Router app): its "Login failed" entries mean the router failed to log in to ASUS servers -- a connectivity issue, not an attack. "firewall_drops" summarizes logged firewall blocks (Skynet logging is rate-limited, so counts are samples): inbound packets the WAN firewall/Skynet already DROPPED -- background internet scanning is normal and harmless, so only mention it if something stands out (e.g. one source hammering persistently, or a sudden spike). "outbound_blocks" is different and important: a LAN device tried to reach a blocklisted (malware/botnet) address -- always mention it, naming the LAN device IP and how often. If nothing is notable, reply exactly "Nothing notable."

""" + LOG_FORMAT_NOTE + """

Data:
{data}""",
    "wifi": """You are analyzing a home AiMesh wifi network (a main router plus satellite nodes; counts cover every node, sampled every 5 minutes over the last 24 hours). In ONE short sentence or two (plain text, no markdown), note anything unusual: devices never seen before (randomized MACs are normal for phones), an unexpectedly high client count, many clients with weak signal. The owner deliberately pins some devices to 2.4 GHz and others to 5 GHz and chooses which node they use, so NEVER comment on how clients are split between bands or between nodes. If nothing is notable, reply exactly "Nothing notable."

""" + LOG_FORMAT_NOTE + """

Data:
{data}""",
    "system": """You are analyzing a home router's system health (CPU load, memory, uptime, temperatures in Celsius, WAN state). The router runs Asuswrt-Merlin (third-party firmware; its version format differs from stock ASUS firmware -- that's expected). "router_wan_events_24h" counts WAN state changes the router itself reported in the last 24 hours, and "watchdog_24h" the internet outages the LAN-side watchdog measured; repeated disconnects are worth flagging, a single nightly reconnect is common with PPPoE ISPs. In ONE short sentence or two (plain text, no markdown), "peaks_24h" are the extremes across the 5-minute checks of the last 24 hours (load, memory, temperatures, checks where the WAN was down, router reboots) while the other numbers are the current values. "connection_quality_24h" comes from connmon (30 s ping test every 5 min; line quality 100% = no loss) -- compare against its 7-day baseline; "speedtest" is spdMerlin's daily test with a 7-day average. Flag anything concerning: high load, low memory, packet loss or ping/jitter well above baseline, speeds well below the 7-day average, overheating (CPU above ~85C, radios above ~95C), WAN down or flapping. If nothing is notable, reply exactly "Nothing notable."

""" + LOG_FORMAT_NOTE + """

Data:
{data}""",
}

OVERALL_PROMPT = """Given these router health findings, write ONE short sentence summarizing overall status plus, if relevant, one concrete recommended action. Plain text, no markdown.

SECURITY: {security}
WIFI: {wifi}
SYSTEM: {system}"""


def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _clean_text(text: str, max_chars: int = 700) -> str:
    text = _strip_think(text)
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)  # markdown headers
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)  # bold
    text = re.sub(r"^-{3,}\s*$", "", text, flags=re.MULTILINE)  # horizontal rules
    text = re.sub(r"^\s*[-*]\s+", "• ", text, flags=re.MULTILINE)  # bullets
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rsplit(" ", 1)[0] + "…"
    return text


_WAN_STATES = {"0": "init", "1": "connecting", "2": "connected", "3": "disconnected", "4": "stopped"}


def _compact(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)


def _is_randomized(mac: str) -> bool:
    # locally-administered bit set -> private/randomized MAC (phones, laptops)
    return len(mac) > 1 and mac[1].upper() in "26AE"


def build_section_data(snapshot: dict, day: dict = None) -> dict:
    """Everything an LLM sees, already summarized: no raw log lines, only
    templated message counts and derived numbers. Returns compact JSON strings.
    `day` is the rendered 24h rollup of the 5-minute checks (rollup.render); when
    given, its syslog/firewall aggregates replace the snapshot's single-tail ones."""
    sec = snapshot.get("security", {})
    system = snapshot.get("system", {})
    wan = snapshot.get("wan", {})
    wifi = snapshot.get("wifi", {})
    day = day or {}
    peaks = day.get("peaks") or {}
    drops = day.get("firewall_drops") or sec.get("firewall_drops") or {}
    # older snapshots have no stored summaries -- summarize their raw tails on the fly
    syslog = split_by_section(
        day.get("syslog_summary") or sec.get("syslog_summary") or summarize_text(sec.get("syslog_tail", ""), top=40)
    )

    security = {
        "aiprotection_enabled": sec.get("aiprotection_enabled"),
        "malware_block_enabled": sec.get("malware_block_enabled"),
        "monitoring_host_ip": snapshot.get("collector_ip"),
        "firewall_drops": {
            "total": drops.get("total"),
            "window": [drops.get("window_start"), drops.get("window_end")],
            "unique_sources": drops.get("unique_sources"),
            "top_ports": (drops.get("top_ports") or [])[:5],
            "top_sources": (drops.get("top_sources") or [])[:5],
            "by_kind": drops.get("by_kind"),
            "outbound_blocks": drops.get("outbound"),
            "skynet_blocklist_sizes": drops.get("skynet_banned"),
        },
        "syslog": syslog["security"],
        "web_and_app_logins": sec.get("security_log_summary") or summarize_text(sec.get("security_log_tail", ""), top=8),
        "asus_cloud_service_log": sec.get("aae_log_summary") or summarize_text(sec.get("aae_log_tail", ""), top=6),
    }

    clients = wifi_client_macs(wifi)
    # no per-band / per-node split: the owner places devices deliberately, so it's not a signal
    wifi_data = {
        "clients_now": wifi.get("client_count"),
        "clients_24h_min_max": [peaks.get("wifi_clients_min"), peaks.get("wifi_clients_max")] if peaks else None,
        "mesh_nodes": len(wifi.get("nodes", [])) or None,
        "weak_signal_clients_below_-75dBm": sum(
            1 for c in wifi.get("clients", []) if c.get("rssi") is not None and c["rssi"] < -75
        ),
        "randomized_macs": sum(_is_randomized(m) for m in clients),
        # None = no history to compare against yet
        "new_clients_never_seen_before": wifi.get("new_clients"),
        "wifi_log": syslog["wifi"],
    }

    mem_total = system.get("mem_total_kb") or 0
    events = wan.get("router_events_24h") or []
    event_counts: dict = {}
    for e in events:
        event_counts[e["event"]] = event_counts.get(e["event"], 0) + 1
    system_data = {
        "firmware": system.get("firmware") or f"{system.get('firmver')}.{system.get('buildno')}",
        "uptime_hours": round(system["uptime_seconds"] / 3600, 1) if system.get("uptime_seconds") else None,
        "loadavg_1_5_15": system.get("loadavg"),
        "mem_used_pct": round(100 * (1 - (system.get("mem_available_kb") or system.get("mem_free_kb", 0)) / mem_total), 1)
        if mem_total else None,
        "temps_c": system.get("temps_c"),
        "peaks_24h": peaks or None,
        "custom_scripts_enabled": system.get("jffs_scripts_enabled"),
        "wan": {
            "state": _WAN_STATES.get(str(wan.get("state")), wan.get("state")),
            "proto": wan.get("proto"),
            "pppd_running": wan.get("pppd_running"),
        },
        "router_wan_events_24h": {"counts": event_counts, "latest": [
            {"ts": e["ts"], "event": e["event"]} for e in events[:5]
        ]},
        "watchdog_24h": wan.get("watchdog_24h"),
        "connection_quality_24h": wan.get("connmon"),
        "speedtest": wan.get("speedtest"),
        "system_log": syslog["system"],
    }
    return {"security": _compact(security), "wifi": _compact(wifi_data), "system": _compact(system_data)}


class GeminiClient:
    def __init__(self, api_key: str = None, api_url: str = None, timeout: int = 20):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.api_url = api_url or os.getenv("GEMINI_API_URL")
        self.timeout = timeout

    def analyze(self, prompt: str) -> str:
        use_gcp = os.getenv("USE_GCP_GEMINI", "").lower() in ("1", "true", "yes") or bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
        if use_gcp:
            return self._analyze_gcp(prompt)
        return self._analyze_bearer(prompt)

    def _analyze_bearer(self, prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY not configured")
        url = self.api_url or "https://api.example.com/v1/gemini"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        r = requests.post(url, json={"input": prompt}, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("output", "")

    def _analyze_gcp(self, prompt: str) -> str:
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        api_key = self.api_key

        token = None
        if cred_path:
            if not GCP_AVAILABLE:
                raise RuntimeError("google-auth library not installed")
            creds = service_account.Credentials.from_service_account_file(cred_path)
            scoped = creds.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
            scoped.refresh(GoogleRequest())
            token = scoped.token
        elif not api_key:
            raise RuntimeError("neither GOOGLE_APPLICATION_CREDENTIALS nor GEMINI_API_KEY provided")

        model = os.getenv("GEMINI_MODEL", "models/gemini-pro-latest")
        base_url = self.api_url or f"https://generativelanguage.googleapis.com/v1beta/{model}:generateContent"

        if token is None:
            sep = "&" if "?" in base_url else "?"
            url = f"{base_url}{sep}key={api_key}"
            headers = {"Content-Type": "application/json"}
        else:
            url = base_url
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        r = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raise RuntimeError(f"unexpected Gemini response: {data}")


class OllamaClient:
    def __init__(self, url: str, model: str, timeout: int = 30):
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def analyze(self, prompt: str) -> str:
        r = requests.post(
            f"{self.url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}},
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        if "response" not in data:
            raise RuntimeError(f"unexpected Ollama response: {data}")
        return data["response"]


class LLMRouter:
    def __init__(self, gemini: GeminiClient, ollama: OllamaClient):
        self.gemini = gemini
        self.ollama = ollama

    def _run_all_sections(self, backend, section_data: dict) -> dict:
        sections = {}
        for name, template in SECTION_PROMPTS.items():
            prompt = template.format(data=section_data[name])
            sections[name] = _clean_text(backend.analyze(prompt))
        overall_prompt = OVERALL_PROMPT.format(
            security=sections["security"], wifi=sections["wifi"], system=sections["system"]
        )
        sections["overall"] = _clean_text(backend.analyze(overall_prompt))
        return sections

    def analyze(self, snapshot: dict, day: dict = None) -> dict:
        section_data = build_section_data(snapshot, day)
        try:
            sections = self._run_all_sections(self.gemini, section_data)
            return {"source": "gemini", "sections": sections}
        except Exception as gemini_err:
            try:
                sections = self._run_all_sections(self.ollama, section_data)
                return {"source": "ollama", "sections": sections}
            except Exception as ollama_err:
                return {
                    "source": "none",
                    "error": f"gemini failed ({gemini_err}); ollama failed ({ollama_err})",
                    "sections": {},
                }
