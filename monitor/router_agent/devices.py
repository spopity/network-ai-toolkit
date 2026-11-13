"""MAC -> human-readable device name, so the AI briefing never shows a bare MAC.

Names come from the current snapshot's wifi clients (router-UI name, then
networkmap's learned name, then vendor) and from known_clients.json, which
remembers the last name seen for every device -- so a device that has since
left the network still resolves.
"""
import json
import re
from pathlib import Path
from typing import Dict, Optional

_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")


def _norm(mac: str) -> str:
    return mac.upper().replace("-", ":")


def label(info: Optional[Dict]) -> str:
    """Display name for a client entry ({"name", "vendor"}); never empty."""
    info = info or {}
    if info.get("name"):
        return info["name"]
    if info.get("vendor"):
        return f"unnamed {info['vendor']} device"
    return "unnamed device"


def snapshot_names(snapshot: Optional[Dict]) -> Dict[str, str]:
    clients = ((snapshot or {}).get("wifi") or {}).get("clients") or []
    return {_norm(c["mac"]): label(c) for c in clients if c.get("mac")}


def device_names(log_dir, snapshot: Optional[Dict] = None) -> Dict[str, str]:
    """{MAC: label} from known_clients.json, overridden by the current snapshot."""
    names: Dict[str, str] = {}
    try:
        known = json.loads((Path(log_dir) / "known_clients.json").read_text())
    except (OSError, ValueError):
        known = {}
    for mac, entry in (known if isinstance(known, dict) else {}).items():
        if isinstance(entry, dict) and (entry.get("name") or entry.get("vendor")):
            names[_norm(mac)] = label(entry)
    names.update({m: n for m, n in snapshot_names(snapshot).items() if not n.startswith("unnamed") or m not in names})
    return names


def name_macs(text: str, names: Dict[str, str]) -> str:
    """Rewrite every MAC in `text` as "Name (MAC)" (or "(Name, MAC)" when the MAC
    is already parenthesized). MACs whose name already appears just before them
    are left alone, so the function is idempotent."""
    if not text:
        return text

    def repl(m: re.Match) -> str:
        mac = _norm(m.group(0))
        name = names.get(mac, "unnamed device")
        before = text[max(0, m.start() - len(name) - 4):m.start()]
        if name.lower() in before.lower():
            return mac
        if m.start() > 0 and text[m.start() - 1] == "(" and text[m.end():m.end() + 1] == ")":
            return f"{name}, {mac}"
        return f"{name} ({mac})"

    return _MAC.sub(repl, text)


def name_analysis(analysis: Optional[Dict], names: Dict[str, str]) -> Optional[Dict]:
    """Copy of an analysis record with every section's MACs named."""
    if not analysis or not analysis.get("sections"):
        return analysis
    return {**analysis, "sections": {k: name_macs(v, names) if isinstance(v, str) else v
                                     for k, v in analysis["sections"].items()}}
