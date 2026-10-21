"""Mask secrets in router output before it reaches Gemini, the UI or the audit log."""
import re

_SECRET_NAME = r"[\w.\-]*(?:passwd|password|_psk|wpa_psk|_key\d?|keystr|secret|token|pin_code|radius_key|_pass)\b"

_KV_LINE = re.compile(rf"^(\s*{_SECRET_NAME}\s*=\s*)(\S.*)$", re.IGNORECASE | re.MULTILINE)
_NVRAM_GET_SECRET = re.compile(rf"\bnvram\s+get\s+{_SECRET_NAME}", re.IGNORECASE)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)

MASK = "***redacted***"


def redact(command: str, output: str) -> str:
    if not output:
        return output
    if _NVRAM_GET_SECRET.search(command or "") and "|" not in command and ";" not in command:
        return MASK if output.strip() else output
    output = _PRIVATE_KEY.sub(MASK, output)
    return _KV_LINE.sub(lambda m: m.group(1) + MASK, output)
