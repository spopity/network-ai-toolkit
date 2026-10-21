"""Minimal Gemini generateContent client with function calling.

Model turns are kept verbatim (including ``thoughtSignature`` parts): Gemini 3
rejects follow-up calls whose function-call turns were altered.
"""
import time

import requests


class GeminiError(RuntimeError):
    pass


class Gemini:
    def __init__(self, api_key: str, model: str, timeout: int = 120, retries: int = 2):
        if not api_key:
            raise GeminiError("GEMINI_API_KEY not configured")
        self.api_key = api_key
        self.model = model if model.startswith("models/") else f"models/{model}"
        self.timeout = timeout
        self.retries = retries
        self.last_model_version = None

    @property
    def url(self) -> str:
        return f"https://generativelanguage.googleapis.com/v1beta/{self.model}:generateContent"

    def generate(self, contents: list, system: str, tools: list) -> dict:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": contents,
            "tools": [{"functionDeclarations": tools}],
        }
        last_err = None
        for attempt in range(self.retries + 1):
            try:
                r = requests.post(self.url, params={"key": self.api_key}, json=body, timeout=self.timeout)
            except requests.RequestException as e:
                last_err = GeminiError(f"Gemini unreachable: {e}")
            else:
                if r.status_code == 200:
                    data = r.json()
                    self.last_model_version = data.get("modelVersion")
                    cands = data.get("candidates") or []
                    content = cands[0].get("content") if cands else None
                    if not content or not content.get("parts"):
                        reason = cands[0].get("finishReason") if cands else data.get("promptFeedback")
                        raise GeminiError(f"Gemini returned no content ({reason})")
                    content.setdefault("role", "model")
                    return content
                msg = r.text[:300]
                last_err = GeminiError(f"Gemini HTTP {r.status_code}: {msg}")
                if r.status_code not in (429, 500, 502, 503, 504):
                    raise last_err
            if attempt < self.retries:
                time.sleep(2 * (attempt + 1))
        raise last_err
