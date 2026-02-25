"""Target adapter — sends prompts to the target system and measures timing."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx


@dataclass
class TargetResponse:
    text: str
    status_code: int
    elapsed_ms: float
    error: str | None = None


class Target:
    def __init__(self, cfg: dict):
        self._url = cfg["url"]
        self._headers = cfg.get("headers", {})
        self._timeout = cfg.get("timeout_s", 30)

        req = cfg.get("request_body", {})
        self._msg_field = req.get("message_field", "message")
        self._session_field = req.get("session_field", "session_id")

        resp = cfg.get("response_body", {})
        self._text_field = resp.get("text_field", "response")

        self._client = httpx.Client(
            headers=self._headers,
            timeout=self._timeout,
        )

    def send(self, message: str, session_id: str) -> TargetResponse:
        payload = {
            self._msg_field: message,
            self._session_field: session_id,
        }
        t0 = time.perf_counter()
        try:
            r = self._client.post(self._url, json=payload)
            elapsed = (time.perf_counter() - t0) * 1000

            if self._text_field:
                try:
                    text = r.json()[self._text_field]
                except (KeyError, ValueError):
                    text = r.text
            else:
                text = r.text

            return TargetResponse(
                text=text,
                status_code=r.status_code,
                elapsed_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return TargetResponse(text="", status_code=0, elapsed_ms=elapsed, error=str(e))

    def close(self):
        self._client.close()
