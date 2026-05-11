from __future__ import annotations

import httpx

from backend.config import get_settings


class OpenRouterService:
    def __init__(self) -> None:
        settings = get_settings()
        self.api_key = settings.openrouter_api_key
        self.model_name = settings.openrouter_model
        self.base_url = settings.openrouter_base_url
        self.http_referer = settings.openrouter_http_referer
        self.app_name = settings.openrouter_app_name

    @property
    def is_enabled(self) -> bool:
        return bool(self.api_key)

    def explain(self, url: str, page_text: str, risk_score: int) -> str:
        if not self.api_key:
            raise RuntimeError("OpenRouter is not configured")

        prompt = (
            "You are a senior security analyst. Explain in 2-3 short, user-friendly sentences why the "
            f"following site may be risky. Be concrete and reference phishing language, URL structure, "
            f"or page signals. Risk score: {risk_score}/10. URL: {url}. Page text: {page_text[:4000]}"
        )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.http_referer,
            "X-Title": self.app_name,
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a concise cybersecurity copilot."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 160,
        }
        with httpx.Client(timeout=30.0) as client:
            response = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
        try:
            return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            raise RuntimeError("OpenRouter response was malformed") from exc
