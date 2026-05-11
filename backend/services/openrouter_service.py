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
        messages = [
            {"role": "system", "content": "You are a concise cybersecurity copilot."},
            {"role": "user", "content": prompt},
        ]
        models_to_try = [self.model_name]
        if self.model_name != "openrouter/auto":
            models_to_try.append("openrouter/auto")

        last_error: str | None = None
        for model_name in models_to_try:
            try:
                return self._request_completion(headers=headers, model_name=model_name, messages=messages)
            except RuntimeError as exc:
                last_error = str(exc)
                if "No endpoints found for" in last_error:
                    continue
                raise

        raise RuntimeError(last_error or "OpenRouter completion failed")

    def _request_completion(
        self,
        *,
        headers: dict[str, str],
        model_name: str,
        messages: list[dict[str, str]],
    ) -> str:
        payload = {
            "model": model_name,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 160,
        }
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            message = exc.response.text
            raise RuntimeError(f"OpenRouter request failed: HTTP {exc.response.status_code} - {message}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"OpenRouter request failed: {exc}") from exc

        try:
            content = data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            raise RuntimeError("OpenRouter response was malformed") from exc
        if not content:
            raise RuntimeError("OpenRouter returned an empty completion")
        return content
