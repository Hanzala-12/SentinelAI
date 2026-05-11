from __future__ import annotations

import httpx


class UrlScanClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = 'https://urlscan.io/api/v1'

    async def lookup_url(self, url: str) -> dict:
        headers = {'API-Key': self.api_key, 'Content-Type': 'application/json'}
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f'{self.base_url}/scan/',
                headers=headers,
                json={'url': url, 'visibility': 'public'},
            )
            response.raise_for_status()
            return response.json()
