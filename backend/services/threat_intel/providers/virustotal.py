from __future__ import annotations

import httpx


class VirusTotalClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'

    async def lookup_url(self, url: str) -> dict:
        headers = {'x-apikey': self.api_key}
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f'{self.base_url}/urls',
                headers=headers,
                data={'url': url},
            )
            response.raise_for_status()
            analysis_id = response.json()['data']['id']
            analysis = await client.get(f'{self.base_url}/analyses/{analysis_id}', headers=headers)
            analysis.raise_for_status()
            return analysis.json()
