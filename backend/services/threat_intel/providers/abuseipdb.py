from __future__ import annotations

import httpx


class AbuseIpDbClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = 'https://api.abuseipdb.com/api/v2'

    async def lookup_ip(self, ip_address: str) -> dict:
        headers = {'Key': self.api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f'{self.base_url}/check', headers=headers, params=params)
            response.raise_for_status()
            return response.json()
