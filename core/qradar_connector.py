from __future__ import annotations
import httpx
import asyncio
import urllib3
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, List, Optional
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from .models import QRadarOffense, QRadarSearch
from .config import Config
from .resilience import CircuitBreaker

urllib3.disable_warnings()
logger = logging.getLogger("qradar_connector")

class QRadarConnector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token: Optional[str] = cfg.qradar_api_token
        self._token_expires: float = 0
        self._cb = CircuitBreaker()

        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        self._client = httpx.AsyncClient(
            base_url=cfg.qradar_host,
            verify=cfg.qradar_verify_ssl,
            timeout=httpx.Timeout(cfg.qradar_request_timeout),
            limits=limits,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
        )

    async def close(self):
        await self._client.aclose()

    @asynccontextmanager
    async def session(self) -> AsyncGenerator["QRadarConnector", None]:
        try:
            await self._maybe_refresh_token()
            yield self
        finally:
            await self.close()

    async def _maybe_refresh_token(self):
        if time.time() + self.cfg.qradar_token_refresh_buffer > self._token_expires:
            self._client.headers.update({"SEC": str(self._token)})
            self._token_expires = time.time() + 3600

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=30),
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        await self._maybe_refresh_token()

        async def _make_call():
            response = await self._client.request(method, endpoint, **kwargs)
            response.raise_for_status()
            return response.json()

        return await self._cb.call(_make_call)

    async def get_offenses(self, filter_str: str = 'status="OPEN"') -> List[QRadarOffense]:
        params = {"filter": filter_str} if filter_str else {}
        data = await self._request("GET", "/api/siem/offenses", params=params)
        return [QRadarOffense(**item) for item in data]

    async def start_ariel_search(self, query: str) -> QRadarSearch:
        payload = {"query_expression": query}
        data = await self._request("POST", "/api/ariel/searches", json=payload)
        return QRadarSearch(**data)

    async def get_search_results(self, search_id: str) -> Dict:
        return await self._request("GET", f"/api/ariel/searches/{search_id}/results")