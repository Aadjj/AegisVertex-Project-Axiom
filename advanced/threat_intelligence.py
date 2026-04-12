import asyncio
import sqlite3
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import httpx
from stix2 import Filter, MemoryStore
from core import settings, logger
from .models import IntelMatch

LOG = logger.bind(module="threat_intel")

class IntelEnricher:
    DB_FILE = Path("cache/threat_intel.db")
    REFRESH_INTERVAL = timedelta(hours=1)

    def __init__(self) -> None:
        self.DB_FILE.parent.mkdir(exist_ok=True)
        self._init_db()
        self._last_refresh = datetime.min.replace(tzinfo=timezone.utc)
        asyncio.create_task(self._periodic_refresh())

    def _init_db(self):
        with sqlite3.connect(self.DB_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs(
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    source TEXT,
                    confidence INT,
                    first_seen TEXT,
                    last_seen TEXT
                )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)")

    async def enrich(self, qev):
        hits = []
        payload = qev.payload

        observables = {
            "ip": [payload.get("source_address"), payload.get("destination_address")],
            "domain": payload.get("domains", [])
        }

        for ip in filter(None, observables["ip"]):
            match = await self._lookup(ip, "ip")
            if match:
                hits.append(match)

        for domain in filter(None, observables["domain"]):
            match = await self._lookup(domain, "domain")
            if match:
                hits.append(match)

        if hits:
            qev.intel_hits = hits
            qev.threat_score = max(qev.threat_score, 90.0)
            qev.tags.append("threat_intel_match")

        return qev

    async def _periodic_refresh(self):
        while True:
            try:
                await self._refresh_feeds()
            except Exception as e:
                LOG.error("Threat intel refresh failed", error=str(e))
            await asyncio.sleep(self.REFRESH_INTERVAL.total_seconds())

    async def _refresh_feeds(self):
        url = "https://feodotracker.abuse.ch/downloads/stix.json"

        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=30)
            r.raise_for_status()
            bundle = r.json()

        store = MemoryStore(stix_data=bundle["objects"])
        indicators = store.query([Filter("type", "=", "indicator")])

        await asyncio.to_thread(self._store_iocs, indicators)
        self._last_refresh = datetime.now(timezone.utc)

    def _store_iocs(self, indicators):
        with sqlite3.connect(self.DB_FILE) as conn:
            for ind in indicators:
                pattern = ind.get("pattern", "")
                ioc, ioc_type = self._parse_pattern(pattern)

                if not ioc:
                    continue

                conn.execute(
                    "INSERT OR REPLACE INTO iocs VALUES (?,?,?,?,?,?)",
                    (
                        ioc,
                        ioc_type,
                        "FeodoTracker",
                        85,
                        ind.get("created"),
                        ind.get("modified")
                    ),
                )

    def _parse_pattern(self, pattern: str) -> Tuple[Optional[str], Optional[str]]:
        ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        if ip_match:
            return ip_match.group(1), "ip"

        domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        if domain_match:
            return domain_match.group(1), "domain"

        return None, None

    async def _lookup(self, value: str, ioc_type: str) -> Optional[IntelMatch]:
        return await asyncio.to_thread(self._sync_lookup, value, ioc_type)

    def _sync_lookup(self, value: str, ioc_type: str) -> Optional[IntelMatch]:
        with sqlite3.connect(self.DB_FILE) as conn:
            cur = conn.execute(
                "SELECT ioc, source, confidence, first_seen, last_seen FROM iocs WHERE ioc=? AND ioc_type=?",
                (value, ioc_type)
            )
            row = cur.fetchone()
            if row:
                return IntelMatch(
                    ioc=row[0],
                    source=row[1],
                    confidence=row[2],
                    first_seen=row[3],
                    last_seen=row[4]
                )
        return None