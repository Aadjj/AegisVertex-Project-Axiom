from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, List

from core import settings, logger, RawEvent
from core.qradar_connector import QRadarConnector
from core.models import QRadarOffense

class Discovery:
    def __init__(self, connector: QRadarConnector | None = None):
        self.logger = logger.bind(module="discovery")
        self._conn = connector

    async def collect_offenses(
            self, status: str = "OPEN", updated_after: datetime | None = None
    ) -> List[RawEvent]:
        updated_after = updated_after or (datetime.now(timezone.utc) - timedelta(hours=24))

        ts_ms = int(updated_after.timestamp() * 1000)
        filter_str = f'status="{status}" and last_updated_time > {ts_ms}'

        async with (self._conn.session() if self._conn else QRadarConnector(settings).session()) as api:
            offenses: list[QRadarOffense] = await api.get_offenses(filter_str)

            self.logger.info(f"Discovered {len(offenses)} offenses", status=status)

            return [
                RawEvent(
                    event_id=off.id,
                    event_time=off.last_updated_time,
                    payload=off.model_dump(),
                )
                for off in offenses
            ]

    async def collect_events(
            self, ariel_query: str, page_size: int = 10_000
    ) -> AsyncGenerator[RawEvent, None]:
        async with (self._conn.session() if self._conn else QRadarConnector(settings).session()) as api:
            search = await api.start_ariel_search(ariel_query)
            sid = search.search_id

            self.logger.info("Ariel search started", search_id=sid)

            while True:
                page = await api.get_search_results(sid)
                events = page.get("events", [])

                if not events:
                    break

                for ev in events:
                    yield RawEvent(
                        event_id=ev.get("id", 0),
                        event_time=datetime.fromtimestamp(
                            ev.get("starttime", 0) / 1000, tz=timezone.utc
                        ),
                        payload=ev,
                    )

                if not page.get("has_more") or len(events) < page_size:
                    break