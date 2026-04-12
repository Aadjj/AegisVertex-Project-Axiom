import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from core import logger, settings
from modules.qualification import QualifiedEvent
from reports.custom_reports import ReportGenerator, ExecutiveReport

class Recovery:
    def __init__(self):
        self.logger = logger.bind(module="recovery")
        self.report_gen = ReportGenerator(template_dir="templates")
        self.archive_dir = Path("data/archive")
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    async def handle(self, analyzed_events: List[QualifiedEvent], actions: List[Dict[str, Any]]) -> Path:
        self.logger.info("Initiating recovery and reporting phase")

        primary_id = analyzed_events[0].event_id if analyzed_events else "000"

        report_data = ExecutiveReport(
            summary={
                "total_incidents": len(analyzed_events),
                "highest_threat_score": max((e.threat_score for e in analyzed_events), default=0.0),
                "type": "APT_Attempt" if any(
                    "apt_detected" in e.tags for e in analyzed_events) else "General_Security_Event",
                "desc": f"Automated response cycle for {len(analyzed_events)} qualified security events."
            },
            actions_taken=actions,
            forensics_manifest=[{
                "event_id": e.event_id,
                "tags": e.tags,
                "timestamp": e.payload.get("start_time")
            } for e in analyzed_events],
            metadata={
                "id": str(primary_id),
                "timestamp": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                "framework": settings.app_name
            }
        )

        report_path = await self.report_gen.generate(report_data, format="json")

        await self._archive_evidence(analyzed_events)

        self.logger.info("Recovery complete",
                         report_vault=str(report_path),
                         archived_events=len(analyzed_events))

        return report_path

    async def _archive_evidence(self, events: List[QualifiedEvent]):
        for ev in events:
            archive_file = self.archive_dir / f"event_{ev.event_id}.forensics"
            await asyncio.to_thread(archive_file.write_text, str(ev.model_dump()))