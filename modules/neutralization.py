from typing import List, Dict, Any
from core import logger
from modules.qualification import QualifiedEvent
from advanced.incident_response import PlaybookExecutor

class Neutralization:
    def __init__(self):
        self.logger = logger.bind(module="neutralization")
        self.executor = PlaybookExecutor()

    async def respond(self, analyzed_events: List[QualifiedEvent]) -> List[Dict[str, Any]]:
        """
        Orchestrates automated response actions based on event criticality
        and identified threat tags.
        """
        actions_taken = []

        for ev in analyzed_events:
            is_critical = "critical_priority" in ev.tags or "apt_detected" in ev.tags
            is_high = "high_priority" in ev.tags

            if is_critical or is_high:
                self.logger.warning(
                    "Initiating counter-measures",
                    event_id=ev.event_id,
                    threat_score=ev.threat_score
                )

                playbook_type = "apt_containment" if "apt_detected" in ev.tags else "generic_block"

                result = await self.executor.execute(
                    event=ev,
                    playbook=playbook_type,
                    auto_approve=is_critical
                )

                actions_taken.append({
                    "event_id": ev.event_id,
                    "playbook": playbook_type,
                    "actions": result.get("executed_steps", []),
                    "status": result.get("status", "completed"),
                    "timestamp": result.get("end_time")
                })

        self.logger.info("Neutralization phase complete",
                         interventions=len(actions_taken))

        return actions_taken