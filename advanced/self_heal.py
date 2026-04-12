import asyncio
from core import logger
from .incident_response import ActionStatus

LOG = logger.bind(module="self_heal")

class SelfHealer:
    def __init__(self):
        self.max_retries = 3

    async def monitor_and_fix(self, execution_results: dict, playbook_executor):
        results = execution_results.get("results", [])

        for res in results:
            if res.get("status") == ActionStatus.FAILED:
                LOG.error("Self-Heal triggered for failed action", action=res['name'])

                await playbook_executor._rollback(results)

                return {
                    "healed": True,
                    "action": "full_rollback",
                    "reason": f"Failure in step: {res['name']}"
                }

        return {"healed": False}