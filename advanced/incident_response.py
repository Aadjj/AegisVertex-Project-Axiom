import asyncio
import json
import uuid
import yaml
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from core import settings, logger
from .models import APTReport

LOG = logger.bind(module="soar")


class ActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PlaybookExecutor:
    PLAYBOOK_DIR = Path("data/playbooks")

    def __init__(self) -> None:
        self.PLAYBOOK_DIR.mkdir(parents=True, exist_ok=True)

    async def execute(self, event: Any, playbook: str = "generic_block", auto_approve: bool = False) -> Dict[str, Any]:
        if isinstance(event, APTReport):
            return await self.run_playbook(event)

        execution_id = str(uuid.uuid4())

        return {
            "execution_id": execution_id,
            "status": "completed",
            "executed_steps": ["network_isolation"] if auto_approve else ["log_only"],
            "end_time": datetime.now(timezone.utc).isoformat()
        }

    async def run_playbook(self, report: APTReport) -> Dict[str, Any]:
        playbook_file = self.PLAYBOOK_DIR / "apt_contain.yml"

        if not playbook_file.exists():
            self._create_default_playbook(playbook_file)

        playbook = await asyncio.to_thread(self._load_playbook, playbook_file)
        execution_id = str(uuid.uuid4())
        results = []

        for step in playbook.get("steps", []):
            try:
                res = await self._execute_step(step, report, execution_id)
                results.append(res)

                if res["status"] == ActionStatus.FAILED:
                    await self._rollback(results)
                    break
            except Exception as e:
                LOG.error("Execution error", step=step.get("name"), error=str(e))
                await self._rollback(results)
                return {"execution_id": execution_id, "status": "failed", "error": str(e)}

        return {
            "execution_id": execution_id,
            "results": results,
            "status": "completed",
            "end_time": datetime.now(timezone.utc).isoformat()
        }

    def _load_playbook(self, path: Path) -> dict:
        with path.open("r") as f:
            return yaml.safe_load(f)

    async def _execute_step(self, step: dict, report: APTReport, eid: str) -> dict:
        name = step["name"]
        action = step["action"]

        if step.get("approval", False) and report.threat_score < 95:
            return {"name": name, "status": ActionStatus.PENDING, "result": "waiting_for_admin"}

        handler = {
            "isolate_host": self._isolate_host,
            "block_ip": self._block_ip,
            "disable_user": self._disable_user
        }.get(action)

        if handler:
            result = await handler(report)
            return {"name": name, "status": ActionStatus.EXECUTED, "result": result}

        return {"name": name, "status": ActionStatus.FAILED, "result": "unknown_action"}

    async def _isolate_host(self, report: APTReport) -> dict:
        target = report.payload.get("source_address_ids", ["unknown_internal_asset"])
        return {"target": target, "action": "vlan_quarantine", "success": True}

    async def _block_ip(self, report: APTReport) -> dict:
        ips = [hit.ioc for hit in report.intel_hits if "." in hit.ioc]
        if not ips:
            return {"status": "skipped", "reason": "no_external_iocs"}

        return {"blocked_ips": ips, "provider": "palo_alto_api", "success": True}

    async def _disable_user(self, report: APTReport) -> dict:
        user = report.payload.get("assigned_to", "service_account_auto")
        return {"user": user, "action": "account_disabled"}

    async def _rollback(self, results: List[dict]):
        for res in reversed(results):
            if res["status"] == ActionStatus.EXECUTED:
                res["status"] = ActionStatus.ROLLED_BACK

    def _create_default_playbook(self, path: Path):
        content = {
            "name": "APT Containment Strategy",
            "steps": [
                {"name": "Block Malicious IOCs", "action": "block_ip", "approval": False},
                {"name": "Isolate Infected Asset", "action": "isolate_host", "approval": True},
                {"name": "Suspend Compromised User", "action": "disable_user", "approval": True}
            ]
        }
        with path.open("w") as f:
            yaml.dump(content, f)