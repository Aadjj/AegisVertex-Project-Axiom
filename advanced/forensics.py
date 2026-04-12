import hashlib
import json
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from core import settings, logger

LOG = logger.bind(module="forensics")

class Forensics:
    VAULT_DIR = Path("data/evidence")
    CHUNK_SIZE = 8192

    def __init__(self) -> None:
        self.VAULT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    async def capture(self, report: Any) -> Path:
        case_id = f"{report.event_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        case_dir = self.VAULT_DIR / case_id
        case_dir.mkdir(exist_ok=True, mode=0o700)

        manifest: List[Dict[str, str]] = []

        payload_file = case_dir / "telemetry_snapshot.json"
        report_data = report.model_dump() if hasattr(report, "model_dump") else report.dict()

        await asyncio.to_thread(self._write_json, payload_file, report_data)
        manifest.append(self._hash_file(payload_file))

        pcap = await self._grab_pcap(report, case_dir)
        if pcap:
            manifest.append(self._hash_file(pcap))

        manifest_file = case_dir / "chain_of_custody.json"
        manifest_meta = {
            "case_id": case_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "files": manifest
        }
        await asyncio.to_thread(self._write_json, manifest_file, manifest_meta)

        LOG.info("Digital evidence sealed and hashed", case_path=str(case_dir))

        report.evidence_dir = case_dir
        return case_dir

    def _write_json(self, path: Path, obj: Any):
        with path.open("w") as f:
            json.dump(obj, f, indent=2, default=str)
        path.chmod(0o400)

    def _hash_file(self, path: Path) -> Dict[str, str]:
        sha256_hash = hashlib.sha256()
        with path.open("rb") as f:
            while chunk := f.read(self.CHUNK_SIZE):
                sha256_hash.update(chunk)

        return {
            "file": path.name,
            "sha256": sha256_hash.hexdigest(),
            "algorithm": "SHA-256"
        }

    async def _grab_pcap(self, report: Any, case_dir: Path) -> Optional[Path]:
        return None