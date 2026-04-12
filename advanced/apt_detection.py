import asyncio
import joblib
import httpx
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest

from core import settings, logger
from .models import APTReport, Tactic, Technique

LOG = logger.bind(module="apt_detector")

class APTDetector:
    MODEL_FILE = Path("models/apt_detector.joblib")
    MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def __init__(self) -> None:
        self._load_models()
        self._mitre = None
        self._refresh_task = asyncio.create_task(self._refresh_mitre())

    def _load_models(self):
        if self.MODEL_FILE.exists():
            self.anomaly_model, self.ttp_model = joblib.load(self.MODEL_FILE)
        else:
            self.anomaly_model = IsolationForest(contamination=0.02, n_estimators=300, random_state=42)
            self.ttp_model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3)

            dummy_features = np.random.random((1000, 20))
            dummy_labels = np.random.randint(0, 2, 1000)
            self.anomaly_model.fit(dummy_features)
            self.ttp_model.fit(dummy_features, dummy_labels)

            self.MODEL_FILE.parent.mkdir(exist_ok=True)
            joblib.dump((self.anomaly_model, self.ttp_model), self.MODEL_FILE)

    async def _refresh_mitre(self):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.MITRE_URL, timeout=30)
                response.raise_for_status()
                data = response.json()
                self._mitre = data.get("objects", [])
        except Exception as e:
            LOG.error("MITRE refresh failed", error=str(e))

    async def _extract_features(self, qev) -> Dict[str, Any]:
        p = qev.payload
        desc = p.get("description", "").lower()

        vec = [
            float(p.get("severity", 0)),
            float(p.get("credibility", 0)),
            float(p.get("relevance", 0)),
            float(p.get("magnitude", 0)),
            float("powershell" in desc),
            float("schtasks" in desc or "taskmgr" in desc),
            float("lsass" in desc or "procdump" in desc),
            float("mimikatz" in desc),
            float("wmic" in desc),
            float("netsh" in desc),
            float("vssadmin" in desc),
            float("encodedcommand" in desc),
            float("bitsadmin" in desc),
            float(len(p.get("source_address_ids", []))),
        ]

        vec += [0.0] * (20 - len(vec))
        return {"vector": np.array(vec).reshape(1, -1), "description": desc}

    async def is_apt(self, qev) -> APTReport:
        feats = await self._extract_features(qev)

        anomaly_score = self.anomaly_model.decision_function(feats["vector"])[0]
        proba = self.ttp_model.predict_proba(feats["vector"])[0][1]

        threat_score = float(np.clip(((0.5 - anomaly_score) * 50) + (proba * 50), 0, 100))
        techniques = await self._map_techniques(feats["description"])

        report = APTReport(
            event_id=qev.event_id,
            techniques=techniques,
            intel_hits=[],
            threat_score=threat_score,
            is_apt=threat_score >= 75.0,
        )

        return report

    async def _map_techniques(self, desc: str) -> List[Technique]:
        techniques = []
        mapping = {
            "powershell": ("T1059.001", "PowerShell", Tactic.EXECUTION),
            "schtasks": ("T1053.005", "Scheduled Task", Tactic.PERSISTENCE),
            "lsass": ("T1003.001", "LSASS Memory", Tactic.CREDENTIAL_ACCESS),
            "mimikatz": ("T1003", "OS Credential Dumping", Tactic.CREDENTIAL_ACCESS),
            "wmic": ("T1047", "Windows Management Instrumentation", Tactic.EXECUTION),
            "encodedcommand": ("T1027", "Obfuscated Files or Information", Tactic.DEFENSE_EVASION),
        }

        for key, (tid, name, tactic) in mapping.items():
            if key in desc:
                techniques.append(Technique(tid=tid, name=name, tactic=tactic))

        return techniques