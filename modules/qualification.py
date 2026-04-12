import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from pydantic import BaseModel, Field
from typing import List, Optional
from core import logger, RawEvent

class QualifiedEvent(BaseModel):
    event_id: int
    threat_score: float = Field(ge=0, le=100)
    is_noise: bool = True
    tags: List[str] = Field(default_factory=list)
    payload: dict

class Qualification:
    def __init__(self, model_path: Optional[str] = None):
        self.logger = logger.bind(module="qualification")
        self._model = None

        resolved_path = Path(model_path) if model_path else Path("models/apt_detector.joblib")

        if resolved_path.exists():
            try:
                self._model = joblib.load(resolved_path)
                self.logger.info("Loaded pre-trained IsolationForest model", path=str(resolved_path))
            except Exception as e:
                self.logger.error("Failed to load model, falling back to cold start", error=str(e))

        if not self._model:
            self._model = IsolationForest(
                contamination=0.05,
                random_state=42,
                n_estimators=200
            )
            calibration_data = np.random.randint(1, 11, size=(100, 3))
            self._model.fit(calibration_data)
            self.logger.warning("IsolationForest started with cold-calibration data")

    async def process(self, events: List[RawEvent]) -> List[QualifiedEvent]:
        if not events:
            return []

        qualified_results = []

        for ev in events:
            features = [
                ev.payload.get("severity", 5),
                ev.payload.get("credibility", 5),
                ev.payload.get("magnitude", 5)
            ]

            prediction = self._model.predict([features])[0]
            raw_anomaly_score = self._model.decision_function([features])[0]

            threat_score = float(np.clip((0.5 - raw_anomaly_score) * 100, 0, 100))

            is_noise = True if (prediction == 1 and threat_score < 70) else False

            if not is_noise:
                res = QualifiedEvent(
                    event_id=ev.event_id,
                    threat_score=threat_score,
                    is_noise=is_noise,
                    tags=["ml_anomaly"] if prediction == -1 else ["high_priority_baseline"],
                    payload=ev.payload
                )
                qualified_results.append(res)

        self.logger.info(
            "Qualification filter complete",
            ingested=len(events),
            qualified=len(qualified_results),
            noise_reduction_pct=round((1 - len(qualified_results) / len(events)) * 100, 2) if events else 0
        )

        return qualified_results