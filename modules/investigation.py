from typing import List
from core import logger
from modules.qualification import QualifiedEvent
from advanced.apt_detection import APTDetector
from advanced.threat_intelligence import IntelEnricher

class Investigation:
    def __init__(self):
        self.logger = logger.bind(module="investigation")
        self.apt_detector = APTDetector()
        self.intel_enricher = IntelEnricher()

    async def analyze(self, qualified_events: List[QualifiedEvent]) -> List[QualifiedEvent]:
        self.logger.info("Starting deep investigation", count=len(qualified_events))

        results = []
        for qev in qualified_events:
            qev = await self.intel_enricher.enrich(qev)

            apt_report = await self.apt_detector.is_apt(qev)

            if apt_report.is_apt:
                qev.threat_score = max(qev.threat_score, apt_report.threat_score)
                qev.tags.append("apt_detected")
                for tech in apt_report.techniques:
                    qev.tags.append(f"mitre:{tech.tid}")

            if qev.threat_score > 85:
                qev.tags.append("critical_priority")
            elif qev.threat_score > 70:
                qev.tags.append("high_priority")

            results.append(qev)

        self.logger.info("Investigation cycle complete",
                         analyzed=len(results),
                         critical=sum(1 for r in results if "critical_priority" in r.tags))

        return results