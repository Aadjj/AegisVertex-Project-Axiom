from core import logger
from .models import Tactic, Technique

LOG = logger.bind(module="graph_predict")

class GraphPredictor:
    def __init__(self):
        self.attack_vectors = {
            Tactic.INITIAL_ACCESS: [Tactic.EXECUTION, Tactic.PERSISTENCE],
            Tactic.EXECUTION: [Tactic.PERSISTENCE, Tactic.DISCOVERY],
            Tactic.DISCOVERY: [Tactic.LATERAL_MOVEMENT, Tactic.COLLECTION],
            Tactic.LATERAL_MOVEMENT: [Tactic.CREDENTIAL_ACCESS, Tactic.EXFILTRATION]
        }

    async def predict_next_step(self, report) -> list:
        current_tactics = report.tactics
        predictions = []

        for tactic in current_tactics:
            next_moves = self.attack_vectors.get(tactic, [])
            for move in next_moves:
                if move not in current_tactics:
                    predictions.append(move)

        if predictions:
            LOG.info("Predictive analysis complete", probable_next_tactics=predictions)
            report.tags.append("predictive_alert")

        return list(set(predictions))