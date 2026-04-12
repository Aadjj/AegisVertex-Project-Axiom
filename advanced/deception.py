from core import logger, settings
from .models import APTReport, Tactic, Technique

LOG = logger.bind(module="deception")

class DeceptionEngine:
    def __init__(self):
        self.honey_ips = settings.get("HONEY_IPS", [])
        self.honey_users = settings.get("HONEY_USERS", [])

    async def check_tripwires(self, event) -> bool:
        payload = event.payload
        src_ip = payload.get("source_address")
        dst_ip = payload.get("destination_address")
        user = payload.get("username")

        if dst_ip in self.honey_ips:
            LOG.critical("DECEPTION ALERT: Honey-IP accessed!", target=dst_ip, attacker=src_ip)
            event.tags.append("deception_tripwire")
            event.threat_score = 100.0
            return True

        if user in self.honey_users:
            LOG.critical("DECEPTION ALERT: Honey-User account activity!", user=user)
            event.tags.append("honey_user_access")
            event.threat_score = 100.0
            return True

        return False