from core import logger, settings

LOG = logger.bind(module="shadow_mode")

class ShadowManager:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    async def intercept(self, func, *args, **kwargs):
        if not self.enabled:
            return await func(*args, **kwargs)

        LOG.warning("SHADOW MODE ACTIVE: Action intercepted and suppressed",
                    function=func.__name__)

        return {
            "status": "shadow_executed",
            "message": "Action would have been performed in live mode",
            "dry_run": True
        }