import asyncio
import signal
import sys
from pathlib import Path

from core import logger, settings
from core.resilience import CircuitBreaker

from modules.discovery import Discovery
from modules.qualification import Qualification
from modules.investigation import Investigation
from modules.neutralization import Neutralization
from modules.recovery import Recovery

from advanced.deception import DeceptionEngine
from advanced.shadow_mode import ShadowManager

LOG = logger.bind(module="main")

class AegisFlow:
    def __init__(self):
        self.discovery = Discovery()
        self.qualification = Qualification()
        self.investigation = Investigation()
        self.neutralization = Neutralization()
        self.recovery = Recovery()

        self.deception = DeceptionEngine()
        self.shadow = ShadowManager(enabled=settings.SHADOW_MODE_ENABLED)
        self.circuit_breaker = CircuitBreaker(failure_threshold=5)

        self._running = True

    async def run_pipeline(self):
        LOG.info("AegisVertex: Project Axiom — Initializing Defensive Shield",
                 shadow_mode=settings.SHADOW_MODE_ENABLED,
                 deception_active=settings.DECEPTION_HONEY_TOKENS_ENABLED)

        while self._running:
            try:
                raw_events = await self.circuit_breaker.call(
                    self.discovery.collect_offenses, status="OPEN"
                )

                if not raw_events:
                    await asyncio.sleep(settings.polling_interval)
                    continue

                qualified = await self.qualification.process(raw_events)
                if not qualified:
                    continue

                for qev in qualified:
                    await self.deception.check_tripwires(qev)

                analyzed = await self.investigation.analyze(qualified)

                actions = await self.shadow.intercept(
                    self.neutralization.respond, analyzed
                )

                if analyzed:
                    report_path = await self.recovery.handle(analyzed, actions)
                    LOG.info("Response cycle complete",
                             incidents=len(analyzed),
                             report=str(report_path))

            except asyncio.CancelledError:
                self._running = False
            except Exception as e:
                LOG.error("Critical pipeline error", error=str(e))
                await asyncio.sleep(10)

            await asyncio.sleep(settings.polling_interval)

    def stop(self):
        self._running = False

async def shutdown(loop, aegis, sig=None):
    if sig:
        LOG.info(f"Received exit signal {sig.name}...")

    aegis.stop()

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for t in tasks:
        t.cancel()

    LOG.info(f"Cancelling {len(tasks)} outstanding tasks")
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()
    LOG.info("AegisFlow shutdown complete.")

if __name__ == "__main__":
    aegis = AegisFlow()
    loop = asyncio.get_event_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig, lambda s=sig: asyncio.create_task(shutdown(loop, aegis, s))
        )

    try:
        loop.run_until_complete(aegis.run_pipeline())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()