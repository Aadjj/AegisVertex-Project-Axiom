import time
import asyncio
from typing import Callable, Any

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures = 0
        self._last_fail = 0.0
        self._state = "closed"

    async def call(self, func: Callable[..., Any], *args, **kwargs) -> Any:
        if self._state == "open":
            if time.time() - self._last_fail > self.recovery_timeout:
                self._state = "half-open"
            else:
                raise RuntimeError("Circuit breaker is open: suppressing requests to prevent cascading failure")

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            if self._state == "half-open":
                self._state = "closed"
                self._failures = 0

            return result
        except Exception as exc:
            self._failures += 1
            self._last_fail = time.time()
            if self._failures >= self.failure_threshold:
                self._state = "open"
            raise exc