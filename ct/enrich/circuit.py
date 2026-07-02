# ct/enrich/circuit.py
"""Per-endpoint circuit breaker.

After `failure_threshold` consecutive failures the circuit opens for
`cooldown_seconds`; while open, calls are skipped and items requeued.
After the cooldown one probe call is allowed (half-open); success closes
the circuit, failure re-opens it.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger(__name__)

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5,
                 cooldown_seconds: float = 300.0, clock=time.monotonic):
        self.name = name
        self.failure_threshold = int(failure_threshold)
        self.cooldown_seconds = float(cooldown_seconds)
        self._clock = clock
        self.state = CLOSED
        self.consecutive_failures = 0
        self._opened_at: float | None = None

    def allow(self) -> bool:
        """May we attempt a call right now?"""
        if self.state == CLOSED:
            return True
        if self.state == OPEN:
            if self._clock() - self._opened_at >= self.cooldown_seconds:
                self.state = HALF_OPEN
                log.info("[circuit:%s] cooldown elapsed -> half-open (probe allowed)", self.name)
                return True
            return False
        # HALF_OPEN: a probe is already implied allowed once
        return True

    def record_success(self):
        if self.state != CLOSED:
            log.info("[circuit:%s] success -> closed", self.name)
        self.state = CLOSED
        self.consecutive_failures = 0
        self._opened_at = None

    def record_failure(self):
        self.consecutive_failures += 1
        if self.state == HALF_OPEN or self.consecutive_failures >= self.failure_threshold:
            if self.state != OPEN:
                log.warning(
                    "[circuit:%s] OPEN after %d consecutive failures (cooldown %.0fs)",
                    self.name, self.consecutive_failures, self.cooldown_seconds,
                )
            self.state = OPEN
            self._opened_at = self._clock()
