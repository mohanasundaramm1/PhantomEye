# ct/enrich/ratelimit.py
"""Token-bucket rate limiter used to pace external enrichment calls."""
from __future__ import annotations

import time


class TokenBucket:
    """Classic token bucket: `rate` tokens/sec, up to `capacity` burst.

    `clock` and `sleep` are injectable for deterministic tests.
    """

    def __init__(self, rate: float, capacity: float | None = None,
                 clock=time.monotonic, sleep=time.sleep):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._clock = clock
        self._sleep = sleep
        self._tokens = self.capacity
        self._last = self._clock()

    def _refill(self):
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Non-blocking: take tokens if available, else return False."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def acquire(self, tokens: float = 1.0):
        """Blocking: sleep until tokens are available, then take them."""
        while not self.try_acquire(tokens):
            deficit = tokens - self._tokens
            self._sleep(max(deficit / self.rate, 0.001))
