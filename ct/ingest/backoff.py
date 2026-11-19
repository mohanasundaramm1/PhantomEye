# ct/ingest/backoff.py
"""Reconnect delay for the CertStream websocket loop in forwarder.py.

Found live: WebSocketApp.run_forever() RETURNS (it doesn't raise) when the
connection is refused or drops, and the forwarder's loop only slept inside its
`except Exception` branch -- so a down CertStream meant reconnecting with no
pause at all, ~850 attempts/second, ~2.3 million log lines in 15 minutes. That
is also what filled the disk (a 178 GB stderr log) and burned a CPU core while
nothing was flowing.

Policy:
  - A connection that stayed up long enough to be "healthy" (the websocket
    drops every couple of minutes on ping/pong timeouts in normal operation)
    reconnects IMMEDIATELY, exactly as before -- every second of delay is a
    second of certificates CertStream skips.
  - A connection that failed quickly backs off exponentially up to a cap, so a
    down CertStream/Kafka costs one attempt a minute, not hundreds a second,
    and recovers within `cap` seconds of the service returning.
"""

BASE_DELAY_S = 2.0
CAP_DELAY_S = 60.0
HEALTHY_AFTER_S = 30.0


def next_delay(
    prev_delay: float,
    ran_for_s: float,
    base: float = BASE_DELAY_S,
    cap: float = CAP_DELAY_S,
    healthy_after: float = HEALTHY_AFTER_S,
) -> float:
    """Seconds to wait before the next connection attempt.

    prev_delay: the delay used before the attempt that just ended (0 initially).
    ran_for_s:  how long that attempt's connection lasted.
    """
    if ran_for_s >= healthy_after:
        return 0.0
    if prev_delay <= 0:
        return base
    return min(prev_delay * 2, cap)
