from ct.ingest.backoff import BASE_DELAY_S, CAP_DELAY_S, HEALTHY_AFTER_S, next_delay


def test_first_quick_failure_waits_base_delay():
    assert next_delay(0.0, 0.1) == BASE_DELAY_S


def test_repeated_quick_failures_back_off_exponentially_to_the_cap():
    delays, d = [], 0.0
    for _ in range(10):
        d = next_delay(d, 0.05)      # connection refused: dies instantly, every time
        delays.append(d)
    assert delays[:4] == [2.0, 4.0, 8.0, 16.0]
    assert delays[-1] == CAP_DELAY_S
    assert all(b >= a for a, b in zip(delays, delays[1:]))     # never shrinks while failing


def test_healthy_connection_reconnects_immediately_and_resets_the_backoff():
    # the websocket normally drops every couple of minutes (ping/pong timeout);
    # each second of delay there is a second of certificates CertStream skips.
    assert next_delay(60.0, HEALTHY_AFTER_S) == 0.0
    assert next_delay(60.0, 120.0) == 0.0
    # ...and the next failure starts from the bottom again, not from the cap
    assert next_delay(next_delay(60.0, 120.0), 0.05) == BASE_DELAY_S


def test_a_down_service_costs_at_most_a_handful_of_attempts_per_minute():
    # the bug: ~850 reconnects/second. Simulate one minute of a dead CertStream.
    t, d, attempts = 0.0, 0.0, 0
    while t < 60.0:
        attempts += 1
        d = next_delay(d, 0.05)
        t += 0.05 + d
    assert attempts <= 6
