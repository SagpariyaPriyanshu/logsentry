from datetime import datetime, timedelta

from logsentry.detectors.bursts import find_bursts
from logsentry.models import Event

START = datetime(2026, 10, 7, 14, 0, 0)


def make_events(count, seconds_apart):
    """`count` fake failed logins, `seconds_apart` seconds after each other."""
    return [
        Event(timestamp=START + timedelta(seconds=i * seconds_apart),
              source="auth", event_type="login_failed", raw=f"line {i}",
              ip="203.0.113.45")
        for i in range(count)
    ]


def test_four_failures_is_not_an_attack():
    assert find_bursts(make_events(4, 10), threshold=5, window_minutes=2) == []


def test_five_failures_in_two_minutes_is_one_burst():
    bursts = find_bursts(make_events(5, 10), threshold=5, window_minutes=2)
    assert len(bursts) == 1
    assert len(bursts[0]) == 5


def test_five_failures_spread_over_ten_minutes_is_not_an_attack():
    assert find_bursts(make_events(5, 150), threshold=5, window_minutes=2) == []


def test_forty_failures_in_a_row_is_exactly_one_burst():
    bursts = find_bursts(make_events(40, 3), threshold=5, window_minutes=2)
    assert len(bursts) == 1
    assert len(bursts[0]) == 40


def test_two_separate_attacks_are_two_bursts():
    morning = make_events(5, 10)
    evening = [Event(e.timestamp + timedelta(hours=8), e.source, e.event_type, e.raw, e.ip)
               for e in morning]
    assert len(find_bursts(morning + evening, threshold=5, window_minutes=2)) == 2


def test_no_events():
    assert find_bursts([], threshold=5, window_minutes=2) == []