"""The sliding-window helper shared by the brute-force and web-scan detectors."""
from datetime import timedelta


def find_bursts(events, threshold, window_minutes):
    """Find runs of at least `threshold` events that fit inside the time window.

    `events` must be sorted by time. Returns a list of bursts; each burst is
    the list of events in it. A long attack comes back as ONE burst, not many.
    """
    window = timedelta(minutes=window_minutes)
    bursts = []
    left = 0

    for right in range(len(events)):
        # Shrink the window from the left until it spans no more than `window`.
        while events[right].timestamp - events[left].timestamp > window:
            left += 1

        if right - left + 1 >= threshold:
            # Found an attack. If the previous burst is still going (this event
            # overlaps it), add to that burst instead of starting a new one.
            if bursts and bursts[-1][-1] is events[right - 1]:
                bursts[-1].append(events[right])
            else:
                bursts.append(events[left:right + 1])

    return bursts