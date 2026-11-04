"""Detect web attacks: 404 bursts from scanners, and known attack paths or tools."""
from collections import defaultdict

from logsentry.detectors.bursts import find_bursts
from logsentry.models import Alert


def detect_web_scan(events, cfg):
    """Return medium-severity Alerts for scanning and attack signatures."""
    settings = cfg["web_scan"]
    requests = sorted((e for e in events if e.event_type == "http_request"),
                      key=lambda e: e.timestamp)
    return find_404_bursts(requests, settings) + find_signatures(requests, settings)


def find_404_bursts(requests, settings):
    """Part 1: many 'not found' responses to one IP in a short time = a scanner guessing."""
    not_found_by_ip = defaultdict(list)
    for e in requests:
        if e.details.get("status") == 404:
            not_found_by_ip[e.ip].append(e)

    alerts = []
    for ip, misses in not_found_by_ip.items():
        for burst in find_bursts(misses, settings["max_404s"], settings["window_minutes"]):
            seconds = int((burst[-1].timestamp - burst[0].timestamp).total_seconds())
            alerts.append(Alert(
                timestamp=burst[0].timestamp,
                rule="web_scan",
                severity="medium",
                message=f"{len(burst)} 'not found' (404) responses to {ip} in {seconds}s: likely a scanner",
                ip=ip,
                evidence=[e.raw for e in burst],
            ))
    return alerts


def find_signatures(requests, settings):
    """Part 2: requests for known attack paths or from known attack tools. One alert per IP."""
    bad_paths = [p.lower() for p in settings["bad_paths"]]
    bad_agents = [a.lower() for a in settings["bad_agents"]]

    hits_by_ip = defaultdict(list)    # ip -> list of (event, reason)
    for e in requests:
        path = e.details.get("path", "").lower()
        agent = e.details.get("agent", "").lower()
        for bad in bad_agents:
            if bad in agent:
                hits_by_ip[e.ip].append((e, f"attack tool '{bad}'"))
                break
        else:   # runs only if the loop above did NOT break
            for bad in bad_paths:
                if bad in path:
                    hits_by_ip[e.ip].append((e, f"suspicious path '{bad}'"))
                    break

    alerts = []
    for ip, hits in hits_by_ip.items():
        reasons = sorted({reason for _, reason in hits})
        alerts.append(Alert(
            timestamp=hits[0][0].timestamp,
            rule="web_attack_signature",
            severity="medium",
            message=f"{len(hits)} malicious-looking requests from {ip}: {', '.join(reasons)}",
            ip=ip,
            evidence=[e.raw for e, _ in hits],
        ))
    return alerts