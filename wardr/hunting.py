"""Explainable defensive detections over Wardr's bounded local event history."""

import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import groupby


_LOOKBACK_HOURS = 24
_MAX_EVENTS = 180
_MAX_ALERTS = 40
_AUTH_WINDOW = timedelta(minutes=5)
_AUTH_MINIMUM = 6
_LISTENER_WINDOW = timedelta(minutes=5)
_LISTENER_MINIMUM = 3
_PROTECTION_WINDOW = timedelta(minutes=10)
_AUTH_SIGNALS = {
    ("Linux SSH journal", "SSH authentication failed"),
    ("Windows Security log", "Windows sign-in failed"),
}
_DEFENDER_LOG = "Microsoft Defender log"
_WINDOWS_CHANGES = {
    ("Windows System log", "Windows service installed"),
    ("Windows Security log", "Windows account created"),
}
_LISTENER_SIGNAL = ("TCP listeners", "New non-loopback TCP listener")
_LISTENER_ADDRESS = re.compile(r"^A local service began listening on (?:\[[^\]]+\]|[^:]+):([0-9]{1,5})\.")
_SEVERITY = {"high": 2, "medium": 1, "low": 0}


@dataclass(frozen=True)
class _Event:
    id: str
    when: datetime
    at: str
    source: str
    title: str
    detail: str

    @property
    def signal(self) -> tuple[str, str]:
        return self.source, self.title

    def evidence(self) -> dict:
        return {"id": self.id, "at": self.at, "source": self.source, "title": self.title, "detail": self.detail}


def _events(rows: list, now: datetime) -> list[_Event]:
    floor = now - timedelta(hours=_LOOKBACK_HOURS)
    by_id: dict[str, _Event] = {}
    limits = {"id": 120, "at": 64, "source": 160, "title": 200, "detail": 1000}
    for row in rows[:_MAX_EVENTS]:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(field), str) or len(row[field]) > limit for field, limit in limits.items()
        ):
            continue
        if not row["id"] or row["id"] in by_id:
            continue
        try:
            when = datetime.fromisoformat(row["at"])
            if when.utcoffset() is None or not floor <= when <= now:
                continue
        except (ValueError, OverflowError):
            continue
        by_id[row["id"]] = _Event(when=when, **{field: row[field] for field in limits})
    return sorted(by_id.values(), key=lambda event: (event.when, event.id))


def _coverage(rows: list, last_poll: str | None, events: list[_Event]) -> tuple[list[dict], str, str]:
    sources = []
    for item in rows[:16]:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            available = item.get("available")
            sources.append({
                "id": item["id"],
                "label": str(item.get("label") or item["id"]),
                "available": available if isinstance(available, bool) else None,
                "detail": str(item.get("detail") or ""),
            })
    if not last_poll:
        state = "waiting"
        if events:
            note = "Wardr evaluated retained event history. The current sources are waiting for a sample."
        else:
            note = "The current sources are waiting for a sample."
    elif not any(source["available"] is True for source in sources):
        state = "unavailable"
        note = "None of the configured sources reported full coverage at the last sample."
    elif any(source["available"] is not True for source in sources):
        state = "partial"
        note = "Some sources were unavailable or had limited access at the last sample."
    else:
        state = "available"
        note = "Configured sources were available at the last sample. Analysis is limited to retained Wardr events."
    return sources, state, note


def _repeated_events(
    records: list[_Event], minimum: int, period: timedelta, key: Callable[[_Event], str | int],
) -> Iterator[tuple[list[_Event], int]]:
    """Find bounded, non-overlapping windows with enough distinct evidence."""
    keys = [key(event) for event in records]
    first = last = 0
    counts: Counter[str | int] = Counter()
    while first < len(records):
        while last < len(records) and records[last].when - records[first].when <= period:
            counts[keys[last]] += 1
            last += 1
        if len(counts) >= minimum:
            yield records[first:last], len(counts)
            first = last
            counts.clear()
            continue
        value = keys[first]
        counts[value] -= 1
        if counts[value] == 0:
            del counts[value]
        first += 1


def _alert(
    rule_id: str, title: str, severity: str, confidence: str, summary: str,
    events: list[_Event], actions: list[str],
) -> dict:
    first, last = events[0], events[-1]
    identity = sha256(f"{rule_id}/{first.id}".encode()).hexdigest()[:24]
    return {
        "id": identity,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "first_seen": first.at,
        "last_seen": last.at,
        "event_ids": [event.id for event in events],
        "evidence": [event.evidence() for event in events],
        "actions": actions,
    }


def _authentication_alerts(events: list[_Event]) -> Iterator[dict]:
    for source, title in sorted(_AUTH_SIGNALS):
        records = [event for event in events if event.signal == (source, title)]
        for group, count in _repeated_events(records, _AUTH_MINIMUM, _AUTH_WINDOW, lambda event: event.id):
            yield _alert(
                "authentication-failure-burst",
                "Repeated sign-in failures",
                "medium",
                "medium",
                f"{source} supplied {count} failure records within five minutes. "
                "Check the native log to group them by account and origin.",
                group,
                [
                    "Review the failure records in the native log and look for successful sign-ins near the same time.",
                    "Check for expected automation or user sign-ins. Escalate unfamiliar activity to the account owner.",
                    "Review access controls for the affected account or service. Restrict unused remote sign-in access.",
                ],
            )


def _listener_port(event: _Event) -> int | None:
    if event.signal == _LISTENER_SIGNAL:
        match = _LISTENER_ADDRESS.match(event.detail)
        if match:
            port = int(match[1])
            if 1 <= port <= 65535:
                return port
    return None


def _exposure_alerts(events: list[_Event]) -> Iterator[dict]:
    ports = {event.id: port for event in events if (port := _listener_port(event)) is not None}
    listeners = [event for event in events if event.id in ports]
    for group, count in _repeated_events(listeners, _LISTENER_MINIMUM, _LISTENER_WINDOW, lambda event: ports[event.id]):
        yield _alert(
            "tcp-listener-burst",
            "Several local service ports began listening",
            "medium",
            "high",
            f"Wardr observed new non-loopback listeners on {count} distinct TCP port numbers within five minutes. "
            "The observation concerns local binds. Review the firewall and network path to determine reachability.",
            group,
            [
                "Use the local exposure inventory to identify the listening services and their owners.",
                "Compare the services and ports with approved software installs and deployments.",
                "Close unneeded listeners or restrict their bind addresses and inbound firewall rules.",
            ],
        )
    for _, sample in groupby(events, key=lambda event: event.when):
        sample_events = list(sample)
        changes = [
            event for event in sample_events
            if event.signal == ("macOS launch items", "macOS launch item changed")
            and event.detail.startswith(("Added ", "Changed "))
            and event.detail.endswith(" in System LaunchDaemons.")
        ]
        sample_listeners = [event for event in sample_events if event.id in ports]
        if changes and sample_listeners:
            evidence = sorted(changes + sample_listeners, key=lambda event: event.id)
            yield _alert(
                "launch-daemon-and-listener",
                "Launch daemon changed alongside new listeners",
                "medium",
                "medium",
                "The same macOS monitoring sample contained a system launch daemon change and a new local listener. "
                "Review the launch configuration and listener ownership to see whether they are related.",
                evidence,
                [
                    "Compare the launch daemon name and change time with recent approved installs or updates.",
                    "Identify the listening process and check whether its executable matches the launch item.",
                    "Preserve the launch configuration and escalate if the executable or installation is unexpected.",
                ],
            )


def _windows_alerts(events: list[_Event]) -> Iterator[dict]:
    latest_protection_change = None
    protection_changes: dict[str, list[_Event]] = {}
    for event in events:
        if event.signal == (_DEFENDER_LOG, "Defender real-time protection disabled"):
            latest_protection_change = event
            protection_changes[event.id] = [event]
        elif (
            event.signal in _WINDOWS_CHANGES
            and latest_protection_change is not None
            and timedelta(0) < event.when - latest_protection_change.when <= _PROTECTION_WINDOW
        ):
            protection_changes[latest_protection_change.id].append(event)

    for group in protection_changes.values():
        if len(group) > 1:
            title = "Defender protection turned off before system changes"
            summary = (
                "Defender reported real-time protection being disabled. Windows then logged a service installation "
                "or account creation within ten minutes. Review the underlying log records to determine whether "
                "the changes were related."
            )
            confidence = "medium"
            actions = [
                "Compare the Defender event and each service install or account creation with approved changes.",
                "Verify the current state of real-time protection and restore the approved policy if it is off.",
                "Preserve the logs. If a change was unauthorized, follow your incident response procedure.",
            ]
        else:
            title = "Defender real-time protection was disabled"
            summary = "Defender logged that real-time protection was disabled. Verify the current state and approved policy."
            confidence = "high"
            actions = [
                "Check real-time protection and policy in Windows Security or your endpoint management console.",
                "Confirm the change was authorized. Restore real-time protection if the approved policy requires it.",
            ]
        yield _alert("defender-protection-change", title, "high", confidence, summary, group, actions)

    for event in events:
        if event.signal == ("Windows Security log", "Windows Security log cleared"):
            yield _alert(
                "windows-security-log-cleared",
                "Windows Security log was cleared",
                "high",
                "high",
                "Windows recorded a Security log clear operation. Confirm it was approved and verify that log collection resumed.",
                [event],
                [
                    "Check the native Windows Security event for the account associated with the clear operation.",
                    "Confirm the change against maintenance records and preserve any centrally retained logs.",
                    "Verify Security events are being generated and forwarded as expected.",
                ],
            )
        elif event.signal == (_DEFENDER_LOG, "Microsoft Defender detection"):
            yield _alert(
                "defender-detection",
                "Microsoft Defender reported a detection",
                "high",
                "high",
                "Defender reported a detection event. Review its details and current remediation status.",
                [event],
                [
                    "Open Windows Security or your endpoint management console and review the matching detection.",
                    "Verify whether Defender blocked, quarantined, or still requires action.",
                    "Preserve the event details and investigate other affected devices through approved monitoring.",
                ],
            )


def analyze(status: dict, *, now: datetime | None = None) -> dict:
    """Summarize recent, locally observed signals for investigation."""
    if now is None:
        now = datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("Threat hunting requires a timezone-aware timestamp.")
    now = now.astimezone(timezone.utc)
    raw_events = status.get("events")
    events = _events(raw_events if isinstance(raw_events, list) else [], now)
    raw_coverage = status.get("coverage")
    coverage, state, note = _coverage(raw_coverage if isinstance(raw_coverage, list) else [], status.get("last_poll"), events)
    alerts = [*_authentication_alerts(events), *_exposure_alerts(events), *_windows_alerts(events)]
    alerts.sort(
        key=lambda item: (_SEVERITY[item["severity"]], datetime.fromisoformat(item["last_seen"]), item["id"]),
        reverse=True,
    )
    return {
        "lookback_hours": _LOOKBACK_HOURS,
        "events_considered": len(events),
        "coverage": coverage,
        "coverage_state": state,
        "coverage_note": note,
        "alerts": alerts[:_MAX_ALERTS],
        "alerts_omitted": max(0, len(alerts) - _MAX_ALERTS),
    }
