from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class Decision:
    status: str
    consecutive_failures: int
    consecutive_successes: int
    open_incident: bool
    close_incident: bool
    event: str | None


def decide(
    *,
    status: str,
    enabled: bool,
    failure_threshold: int,
    recovery_threshold: int,
    consecutive_failures: int,
    consecutive_successes: int,
    has_open_incident: bool,
    success: bool,
    valid: bool,
) -> Decision:
    if not enabled or status == "paused" or not valid:
        return Decision(
            status=status,
            consecutive_failures=consecutive_failures,
            consecutive_successes=consecutive_successes,
            open_incident=False,
            close_incident=False,
            event=None,
        )
    if success:
        successes = consecutive_successes + 1
        failures = 0
        new_status = status
        close_incident = False
        event = None
        if status in {"down", "unknown"} and successes >= recovery_threshold:
            new_status = "up"
            if status == "down" and has_open_incident:
                close_incident = True
                event = "recovered"
        return Decision(new_status, failures, successes, False, close_incident, event)
    failures = consecutive_failures + 1
    if failures >= failure_threshold and status != "down":
        return Decision("down", failures, 0, not has_open_incident, False, "down" if not has_open_incident else None)
    return Decision(status, failures, 0, False, False, None)


def display_status(
    *,
    enabled: bool,
    stored_status: str,
    last_valid_at: datetime | None,
    interval_seconds: int,
    timeout_seconds: int,
    now: datetime,
) -> tuple[str, bool]:
    if not enabled or stored_status == "paused":
        return "paused", False
    if last_valid_at is None:
        return "unknown", False
    if last_valid_at.tzinfo is None:
        last_valid_at = last_valid_at.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    grace = timedelta(seconds=interval_seconds * 2 + timeout_seconds)
    if now - last_valid_at > grace:
        return "unknown", True
    return stored_status, False
