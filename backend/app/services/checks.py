from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.ids import new_id
from app.models import CheckJob, CheckResult, Incident, Monitor, MonitorChannel, MonitorRuntime, NotificationChannel
from app.monitoring.checker import ProbeResult, probe_http
from app.monitoring.state import decide
from app.notifications.webhook import build_payload, enqueue_delivery
from app.security import decrypt_json, sanitize_error_text
from app.timeutil import utcnow

logger = logging.getLogger(__name__)


@dataclass
class ClaimOutcome:
    state: str
    monitor: ClaimedMonitor | None = None


@dataclass
class ClaimedMonitor:
    id: str
    name: str
    url: str
    method: str
    headers: dict[str, str]
    body: str | None
    timeout_seconds: int
    expected_status: str
    assertions: list
    follow_redirects: bool


def _headers_map(raw: object) -> dict[str, str]:
    if not isinstance(raw, list):
        return {}
    mapped: dict[str, str] = {}
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            mapped[str(item["name"])] = str(item.get("value") or "")
    return mapped


def claim_monitor(session: Session, settings: Settings, monitor_id: str, trigger: str) -> ClaimOutcome:
    monitor = session.get(Monitor, monitor_id)
    if monitor is None or monitor.deleted_at is not None or not monitor.enabled or trigger not in {"auto", "manual"}:
        return ClaimOutcome("skipped")
    now = utcnow()
    lease_until = now + timedelta(seconds=max(monitor.timeout_seconds * 2, monitor.timeout_seconds + 5))
    updated = session.execute(
        update(MonitorRuntime)
        .where(MonitorRuntime.monitor_id == monitor_id)
        .where(or_(MonitorRuntime.lease_until.is_(None), MonitorRuntime.lease_until < now))
        .values(lease_until=lease_until)
    )
    if updated.rowcount != 1:
        session.rollback()
        return ClaimOutcome("busy")
    headers: dict[str, str] = {}
    body = None
    try:
        if monitor.encrypted_headers:
            headers = _headers_map(decrypt_json(settings.encryption_key_bytes(), monitor.encrypted_headers))
        if monitor.encrypted_body:
            body = str(decrypt_json(settings.encryption_key_bytes(), monitor.encrypted_body))
    except Exception as exc:  # noqa: BLE001
        session.rollback()
        raise RuntimeError(sanitize_error_text(str(exc)) or "凭证解密失败") from exc
    claimed = ClaimedMonitor(
        id=monitor.id,
        name=monitor.name,
        url=monitor.url,
        method=monitor.method,
        headers=headers,
        body=body,
        timeout_seconds=monitor.timeout_seconds,
        expected_status=monitor.expected_status,
        assertions=list(monitor.assertions or []),
        follow_redirects=monitor.follow_redirects,
    )
    session.commit()
    return ClaimOutcome("claimed", claimed)


def clear_lease(session: Session, monitor_id: str) -> None:
    runtime = session.get(MonitorRuntime, monitor_id)
    if runtime is not None:
        runtime.lease_until = None
        session.commit()


def persist_probe(session: Session, settings: Settings, monitor_id: str, probe: ProbeResult, trigger: str) -> str:
    monitor = session.get(Monitor, monitor_id)
    runtime = session.get(MonitorRuntime, monitor_id)
    if monitor is None or runtime is None:
        session.rollback()
        raise RuntimeError("监控目标不存在")
    now = probe.finished_at
    result = CheckResult(
        id=new_id(),
        monitor_id=monitor.id,
        trigger_type=trigger,
        started_at=probe.started_at,
        finished_at=probe.finished_at,
        success=probe.success,
        valid=probe.valid,
        http_status=probe.http_status,
        latency_ms=probe.latency_ms,
        error_type=probe.error_type,
        error_message=probe.error_message,
    )
    session.add(result)
    runtime.last_checked_at = probe.finished_at
    runtime.last_http_status = probe.http_status
    runtime.last_latency_ms = probe.latency_ms
    runtime.lease_until = None
    if probe.valid:
        runtime.last_valid_at = probe.finished_at
        runtime.last_success = probe.success
        runtime.last_error_type = None if probe.success else probe.error_type
    else:
        runtime.last_error_type = probe.error_type
    open_incident = session.scalar(
        select(Incident).where(Incident.monitor_id == monitor.id, Incident.status == "open")
    )
    decision = decide(
        status=monitor.current_status,
        enabled=monitor.enabled and monitor.deleted_at is None,
        failure_threshold=monitor.failure_threshold,
        recovery_threshold=monitor.recovery_threshold,
        consecutive_failures=runtime.consecutive_failures,
        consecutive_successes=runtime.consecutive_successes,
        has_open_incident=open_incident is not None,
        success=probe.success,
        valid=probe.valid,
    )
    runtime.consecutive_failures = decision.consecutive_failures
    runtime.consecutive_successes = decision.consecutive_successes
    if monitor.enabled and monitor.deleted_at is None:
        monitor.current_status = decision.status
        monitor.next_run_at = probe.finished_at + timedelta(seconds=monitor.interval_seconds)
        monitor.updated_at = now
    incident_for_event: Incident | None = None
    event_type: str | None = None
    if decision.event == "down" and decision.open_incident:
        incident_for_event = Incident(
            id=new_id(),
            monitor_id=monitor.id,
            status="open",
            started_at=probe.finished_at,
            recovered_at=None,
            error_type=probe.error_type,
            http_status=probe.http_status,
            summary=(probe.error_message or "连续检测失败")[:500],
        )
        session.add(incident_for_event)
        event_type = "down"
    elif decision.event == "recovered" and open_incident is not None:
        open_incident.status = "recovered"
        open_incident.recovered_at = probe.finished_at
        incident_for_event = open_incident
        event_type = "recovered"
    session.flush()
    if incident_for_event is not None and event_type is not None:
        _queue_incident_notifications(session, monitor, incident_for_event, event_type)
    session.commit()
    logger.info(
        "check monitor=%s trigger=%s success=%s valid=%s error=%s",
        monitor.id,
        trigger,
        probe.success,
        probe.valid,
        probe.error_type,
    )
    return result.id


def _queue_incident_notifications(session: Session, monitor: Monitor, incident: Incident, event_type: str) -> None:
    channel_ids = list(
        session.scalars(select(MonitorChannel.channel_id).where(MonitorChannel.monitor_id == monitor.id))
    )
    if not channel_ids:
        return
    channels = session.scalars(
        select(NotificationChannel).where(
            NotificationChannel.id.in_(channel_ids),
            NotificationChannel.enabled.is_(True),
        )
    ).all()
    event_id = new_id()
    payload = build_payload(event_id=event_id, event_type=event_type, monitor=monitor, incident=incident)
    for channel in channels:
        enqueue_delivery(
            session,
            channel_id=channel.id,
            event_type=event_type,
            payload=payload,
            incident_id=incident.id,
        )


def _internal_probe(message: str) -> ProbeResult:
    now = utcnow()
    return ProbeResult(
        success=False,
        valid=False,
        http_status=None,
        latency_ms=None,
        error_type="internal",
        error_message=message[:500],
        started_at=now,
        finished_at=now,
    )


async def perform_check(settings: Settings, session_factory: sessionmaker, monitor_id: str, trigger: str) -> str | None:
    def _claim() -> ClaimOutcome:
        with session_factory() as session:
            return claim_monitor(session, settings, monitor_id, trigger)

    try:
        outcome = await asyncio.to_thread(_claim)
    except Exception as exc:  # noqa: BLE001
        logger.exception("claim failed monitor=%s", monitor_id)
        with session_factory() as session:
            clear_lease(session, monitor_id)
            persist_probe(session, settings, monitor_id, _internal_probe(sanitize_error_text(str(exc))), trigger)
        return "error"
    if outcome.state == "busy":
        return None
    if outcome.state != "claimed" or outcome.monitor is None:
        return "skipped"
    claimed = outcome.monitor
    try:
        probe = await probe_http(
            url=claimed.url,
            method=claimed.method,
            headers=claimed.headers,
            body=claimed.body,
            timeout_seconds=claimed.timeout_seconds,
            follow_redirects=claimed.follow_redirects,
            expected_status=claimed.expected_status,
            assertions=claimed.assertions,
            allow_private=settings.allow_private_targets,
            allowlist=settings.allowlist_entries(),
            max_response_bytes=settings.max_response_bytes,
            max_redirects=settings.max_redirects,
        )
    except Exception as exc:  # noqa: BLE001
        probe = _internal_probe(sanitize_error_text(str(exc)) or "检测器内部异常")

    def _save() -> str:
        with session_factory() as session:
            return persist_probe(session, settings, monitor_id, probe, trigger)

    try:
        return await asyncio.to_thread(_save)
    except Exception:
        logger.exception("persist failed monitor=%s", monitor_id)
        with session_factory() as session:
            clear_lease(session, monitor_id)
        raise


def enqueue_manual_check(session: Session, monitor: Monitor) -> CheckJob:
    if monitor.deleted_at is not None:
        raise RuntimeError("监控目标不存在")
    if not monitor.enabled:
        raise RuntimeError("暂停中的监控不能立即检测")
    job = CheckJob(
        id=new_id(),
        monitor_id=monitor.id,
        status="pending",
        check_result_id=None,
        error=None,
        created_at=utcnow(),
        started_at=None,
        finished_at=None,
    )
    session.add(job)
    session.commit()
    return job


def claim_job(session: Session, job_id: str) -> bool:
    updated = session.execute(
        update(CheckJob)
        .where(CheckJob.id == job_id, CheckJob.status == "pending")
        .values(status="running", started_at=utcnow())
    )
    if updated.rowcount != 1:
        session.rollback()
        return False
    session.commit()
    return True


def finish_job(session: Session, job_id: str, result_id: str | None, error: str | None, retry: bool) -> None:
    job = session.get(CheckJob, job_id)
    if job is None:
        return
    if retry:
        job.status = "pending"
        job.error = error
        session.commit()
        return
    job.status = "failed" if error else "succeeded"
    job.check_result_id = result_id
    job.error = error
    job.finished_at = utcnow()
    session.commit()
