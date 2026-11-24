from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.ids import new_id
from app.models import CertificateReminder, CertificateResult, Monitor, MonitorChannel, NotificationChannel
from app.monitoring.ssrf import DNSError, SSRFError, parse_and_resolve
from app.notifications.webhook import build_payload, enqueue_delivery
from app.security import sanitize_error_text
from app.timeutil import utcnow


@dataclass
class CertInfo:
    validation_status: str
    expires_at: datetime | None
    days_remaining: int | None
    fingerprint: str | None
    error_message: str | None


def inspect_certificate(hostname: str, ip: str, port: int, timeout: float) -> CertInfo:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                cert = tls.getpeercert()
        if not der or not cert or "notAfter" not in cert:
            return CertInfo("invalid", None, None, None, "未读取到证书")
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days = int((expires - utcnow()).total_seconds() // 86400)
        fingerprint = hashlib.sha256(der).hexdigest()
        if days < 0:
            status = "expired"
        elif days <= 30:
            status = "expiring"
        else:
            status = "valid"
        return CertInfo(status, expires, days, fingerprint, None)
    except Exception as exc:  # noqa: BLE001
        return CertInfo("invalid", None, None, None, sanitize_error_text(str(exc)) or "TLS 校验失败")


def record_certificate(
    session: Session,
    settings: Settings,
    monitor: Monitor,
    *,
    fetcher=None,
) -> CertificateResult:
    now = utcnow()
    info = CertInfo("invalid", None, None, None, "未检查")
    if urlsplit_https(monitor.url):
        try:
            target = parse_and_resolve(
                monitor.url,
                allow_private=settings.allow_private_targets,
                allowlist=settings.allowlist_entries(),
            )
            reader = fetcher or inspect_certificate
            info = reader(target.hostname, target.ips[0], target.port, monitor.timeout_seconds)
        except SSRFError as exc:
            info = CertInfo("invalid", None, None, None, exc.message)
        except DNSError as exc:
            info = CertInfo("invalid", None, None, None, exc.message)
    else:
        info = CertInfo("invalid", None, None, None, "非 HTTPS 目标不检查证书")
    row = CertificateResult(
        id=new_id(),
        monitor_id=monitor.id,
        checked_at=now,
        expires_at=info.expires_at,
        days_remaining=info.days_remaining,
        validation_status=info.validation_status,
        fingerprint=info.fingerprint,
        error_message=info.error_message,
    )
    session.add(row)
    if info.fingerprint and info.days_remaining is not None and info.validation_status in {"valid", "expiring"}:
        _queue_expiry_reminders(session, settings, monitor, info)
    monitor.next_cert_check_at = now + timedelta(seconds=settings.cert_check_interval_seconds)
    return row


def _queue_expiry_reminders(session: Session, settings: Settings, monitor: Monitor, info: CertInfo) -> None:
    if info.days_remaining is None or info.fingerprint is None or info.days_remaining < 0:
        return
    channel_ids = list(session.scalars(select(MonitorChannel.channel_id).where(MonitorChannel.monitor_id == monitor.id)))
    channels = []
    if channel_ids:
        channels = list(
            session.scalars(
                select(NotificationChannel).where(
                    NotificationChannel.id.in_(channel_ids),
                    NotificationChannel.enabled.is_(True),
                )
            )
        )
    for threshold in settings.remind_thresholds():
        if info.days_remaining > threshold:
            continue
        exists = session.scalar(
            select(CertificateReminder).where(
                CertificateReminder.monitor_id == monitor.id,
                CertificateReminder.fingerprint == info.fingerprint,
                CertificateReminder.threshold_days == threshold,
            )
        )
        if exists is not None:
            continue
        session.add(
            CertificateReminder(
                id=new_id(),
                monitor_id=monitor.id,
                fingerprint=info.fingerprint,
                threshold_days=threshold,
                sent_at=utcnow(),
            )
        )
        session.flush()
        if not channels:
            continue
        event_id = new_id()
        payload = build_payload(
            event_id=event_id,
            event_type="certificate_expiring",
            monitor=monitor,
            extra={
                "error_type": "certificate",
                "days_remaining": info.days_remaining,
                "expires_at": info.expires_at.isoformat() if info.expires_at else None,
                "fingerprint": info.fingerprint,
                "threshold_days": threshold,
            },
        )
        for channel in channels:
            enqueue_delivery(session, channel_id=channel.id, event_type="certificate_expiring", payload=payload)


def urlsplit_https(url: str) -> bool:
    return url.lower().startswith("https://")
