from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.ids import new_id
from app.models import Incident, Monitor, NotificationChannel, NotificationDelivery
from app.monitoring.checker import _host_header, _pinned_url
from app.monitoring.ssrf import DNSError, SSRFError, parse_and_resolve
from app.security import decrypt_json, redact_url, sanitize_error_text
from app.timeutil import utcnow

RETRY_DELAYS = (30, 120, 600)


def channel_config(settings: Settings, channel: NotificationChannel) -> dict:
    value = decrypt_json(settings.encryption_key_bytes(), channel.encrypted_config)
    if not isinstance(value, dict):
        raise RuntimeError("告警渠道配置无效")
    return value


def build_payload(
    *,
    event_id: str,
    event_type: str,
    monitor: Monitor,
    incident: Incident | None = None,
    extra: dict | None = None,
) -> dict:
    occurred = utcnow()
    if incident is not None:
        occurred = incident.recovered_at or incident.started_at
    payload = {
        "event_id": event_id,
        "event_type": event_type,
        "monitor_id": monitor.id,
        "monitor_name": monitor.name,
        "url": redact_url(monitor.url),
        "occurred_at": occurred.isoformat(),
        "error_type": incident.error_type if incident else None,
        "http_status": incident.http_status if incident else None,
        "duration_seconds": None,
    }
    if incident is not None and incident.recovered_at is not None:
        payload["duration_seconds"] = max(0, int((incident.recovered_at - incident.started_at).total_seconds()))
    if extra:
        payload.update(extra)
    return payload


def enqueue_delivery(
    session: Session,
    *,
    channel_id: str,
    event_type: str,
    payload: dict,
    incident_id: str | None = None,
) -> NotificationDelivery | None:
    event_id = payload["event_id"]
    existing = session.scalar(
        select(NotificationDelivery).where(
            NotificationDelivery.channel_id == channel_id,
            NotificationDelivery.event_id == event_id,
        )
    )
    if existing is not None:
        return None
    if incident_id is not None:
        duplicated = session.scalar(
            select(NotificationDelivery.id).where(
                NotificationDelivery.incident_id == incident_id,
                NotificationDelivery.channel_id == channel_id,
                NotificationDelivery.event_type == event_type,
            )
        )
        if duplicated is not None:
            return None
    delivery = NotificationDelivery(
        id=new_id(),
        incident_id=incident_id,
        channel_id=channel_id,
        event_id=event_id,
        event_type=event_type,
        status="pending",
        attempts=0,
        next_retry_at=utcnow(),
        last_error=None,
        payload=payload,
        created_at=utcnow(),
        delivered_at=None,
    )
    session.add(delivery)
    return delivery


def sign_body(secret: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(utcnow().timestamp()))
    digest = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256).hexdigest()
    return {
        "X-LoopMonitor-Timestamp": timestamp,
        "X-LoopMonitor-Signature": f"sha256={digest}",
    }


async def post_webhook(settings: Settings, url: str, secret: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "LoopMonitor/0.1"}
    if secret:
        headers.update(sign_body(secret, body))
    try:
        target = parse_and_resolve(
            url,
            allow_private=settings.allow_private_targets,
            allowlist=settings.allowlist_entries(),
        )
    except (SSRFError, DNSError) as exc:
        raise RuntimeError(str(exc)) from exc
    headers["Host"] = _host_header(target.hostname, target.port, target.scheme)
    pinned = _pinned_url(url, target.ips[0], target.port)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10), follow_redirects=False, trust_env=False, verify=True) as client:
            request = client.build_request("POST", pinned, content=body, headers=headers)
            request.extensions["sni_hostname"] = target.hostname
            response = await client.send(request)
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"Webhook 返回状态码 {response.status_code}")
    except RuntimeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(sanitize_error_text(str(exc)) or "Webhook 投递失败") from exc


def mark_delivered(delivery: NotificationDelivery) -> None:
    delivery.attempts += 1
    delivery.status = "delivered"
    delivery.delivered_at = utcnow()
    delivery.last_error = None
    delivery.next_retry_at = None


def _mark_attempt(delivery: NotificationDelivery, error: str) -> None:
    delivery.attempts += 1
    delivery.last_error = error[:500]
    if delivery.attempts <= len(RETRY_DELAYS):
        delivery.status = "pending"
        delivery.next_retry_at = utcnow() + timedelta(seconds=RETRY_DELAYS[delivery.attempts - 1])
    else:
        delivery.status = "failed"
        delivery.next_retry_at = None
