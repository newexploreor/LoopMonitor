from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.ids import new_id
from app.models import Monitor, MonitorChannel, MonitorRuntime, NotificationChannel
from app.monitoring.checker import validate_expected_status
from app.monitoring.ssrf import DNSError, SSRFError, parse_and_resolve
from app.monitoring.state import display_status
from app.security import encrypt_json
from app.services.certificates import urlsplit_https
from app.timeutil import utcnow

HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
JSON_PATH = re.compile(r"[A-Za-z0-9_.-]{1,128}")


class InputError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def normalize_url(value: str) -> str:
    text = value.strip()
    if not text or len(text) > 2000:
        raise InputError("目标 URL 无效")
    if "://" not in text:
        text = "https://" + text
    return text


def ensure_target_policy(url: str, settings: Settings) -> None:
    try:
        parse_and_resolve(url, allow_private=settings.allow_private_targets, allowlist=settings.allowlist_entries())
    except SSRFError as exc:
        raise InputError(exc.message) from exc
    except DNSError:
        return


def clean_headers(headers: list[dict] | None) -> list[dict]:
    items = headers or []
    if len(items) > 20:
        raise InputError("请求头最多 20 个")
    cleaned = []
    for item in items:
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        if not HEADER_NAME.fullmatch(name):
            raise InputError("请求头名称无效")
        if any(char in value for char in "\r\n\x00"):
            raise InputError("请求头内容无效")
        if len(value) > 4096:
            raise InputError("请求头过长")
        cleaned.append({"name": name, "value": value})
    return cleaned


def clean_assertions(assertions: list[dict] | None) -> list[dict]:
    items = assertions or []
    if len(items) > 10:
        raise InputError("响应断言最多 10 条")
    cleaned = []
    for item in items:
        kind = item.get("type")
        value = str(item.get("value") or "")
        path = item.get("path")
        if kind not in {"contains", "json_eq"}:
            raise InputError("不支持的响应断言")
        if not value or len(value) > 500:
            raise InputError("断言内容无效")
        if kind == "json_eq":
            if not path or not JSON_PATH.fullmatch(str(path)):
                raise InputError("JSON 字段路径无效")
        elif path:
            path = None
        cleaned.append({"type": kind, "value": value, "path": path})
    return cleaned


def clean_schedule(interval_seconds: int, timeout_seconds: int, failure_threshold: int, recovery_threshold: int) -> None:
    if not 30 <= interval_seconds <= 3600:
        raise InputError("检测间隔需要在 30 到 3600 秒之间")
    if not 1 <= timeout_seconds <= 30:
        raise InputError("请求超时需要在 1 到 30 秒之间")
    if timeout_seconds >= interval_seconds:
        raise InputError("请求超时必须小于检测间隔")
    if not 1 <= failure_threshold <= 20 or not 1 <= recovery_threshold <= 20:
        raise InputError("故障阈值和恢复阈值需要在 1 到 20 之间")


def clean_body(method: str, body: str | None, limit: int) -> str | None:
    if body is None or body == "":
        return None
    if method != "POST":
        raise InputError("只有 POST 检测可以携带请求体")
    if len(body.encode("utf-8")) > limit:
        raise InputError("请求体超过大小限制")
    return body


def _replace_channels(session: Session, monitor_id: str, channel_ids: list[str]) -> None:
    unique = list(dict.fromkeys(channel_ids))
    if len(unique) > 20:
        raise InputError("关联的告警渠道过多")
    if unique:
        found = set(session.scalars(select(NotificationChannel.id).where(NotificationChannel.id.in_(unique))))
        missing = [item for item in unique if item not in found]
        if missing:
            raise InputError("告警渠道不存在")
    existing = session.scalars(select(MonitorChannel).where(MonitorChannel.monitor_id == monitor_id)).all()
    for row in existing:
        session.delete(row)
    for channel_id in unique:
        session.add(MonitorChannel(monitor_id=monitor_id, channel_id=channel_id))


def create_monitor(session: Session, settings: Settings, data: dict) -> Monitor:
    now = utcnow()
    url = normalize_url(data["url"])
    method = data.get("method") or "GET"
    if method not in {"GET", "HEAD", "POST"}:
        raise InputError("HTTP 方法只支持 GET、HEAD、POST")
    ensure_target_policy(url, settings)
    interval = int(data.get("interval_seconds") or settings.default_check_interval_seconds)
    timeout = int(data.get("timeout_seconds") or settings.default_timeout_seconds)
    failure = int(data.get("failure_threshold") or 3)
    recovery = int(data.get("recovery_threshold") or 1)
    clean_schedule(interval, timeout, failure, recovery)
    headers = clean_headers(data.get("headers"))
    assertions = clean_assertions(data.get("assertions"))
    body = clean_body(method, data.get("body"), settings.max_request_body_bytes)
    try:
        expected = validate_expected_status(data.get("expected_status") or "200-299")
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 100:
        raise InputError("服务名称必填，且不超过 100 个字符")
    group_name = data.get("group_name")
    if group_name is not None:
        group_name = str(group_name).strip() or None
        if group_name and len(group_name) > 100:
            raise InputError("分组名称过长")
    enabled = bool(data.get("enabled", True))
    monitor = Monitor(
        id=new_id(),
        name=name,
        group_name=group_name,
        url=url,
        method=method,
        encrypted_headers=encrypt_json(settings.encryption_key_bytes(), headers) if headers else None,
        encrypted_body=encrypt_json(settings.encryption_key_bytes(), body) if body else None,
        interval_seconds=interval,
        timeout_seconds=timeout,
        expected_status=expected,
        assertions=assertions,
        failure_threshold=failure,
        recovery_threshold=recovery,
        follow_redirects=bool(data.get("follow_redirects", False)),
        enabled=enabled,
        current_status="unknown" if enabled else "paused",
        next_run_at=now if enabled else None,
        next_cert_check_at=now if enabled and urlsplit_https(url) else None,
        deleted_at=None,
        created_at=now,
        updated_at=now,
    )
    session.add(monitor)
    session.flush()
    session.add(
        MonitorRuntime(
            monitor_id=monitor.id,
            consecutive_failures=0,
            consecutive_successes=0,
            last_checked_at=None,
            last_valid_at=None,
            last_success=None,
            last_error_type=None,
            last_http_status=None,
            last_latency_ms=None,
            lease_until=None,
        )
    )
    _replace_channels(session, monitor.id, list(data.get("channel_ids") or []))
    session.commit()
    session.refresh(monitor)
    return monitor


def update_monitor(session: Session, settings: Settings, monitor: Monitor, data: dict, fields: set[str]) -> Monitor:
    if "name" in fields and data.get("name") is not None:
        name = str(data["name"]).strip()
        if not name or len(name) > 100:
            raise InputError("服务名称必填，且不超过 100 个字符")
        monitor.name = name
    if "group_name" in fields:
        group_name = data.get("group_name")
        if group_name is not None:
            group_name = str(group_name).strip() or None
        if group_name and len(group_name) > 100:
            raise InputError("分组名称过长")
        monitor.group_name = group_name
    if "url" in fields and data.get("url") is not None:
        monitor.url = normalize_url(data["url"])
        ensure_target_policy(monitor.url, settings)
    if "method" in fields and data.get("method") is not None:
        if data["method"] not in {"GET", "HEAD", "POST"}:
            raise InputError("HTTP 方法只支持 GET、HEAD、POST")
        monitor.method = data["method"]
    if "interval_seconds" in fields and data.get("interval_seconds") is not None:
        monitor.interval_seconds = int(data["interval_seconds"])
    if "timeout_seconds" in fields and data.get("timeout_seconds") is not None:
        monitor.timeout_seconds = int(data["timeout_seconds"])
    if "failure_threshold" in fields and data.get("failure_threshold") is not None:
        monitor.failure_threshold = int(data["failure_threshold"])
    if "recovery_threshold" in fields and data.get("recovery_threshold") is not None:
        monitor.recovery_threshold = int(data["recovery_threshold"])
    clean_schedule(
        monitor.interval_seconds,
        monitor.timeout_seconds,
        monitor.failure_threshold,
        monitor.recovery_threshold,
    )
    if "expected_status" in fields and data.get("expected_status") is not None:
        try:
            monitor.expected_status = validate_expected_status(data["expected_status"])
        except ValueError as exc:
            raise InputError(str(exc)) from exc
    if "assertions" in fields:
        monitor.assertions = clean_assertions(data.get("assertions"))
    if "follow_redirects" in fields and data.get("follow_redirects") is not None:
        monitor.follow_redirects = bool(data["follow_redirects"])
    if "headers" in fields:
        headers = clean_headers(data.get("headers"))
        monitor.encrypted_headers = encrypt_json(settings.encryption_key_bytes(), headers) if headers else None
    if "body" in fields:
        body = clean_body(monitor.method, data.get("body"), settings.max_request_body_bytes)
        monitor.encrypted_body = encrypt_json(settings.encryption_key_bytes(), body) if body else None
    elif monitor.method != "POST":
        monitor.encrypted_body = None
    if "channel_ids" in fields:
        _replace_channels(session, monitor.id, list(data.get("channel_ids") or []))
    if "enabled" in fields and data.get("enabled") is not None:
        _set_enabled(session, monitor, bool(data["enabled"]))
    if monitor.enabled and urlsplit_https(monitor.url) and monitor.next_cert_check_at is None:
        monitor.next_cert_check_at = utcnow()
    if not urlsplit_https(monitor.url):
        monitor.next_cert_check_at = None
    monitor.updated_at = utcnow()
    session.commit()
    session.refresh(monitor)
    return monitor


def _set_enabled(session: Session, monitor: Monitor, enabled: bool) -> None:
    runtime = session.get(MonitorRuntime, monitor.id)
    if enabled and not monitor.enabled:
        monitor.enabled = True
        monitor.current_status = "unknown"
        monitor.next_run_at = utcnow()
        if runtime is not None:
            runtime.consecutive_failures = 0
            runtime.consecutive_successes = 0
            runtime.lease_until = None
    elif not enabled and monitor.enabled:
        monitor.enabled = False
        monitor.current_status = "paused"
        monitor.next_run_at = None
        if runtime is not None:
            runtime.lease_until = None
    else:
        monitor.enabled = enabled


def delete_monitor(session: Session, monitor: Monitor) -> None:
    now = utcnow()
    monitor.deleted_at = now
    monitor.enabled = False
    monitor.current_status = "paused"
    monitor.next_run_at = None
    monitor.updated_at = now
    runtime = session.get(MonitorRuntime, monitor.id)
    if runtime is not None:
        runtime.lease_until = None
    session.commit()


def active_monitor(session: Session, monitor_id: str) -> Monitor:
    monitor = session.get(Monitor, monitor_id)
    if monitor is None or monitor.deleted_at is not None:
        raise InputError("监控目标不存在", 404)
    return monitor


def masked_headers(monitor: Monitor) -> list[dict]:
    if not monitor.encrypted_headers:
        return []
    return [{"name": "configured", "masked": True}]


def header_names(settings: Settings, monitor: Monitor) -> list[dict]:
    if not monitor.encrypted_headers:
        return []
    from app.security import decrypt_json

    raw = decrypt_json(settings.encryption_key_bytes(), monitor.encrypted_headers)
    if not isinstance(raw, list):
        return []
    names = []
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            names.append({"name": str(item["name"]), "masked": True})
    return names


def serialize_monitor(session: Session, settings: Settings, monitor: Monitor, stats: dict | None = None, recent: list | None = None) -> dict:
    runtime = session.get(MonitorRuntime, monitor.id)
    now = utcnow()
    status, stale = display_status(
        enabled=monitor.enabled,
        stored_status=monitor.current_status,
        last_valid_at=runtime.last_valid_at if runtime else None,
        interval_seconds=monitor.interval_seconds,
        timeout_seconds=monitor.timeout_seconds,
        now=now,
    )
    channel_ids = list(session.scalars(select(MonitorChannel.channel_id).where(MonitorChannel.monitor_id == monitor.id)))
    from app.security import redact_url

    payload = {
        "id": monitor.id,
        "name": monitor.name,
        "group_name": monitor.group_name,
        "url": redact_url(monitor.url),
        "method": monitor.method,
        "headers": header_names(settings, monitor),
        "has_body": bool(monitor.encrypted_body),
        "interval_seconds": monitor.interval_seconds,
        "timeout_seconds": monitor.timeout_seconds,
        "expected_status": monitor.expected_status,
        "assertions": monitor.assertions or [],
        "failure_threshold": monitor.failure_threshold,
        "recovery_threshold": monitor.recovery_threshold,
        "follow_redirects": monitor.follow_redirects,
        "enabled": monitor.enabled,
        "current_status": monitor.current_status,
        "display_status": status,
        "data_stale": stale,
        "next_run_at": monitor.next_run_at.isoformat() if monitor.next_run_at else None,
        "last_checked_at": runtime.last_checked_at.isoformat() if runtime and runtime.last_checked_at else None,
        "last_valid_at": runtime.last_valid_at.isoformat() if runtime and runtime.last_valid_at else None,
        "last_success": runtime.last_success if runtime else None,
        "last_error_type": runtime.last_error_type if runtime else None,
        "last_http_status": runtime.last_http_status if runtime else None,
        "last_latency_ms": runtime.last_latency_ms if runtime else None,
        "consecutive_failures": runtime.consecutive_failures if runtime else 0,
        "consecutive_successes": runtime.consecutive_successes if runtime else 0,
        "channel_ids": channel_ids,
        "availability": None if stats is None else stats.get("availability"),
        "avg_latency_ms": None if stats is None else stats.get("avg_latency_ms"),
        "recent": recent or [],
        "created_at": monitor.created_at.isoformat(),
        "updated_at": monitor.updated_at.isoformat(),
    }
    return payload


def stale_after(monitor: Monitor) -> timedelta:
    return timedelta(seconds=monitor.interval_seconds * 2 + monitor.timeout_seconds)
