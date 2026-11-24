from __future__ import annotations

import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.orm import Session

from app import __version__
from app.api.deps import csrf_protect, current_user, get_db
from app.models import (
    CertificateResult,
    CheckJob,
    CheckResult,
    Incident,
    Monitor,
    MonitorChannel,
    MonitorRuntime,
    NotificationChannel,
    NotificationDelivery,
    SystemSetting,
    User,
)
from app.monitoring.checker import probe_http
from app.monitoring.state import display_status
from app.notifications.webhook import build_payload, enqueue_delivery, post_webhook
from app.schemas import ChannelIn, ChannelPatch, LoginIn, MonitorIn, MonitorPatch, PasswordIn, SettingsPatch
from app.security import RateLimiter, dump_session, dummy_password_hash, encrypt_json, redact_url, verify_password
from app.security import hash_password
from app.services.catalog import (
    InputError,
    active_monitor,
    create_monitor,
    delete_monitor,
    header_names,
    normalize_url,
    serialize_monitor,
    update_monitor,
)
from app.services.checks import enqueue_manual_check
from app.services.maintenance import (
    RETENTION_CHECK_KEY,
    RETENTION_INCIDENT_KEY,
    ensure_admin,
    get_int_setting,
    seed_settings,
    set_int_setting,
    validate_password,
)
from app.services.stats import bucket_trend, load_auto_checks, per_monitor, recent_statuses, summarize_checks, window_delta
from app.timeutil import ensure_utc, utcnow

public_router = APIRouter()
api_router = APIRouter(prefix="/api/v1", dependencies=[Depends(current_user), Depends(csrf_protect)])


def _bad(exc: InputError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message)


def _cookie_kwargs(settings) -> dict:
    return {
        "secure": settings.cookie_is_secure(),
        "samesite": "lax",
        "max_age": settings.session_seconds,
        "path": "/",
    }


def _set_auth_cookies(response: Response, settings, user: User, csrf: str) -> None:
    common = _cookie_kwargs(settings)
    response.set_cookie("lm_session", dump_session(settings.app_secret_key, user.id, user.username), httponly=True, **common)
    response.set_cookie("lm_csrf", csrf, httponly=False, **common)


@public_router.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@public_router.get("/api/ready")
def ready(request: Request, session: Session = Depends(get_db)) -> Response:
    settings = request.app.state.settings
    database = "ok"
    try:
        session.execute(text("SELECT 1"))
    except Exception:
        database = "error"
    worker = "missing"
    if database == "ok":
        row = session.get(SystemSetting, "worker_heartbeat")
        if row is not None:
            try:
                seen = ensure_utc(datetime.fromisoformat(row.value))
                age = (utcnow() - seen).total_seconds()
                worker = "ok" if age <= settings.worker_stale_seconds else "stale"
            except ValueError:
                worker = "stale"
    status = "ready" if database == "ok" and worker == "ok" else "not_ready"
    body = {"status": status, "database": database, "worker": worker}
    return Response(
        content=__import__("json").dumps(body),
        media_type="application/json",
        status_code=200 if status == "ready" else 503,
    )


@public_router.post("/api/v1/auth/login")
def login(payload: LoginIn, request: Request, response: Response, session: Session = Depends(get_db)) -> dict:
    settings = request.app.state.settings
    limiter: RateLimiter = request.app.state.login_limiter
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(f"login:{client}", settings.login_limit, settings.login_window_seconds):
        raise HTTPException(status_code=429, detail="尝试次数过多，请稍后再试")
    user = session.scalar(select(User).where(User.username == payload.username))
    password_hash = user.password_hash if user else dummy_password_hash()
    if user is None or not verify_password(payload.password, password_hash):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    csrf = secrets.token_urlsafe(32)
    _set_auth_cookies(response, settings, user, csrf)
    return {"username": user.username, "csrf_token": csrf}


@api_router.post("/auth/logout")
def logout(response: Response) -> dict:
    response.delete_cookie("lm_session", path="/")
    response.delete_cookie("lm_csrf", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
def me(user: User = Depends(current_user)) -> dict:
    return {"username": user.username}


@api_router.get("/auth/csrf")
def issue_csrf(request: Request, response: Response, user: User = Depends(current_user)) -> dict:
    token = secrets.token_urlsafe(32)
    response.set_cookie("lm_csrf", token, httponly=False, **_cookie_kwargs(request.app.state.settings))
    return {"username": user.username, "csrf_token": token}


@api_router.post("/auth/password")
def change_password(
    payload: PasswordIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict:
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="当前密码错误")
    try:
        validate_password(payload.new_password, user.username)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    user.password_hash = hash_password(payload.new_password)
    session.commit()
    csrf = secrets.token_urlsafe(32)
    _set_auth_cookies(response, request.app.state.settings, user, csrf)
    return {"ok": True, "csrf_token": csrf}


def _monitor_query(session: Session, q: str | None, group: str | None) -> list[Monitor]:
    stmt = select(Monitor).where(Monitor.deleted_at.is_(None))
    if q:
        pattern = f"%{q.replace('%', '').replace('_', '')}%"
        stmt = stmt.where(or_(Monitor.name.ilike(pattern), Monitor.url.ilike(pattern), Monitor.group_name.ilike(pattern)))
    if group:
        stmt = stmt.where(Monitor.group_name == group)
    return list(session.scalars(stmt.order_by(Monitor.created_at.desc())))


def _decorate(session: Session, settings, monitors: list[Monitor], window: str) -> list[dict]:
    now = utcnow()
    start = now - window_delta(window)
    ids = [monitor.id for monitor in monitors]
    summary = per_monitor(load_auto_checks(session, monitor_ids=ids, start=start, end=now))
    recent = recent_statuses(session, ids)
    return [
        serialize_monitor(session, settings, monitor, summary.get(monitor.id), recent.get(monitor.id, []))
        for monitor in monitors
    ]


@api_router.get("/dashboard")
def dashboard(
    request: Request,
    session: Session = Depends(get_db),
    window: str = "24h",
    q: str | None = None,
    group: str | None = None,
    status: str | None = None,
) -> dict:
    try:
        delta = window_delta(window)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    settings = request.app.state.settings
    all_monitors = list(session.scalars(select(Monitor).where(Monitor.deleted_at.is_(None))))
    now = utcnow()
    counts = {"up": 0, "down": 0, "paused": 0, "unknown": 0}
    for monitor in all_monitors:
        runtime = session.get(MonitorRuntime, monitor.id)
        shown, _stale = display_status(
            enabled=monitor.enabled,
            stored_status=monitor.current_status,
            last_valid_at=runtime.last_valid_at if runtime else None,
            interval_seconds=monitor.interval_seconds,
            timeout_seconds=monitor.timeout_seconds,
            now=now,
        )
        counts[shown] = counts.get(shown, 0) + 1
    rows = load_auto_checks(session, monitor_ids=[item.id for item in all_monitors], start=now - delta, end=now)
    summary = summarize_checks(rows)
    open_incidents = session.scalar(select(func.count()).select_from(Incident).where(Incident.status == "open")) or 0
    filtered = _monitor_query(session, q, group)
    items = _decorate(session, settings, filtered, window)
    if status:
        items = [item for item in items if item["display_status"] == status]
    return {
        "total": len(all_monitors),
        "up": counts["up"],
        "down": counts["down"],
        "paused": counts["paused"],
        "unknown": counts["unknown"],
        "open_incidents": open_incidents,
        "availability": summary["availability"],
        "avg_latency_ms": summary["avg_latency_ms"],
        "p95_latency_ms": summary["p95_latency_ms"],
        "window": window,
        "trend": bucket_trend(rows, now - delta, now, window),
        "monitors": items,
    }


@api_router.get("/monitors/groups")
def monitor_groups(session: Session = Depends(get_db)) -> dict:
    rows = session.scalars(
        select(Monitor.group_name)
        .where(Monitor.deleted_at.is_(None), Monitor.group_name.is_not(None))
        .distinct()
        .order_by(Monitor.group_name)
    )
    return {"items": [row for row in rows if row]}


@api_router.get("/monitors")
def list_monitors(
    request: Request,
    session: Session = Depends(get_db),
    q: str | None = None,
    group: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    window: str = "24h",
) -> dict:
    try:
        window_delta(window)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    items = _decorate(session, request.app.state.settings, _monitor_query(session, q, group), window)
    if status:
        items = [item for item in items if item["display_status"] == status]
    total = len(items)
    return {"items": items[offset : offset + limit], "total": total, "limit": limit, "offset": offset}


@api_router.post("/monitors", status_code=201)
def post_monitor(payload: MonitorIn, request: Request, session: Session = Depends(get_db)) -> dict:
    try:
        monitor = create_monitor(session, request.app.state.settings, payload.model_dump())
    except InputError as exc:
        session.rollback()
        raise _bad(exc) from exc
    return serialize_monitor(session, request.app.state.settings, monitor)


@api_router.post("/monitors/test")
async def test_monitor(payload: MonitorIn, request: Request) -> dict:
    settings = request.app.state.settings
    limiter: RateLimiter = request.app.state.probe_limiter
    if not limiter.allow("probe", 30, 60):
        raise HTTPException(status_code=429, detail="测试连接过于频繁，请稍后再试")
    try:
        url = normalize_url(payload.url)
    except InputError as exc:
        raise _bad(exc) from exc
    headers = {item.name: item.value for item in payload.headers}
    result = await probe_http(
        url=url,
        method=payload.method,
        headers=headers,
        body=payload.body,
        timeout_seconds=payload.timeout_seconds or settings.default_timeout_seconds,
        follow_redirects=payload.follow_redirects,
        expected_status=payload.expected_status,
        assertions=[item.model_dump() for item in payload.assertions],
        allow_private=settings.allow_private_targets,
        allowlist=settings.allowlist_entries(),
        max_response_bytes=settings.max_response_bytes,
        max_redirects=settings.max_redirects,
    )
    return {
        "success": result.success,
        "valid": result.valid,
        "http_status": result.http_status,
        "latency_ms": result.latency_ms,
        "error_type": result.error_type,
        "error_message": result.error_message,
        "url": redact_url(url),
    }


@api_router.get("/monitors/{monitor_id}")
def get_monitor(monitor_id: str, request: Request, session: Session = Depends(get_db)) -> dict:
    try:
        monitor = active_monitor(session, monitor_id)
    except InputError as exc:
        raise _bad(exc) from exc
    items = _decorate(session, request.app.state.settings, [monitor], "24h")
    return items[0]


@api_router.patch("/monitors/{monitor_id}")
def patch_monitor(monitor_id: str, payload: MonitorPatch, request: Request, session: Session = Depends(get_db)) -> dict:
    try:
        monitor = active_monitor(session, monitor_id)
        updated = update_monitor(
            session,
            request.app.state.settings,
            monitor,
            payload.model_dump(),
            set(payload.model_fields_set),
        )
    except InputError as exc:
        session.rollback()
        raise _bad(exc) from exc
    return serialize_monitor(session, request.app.state.settings, updated)


@api_router.delete("/monitors/{monitor_id}")
def remove_monitor(monitor_id: str, session: Session = Depends(get_db)) -> dict:
    try:
        monitor = active_monitor(session, monitor_id)
    except InputError as exc:
        raise _bad(exc) from exc
    delete_monitor(session, monitor)
    return {"ok": True}


@api_router.post("/monitors/{monitor_id}/check", status_code=202)
def check_now(monitor_id: str, session: Session = Depends(get_db)) -> dict:
    try:
        monitor = active_monitor(session, monitor_id)
        job = enqueue_manual_check(session, monitor)
    except InputError as exc:
        raise _bad(exc) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"job_id": job.id, "status": job.status}


@api_router.get("/check-jobs/{job_id}")
def get_job(job_id: str, session: Session = Depends(get_db)) -> dict:
    job = session.get(CheckJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="检测任务不存在")
    return {
        "job_id": job.id,
        "monitor_id": job.monitor_id,
        "status": job.status,
        "check_result_id": job.check_result_id,
        "error": job.error,
        "created_at": job.created_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@api_router.get("/monitors/{monitor_id}/checks")
def list_checks(
    monitor_id: str,
    session: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    trigger_type: str | None = None,
) -> dict:
    try:
        active_monitor(session, monitor_id)
    except InputError as exc:
        raise _bad(exc) from exc
    filters = [CheckResult.monitor_id == monitor_id]
    if trigger_type:
        filters.append(CheckResult.trigger_type == trigger_type)
    total = session.scalar(select(func.count()).select_from(CheckResult).where(*filters)) or 0
    rows = session.scalars(
        select(CheckResult).where(*filters).order_by(CheckResult.started_at.desc()).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_check_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@api_router.get("/monitors/{monitor_id}/statistics")
def statistics(monitor_id: str, session: Session = Depends(get_db), window: str = "24h") -> dict:
    try:
        monitor = active_monitor(session, monitor_id)
        delta = window_delta(window)
    except InputError as exc:
        raise _bad(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    now = utcnow()
    start = now - delta
    rows = load_auto_checks(session, monitor_ids=[monitor.id], start=start, end=now)
    summary = summarize_checks(rows)
    manual_total = session.scalar(
        select(func.count())
        .select_from(CheckResult)
        .where(
            CheckResult.monitor_id == monitor.id,
            CheckResult.trigger_type == "manual",
            CheckResult.started_at >= start,
            CheckResult.started_at < now,
        )
    ) or 0
    incidents = session.scalars(
        select(Incident).where(Incident.monitor_id == monitor.id).order_by(Incident.started_at.desc()).limit(20)
    ).all()
    cert = session.scalar(
        select(CertificateResult)
        .where(CertificateResult.monitor_id == monitor.id)
        .order_by(CertificateResult.checked_at.desc())
    )
    return {
        "window": window,
        **summary,
        "manual_total": manual_total,
        "trend": bucket_trend(rows, start, now, window),
        "incidents": [_incident_dict(session, row) for row in incidents],
        "certificate": _cert_dict(cert),
    }


@api_router.get("/incidents")
def list_incidents(
    session: Session = Depends(get_db),
    status: str | None = None,
    monitor_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    filters = []
    if status:
        filters.append(Incident.status == status)
    if monitor_id:
        filters.append(Incident.monitor_id == monitor_id)
    total = session.scalar(select(func.count()).select_from(Incident).where(*filters)) or 0
    rows = session.scalars(
        select(Incident).where(*filters).order_by(Incident.started_at.desc()).limit(limit).offset(offset)
    ).all()
    return {"items": [_incident_dict(session, row) for row in rows], "total": total, "limit": limit, "offset": offset}


@api_router.get("/notification-channels")
def list_channels(request: Request, session: Session = Depends(get_db)) -> dict:
    rows = session.scalars(select(NotificationChannel).order_by(NotificationChannel.created_at.desc())).all()
    return {"items": [_channel_dict(request.app.state.settings, row) for row in rows]}


@api_router.post("/notification-channels", status_code=201)
def post_channel(payload: ChannelIn, request: Request, session: Session = Depends(get_db)) -> dict:
    settings = request.app.state.settings
    _validate_channel_url(payload.url, settings)
    now = utcnow()
    channel = NotificationChannel(
        id=secrets.token_hex(16),
        name=payload.name.strip(),
        type="webhook",
        encrypted_config=encrypt_json(
            settings.encryption_key_bytes(),
            {"url": normalize_channel_url(payload.url), "secret": payload.secret or ""},
        ),
        enabled=payload.enabled,
        created_at=now,
        updated_at=now,
    )
    session.add(channel)
    session.commit()
    return _channel_dict(settings, channel)


@api_router.patch("/notification-channels/{channel_id}")
def patch_channel(channel_id: str, payload: ChannelPatch, request: Request, session: Session = Depends(get_db)) -> dict:
    settings = request.app.state.settings
    channel = session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="告警渠道不存在")
    from app.notifications.webhook import channel_config

    config = channel_config(settings, channel)
    if "name" in payload.model_fields_set and payload.name is not None:
        channel.name = payload.name.strip()
    if "url" in payload.model_fields_set and payload.url is not None:
        _validate_channel_url(payload.url, settings)
        config["url"] = normalize_channel_url(payload.url)
    if "secret" in payload.model_fields_set and payload.secret is not None:
        config["secret"] = payload.secret
    if "enabled" in payload.model_fields_set and payload.enabled is not None:
        channel.enabled = payload.enabled
    channel.encrypted_config = encrypt_json(settings.encryption_key_bytes(), config)
    channel.updated_at = utcnow()
    session.commit()
    return _channel_dict(settings, channel)


@api_router.delete("/notification-channels/{channel_id}")
def delete_channel(channel_id: str, session: Session = Depends(get_db)) -> dict:
    channel = session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="告警渠道不存在")
    session.execute(delete(MonitorChannel).where(MonitorChannel.channel_id == channel_id))
    session.execute(delete(NotificationDelivery).where(NotificationDelivery.channel_id == channel_id))
    session.delete(channel)
    session.commit()
    return {"ok": True}


@api_router.post("/notification-channels/{channel_id}/test")
async def test_channel(channel_id: str, request: Request, session: Session = Depends(get_db)) -> dict:
    settings = request.app.state.settings
    channel = session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="告警渠道不存在")
    from app.notifications.webhook import channel_config

    config = channel_config(settings, channel)
    monitor = session.scalar(select(Monitor).where(Monitor.deleted_at.is_(None)).limit(1))
    placeholder_name = monitor.name if monitor else "LoopMonitor"
    placeholder_id = monitor.id if monitor else "test"
    placeholder_url = monitor.url if monitor else "https://monitor.example.com"
    event_id = secrets.token_hex(16)
    payload = {
        "event_id": event_id,
        "event_type": "test",
        "monitor_id": placeholder_id,
        "monitor_name": placeholder_name,
        "url": redact_url(placeholder_url),
        "occurred_at": utcnow().isoformat(),
        "error_type": None,
        "http_status": None,
        "duration_seconds": None,
    }
    delivery = enqueue_delivery(session, channel_id=channel.id, event_type="test", payload=payload)
    session.commit()
    error = None
    try:
        await post_webhook(settings, str(config.get("url") or ""), str(config.get("secret") or ""), payload)
    except Exception as exc:  # noqa: BLE001
        error = str(exc)[:500]
    if delivery is not None:
        stored = session.get(NotificationDelivery, delivery.id)
        if stored is not None:
            if error is None:
                from app.notifications.webhook import mark_delivered

                mark_delivered(stored)
            else:
                from app.notifications.webhook import _mark_attempt

                _mark_attempt(stored, error)
            session.commit()
            return {"ok": error is None, "delivery_id": stored.id, "status": stored.status, "error": stored.last_error}
    return {"ok": error is None, "error": error}


@api_router.get("/notification-deliveries")
def list_deliveries(
    session: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    total = session.scalar(select(func.count()).select_from(NotificationDelivery)) or 0
    rows = session.scalars(
        select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "channel_id": row.channel_id,
                "event_id": row.event_id,
                "event_type": row.event_type,
                "status": row.status,
                "attempts": row.attempts,
                "next_retry_at": row.next_retry_at.isoformat() if row.next_retry_at else None,
                "last_error": row.last_error,
                "created_at": row.created_at.isoformat(),
                "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
            }
            for row in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@api_router.get("/settings")
def get_settings_view(request: Request, session: Session = Depends(get_db)) -> dict:
    settings = request.app.state.settings
    seed_settings(session, settings)
    session.commit()
    heartbeat = session.get(SystemSetting, "worker_heartbeat")
    worker = "missing"
    heartbeat_at = None
    if heartbeat is not None:
        heartbeat_at = heartbeat.value
        try:
            seen = ensure_utc(datetime.fromisoformat(heartbeat.value))
            age = (utcnow() - seen).total_seconds()
            worker = "ok" if age <= settings.worker_stale_seconds else "stale"
        except ValueError:
            worker = "stale"
    return {
        "version": __version__,
        "env": settings.env,
        "check_retention_days": get_int_setting(session, RETENTION_CHECK_KEY, settings.check_retention_days),
        "incident_retention_days": get_int_setting(session, RETENTION_INCIDENT_KEY, settings.incident_retention_days),
        "allow_private_targets": settings.allow_private_targets,
        "worker": worker,
        "worker_heartbeat": heartbeat_at,
        "database": "sqlite",
    }


@api_router.patch("/settings")
def patch_settings(payload: SettingsPatch, request: Request, session: Session = Depends(get_db)) -> dict:
    if payload.check_retention_days is not None:
        if not 1 <= payload.check_retention_days <= 365:
            raise HTTPException(status_code=400, detail="检测记录保留天数需要在 1 到 365 之间")
        set_int_setting(session, RETENTION_CHECK_KEY, payload.check_retention_days)
    if payload.incident_retention_days is not None:
        if not 1 <= payload.incident_retention_days <= 3650:
            raise HTTPException(status_code=400, detail="事件保留天数需要在 1 到 3650 之间")
        set_int_setting(session, RETENTION_INCIDENT_KEY, payload.incident_retention_days)
    session.commit()
    return get_settings_view(request, session)


def _check_dict(row: CheckResult) -> dict:
    return {
        "id": row.id,
        "monitor_id": row.monitor_id,
        "trigger_type": row.trigger_type,
        "started_at": row.started_at.isoformat(),
        "finished_at": row.finished_at.isoformat(),
        "success": row.success,
        "valid": row.valid,
        "http_status": row.http_status,
        "latency_ms": row.latency_ms,
        "error_type": row.error_type,
        "error_message": row.error_message,
    }


def _incident_dict(session: Session, row: Incident) -> dict:
    monitor = session.get(Monitor, row.monitor_id)
    end = ensure_utc(row.recovered_at) if row.recovered_at else utcnow()
    duration = max(0, int((end - ensure_utc(row.started_at)).total_seconds()))
    return {
        "id": row.id,
        "monitor_id": row.monitor_id,
        "monitor_name": monitor.name if monitor else None,
        "status": row.status,
        "started_at": row.started_at.isoformat(),
        "recovered_at": row.recovered_at.isoformat() if row.recovered_at else None,
        "duration_seconds": duration,
        "error_type": row.error_type,
        "http_status": row.http_status,
        "summary": row.summary,
    }


def _cert_dict(row: CertificateResult | None) -> dict | None:
    if row is None:
        return None
    return {
        "checked_at": row.checked_at.isoformat(),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "days_remaining": row.days_remaining,
        "validation_status": row.validation_status,
        "fingerprint": row.fingerprint,
        "error_message": row.error_message,
    }


def normalize_channel_url(url: str) -> str:
    try:
        return normalize_url(url)
    except InputError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


def _validate_channel_url(url: str, settings) -> None:
    from app.monitoring.ssrf import DNSError, SSRFError, parse_and_resolve

    normalized = normalize_channel_url(url)
    try:
        parse_and_resolve(normalized, allow_private=settings.allow_private_targets, allowlist=settings.allowlist_entries())
    except SSRFError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    except DNSError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


def _channel_dict(settings, channel: NotificationChannel) -> dict:
    from app.notifications.webhook import channel_config

    config = channel_config(settings, channel)
    return {
        "id": channel.id,
        "name": channel.name,
        "type": channel.type,
        "url": redact_url(str(config.get("url") or "")),
        "has_secret": bool(config.get("secret")),
        "enabled": channel.enabled,
        "created_at": channel.created_at.isoformat(),
        "updated_at": channel.updated_at.isoformat(),
    }


def bootstrap_admin(session: Session, settings) -> None:
    seed_settings(session, settings)
    if settings.admin_password:
        ensure_admin(session, settings)
    session.commit()
