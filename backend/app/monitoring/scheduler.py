from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.db import make_engine, make_session_factory
from app.models import CheckJob, Monitor, NotificationChannel, NotificationDelivery
from app.notifications.webhook import channel_config, mark_delivered, post_webhook
from app.notifications.webhook import _mark_attempt
from app.services.certificates import record_certificate, urlsplit_https
from app.services.checks import claim_job, finish_job, perform_check
from app.services.maintenance import cleanup, get_int_setting, record_heartbeat, seed_settings
from app.timeutil import utcnow

logger = logging.getLogger(__name__)


def _heartbeat_file(settings: Settings) -> Path | None:
    url = make_url(settings.database_url)
    if url.drivername != "sqlite" or not url.database:
        return None
    return Path(url.database).parent / "worker-heartbeat"


def write_heartbeat(session: Session, settings: Settings) -> None:
    now = utcnow()
    record_heartbeat(session, now)
    session.commit()
    path = _heartbeat_file(settings)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(now.isoformat(), encoding="utf-8")


def due_monitor_ids(session: Session, limit: int) -> list[str]:
    now = utcnow()
    return list(
        session.scalars(
            select(Monitor.id)
            .where(
                Monitor.enabled.is_(True),
                Monitor.deleted_at.is_(None),
                Monitor.next_run_at.is_not(None),
                Monitor.next_run_at <= now,
            )
            .order_by(Monitor.next_run_at)
            .limit(limit)
        )
    )


def pending_job_ids(session: Session, limit: int) -> list[str]:
    return list(
        session.scalars(
            select(CheckJob.id)
            .where(CheckJob.status == "pending")
            .order_by(CheckJob.created_at)
            .limit(limit)
        )
    )


def due_delivery_ids(session: Session, limit: int) -> list[str]:
    now = utcnow()
    return list(
        session.scalars(
            select(NotificationDelivery.id)
            .where(
                NotificationDelivery.status == "pending",
                NotificationDelivery.next_retry_at.is_not(None),
                NotificationDelivery.next_retry_at <= now,
            )
            .order_by(NotificationDelivery.next_retry_at)
            .limit(limit)
        )
    )


def due_cert_ids(session: Session, limit: int) -> list[str]:
    now = utcnow()
    return list(
        session.scalars(
            select(Monitor.id)
            .where(
                Monitor.enabled.is_(True),
                Monitor.deleted_at.is_(None),
                Monitor.next_cert_check_at.is_not(None),
                Monitor.next_cert_check_at <= now,
            )
            .order_by(Monitor.next_cert_check_at)
            .limit(limit)
        )
    )


async def dispatch_due(settings: Settings, session_factory: sessionmaker, semaphore: asyncio.Semaphore) -> None:
    with session_factory() as session:
        ids = due_monitor_ids(session, max(settings.max_concurrent_checks * 2, 1))

    async def run(monitor_id: str) -> None:
        async with semaphore:
            try:
                await perform_check(settings, session_factory, monitor_id, "auto")
            except Exception:
                logger.exception("scheduled check failed monitor=%s", monitor_id)

    if ids:
        await asyncio.gather(*(run(monitor_id) for monitor_id in ids))


async def dispatch_jobs(settings: Settings, session_factory: sessionmaker, semaphore: asyncio.Semaphore) -> None:
    with session_factory() as session:
        ids = pending_job_ids(session, settings.max_concurrent_checks)

    async def run(job_id: str) -> None:
        async with semaphore:
            with session_factory() as session:
                if not claim_job(session, job_id):
                    return
                job = session.get(CheckJob, job_id)
                monitor_id = job.monitor_id if job else None
            if monitor_id is None:
                return
            try:
                result_id = await perform_check(settings, session_factory, monitor_id, "manual")
            except Exception as exc:  # noqa: BLE001
                with session_factory() as session:
                    finish_job(session, job_id, None, str(exc)[:500], retry=False)
                return
            with session_factory() as session:
                if result_id is None:
                    finish_job(session, job_id, None, "检测任务正在执行，稍后重试", retry=True)
                elif result_id == "skipped":
                    finish_job(session, job_id, None, "监控已暂停或不存在", retry=False)
                elif result_id == "error":
                    finish_job(session, job_id, None, "检测器内部异常", retry=False)
                else:
                    finish_job(session, job_id, result_id, None, retry=False)

    if ids:
        await asyncio.gather(*(run(job_id) for job_id in ids))


async def dispatch_notifications(settings: Settings, session_factory: sessionmaker) -> None:
    with session_factory() as session:
        ids = due_delivery_ids(session, 20)
    for delivery_id in ids:
        await _send_delivery(settings, session_factory, delivery_id)


async def _send_delivery(settings: Settings, session_factory: sessionmaker, delivery_id: str) -> None:
    with session_factory() as session:
        delivery = session.get(NotificationDelivery, delivery_id)
        if delivery is None or delivery.status != "pending":
            return
        channel = session.get(NotificationChannel, delivery.channel_id)
        if channel is None or not channel.enabled:
            _mark_attempt(delivery, "告警渠道不可用")
            session.commit()
            return
        try:
            config = channel_config(settings, channel)
        except Exception as exc:  # noqa: BLE001
            _mark_attempt(delivery, str(exc)[:500])
            session.commit()
            return
        url = str(config.get("url") or "")
        secret = str(config.get("secret") or "")
        payload = dict(delivery.payload)
    try:
        await post_webhook(settings, url, secret, payload)
        error = None
    except Exception as exc:  # noqa: BLE001
        error = str(exc)[:500]
    with session_factory() as session:
        delivery = session.get(NotificationDelivery, delivery_id)
        if delivery is None or delivery.status != "pending":
            return
        if error is None:
            mark_delivered(delivery)
        else:
            _mark_attempt(delivery, error)
        session.commit()


async def dispatch_certificates(settings: Settings, session_factory: sessionmaker) -> None:
    with session_factory() as session:
        ids = due_cert_ids(session, 5)
    for monitor_id in ids:
        with session_factory() as session:
            monitor = session.get(Monitor, monitor_id)
            if monitor is None or monitor.deleted_at is not None or not urlsplit_https(monitor.url):
                if monitor is not None:
                    monitor.next_cert_check_at = None
                    session.commit()
                continue
            try:
                record_certificate(session, settings, monitor)
                session.commit()
            except Exception:
                logger.exception("certificate check failed monitor=%s", monitor_id)
                monitor.next_cert_check_at = utcnow() + timedelta(seconds=settings.cert_check_interval_seconds)
                session.commit()


async def dispatch_retention(settings: Settings, session_factory: sessionmaker) -> None:
    with session_factory() as session:
        seed_settings(session, settings)
        removed = cleanup(
            session,
            check_days=get_int_setting(session, "check_retention_days", settings.check_retention_days),
            incident_days=get_int_setting(session, "incident_retention_days", settings.incident_retention_days),
        )
        session.commit()
        logger.info("retention %s", removed)


async def serve(settings: Settings) -> None:
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)
    with session_factory() as session:
        seed_settings(session, settings)
        write_heartbeat(session, settings)
    semaphore = asyncio.Semaphore(settings.max_concurrent_checks)
    scheduler = AsyncIOScheduler(timezone="UTC")

    async def heartbeat_job() -> None:
        try:
            with session_factory() as session:
                write_heartbeat(session, settings)
        except Exception:
            logger.exception("heartbeat failed")

    async def due_job() -> None:
        try:
            await dispatch_due(settings, session_factory, semaphore)
        except Exception:
            logger.exception("check dispatch failed")

    async def manual_job() -> None:
        try:
            await dispatch_jobs(settings, session_factory, semaphore)
        except Exception:
            logger.exception("manual check dispatch failed")

    async def notify_job() -> None:
        try:
            await dispatch_notifications(settings, session_factory)
        except Exception:
            logger.exception("notification dispatch failed")

    async def cert_job() -> None:
        try:
            await dispatch_certificates(settings, session_factory)
        except Exception:
            logger.exception("certificate dispatch failed")

    async def retention_job() -> None:
        try:
            await dispatch_retention(settings, session_factory)
        except Exception:
            logger.exception("retention failed")

    scheduler.add_job(heartbeat_job, "interval", seconds=10, max_instances=1, coalesce=True)
    scheduler.add_job(due_job, "interval", seconds=2, max_instances=1, coalesce=True)
    scheduler.add_job(manual_job, "interval", seconds=2, max_instances=1, coalesce=True)
    scheduler.add_job(notify_job, "interval", seconds=5, max_instances=1, coalesce=True)
    scheduler.add_job(cert_job, "interval", seconds=30, max_instances=1, coalesce=True)
    scheduler.add_job(retention_job, "interval", hours=1, max_instances=1, coalesce=True)
    scheduler.start()
    logger.info("worker started")
    try:
        await asyncio.Event().wait()
    finally:
        scheduler.shutdown(wait=False)
        engine.dispose()
