from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.config import Settings
from app.ids import new_id
from app.models import (
    CertificateResult,
    CheckJob,
    CheckResult,
    Incident,
    NotificationDelivery,
    SystemSetting,
    User,
)
from app.security import hash_password
from app.timeutil import utcnow

RETENTION_CHECK_KEY = "check_retention_days"
RETENTION_INCIDENT_KEY = "incident_retention_days"
HEARTBEAT_KEY = "worker_heartbeat"


def seed_settings(session: Session, settings: Settings) -> None:
    now = utcnow()
    defaults = {
        RETENTION_CHECK_KEY: str(settings.check_retention_days),
        RETENTION_INCIDENT_KEY: str(settings.incident_retention_days),
    }
    for key, value in defaults.items():
        if session.get(SystemSetting, key) is None:
            session.add(SystemSetting(key=key, value=value, updated_at=now))


def get_int_setting(session: Session, key: str, fallback: int) -> int:
    row = session.get(SystemSetting, key)
    if row is None:
        return fallback
    try:
        return int(row.value)
    except ValueError:
        return fallback


def set_int_setting(session: Session, key: str, value: int) -> None:
    now = utcnow()
    row = session.get(SystemSetting, key)
    if row is None:
        session.add(SystemSetting(key=key, value=str(value), updated_at=now))
    else:
        row.value = str(value)
        row.updated_at = now


def ensure_admin(session: Session, settings: Settings) -> str:
    existing = session.scalar(select(User).where(User.username == settings.admin_username))
    if existing is not None:
        return "exists"
    if not settings.admin_password:
        raise RuntimeError("没有管理员账号，请设置 ADMIN_USERNAME 和 ADMIN_PASSWORD 后执行初始化")
    validate_password(settings.admin_password, settings.admin_username)
    session.add(
        User(
            id=new_id(),
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            created_at=utcnow(),
        )
    )
    return "created"


def validate_password(password: str, username: str) -> None:
    if len(password) < 12 or len(password) > 128:
        raise RuntimeError("密码长度需要在 12 到 128 个字符之间")
    if password == username:
        raise RuntimeError("密码不能与用户名相同")


def record_heartbeat(session: Session, when=None) -> None:
    now = when or utcnow()
    row = session.get(SystemSetting, HEARTBEAT_KEY)
    if row is None:
        session.add(SystemSetting(key=HEARTBEAT_KEY, value=now.isoformat(), updated_at=now))
    else:
        row.value = now.isoformat()
        row.updated_at = now


def cleanup(session: Session, *, check_days: int, incident_days: int, now=None) -> dict[str, int]:
    current = now or utcnow()
    check_before = current - timedelta(days=check_days)
    incident_before = current - timedelta(days=incident_days)
    checks = session.execute(delete(CheckResult).where(CheckResult.started_at < check_before)).rowcount or 0
    certs = session.execute(delete(CertificateResult).where(CertificateResult.checked_at < check_before)).rowcount or 0
    jobs = session.execute(
        delete(CheckJob).where(CheckJob.finished_at.is_not(None), CheckJob.finished_at < check_before)
    ).rowcount or 0
    old_ids = list(
        session.scalars(
            select(Incident.id).where(Incident.status == "recovered", Incident.recovered_at.is_not(None), Incident.recovered_at < incident_before)
        )
    )
    deliveries = 0
    incidents = 0
    if old_ids:
        deliveries += session.execute(
            delete(NotificationDelivery).where(
                NotificationDelivery.incident_id.in_(old_ids),
                NotificationDelivery.status != "pending",
            )
        ).rowcount or 0
        incidents = session.execute(delete(Incident).where(Incident.id.in_(old_ids))).rowcount or 0
    deliveries += session.execute(
        delete(NotificationDelivery).where(
            NotificationDelivery.incident_id.is_(None),
            NotificationDelivery.created_at < incident_before,
            NotificationDelivery.status != "pending",
        )
    ).rowcount or 0
    return {"checks": checks, "certificates": certs, "jobs": jobs, "incidents": incidents, "deliveries": deliveries}


def sqlite_file(database_url: str) -> Path:
    url = make_url(database_url)
    if url.drivername != "sqlite" or not url.database:
        raise RuntimeError("当前仅支持备份 SQLite 数据库")
    return Path(url.database)


def backup_database(database_url: str, destination: str) -> None:
    source = sqlite_file(database_url)
    if not source.exists():
        raise RuntimeError("数据库文件不存在")
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(source)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def restore_database(database_url: str, source: str) -> None:
    src_path = Path(source)
    if not src_path.exists():
        raise RuntimeError("备份文件不存在")
    src = sqlite3.connect(src_path)
    try:
        integrity = src.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError("备份完整性检查失败")
        dest = sqlite_file(database_url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary = dest.with_suffix(dest.suffix + ".restore")
        dst = sqlite3.connect(temporary)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    os.replace(temporary, dest)
