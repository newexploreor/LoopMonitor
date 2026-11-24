from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Monitor(Base):
    __tablename__ = "monitors"
    __table_args__ = (Index("ix_monitors_due", "enabled", "next_run_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    group_name: Mapped[str | None] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False, default="GET")
    encrypted_headers: Mapped[str | None] = mapped_column(Text)
    encrypted_body: Mapped[str | None] = mapped_column(Text)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_status: Mapped[str] = mapped_column(String(64), nullable=False, default="200-299")
    assertions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    failure_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    recovery_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    follow_redirects: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    current_status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_cert_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MonitorRuntime(Base):
    __tablename__ = "monitor_runtime"

    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), primary_key=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_successes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_valid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success: Mapped[bool | None] = mapped_column(Boolean)
    last_error_type: Mapped[str | None] = mapped_column(String(32))
    last_http_status: Mapped[int | None] = mapped_column(Integer)
    last_latency_ms: Mapped[int | None] = mapped_column(Integer)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CheckResult(Base):
    __tablename__ = "check_results"
    __table_args__ = (Index("ix_check_results_monitor_started", "monitor_id", "started_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    http_status: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error_type: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(String(500))


class CheckJob(Base):
    __tablename__ = "check_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    check_result_id: Mapped[str | None] = mapped_column(String(36))
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index(
            "uq_incident_open_per_monitor",
            "monitor_id",
            unique=True,
            sqlite_where=text("status = 'open'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_type: Mapped[str | None] = mapped_column(String(32))
    http_status: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_config: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MonitorChannel(Base):
    __tablename__ = "monitor_channels"

    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), primary_key=True)
    channel_id: Mapped[str] = mapped_column(ForeignKey("notification_channels.id"), primary_key=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_deliveries_retry", "status", "next_retry_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"))
    channel_id: Mapped[str] = mapped_column(ForeignKey("notification_channels.id"), nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CertificateResult(Base):
    __tablename__ = "certificate_results"
    __table_args__ = (Index("ix_certificate_results_monitor_checked", "monitor_id", "checked_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    days_remaining: Mapped[int | None] = mapped_column(Integer)
    validation_status: Mapped[str] = mapped_column(String(16), nullable=False)
    fingerprint: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(String(500))


class CertificateReminder(Base):
    __tablename__ = "certificate_reminders"
    __table_args__ = (
        UniqueConstraint("monitor_id", "fingerprint", "threshold_days", name="uq_cert_reminder"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    monitor_id: Mapped[str] = mapped_column(ForeignKey("monitors.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    threshold_days: Mapped[int] = mapped_column(Integer, nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
