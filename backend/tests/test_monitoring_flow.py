from __future__ import annotations

import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select

from app.models import CheckResult, Incident, Monitor
from app.monitoring.checker import probe_http
from app.monitoring.scheduler import dispatch_jobs, dispatch_notifications
from app.services.certificates import CertInfo, record_certificate
from app.services.checks import perform_check
from app.services.maintenance import backup_database, cleanup, restore_database
from app.timeutil import utcnow
from tests.conftest import login, make_settings
from app.db import Base
from app.main import create_app
from app.services.maintenance import ensure_admin, seed_settings


class ProbeState:
    mode = "ok"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if ProbeState.mode == "fail":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"no")
            return
        if self.path.startswith("/redirect"):
            self.send_response(302)
            host, port = self.server.server_address[:2]
            self.send_header("Location", f"http://127.0.0.1:{port + 1}/secret")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


@pytest.fixture
def probe_server():
    ProbeState.mode = "ok"
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def _client_for(tmp_path, port):
    settings = make_settings(
        tmp_path,
        allow_private_targets=True,
        private_target_allowlist=f"127.0.0.1:{port}",
    )
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    with application.state.SessionLocal() as session:
        seed_settings(session, settings)
        ensure_admin(session, settings)
        session.commit()
    return application, settings


@pytest.mark.asyncio
async def test_pin_connects_to_validated_address(probe_server):
    port = probe_server.server_address[1]
    result = await probe_http(
        url=f"http://monitor.test.invalid:{port}/health",
        method="GET",
        headers=None,
        body=None,
        timeout_seconds=2,
        follow_redirects=False,
        expected_status="200-299",
        assertions=[{"type": "json_eq", "path": "status", "value": "ok"}],
        allow_private=True,
        allowlist=[f"127.0.0.1:{port}"],
        max_response_bytes=10000,
        max_redirects=2,
        resolver=lambda _host: ["127.0.0.1"],
    )
    assert result.success, result.error_message


@pytest.mark.asyncio
async def test_failure_threshold_recovery_and_statistics(tmp_path, probe_server):
    port = probe_server.server_address[1]
    application, settings = await _client_for(tmp_path, port)
    factory = application.state.SessionLocal
    with factory() as session:
        from app.services.catalog import create_monitor

        monitor = create_monitor(
            session,
            settings,
            {
                "name": "Probe",
                "group_name": "Lab",
                "url": f"http://127.0.0.1:{port}/health",
                "method": "GET",
                "failure_threshold": 3,
                "recovery_threshold": 1,
                "interval_seconds": 30,
                "timeout_seconds": 2,
                "enabled": True,
            },
        )
        monitor_id = monitor.id
    ProbeState.mode = "fail"
    for _ in range(3):
        await perform_check(settings, factory, monitor_id, "auto")
    with factory() as session:
        monitor = session.get(Monitor, monitor_id)
        incidents = list(session.scalars(select(Incident).where(Incident.monitor_id == monitor_id)))
        assert monitor.current_status == "down"
        assert len(incidents) == 1 and incidents[0].status == "open"
    await perform_check(settings, factory, monitor_id, "auto")
    with factory() as session:
        assert session.scalar(select(Incident).where(Incident.monitor_id == monitor_id, Incident.status == "open"))
        assert len(list(session.scalars(select(Incident).where(Incident.monitor_id == monitor_id)))) == 1
    ProbeState.mode = "ok"
    await perform_check(settings, factory, monitor_id, "auto")
    with factory() as session:
        monitor = session.get(Monitor, monitor_id)
        incident = session.scalar(select(Incident).where(Incident.monitor_id == monitor_id))
        assert monitor.current_status == "up"
        assert incident.status == "recovered"
        rows = list(session.scalars(select(CheckResult).where(CheckResult.monitor_id == monitor_id, CheckResult.trigger_type == "auto", CheckResult.valid.is_(True))))
        assert len(rows) == 5
        assert sum(1 for row in rows if row.success) == 1
    await perform_check(settings, factory, monitor_id, "auto")
    ProbeState.mode = "fail"
    await perform_check(settings, factory, monitor_id, "auto")
    with factory() as session:
        monitor = session.get(Monitor, monitor_id)
        open_count = list(session.scalars(select(Incident).where(Incident.monitor_id == monitor_id, Incident.status == "open")))
        assert monitor.current_status == "up"
        assert open_count == []

    import httpx

    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await login(client)
        stats = await client.get(f"/api/v1/monitors/{monitor_id}/statistics?window=24h")
        assert stats.status_code == 200, stats.text
        payload = stats.json()
        assert payload["total"] == 7
        assert payload["success"] == 2
        assert payload["availability"] == round(2 * 100 / 7, 2)
        empty = await client.post(
            "/api/v1/monitors",
            json={"name": "Quiet", "url": "https://1.1.1.1/none", "interval_seconds": 60, "timeout_seconds": 5},
        )
        assert empty.status_code == 201, empty.text
        quiet = await client.get(f"/api/v1/monitors/{empty.json()['id']}/statistics")
        assert quiet.json()["availability"] is None
        dashboard = await client.get("/api/v1/dashboard")
        assert dashboard.status_code == 200
        assert dashboard.json()["availability"] == payload["availability"]
        manual = await client.post(f"/api/v1/monitors/{monitor_id}/check")
        assert manual.status_code == 202
    ProbeState.mode = "ok"
    await dispatch_jobs(settings, factory, __import__("asyncio").Semaphore(2))
    with factory() as session:
        manual_rows = list(session.scalars(select(CheckResult).where(CheckResult.monitor_id == monitor_id, CheckResult.trigger_type == "manual")))
        assert len(manual_rows) == 1
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await login(client)
        stats = await client.get(f"/api/v1/monitors/{monitor_id}/statistics?window=24h")
        assert stats.json()["manual_total"] == 1
        assert stats.json()["total"] == 7
    application.state.engine.dispose()


@pytest.mark.asyncio
async def test_redirect_to_unlist_private_is_not_a_target_failure(probe_server):
    port = probe_server.server_address[1]
    result = await probe_http(
        url=f"http://127.0.0.1:{port}/redirect",
        method="GET",
        headers={"Authorization": "Bearer secret"},
        body=None,
        timeout_seconds=2,
        follow_redirects=True,
        expected_status="200-299",
        assertions=[],
        allow_private=True,
        allowlist=[f"127.0.0.1:{port}"],
        max_response_bytes=1000,
        max_redirects=2,
    )
    assert result.valid is False and result.error_type == "ssrf"


@pytest.mark.asyncio
async def test_webhook_retry_and_certificate_reminder(tmp_path):
    received = []

    class Webhook(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            received.append(
                {
                    "body": body,
                    "signature": self.headers.get("X-LoopMonitor-Signature"),
                    "timestamp": self.headers.get("X-LoopMonitor-Timestamp"),
                }
            )
            if len(received) == 1:
                self.send_response(500)
            else:
                self.send_response(204)
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Webhook)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        settings = make_settings(
            tmp_path,
            allow_private_targets=True,
            private_target_allowlist=f"127.0.0.1:{port}",
        )
        application = create_app(settings)
        Base.metadata.create_all(application.state.engine)
        factory = application.state.SessionLocal
        with factory() as session:
            seed_settings(session, settings)
            ensure_admin(session, settings)
            session.commit()
            from app.ids import new_id
            from app.models import MonitorChannel, NotificationChannel
            from app.security import encrypt_json
            from app.services.catalog import create_monitor

            channel = NotificationChannel(
                id=new_id(),
                name="Hook",
                type="webhook",
                encrypted_config=encrypt_json(
                    settings.encryption_key_bytes(),
                    {"url": f"http://127.0.0.1:{port}/hook", "secret": "signing-secret"},
                ),
                enabled=True,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            session.add(channel)
            session.commit()
            monitor = create_monitor(
                session,
                settings,
                {
                    "name": "Notify",
                    "url": "https://1.1.1.1/health",
                    "failure_threshold": 1,
                    "recovery_threshold": 1,
                    "interval_seconds": 30,
                    "timeout_seconds": 2,
                    "channel_ids": [channel.id],
                },
            )
            session.add(MonitorChannel(monitor_id=monitor.id, channel_id=channel.id)) if False else None
            from app.monitoring.checker import ProbeResult

            from app.services.checks import persist_probe

            persist_probe(
                session,
                settings,
                monitor.id,
                ProbeResult(False, True, 500, 12, "status", "状态码 500 不在期望范围 200-299", utcnow(), utcnow()),
                "auto",
            )
        from app.models import NotificationDelivery

        with factory() as session:
            delivery = session.scalar(select(NotificationDelivery))
            assert delivery is not None and delivery.status == "pending"
            delivery.next_retry_at = utcnow() - timedelta(seconds=1)
            session.commit()
        await dispatch_notifications(settings, factory)
        with factory() as session:
            delivery = session.scalar(select(NotificationDelivery))
            assert delivery.status == "pending" and delivery.attempts == 1
            delivery.next_retry_at = utcnow() - timedelta(seconds=1)
            session.commit()
        await dispatch_notifications(settings, factory)
        with factory() as session:
            delivery = session.scalar(select(NotificationDelivery))
            assert delivery.status == "delivered"
            assert delivery.payload["event_type"] == "down"
            assert "1.1.1.1" in delivery.payload["url"]
        assert received[1]["signature"].startswith("sha256=")
        with factory() as session:
            monitor = session.get(Monitor, monitor.id)
            record_certificate(
                session,
                settings,
                monitor,
                fetcher=lambda *_args: CertInfo(
                    "expiring",
                    utcnow() + timedelta(days=6),
                    6,
                    "abc123",
                    None,
                ),
            )
            record_certificate(
                session,
                settings,
                monitor,
                fetcher=lambda *_args: CertInfo(
                    "expiring",
                    utcnow() + timedelta(days=6),
                    6,
                    "abc123",
                    None,
                ),
            )
            session.commit()
            from app.models import CertificateReminder, NotificationDelivery as Delivery

            reminders = list(session.scalars(select(CertificateReminder)))
            assert {item.threshold_days for item in reminders} == {30, 7}
            cert_events = list(session.scalars(select(Delivery).where(Delivery.event_type == "certificate_expiring")))
            assert len(cert_events) == 2
        application.state.engine.dispose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_backup_restore_and_retention(tmp_path):
    settings = make_settings(tmp_path)
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    factory = application.state.SessionLocal
    from app.ids import new_id
    from app.models import CheckResult, Incident, Monitor, MonitorRuntime

    now = utcnow()
    with factory() as session:
        monitor = Monitor(
            id=new_id(),
            name="Keep",
            group_name=None,
            url="https://example.com",
            method="GET",
            encrypted_headers=None,
            encrypted_body=None,
            interval_seconds=60,
            timeout_seconds=5,
            expected_status="200-299",
            assertions=[],
            failure_threshold=3,
            recovery_threshold=1,
            follow_redirects=False,
            enabled=True,
            current_status="up",
            next_run_at=now,
            next_cert_check_at=None,
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
                consecutive_successes=1,
                last_checked_at=now,
                last_valid_at=now,
                last_success=True,
                last_error_type=None,
                last_http_status=200,
                last_latency_ms=10,
                lease_until=None,
            )
        )
        session.add(
            CheckResult(
                id=new_id(),
                monitor_id=monitor.id,
                trigger_type="auto",
                started_at=now - timedelta(days=40),
                finished_at=now - timedelta(days=40),
                success=True,
                valid=True,
                http_status=200,
                latency_ms=10,
                error_type=None,
                error_message=None,
            )
        )
        session.add(
            CheckResult(
                id=new_id(),
                monitor_id=monitor.id,
                trigger_type="auto",
                started_at=now,
                finished_at=now,
                success=True,
                valid=True,
                http_status=200,
                latency_ms=11,
                error_type=None,
                error_message=None,
            )
        )
        session.add(
            Incident(
                id=new_id(),
                monitor_id=monitor.id,
                status="open",
                started_at=now - timedelta(days=120),
                recovered_at=None,
                error_type="status",
                http_status=500,
                summary="仍未恢复",
            )
        )
        session.flush()
        removed = cleanup(session, check_days=30, incident_days=90, now=now)
        session.commit()
        assert removed["checks"] == 1
        assert session.scalar(select(CheckResult).where(CheckResult.latency_ms == 11)) is not None
        assert session.scalar(select(Incident).where(Incident.status == "open")) is not None
    destination = tmp_path / "backup.db"
    backup_database(settings.database_url, str(destination))
    restored = tmp_path / "restored.db"
    restore_database(f"sqlite:///{restored}", str(destination))
    assert restored.exists() and restored.stat().st_size > 0
    application.state.engine.dispose()
