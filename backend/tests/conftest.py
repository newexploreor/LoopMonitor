from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

os.environ.setdefault("ENV", "test")
os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-should-be-long-enough-32")
os.environ.setdefault(
    "CREDENTIAL_ENCRYPTION_KEY",
    base64.b64encode(b"0123456789abcdef0123456789abcdef").decode(),
)
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "test-password-123")
os.environ.setdefault("DATABASE_URL", "sqlite:///" + str(Path(tempfile.mkdtemp(prefix="lm-boot-")) / "boot.db"))
os.environ.setdefault("ALLOW_PRIVATE_TARGETS", "false")

import httpx
import pytest

from app.config import Settings
from app.db import Base
from app.main import create_app
from app.services.maintenance import ensure_admin, seed_settings

SECRET = os.environ["APP_SECRET_KEY"]
KEY = os.environ["CREDENTIAL_ENCRYPTION_KEY"]


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = dict(
        env="test",
        database_url=f"sqlite:///{tmp_path / 'app.db'}",
        app_secret_key=SECRET,
        credential_encryption_key=KEY,
        cookie_secure=False,
        admin_username="admin",
        admin_password="test-password-123",
        allow_private_targets=False,
        private_target_allowlist="",
        login_limit=1000,
        login_window_seconds=60,
        max_concurrent_checks=4,
        worker_stale_seconds=45,
    )
    values.update(overrides)
    settings = Settings(**values)
    settings.check()
    return settings


@pytest.fixture
async def env(tmp_path):
    settings = make_settings(tmp_path)
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    with application.state.SessionLocal() as session:
        seed_settings(session, settings)
        ensure_admin(session, settings)
        session.commit()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield {"client": client, "app": application, "settings": settings}
    application.state.engine.dispose()


async def login(client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "test-password-123"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = token
    return token
