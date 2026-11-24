from __future__ import annotations

import base64
import binascii
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    env: str = "development"
    database_url: str = "sqlite:///./loopmonitor.db"
    app_secret_key: str = ""
    credential_encryption_key: str = ""
    max_concurrent_checks: int = 10
    default_check_interval_seconds: int = 60
    default_timeout_seconds: int = 10
    check_retention_days: int = 30
    incident_retention_days: int = 90
    allow_private_targets: bool = False
    private_target_allowlist: str = ""
    cookie_secure: bool | None = None
    admin_username: str = "admin"
    admin_password: str = ""
    monitor_domain: str = "monitor.example.com"
    max_response_bytes: int = 262144
    max_request_body_bytes: int = 65536
    max_redirects: int = 5
    worker_stale_seconds: int = 45
    session_seconds: int = 43200
    login_limit: int = 10
    login_window_seconds: int = 600
    cert_check_interval_seconds: int = 86400
    cert_remind_days: str = "30,7,1"
    tz: str = "UTC"

    def cookie_is_secure(self) -> bool:
        if self.cookie_secure is None:
            return self.env == "production"
        return self.cookie_secure

    def encryption_key_bytes(self) -> bytes:
        return decode_encryption_key(self.credential_encryption_key)

    def remind_thresholds(self) -> list[int]:
        values: list[int] = []
        for part in self.cert_remind_days.split(","):
            part = part.strip()
            if not part:
                continue
            days = int(part)
            if days > 0:
                values.append(days)
        return sorted(set(values), reverse=True)

    def allowlist_entries(self) -> list[str]:
        return [item.strip() for item in self.private_target_allowlist.split(",") if item.strip()]

    def check(self) -> None:
        if self.env == "test" and not self.app_secret_key:
            object.__setattr__(self, "app_secret_key", "test-secret-key-should-be-long-enough")
        if self.env == "test" and not self.credential_encryption_key:
            object.__setattr__(
                self,
                "credential_encryption_key",
                base64.b64encode(b"0123456789abcdef0123456789abcdef").decode(),
            )
        if len(self.app_secret_key) < 32:
            raise RuntimeError("APP_SECRET_KEY 至少需要 32 个字符，生产环境禁止空密钥启动")
        self.encryption_key_bytes()
        if self.max_concurrent_checks < 1:
            raise RuntimeError("MAX_CONCURRENT_CHECKS 必须大于 0")
        if self.env == "production" and self.allow_private_targets and not self.allowlist_entries():
            raise RuntimeError("放开私网目标时必须配置明确的 PRIVATE_TARGET_ALLOWLIST，不能只打开布尔开关")


def decode_encryption_key(value: str) -> bytes:
    if not value:
        raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY 未配置，生产环境禁止空密钥启动")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY 必须是 32 字节的 base64") from exc
    if len(raw) != 32:
        raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY 解码后必须是 32 字节")
    return raw


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.check()
    return settings


def reset_settings_cache() -> None:
    get_settings.cache_clear()
