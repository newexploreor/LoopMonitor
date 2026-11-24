from __future__ import annotations

import json
import re
import threading
import time
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.crypto import decrypt_text, encrypt_text

_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
_dummy_hash: str | None = None
_dummy_lock = threading.Lock()

SENSITIVE_QUERY_KEYS = {
    "token",
    "key",
    "secret",
    "password",
    "api_key",
    "apikey",
    "access_token",
    "signature",
    "auth",
    "credential",
    "sig",
}
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def dummy_password_hash() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        with _dummy_lock:
            if _dummy_hash is None:
                _dummy_hash = hash_password("dummy-password-not-used")
    return _dummy_hash


def serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="loopmonitor-session")


def dump_session(secret: str, user_id: str, username: str) -> str:
    return serializer(secret).dumps({"uid": user_id, "username": username})


def load_session(secret: str, token: str, max_age: int) -> dict:
    return serializer(secret).loads(token, max_age=max_age)


def session_error(exc: Exception) -> bool:
    return isinstance(exc, (BadSignature, SignatureExpired))


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    if parts.port:
        netloc = f"{hostname}:{parts.port}"
    else:
        netloc = hostname
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            query.append(f"{key}=***")
        else:
            query.append(f"{key}={value}")
    return urlunsplit((parts.scheme, netloc, parts.path, "&".join(query), ""))


def sanitize_error_text(message: str) -> str:
    text = re.sub(r"https?://\S+", "[url]", message)
    text = re.sub(r"(?i)(bearer|token|api[_-]?key|password)\s+[A-Za-z0-9._~+/=-]{6,}", r"\1 ***", text)
    return text[:500]


def encrypt_json(key: bytes, value: object) -> str:
    return encrypt_text(key, json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def decrypt_json(key: bytes, encoded: str) -> object:
    return json.loads(decrypt_text(key, encoded))


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [stamp for stamp in self._events[key] if now - stamp < window_seconds]
            if len(recent) >= limit:
                self._events[key] = recent
                return False
            recent.append(now)
            self._events[key] = recent
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
