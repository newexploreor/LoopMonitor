from __future__ import annotations

import contextvars
import ipaddress
import json
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.monitoring.ssrf import DNSError, SSRFError, Target, parse_and_resolve
from app.security import SENSITIVE_HEADER_NAMES, sanitize_error_text
from app.timeutil import utcnow

_PIN: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar("ssrf_pin", default=None)
_ORIGINAL_GETADDRINFO = socket.getaddrinfo
_PATCHED = False


def install_dns_pin() -> None:
    global _PATCHED
    if _PATCHED:
        return

    def patched(host, port, family=0, type=0, proto=0, flags=0):  # type: ignore[no-untyped-def]
        pin = _PIN.get()
        if pin and host == pin["hostname"]:
            ip = ipaddress.ip_address(pin["ip"])
            address_family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            sockaddr = (pin["ip"], port, 0, 0) if ip.version == 6 else (pin["ip"], port)
            socktype = type or socket.SOCK_STREAM
            protocol = proto or socket.IPPROTO_TCP
            return [(address_family, socktype, protocol, "", sockaddr)]
        return _ORIGINAL_GETADDRINFO(host, port, family, type, proto, flags)

    socket.getaddrinfo = patched
    _PATCHED = True


@dataclass
class ProbeResult:
    success: bool
    valid: bool
    http_status: int | None
    latency_ms: int | None
    error_type: str | None
    error_message: str | None
    started_at: datetime
    finished_at: datetime


def status_matches(code: int, expected: str) -> bool:
    for part in expected.split(","):
        piece = part.strip()
        if not piece:
            continue
        if "-" in piece:
            left, right = piece.split("-", 1)
            if int(left) <= code <= int(right):
                return True
        elif int(piece) == code:
            return True
    return False


def validate_expected_status(expected: str) -> str:
    text = expected.strip()
    if not text or len(text) > 64:
        raise ValueError("预期状态码格式无效")
    for part in text.split(","):
        piece = part.strip()
        if "-" in piece:
            left, right = piece.split("-", 1)
            start, end = int(left), int(right)
            if not (100 <= start <= end <= 599):
                raise ValueError("预期状态码范围无效")
        else:
            code = int(piece)
            if not 100 <= code <= 599:
                raise ValueError("预期状态码无效")
    return text


def _values_equal(actual: Any, expected: str) -> bool:
    if isinstance(actual, str) and actual == expected:
        return True
    try:
        parsed = json.loads(expected)
    except json.JSONDecodeError:
        parsed = expected
    return actual == parsed


def _lookup_path(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current


def judge_response(
    *,
    status_code: int,
    body: str,
    expected_status: str,
    assertions: list[dict],
    truncated: bool,
) -> tuple[bool, str | None, str | None]:
    if not status_matches(status_code, expected_status):
        return False, "status", f"状态码 {status_code} 不在期望范围 {expected_status}"
    for assertion in assertions:
        kind = assertion.get("type")
        if kind == "contains":
            if assertion.get("value", "") not in body:
                if truncated:
                    return False, "response_too_large", "响应超过大小限制，且未满足内容断言"
                return False, "assertion", "响应未包含指定内容"
        elif kind == "json_eq":
            path = assertion.get("path") or ""
            try:
                payload = json.loads(body) if body else None
                actual = _lookup_path(payload, path)
            except (json.JSONDecodeError, KeyError, TypeError):
                if truncated:
                    return False, "response_too_large", "响应超过大小限制，且 JSON 断言未完成"
                return False, "assertion", f"JSON 字段 {path} 不存在或响应不是 JSON"
            if not _values_equal(actual, str(assertion.get("value", ""))):
                return False, "assertion", f"JSON 字段 {path} 不匹配"
        else:
            return False, "assertion", "不支持的响应断言"
    return True, None, None


def _pinned_url(url: str, ip: str, port: int) -> str:
    parts = urlsplit(url)
    host = f"[{ip}]" if ":" in ip else ip
    return urlunsplit((parts.scheme, f"{host}:{port}", parts.path or "/", parts.query, ""))


def _host_header(hostname: str, port: int, scheme: str) -> str:
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return hostname
    return f"{hostname}:{port}"


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, (parts.hostname or "").lower(), port


def _strip_sensitive(headers: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() not in SENSITIVE_HEADER_NAMES}


def _classify_http_error(exc: Exception) -> tuple[str, str]:
    text = sanitize_error_text(str(exc))
    lowered = text.lower()
    if isinstance(exc, httpx.TimeoutException) or "timed out" in lowered:
        return "timeout", "请求超时"
    if any(word in lowered for word in ("certificate", "tls", "ssl", "handshake")):
        return "tls", "TLS 校验失败"
    if isinstance(exc, (httpx.ConnectError, httpx.NetworkError, httpx.RemoteProtocolError)):
        return "connect", "连接失败"
    return "connect", text or "请求失败"


def _finished(started: datetime, **kwargs: Any) -> ProbeResult:
    return ProbeResult(started_at=started, finished_at=utcnow(), **kwargs)


async def probe_http(
    *,
    url: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout_seconds: float,
    follow_redirects: bool,
    expected_status: str,
    assertions: list[dict],
    allow_private: bool,
    allowlist: list[str],
    max_response_bytes: int,
    max_redirects: int,
    resolver: Callable[[str], list[str]] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ProbeResult:
    install_dns_pin()
    started = utcnow()
    request_headers = {key: value for key, value in (headers or {}).items() if key.lower() != "host"}
    current = url
    current_headers = dict(request_headers)
    origin = _origin(url)
    redirects = 0
    hop_method = method.upper()
    hop_body = body if hop_method == "POST" else None
    timeout = httpx.Timeout(timeout_seconds)
    client_kwargs: dict[str, Any] = {
        "timeout": timeout,
        "follow_redirects": False,
        "trust_env": False,
        "verify": transport is None,
        "limits": httpx.Limits(max_connections=5, max_keepalive_connections=0),
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            while True:
                try:
                    target = parse_and_resolve(
                        current,
                        allow_private=allow_private,
                        allowlist=allowlist,
                        resolver=resolver,
                    )
                except SSRFError as exc:
                    return _finished(
                        started,
                        success=False,
                        valid=False,
                        http_status=None,
                        latency_ms=None,
                        error_type="ssrf",
                        error_message=exc.message,
                    )
                except DNSError as exc:
                    return _finished(
                        started,
                        success=False,
                        valid=True,
                        http_status=None,
                        latency_ms=None,
                        error_type="dns",
                        error_message=exc.message,
                    )
                pinned = target.ips[0]
                token = _PIN.set({"hostname": target.hostname, "ip": pinned})
                try:
                    hop_headers = dict(current_headers)
                    hop_headers["Host"] = _host_header(target.hostname, target.port, target.scheme)
                    request = client.build_request(
                        hop_method,
                        _pinned_url(current, pinned, target.port),
                        headers=hop_headers,
                        content=hop_body.encode("utf-8") if hop_body else None,
                    )
                    request.extensions["sni_hostname"] = target.hostname
                    response = await client.send(request, stream=True)
                    try:
                        status_code = response.status_code
                        location = response.headers.get("location")
                        if follow_redirects and status_code in {301, 302, 303, 307, 308} and location:
                            redirects += 1
                            if redirects > max_redirects:
                                return _finished(
                                    started,
                                    success=False,
                                    valid=True,
                                    http_status=status_code,
                                    latency_ms=_latency(started),
                                    error_type="redirect",
                                    error_message="重定向次数超过上限",
                                )
                            next_url = urljoin(current, location)
                            next_origin = _origin(next_url)
                            current_headers = current_headers if next_origin == origin else _strip_sensitive(current_headers)
                            if status_code in {301, 302, 303}:
                                hop_method = "GET"
                                hop_body = None
                            current = next_url
                            origin = next_origin
                            continue
                        raw, truncated = await _read_limited(response, max_response_bytes, hop_method)
                    finally:
                        await response.aclose()
                except Exception as exc:  # noqa: BLE001
                    error_type, message = _classify_http_error(exc)
                    return _finished(
                        started,
                        success=False,
                        valid=True,
                        http_status=None,
                        latency_ms=_latency(started) if error_type != "timeout" else None,
                        error_type=error_type,
                        error_message=message,
                    )
                finally:
                    _PIN.reset(token)
                text = raw.decode("utf-8", errors="replace")
                success, error_type, error_message = judge_response(
                    status_code=status_code,
                    body=text,
                    expected_status=expected_status,
                    assertions=assertions,
                    truncated=truncated,
                )
                return _finished(
                    started,
                    success=success,
                    valid=True,
                    http_status=status_code,
                    latency_ms=_latency(started),
                    error_type=error_type,
                    error_message=error_message,
                )
    except Exception as exc:  # noqa: BLE001
        return _finished(
            started,
            success=False,
            valid=False,
            http_status=None,
            latency_ms=None,
            error_type="internal",
            error_message=sanitize_error_text(str(exc)) or "检测器内部异常",
        )


async def _read_limited(response: httpx.Response, limit: int, method: str) -> tuple[bytes, bool]:
    if method.upper() == "HEAD":
        return b"", False
    chunks: list[bytes] = []
    size = 0
    truncated = False
    async for chunk in response.aiter_bytes():
        if size + len(chunk) > limit:
            chunks.append(chunk[: max(0, limit - size)])
            truncated = True
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), truncated


def _latency(started: datetime) -> int:
    return max(0, int((utcnow() - started).total_seconds() * 1000))
