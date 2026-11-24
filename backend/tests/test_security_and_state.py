from __future__ import annotations

import httpx
import pytest

from app.monitoring.checker import judge_response, probe_http
from app.monitoring.ssrf import SSRFError, is_blocked_ip, parse_and_resolve
from app.monitoring.state import decide, display_status
from app.security import redact_url
from app.timeutil import utcnow
from datetime import timedelta

from tests.conftest import login


def test_blocked_addresses():
    for value in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.8",
        "172.16.0.4",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "0.0.0.0",
        "::ffff:127.0.0.1",
    ]:
        assert is_blocked_ip(value) if ":" not in value or value.count(":") > 1 or value.startswith("::") else is_blocked_ip(value)
    assert is_blocked_ip("127.0.0.1")
    assert is_blocked_ip("10.1.2.3")
    assert is_blocked_ip("169.254.169.254")
    assert is_blocked_ip("::1")
    assert is_blocked_ip("fc00::1")
    assert is_blocked_ip("fe80::1")
    assert not is_blocked_ip("1.1.1.1")
    assert not is_blocked_ip("8.8.8.8")


def test_url_policy_rejects_credentials_metadata_and_decimal_loopback():
    with pytest.raises(SSRFError):
        parse_and_resolve("http://user:pass@example.com/", allow_private=False, allowlist=[])
    with pytest.raises(SSRFError):
        parse_and_resolve("file:///etc/passwd", allow_private=False, allowlist=[])
    with pytest.raises(SSRFError):
        parse_and_resolve("http://169.254.169.254/latest/meta-data", allow_private=True, allowlist=["169.254.169.254:80"])
    with pytest.raises(SSRFError):
        parse_and_resolve("http://2130706433/", allow_private=False, allowlist=[])
    with pytest.raises(SSRFError):
        parse_and_resolve("http://[::1]/", allow_private=False, allowlist=[])
    with pytest.raises(SSRFError):
        parse_and_resolve(
            "http://10.0.0.8/",
            allow_private=True,
            allowlist=["10.0.0.9:80"],
        )


def test_allowlist_permits_explicit_private_target():
    target = parse_and_resolve(
        "http://10.0.0.8/health",
        allow_private=True,
        allowlist=["10.0.0.8:80"],
    )
    assert target.ips == ("10.0.0.8",)


def test_mixed_dns_is_rejected():
    with pytest.raises(SSRFError):
        parse_and_resolve(
            "http://monitor.test.invalid/health",
            allow_private=True,
            allowlist=["10.0.0.1:80"],
            resolver=lambda _host: ["1.1.1.1", "10.0.0.1"],
        )


def test_redact_url_hides_query_secrets():
    assert redact_url("https://user:pw@example.com/health?token=abc&x=1") == "https://example.com/health?token=***&x=1"


def test_assertions_and_empty_stats_rules():
    ok, error, _message = judge_response(
        status_code=200,
        body='{"status":"ok"}',
        expected_status="200-299",
        assertions=[{"type": "contains", "value": "ok"}, {"type": "json_eq", "path": "status", "value": "ok"}],
        truncated=False,
    )
    assert ok and error is None
    failed, error, _message = judge_response(
        status_code=500,
        body="no",
        expected_status="200-299",
        assertions=[],
        truncated=False,
    )
    assert not failed and error == "status"


def test_state_machine_thresholds():
    base = dict(
        enabled=True,
        failure_threshold=3,
        recovery_threshold=1,
        has_open_incident=False,
        valid=True,
    )
    first = decide(status="unknown", consecutive_failures=0, consecutive_successes=0, success=False, **base)
    assert first.status == "unknown" and first.event is None and first.consecutive_failures == 1
    second = decide(status="unknown", consecutive_failures=2, consecutive_successes=0, success=False, **base)
    assert second.status == "down" and second.open_incident and second.event == "down"
    repeat = decide(
        status="down",
        consecutive_failures=3,
        consecutive_successes=0,
        success=False,
        has_open_incident=True,
        enabled=True,
        failure_threshold=3,
        recovery_threshold=1,
        valid=True,
    )
    assert repeat.event is None and not repeat.open_incident
    recovered = decide(
        status="down",
        consecutive_failures=3,
        consecutive_successes=0,
        success=True,
        has_open_incident=True,
        enabled=True,
        failure_threshold=3,
        recovery_threshold=1,
        valid=True,
    )
    assert recovered.status == "up" and recovered.event == "recovered"
    flake = decide(
        status="up",
        consecutive_failures=0,
        consecutive_successes=1,
        success=False,
        has_open_incident=False,
        enabled=True,
        failure_threshold=3,
        recovery_threshold=1,
        valid=True,
    )
    assert flake.status == "up" and flake.event is None
    ignored = decide(
        status="up",
        consecutive_failures=0,
        consecutive_successes=2,
        success=False,
        has_open_incident=False,
        enabled=True,
        failure_threshold=3,
        recovery_threshold=1,
        valid=False,
    )
    assert ignored.status == "up" and ignored.consecutive_successes == 2


def test_stale_display_does_not_invent_uptime():
    now = utcnow()
    status, stale = display_status(
        enabled=True,
        stored_status="down",
        last_valid_at=now - timedelta(hours=3),
        interval_seconds=60,
        timeout_seconds=10,
        now=now,
    )
    assert status == "unknown" and stale
    fresh, stale = display_status(
        enabled=True,
        stored_status="up",
        last_valid_at=now,
        interval_seconds=60,
        timeout_seconds=10,
        now=now,
    )
    assert fresh == "up" and not stale
    paused, _stale = display_status(
        enabled=False,
        stored_status="paused",
        last_valid_at=now,
        interval_seconds=60,
        timeout_seconds=10,
        now=now,
    )
    assert paused == "paused"


@pytest.mark.asyncio
async def test_redirect_strips_sensitive_headers_and_blocks_private_hop():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "https://other.example/next"})
        return httpx.Response(200, content=b"ok")

    result = await probe_http(
        url="https://origin.example/start",
        method="GET",
        headers={"Authorization": "Bearer secret"},
        body=None,
        timeout_seconds=2,
        follow_redirects=True,
        expected_status="200-299",
        assertions=[],
        allow_private=False,
        allowlist=[],
        max_response_bytes=1000,
        max_redirects=3,
        resolver=lambda _host: ["1.1.1.1"],
        transport=httpx.MockTransport(handler),
    )
    assert result.success
    assert seen == ["Bearer secret", None]

    blocked = await probe_http(
        url="https://origin.example/start",
        method="GET",
        headers={"Authorization": "Bearer secret"},
        body=None,
        timeout_seconds=2,
        follow_redirects=True,
        expected_status="200-299",
        assertions=[],
        allow_private=False,
        allowlist=[],
        max_response_bytes=1000,
        max_redirects=3,
        resolver=lambda host: ["10.0.0.4"] if host == "evil.example" else ["1.1.1.1"],
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"location": "http://evil.example/secret"})
        ),
    )
    assert blocked.error_type == "ssrf" and blocked.valid is False


@pytest.mark.asyncio
async def test_api_requires_login_and_hides_secrets(env):
    client = env["client"]
    denied = await client.get("/api/v1/monitors")
    assert denied.status_code == 401
    await login(client)
    created = await client.post(
        "/api/v1/monitors",
        json={
            "name": "Example",
            "url": "https://1.1.1.1/health?token=abc",
            "headers": [{"name": "Authorization", "value": "Bearer super-secret"}],
            "body": None,
            "failure_threshold": 3,
            "recovery_threshold": 1,
        },
    )
    assert created.status_code == 201, created.text
    body = created.text
    assert "super-secret" not in body
    assert "Bearer" not in body
    assert "token=abc" not in body
    assert created.json()["headers"] == [{"name": "Authorization", "masked": True}]
    private = await client.post("/api/v1/monitors", json={"name": "Local", "url": "http://127.0.0.1/"})
    assert private.status_code == 400
    meta = await client.post("/api/v1/monitors", json={"name": "Meta", "url": "http://169.254.169.254/latest"})
    assert meta.status_code == 400
