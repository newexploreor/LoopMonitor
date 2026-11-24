from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

METADATA_IPS = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
}
METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.google.com",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}


class SSRFError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class DNSError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    hostname: str
    port: int
    ips: tuple[str, ...]


def _parse_numeric_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-fA-F]+", candidate):
        try:
            return ipaddress.ip_address(int(candidate, 16))
        except ValueError:
            return None
    if re.fullmatch(r"\d+", candidate):
        try:
            value = int(candidate, 10)
        except ValueError:
            return None
        if 0 <= value <= 0xFFFFFFFF:
            try:
                return ipaddress.ip_address(value)
            except ValueError:
                return None
    parts = candidate.split(".")
    if 1 < len(parts) <= 4 and all(re.fullmatch(r"\d+", part) for part in parts):
        numbers: list[int] = []
        for part in parts:
            base = 8 if len(part) > 1 and part.startswith("0") else 10
            try:
                numbers.append(int(part, base))
            except ValueError:
                return None
        if len(numbers) == 4 and all(0 <= number <= 255 for number in numbers):
            try:
                return ipaddress.ip_address(".".join(str(number) for number in numbers))
            except ValueError:
                return None
    return None


def canonical_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_metadata_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    text = str(ip)
    if text in METADATA_IPS:
        return True
    canonical = canonical_ip(ip)
    return str(canonical) in METADATA_IPS


def is_blocked_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = canonical_ip(value)
    if is_metadata_ip(ip):
        return True
    return not ip.is_global


def is_metadata_host(hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    return host in METADATA_HOSTS or host.endswith(".metadata.google.internal")


def _allow_entry_matches(entry: str, hostname: str, port: int, ips: list[str]) -> bool:
    if ":" not in entry:
        return False
    host_part, port_part = entry.rsplit(":", 1)
    if port_part != str(port):
        return False
    host_part = host_part.strip().lower().strip("[]")
    if host_part == hostname.lower():
        return True
    try:
        network = ipaddress.ip_network(host_part, strict=False)
    except ValueError:
        network = None
    if network is not None:
        return all(canonical_ip(ip) in network for ip in ips)
    literal = _parse_numeric_ip(host_part)
    if literal is not None:
        return all(canonical_ip(ip) == canonical_ip(literal) for ip in ips)
    return False


def assert_safe_target(hostname: str, port: int, ips: list[str], *, allow_private: bool, allowlist: list[str]) -> None:
    if is_metadata_host(hostname) or any(is_metadata_ip(canonical_ip(ip)) for ip in ips):
        raise SSRFError("云元数据地址始终禁止访问")
    blocked = [ip for ip in ips if is_blocked_ip(ip)]
    if blocked and len(blocked) != len(ips):
        raise SSRFError("DNS 结果同时包含公网和受限地址，已拒绝连接")
    if not blocked:
        return
    if not allow_private:
        raise SSRFError("默认禁止访问回环、私网、链路本地和非公网地址")
    if not any(_allow_entry_matches(entry, hostname, port, ips) for entry in allowlist):
        raise SSRFError("该内网目标不在管理员配置的域名、网段和端口白名单中")


def parse_and_resolve(
    url: str,
    *,
    allow_private: bool,
    allowlist: list[str],
    resolver=None,
) -> Target:
    if any(char in url for char in ("\r", "\n", "\t", " ")):
        raise SSRFError("URL 包含非法空白字符")
    parts = urlsplit(url)
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise SSRFError("禁止在 URL 中内嵌凭证")
    if parts.scheme not in {"http", "https"}:
        raise SSRFError("只允许 http 和 https")
    hostname = parts.hostname
    if not hostname:
        raise SSRFError("URL 缺少主机名")
    hostname = hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SSRFError("主机名无效") from exc
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port < 1 or port > 65535:
        raise SSRFError("端口无效")
    literal = _parse_numeric_ip(hostname)
    if literal is not None:
        ips = [str(canonical_ip(literal))]
    else:
        try:
            ips = list((resolver or resolve_all)(hostname))
        except DNSError:
            raise
        except Exception as exc:
            raise DNSError("DNS 解析失败") from exc
    if not ips:
        raise DNSError("DNS 没有返回地址")
    unique: list[str] = []
    for ip in ips:
        cleaned = ip.split("%", 1)[0]
        if cleaned not in unique:
            unique.append(cleaned)
    assert_safe_target(hostname, port, unique, allow_private=allow_private, allowlist=allowlist)
    return Target(url=url, scheme=parts.scheme, hostname=hostname, port=port, ips=tuple(unique))


def resolve_all(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DNSError("DNS 解析失败") from exc
    ips: list[str] = []
    for info in infos:
        ip = info[4][0].split("%", 1)[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise DNSError("DNS 没有返回地址")
    return ips
