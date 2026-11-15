"""SSRF protection: URL validation, public-IP resolution and an IP-pinned httpx transport."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from app.lib.errors import PayloadTooLarge, Unprocessable, UpstreamError, UpstreamTimeout

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}

_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/96",
        "::1/128",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/12",
    )
]
_METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}
_LEGACY_IPV4 = re.compile(r"^[0-9a-fA-FxX.]+$")


class InvalidUrl(Unprocessable):
    code = "invalid_url"
    message = "The URL is not valid."


class BlockedDestination(Unprocessable):
    code = "blocked_destination"
    message = "This destination is not allowed."


class DnsResolutionFailed(UpstreamError):
    code = "dns_resolution_failed"
    message = "Could not resolve the host name."


class TooManyRedirects(UpstreamError):
    code = "too_many_redirects"
    message = "Too many redirects."


class FetchTooLarge(PayloadTooLarge):
    code = "fetch_too_large"
    message = "The remote document is too large."


class UpstreamTimedOut(UpstreamTimeout):
    code = "upstream_timeout"
    message = "The remote server timed out."


@dataclass(frozen=True, slots=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    literal_ip: IPAddress | None


def is_blocked_ip(ip: IPAddress) -> bool:
    """True if the address is not a globally routable unicast address."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in _METADATA:
        return True
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return True
    return any(ip in net for net in _BLOCKED_NETWORKS if net.version == ip.version)


def parse_ip_literal(host: str) -> IPAddress | None:
    """Parse IP literals including legacy IPv4 forms (decimal, octal, hex, short)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if _LEGACY_IPV4.match(host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def parse_url(url: str) -> Target:
    """Validate scheme, userinfo, port and host syntax (step 1 of the SSRF checks)."""
    if not url or len(url) > MAX_URL_LENGTH or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        raise InvalidUrl()
    if "\\" in url:
        raise InvalidUrl()
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise InvalidUrl() from None
    if parts.scheme.lower() not in ALLOWED_SCHEMES or not host:
        raise InvalidUrl()
    if "@" in parts.netloc:
        raise InvalidUrl("URLs with credentials are not allowed.")
    scheme = parts.scheme.lower()
    if port is None:
        port = 443 if scheme == "https" else 80
    if not (port in (80, 443) or 1024 <= port <= 65535):
        raise InvalidUrl("Port is not allowed.")
    host = host.rstrip(".").lower()
    if "%" in host or not host:
        raise InvalidUrl()
    literal = parse_ip_literal(host)
    if literal is None:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidUrl() from None
        if host == "localhost" or host.endswith(".localhost"):
            raise BlockedDestination()
    return Target(url=url, scheme=scheme, host=host, port=port, literal_ip=literal)


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve a host name to a list of IP strings (replaceable in tests)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise DnsResolutionFailed() from None
    seen: dict[str, None] = {}
    for info in infos:
        seen[str(info[4][0]).split("%", 1)[0]] = None
    return list(seen)


async def resolve_public(target: Target) -> list[str]:
    """Resolve the target and ensure *every* address is publicly routable (step 2)."""
    if target.literal_ip is not None:
        ips: list[str] = [str(target.literal_ip)]
    else:
        ips = await resolve_host(target.host, target.port)
    if not ips:
        raise DnsResolutionFailed()
    parsed: list[IPAddress] = []
    for raw in ips:
        try:
            parsed.append(ipaddress.ip_address(raw))
        except ValueError:
            raise BlockedDestination() from None
    if any(is_blocked_ip(ip) for ip in parsed):
        raise BlockedDestination()
    return [str(ip) for ip in parsed]


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Network backend that always connects to pre-validated IPs, ignoring the host name.

    The URL host name is still used by httpcore for the Host header, TLS SNI and
    certificate verification, so DNS rebinding between validation and connect is impossible.
    """

    def __init__(self, ips: Iterable[str]) -> None:
        self._ips = list(ips)
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        last: Exception | None = None
        for ip in self._ips:
            try:
                return await self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        assert last is not None
        raise last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109
        socket_options: Any = None,
    ) -> Any:
        raise httpcore.ConnectError("Unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool is pinned to validated IP addresses."""

    def __init__(self, ips: Iterable[str]) -> None:
        super().__init__(trust_env=False, retries=0)
        self.backend = PinnedBackend(ips)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            max_connections=1,
            network_backend=self.backend,
            retries=0,
        )
