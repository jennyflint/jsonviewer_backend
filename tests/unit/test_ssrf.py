from __future__ import annotations

import ipaddress

import httpcore
import pytest

from app.domain.fetch import ssrf
from app.domain.fetch.ssrf import (
    BlockedDestination,
    DnsResolutionFailed,
    InvalidUrl,
    PinnedBackend,
    PinnedTransport,
    is_blocked_ip,
    parse_ip_literal,
    parse_url,
    resolve_public,
)


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "127.0.0.1",
        "127.1.2.3",
        "0.0.0.0",
        "169.254.169.254",
        "169.254.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
        "fd12:3456::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:192.168.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::1",
        "2001:db8::1",
        "::127.0.0.1",
    ],
)
def test_blocked_ips(ip: str) -> None:
    assert is_blocked_ip(ipaddress.ip_address(ip)) is True


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "172.32.0.1",
        "11.0.0.1",
        "2606:4700:4700::1111",
        "2a00:1450:4001::200e",
    ],
)
def test_allowed_ips(ip: str) -> None:
    assert is_blocked_ip(ipaddress.ip_address(ip)) is False


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("2130706433", "127.0.0.1"),  # decimal
        ("0177.0.0.1", "127.0.0.1"),  # octal
        ("0x7f.0.0.1", "127.0.0.1"),  # hex
        ("127.1", "127.0.0.1"),  # short form
        ("::1", "::1"),
        ("example.com", None),
        ("deadbeef", None),
    ],
)
def test_parse_ip_literal(host: str, expected: str | None) -> None:
    result = parse_ip_literal(host)
    assert (str(result) if result else None) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com",
        "javascript:alert(1)",
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "https://example.com:22/",
        "http://example.com:25/",
        "http://example.com:70000/",
        "http://example.com:0/",
        "example.com",
        "http:///path",
        "http://exa mple.com/",
        "http://example.com/\nfoo",
        "http://example.com\\@evil.com/",
        "http://[::1/",
        "http://" + "a" * 3000,
    ],
)
def test_invalid_urls(url: str) -> None:
    with pytest.raises(InvalidUrl):
        parse_url(url)


@pytest.mark.parametrize(
    "url",
    ["http://localhost/", "http://LOCALHOST:8080/", "http://foo.localhost/", "http://localhost./"],
)
def test_localhost_blocked(url: str) -> None:
    with pytest.raises(BlockedDestination):
        parse_url(url)


@pytest.mark.parametrize(
    ("url", "host", "port"),
    [
        ("http://example.com/x", "example.com", 80),
        ("https://Example.COM/x", "example.com", 443),
        ("https://example.com:8443/x", "example.com", 8443),
        ("http://example.com:1024/", "example.com", 1024),
        ("https://bücher.example/", "xn--bcher-kva.example", 443),
        ("http://example.com./", "example.com", 80),
    ],
)
def test_valid_urls(url: str, host: str, port: int) -> None:
    target = parse_url(url)
    assert (target.host, target.port) == (host, port)


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://10.0.0.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fd00:ec2::254]/",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
    ],
)
async def test_literal_private_destinations_blocked(url: str) -> None:
    target = parse_url(url)
    with pytest.raises(BlockedDestination):
        await resolve_public(target)


async def test_literal_public_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    assert await resolve_public(parse_url("http://8.8.8.8/")) == ["8.8.8.8"]


async def test_dns_any_private_address_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "10.0.0.1"]  # mixed answer: must be rejected

    monkeypatch.setattr(ssrf, "resolve_host", fake)
    with pytest.raises(BlockedDestination):
        await resolve_public(parse_url("http://rebind.example/"))


async def test_dns_public_ok_and_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    monkeypatch.setattr(ssrf, "resolve_host", ok)
    assert len(await resolve_public(parse_url("https://example.com/"))) == 2

    async def empty(host: str, port: int) -> list[str]:
        return []

    monkeypatch.setattr(ssrf, "resolve_host", empty)
    with pytest.raises(DnsResolutionFailed):
        await resolve_public(parse_url("https://example.com/"))


async def test_real_resolver_failure() -> None:
    with pytest.raises(DnsResolutionFailed):
        await ssrf.resolve_host("nonexistent.invalid", 80)


async def test_real_resolver_localhost() -> None:
    ips = await ssrf.resolve_host("localhost", 80)
    assert ips and all(is_blocked_ip(ipaddress.ip_address(i)) for i in ips)


async def test_pinned_backend_connects_to_ip_not_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS rebinding protection: whatever host httpcore asks for, the validated IP is dialed."""
    calls: list[tuple[str, int]] = []

    class FakeInner:
        async def connect_tcp(self, host: str, port: int, **kw: object) -> str:
            calls.append((host, port))
            if host == "203.0.113.1":
                raise httpcore.ConnectError("down")
            return "stream"

        async def sleep(self, seconds: float) -> None:
            return None

    backend = PinnedBackend(["203.0.113.1", "198.51.100.7"])
    backend._inner = FakeInner()  # type: ignore[assignment]
    stream = await backend.connect_tcp("evil.example", 443)
    assert stream == "stream"
    assert calls == [("203.0.113.1", 443), ("198.51.100.7", 443)]
    assert all(h != "evil.example" for h, _ in calls)
    await backend.sleep(0)
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_unix_socket("/var/run/docker.sock")


async def test_pinned_backend_all_fail() -> None:
    class Failing:
        async def connect_tcp(self, host: str, port: int, **kw: object) -> None:
            raise httpcore.ConnectError("nope")

    backend = PinnedBackend(["198.51.100.7"])
    backend._inner = Failing()  # type: ignore[assignment]
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("x", 80)


async def test_pinned_transport_uses_pinned_backend() -> None:
    transport = PinnedTransport(["93.184.216.34"])
    assert isinstance(transport._pool._network_backend, PinnedBackend)  # type: ignore[attr-defined]
    await transport.aclose()
