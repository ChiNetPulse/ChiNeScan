"""Outbound destination validation and pinned transports for ARTEX.

The policy resolves a destination once, validates every returned address, and
connects to the validated sockaddr directly.  The original hostname is kept
for the HTTP Host header and TLS SNI/certificate verification.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit


class DestinationPolicyError(ValueError):
    """A configured ARTEX destination cannot be used safely."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ValidatedDestination:
    hostname: str
    port: int
    scheme: str
    family: socket.AddressFamily
    sockaddr: tuple[object, ...]


def _normalize_hostname(hostname: str) -> str:
    if not hostname or "%" in hostname:
        raise DestinationPolicyError("configuration_invalid")
    try:
        normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise DestinationPolicyError("configuration_invalid") from None
    if not normalized or len(normalized) > 253:
        raise DestinationPolicyError("configuration_invalid")
    return normalized


def _ip_from_sockaddr(
    sockaddr: tuple[object, ...],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    value = sockaddr[0]
    if not isinstance(value, str) or "%" in value:
        raise DestinationPolicyError("destination_not_allowed")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise DestinationPolicyError("destination_not_allowed") from None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def _is_explicit_loopback(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_loopback: bool
) -> None:
    if address.is_loopback:
        if allow_loopback:
            return
        raise DestinationPolicyError("destination_not_allowed")
    if (
        not address.is_global
        or address.is_private
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    ):
        raise DestinationPolicyError("destination_not_allowed")


def validate_url(base_url: str) -> tuple[SplitResult, str, int]:
    """Parse and validate the ARTEX base URL before resolution or connection."""
    try:
        parsed = urlsplit(base_url)
        hostname_value = parsed.hostname
        username = parsed.username
        password = parsed.password
        parsed_port = parsed.port
    except ValueError:
        raise DestinationPolicyError("configuration_invalid") from None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or username or password:
        raise DestinationPolicyError("configuration_invalid")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise DestinationPolicyError("configuration_invalid")
    if not hostname_value:
        raise DestinationPolicyError("configuration_invalid")
    hostname = _normalize_hostname(hostname_value)
    port = parsed_port
    explicit_loopback = _is_explicit_loopback(hostname)
    if scheme == "http" and not explicit_loopback:
        raise DestinationPolicyError("insecure_non_loopback_transport")
    if port is None:
        port = 80 if scheme == "http" else 443
    if not 1 <= port <= 65535:
        raise DestinationPolicyError("configuration_invalid")
    if not explicit_loopback and port != 443:
        raise DestinationPolicyError("unexpected_port")
    return parsed, hostname, port


def resolve_destination(base_url: str) -> ValidatedDestination:
    """Resolve and validate every address, returning one pinned destination."""
    parsed, hostname, port = validate_url(base_url)
    explicit_loopback = _is_explicit_loopback(hostname)
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    infos: list[tuple[socket.AddressFamily, int, int, str, tuple[object, ...]]]
    if literal is not None:
        sockaddr: tuple[object, ...] = (
            (hostname, port, 0, 0) if literal.version == 6 else (hostname, port)
        )
        infos = [
            (
                socket.AF_INET6 if literal.version == 6 else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                sockaddr,
            )
        ]
    else:
        try:
            raw_infos = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except (OSError, socket.gaierror):
            raise DestinationPolicyError("dns_resolution_failed") from None
        infos = [
            (family, socktype, proto, canonname, tuple(sockaddr))
            for family, socktype, proto, canonname, sockaddr in raw_infos
        ]
    if not infos:
        raise DestinationPolicyError("dns_resolution_failed")
    seen: set[tuple[int, tuple[object, ...]]] = set()
    validated: list[tuple[socket.AddressFamily, tuple[object, ...]]] = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = _ip_from_sockaddr(sockaddr)
        _validate_address(address, allow_loopback=explicit_loopback)
        key = (int(family), tuple(sockaddr))
        if key not in seen:
            seen.add(key)
            validated.append((family, tuple(sockaddr)))
    if not validated:
        raise DestinationPolicyError("dns_resolution_failed")
    family, sockaddr = validated[0]
    return ValidatedDestination(hostname, port, parsed.scheme.lower(), family, sockaddr)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that never resolves the hostname during connect."""

    def __init__(self, destination: ValidatedDestination, *, timeout: float) -> None:
        super().__init__(destination.hostname, destination.port, timeout=timeout)
        self._destination = destination

    def connect(self) -> None:
        sock = socket.socket(self._destination.family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._destination.sockaddr)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated address with hostname SNI."""

    def __init__(
        self,
        destination: ValidatedDestination,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(destination.hostname, destination.port, timeout=timeout, context=context)
        self._destination = destination
        self._ssl_context = context

    def connect(self) -> None:
        sock = socket.socket(self._destination.family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._destination.sockaddr)
            self.sock = self._ssl_context.wrap_socket(
                sock, server_hostname=self._destination.hostname
            )
        except BaseException:
            sock.close()
            raise
