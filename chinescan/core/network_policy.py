"""Immutable worker network policy and deployment-helper contract."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

NetworkMode = Literal["deny_all", "approved_destinations"]


class NetworkPolicyError(ValueError):
    """An execution network policy is invalid or cannot be enforced."""


@dataclass(frozen=True)
class ApprovedDestination:
    hostname: str
    addresses: tuple[str, ...]
    protocols: tuple[str, ...] = ("tcp",)
    ports: tuple[int, ...] = (443,)

    def normalized(self) -> ApprovedDestination:
        try:
            hostname = self.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise NetworkPolicyError("invalid_destination_hostname") from None
        if not hostname or len(hostname) > 253 or not self.addresses:
            raise NetworkPolicyError("invalid_destination_hostname")
        addresses: list[str] = []
        for value in self.addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                raise NetworkPolicyError("invalid_destination_address") from None
            effective = (
                address.ipv4_mapped
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
                else address
            )
            if not effective.is_global or effective.is_private or effective.is_loopback:
                raise NetworkPolicyError("destination_address_not_allowed")
            if effective.is_link_local or effective.is_multicast or effective.is_reserved:
                raise NetworkPolicyError("destination_address_not_allowed")
            if effective.is_unspecified:
                raise NetworkPolicyError("destination_address_not_allowed")
            addresses.append(str(address))
        protocols = tuple(sorted(set(self.protocols)))
        if not protocols or not set(protocols).issubset({"tcp", "udp"}):
            raise NetworkPolicyError("invalid_destination_protocol")
        ports = tuple(sorted(set(self.ports)))
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise NetworkPolicyError("invalid_destination_port")
        return ApprovedDestination(hostname, tuple(sorted(set(addresses))), protocols, ports)


@dataclass(frozen=True)
class NetworkPolicy:
    mode: NetworkMode = "deny_all"
    destinations: tuple[ApprovedDestination, ...] = ()
    scope_revision_id: str | None = None
    authorization_id: str | None = None
    expires_at: float | None = None

    def validated(self, *, now: float | None = None) -> NetworkPolicy:
        if self.mode == "deny_all":
            if self.destinations or self.scope_revision_id or self.authorization_id:
                raise NetworkPolicyError("deny_all_policy_has_allowlist")
            return self
        if self.mode != "approved_destinations":
            raise NetworkPolicyError("invalid_network_mode")
        if not self.destinations or not self.scope_revision_id or not self.authorization_id:
            raise NetworkPolicyError("approved_policy_binding_required")
        if self.expires_at is not None and self.expires_at <= (
            now or datetime.now(UTC).timestamp()
        ):
            raise NetworkPolicyError("network_policy_expired")
        return NetworkPolicy(
            mode=self.mode,
            destinations=tuple(item.normalized() for item in self.destinations),
            scope_revision_id=self.scope_revision_id,
            authorization_id=self.authorization_id,
            expires_at=self.expires_at,
        )

    def json(self) -> str:
        policy = self.validated()
        return json.dumps(
            {
                "mode": policy.mode,
                "scope_revision_id": policy.scope_revision_id,
                "authorization_id": policy.authorization_id,
                "expires_at": policy.expires_at,
                "destinations": [
                    {
                        "hostname": item.hostname,
                        "addresses": list(item.addresses),
                        "protocols": list(item.protocols),
                        "ports": list(item.ports),
                    }
                    for item in policy.destinations
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def deployment_helper() -> str | None:
    configured = os.environ.get("CHINESCAN_NETWORK_POLICY_HELPER")
    if not configured:
        return None
    resolved = shutil.which(configured) if not os.path.isabs(configured) else configured
    if not resolved or not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        return None
    return resolved


def approved_policy_available(policy: NetworkPolicy) -> tuple[bool, str | None]:
    try:
        policy.validated()
    except NetworkPolicyError as exc:
        return False, str(exc)
    if policy.mode == "deny_all":
        return False, "network_namespace_runtime_verification_required"
    if deployment_helper() is None:
        return False, "network_policy_helper_unavailable"
    return True, None
