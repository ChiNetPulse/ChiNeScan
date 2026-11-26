"""Strict Nmap target validation.

The first governed foundation accepts only canonical IP addresses and bounded
CIDR networks. Hostname targets are intentionally rejected until a resolver
that can bind every resolved address to the approved scope is reviewed.
"""

from __future__ import annotations

import ipaddress


class NmapTargetError(ValueError):
    """A target is not an explicitly approved Nmap host/network form."""


def validate_nmap_target(target: str, *, asset_type: str) -> str:
    if not isinstance(target, str) or not target or target != target.strip() or len(target) > 2048:
        raise NmapTargetError("target_invalid")
    if any(char in target for char in " \t\r\n,;|&$`()<>\\*?"):
        raise NmapTargetError("target_invalid")
    try:
        if asset_type == "ip":
            address = ipaddress.ip_address(target)
            if address.is_unspecified or address.is_multicast or address.is_reserved:
                raise NmapTargetError("target_not_allowed")
            return address.compressed.lower()
        if asset_type == "cidr":
            network = ipaddress.ip_network(target, strict=True)
            if network.is_unspecified or network.is_multicast or network.is_reserved:
                raise NmapTargetError("target_not_allowed")
            # Keep a single governed job bounded; wider reconnaissance requires
            # an explicitly reviewed profile and capacity policy.
            max_prefix = 24 if network.version == 4 else 112
            if network.prefixlen < max_prefix:
                raise NmapTargetError("target_range_too_large")
            return str(network)
    except ValueError:
        raise NmapTargetError("target_invalid") from None
    raise NmapTargetError("hostname_targets_not_supported")
