"""Administrator-controlled Nmap profiles and structured argument building."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chinescan.integrations.nmap.models import NmapProfileName


@dataclass(frozen=True)
class NmapProfile:
    name: NmapProfileName
    description: str
    allowed_ports: tuple[int, ...]
    max_ports: int
    arguments: tuple[str, ...]


NMAP_PROFILES: dict[NmapProfileName, NmapProfile] = {
    "host_discovery": NmapProfile(
        "host_discovery", "Identify approved live hosts", (), 0, ("-sn", "-T2")
    ),
    "basic_port_assessment": NmapProfile(
        "basic_port_assessment",
        "Inspect an explicitly approved TCP port set",
        tuple(range(1, 65536)),
        64,
        ("-sT", "-T2", "--max-retries", "2"),
    ),
    "service_identification": NmapProfile(
        "service_identification",
        "Identify services on an explicitly approved TCP port set",
        tuple(range(1, 65536)),
        32,
        ("-sT", "-sV", "--version-light", "-T2", "--max-retries", "2"),
    ),
}


def build_nmap_arguments(
    profile_name: NmapProfileName, target: str, *, ports: list[int] | None = None
) -> list[str]:
    profile = NMAP_PROFILES.get(profile_name)
    if profile is None:
        raise ValueError("profile_invalid")
    if not target or target.startswith("-") or any(c in target for c in "\r\n \t;|&$`()<>\\"):
        raise ValueError("target_invalid")
    chosen_ports = [] if ports is None else sorted(set(ports))
    if profile.max_ports == 0 and chosen_ports:
        raise ValueError("ports_not_supported_for_profile")
    if len(chosen_ports) > profile.max_ports:
        raise ValueError("port_limit_exceeded")
    if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in chosen_ports):
        raise ValueError("port_invalid")
    args = ["--noninteractive", *profile.arguments]
    if chosen_ports:
        args.extend(("-p", ",".join(str(port) for port in chosen_ports)))
    args.extend(("-oX", "-", "--", target))
    return args


def profile_listing() -> list[dict[str, Any]]:
    return [
        {
            "name": profile.name,
            "description": profile.description,
            "max_ports": profile.max_ports,
            "external_operations": True,
        }
        for profile in NMAP_PROFILES.values()
    ]
