"""Bounded, non-executing parser for Nmap XML output."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from chinescan.integrations.nmap.models import NmapHost, NmapPort, NmapProfileName, NmapScanResult


class NmapParseError(ValueError):
    """Nmap output is malformed, hostile, truncated, or exceeds bounds."""


def parse_nmap_xml(
    raw: bytes,
    *,
    profile: NmapProfileName,
    target: str,
    max_bytes: int = 4_194_304,
    max_hosts: int = 1024,
    max_ports: int = 10_000,
) -> NmapScanResult:
    if not raw or len(raw) > max_bytes or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise NmapParseError("nmap_output_invalid")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise NmapParseError("nmap_output_invalid") from None
    if root.tag != "nmaprun":
        raise NmapParseError("nmap_output_invalid")
    version = root.attrib.get("version", "")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?", version):
        raise NmapParseError("nmap_version_missing")
    hosts: list[NmapHost] = []
    port_count = 0
    for host_node in root.findall("host"):
        if len(hosts) >= max_hosts:
            raise NmapParseError("nmap_host_limit_exceeded")
        status_node = host_node.find("status")
        status_value = (
            status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"
        )
        status = status_value if status_value in {"up", "down"} else "unknown"
        address_node = host_node.find("address")
        if address_node is None or address_node.attrib.get("addrtype") not in {"ipv4", "ipv6"}:
            raise NmapParseError("nmap_address_missing")
        address = address_node.attrib.get("addr", "")
        try:
            parsed_address = (
                IPv4Address(address)
                if address_node.attrib["addrtype"] == "ipv4"
                else IPv6Address(address)
            )
        except ValueError:
            raise NmapParseError("nmap_address_invalid") from None
        hostnames = tuple(
            item.attrib["name"][:253]
            for item in host_node.findall("hostnames/hostname")
            if item.attrib.get("name")
        )
        ports: list[NmapPort] = []
        for port_node in host_node.findall("ports/port"):
            port_count += 1
            if port_count > max_ports:
                raise NmapParseError("nmap_port_limit_exceeded")
            try:
                number = int(port_node.attrib["portid"])
            except (KeyError, ValueError):
                raise NmapParseError("nmap_port_invalid") from None
            if not 1 <= number <= 65535:
                raise NmapParseError("nmap_port_invalid")
            protocol = port_node.attrib.get("protocol")
            if protocol not in {"tcp", "udp"}:
                raise NmapParseError("nmap_port_invalid")
            state_node = port_node.find("state")
            raw_state = (
                state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
            )
            state = (
                raw_state
                if raw_state in {"open", "closed", "filtered", "open|filtered"}
                else "unknown"
            )
            service_node = port_node.find("service")
            ports.append(
                NmapPort(
                    port=number,
                    protocol=protocol,
                    state=state,
                    service=(service_node.attrib.get("name", "")[:120] or None)
                    if service_node is not None
                    else None,
                    product=(service_node.attrib.get("product", "")[:200] or None)
                    if service_node is not None
                    else None,
                    version=(service_node.attrib.get("version", "")[:120] or None)
                    if service_node is not None
                    else None,
                )
            )
        hosts.append(
            NmapHost(
                address=str(parsed_address),
                address_type="ipv4" if address_node.attrib["addrtype"] == "ipv4" else "ipv6",
                status=status,
                hostnames=hostnames,
                ports=tuple(ports),
            )
        )
    finished = root.find("runstats/finished")
    finished_at = datetime.now(UTC).isoformat()
    if finished is not None and finished.attrib.get("timestr"):
        finished_at = finished.attrib["timestr"][:40]
    return NmapScanResult(
        profile=profile,
        target=target,
        nmap_version=version,
        hosts=tuple(hosts),
        host_count=len(hosts),
        port_count=port_count,
        finished_at=finished_at,
    )
