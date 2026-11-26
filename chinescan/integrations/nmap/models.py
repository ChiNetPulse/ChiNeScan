"""Typed Nmap integration models with bounded result shapes."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NmapProfileName = Literal["host_discovery", "basic_port_assessment", "service_identification"]


class NmapPort(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    state: Literal["open", "closed", "filtered", "open|filtered", "unknown"]
    service: str | None = Field(default=None, max_length=120)
    product: str | None = Field(default=None, max_length=200)
    version: str | None = Field(default=None, max_length=120)


class NmapHost(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    address: str = Field(min_length=1, max_length=64)
    address_type: Literal["ipv4", "ipv6"]
    status: Literal["up", "down", "unknown"]
    hostnames: tuple[str, ...] = ()
    ports: tuple[NmapPort, ...] = ()


class NmapScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: NmapProfileName
    target: str = Field(min_length=1, max_length=2048)
    nmap_version: str = Field(min_length=1, max_length=80)
    hosts: tuple[NmapHost, ...] = ()
    host_count: int = Field(ge=0)
    port_count: int = Field(ge=0)
    finished_at: str = Field(min_length=1, max_length=40)
    evidence_record_type: Literal["nmap_result"] = "nmap_result"
