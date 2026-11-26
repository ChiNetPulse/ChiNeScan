"""Typed application settings and CHINESCAN_ environment overrides."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from chinescan.core.accounts import (
    SESSION_ABSOLUTE_TTL_SECONDS,
    SESSION_IDLE_TTL_SECONDS,
)


def default_config_path() -> Path:
    return Path.home() / ".config" / "chinescan" / "config.toml"


def default_data_path() -> Path:
    return Path.home() / ".local" / "share" / "chinescan" / "chinescan.sqlite3"


def default_reports_path() -> Path:
    return Path.home() / ".local" / "share" / "chinescan" / "reports"


class ArtexIntegrationSettings(BaseModel):
    """Milestone 1 ARTEX health-only settings. No credential field is intentional."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    mode: Literal["disabled", "health_only", "read_only_authenticated", "active_blocked"] = (
        "disabled"
    )
    release_id: str | None = None
    base_url: str | None = None
    health_enabled: bool = False
    task_list_enabled: bool = False
    task_detail_enabled: bool = False
    findings_list_enabled: bool = False
    finding_detail_enabled: bool = False
    findings_export_enabled: bool = False
    report_enabled: bool = False
    sensitive_data_acknowledged: bool = False
    retention_policy_acknowledged: bool = False
    max_response_bytes: int = Field(default=65_536, ge=256, le=1_048_576)
    timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    requests_per_minute: int = Field(default=10, ge=1, le=60)

    @model_validator(mode="after")
    def validate_health_profile(self) -> ArtexIntegrationSettings:
        if any(
            (
                self.task_list_enabled,
                self.task_detail_enabled,
                self.findings_list_enabled,
                self.finding_detail_enabled,
                self.findings_export_enabled,
                self.report_enabled,
            )
        ):
            raise ValueError(
                "authenticated ARTEX features are blocked: "
                "no safe ARTEX service credential model is available"
            )
        if not self.enabled:
            if self.mode not in {"disabled", "active_blocked"} or self.health_enabled:
                raise ValueError(
                    "disabled ARTEX integration must use mode=disabled or active_blocked "
                    "and all feature flags false"
                )
            return self
        if self.mode != "health_only":
            raise ValueError("Milestone 1 permits only the explicit health_only mode")
        if not self.health_enabled:
            raise ValueError("enabled ARTEX integration requires health_enabled=true")
        if not self.release_id or len(self.release_id) > 128:
            raise ValueError("enabled ARTEX health requires a pinned release_id")
        if not self.base_url:
            raise ValueError("enabled ARTEX health requires a base_url")
        from urllib.parse import urlsplit

        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError(
                "ARTEX base_url must be an absolute HTTP(S) URL without user information"
            )
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("ARTEX base_url cannot include a path, query, or fragment")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("non-loopback ARTEX connections require HTTPS")
        if not self.sensitive_data_acknowledged or not self.retention_policy_acknowledged:
            raise ValueError(
                "ARTEX health enablement requires sensitive-data and retention acknowledgements"
            )
        return self


class NmapIntegrationSettings(BaseModel):
    """Explicit administrator gate for the constrained Nmap foundation."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    binary: str = Field(default="nmap", min_length=1, max_length=255)
    expected_major: int | None = Field(default=None, ge=1, le=99)
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_output_bytes: int = Field(default=4_194_304, ge=1024, le=33_554_432)


class IntegrationsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artex: ArtexIntegrationSettings = Field(default_factory=ArtexIntegrationSettings)
    nmap: NmapIntegrationSettings = Field(default_factory=NmapIntegrationSettings)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHINESCAN_", extra="ignore")
    database_path: Path = Field(default_factory=default_data_path)
    reports_dir: Path = Field(default_factory=default_reports_path)
    malware_managed_directory: Path | None = None
    malware_evidence_org_quota_bytes: int = Field(
        default=1_073_741_824, ge=67_108_864, le=20_000_000_000
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_token: str | None = Field(default=None, repr=False)
    session_absolute_ttl_seconds: int = Field(
        default=SESSION_ABSOLUTE_TTL_SECONDS, ge=60, le=86_400
    )
    session_idle_ttl_seconds: int = Field(default=SESSION_IDLE_TTL_SECONDS, ge=60, le=86_400)
    auth_rate_limit: int = Field(default=60, ge=1, le=10_000)
    job_start_rate_limit: int = Field(default=120, ge=1, le=10_000)
    export_rate_limit: int = Field(default=240, ge=1, le=10_000)
    read_rate_limit: int = Field(default=1000, ge=1, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    trusted_proxy: bool = False
    allowed_roots: list[Path] = Field(default_factory=list)
    extra_denied_paths: list[Path] = Field(default_factory=list)
    allow_soft_denied: bool = False
    github_import_enabled: bool = False
    chain_network_enabled: bool = False
    chain_labels_path: Path | None = None
    chain_trace_deadline_seconds: int = Field(default=120, ge=1, le=600)
    chain_trace_max_requests: int = Field(default=100, ge=1, le=10_000)
    chain_trace_max_addresses: int = Field(default=500, ge=1, le=5000)
    github_import_timeout_seconds: int = Field(default=120, ge=1, le=600)
    github_import_max_bytes: int = Field(default=524_288_000, ge=1, le=10_737_418_240)
    github_import_max_files: int = Field(default=50_000, ge=1, le=1_000_000)
    github_import_max_projects: int = Field(default=20, ge=1, le=10_000)
    max_files: int = Field(default=50_000, ge=1, le=200_000)
    max_total_bytes: int = Field(default=1_073_741_824, ge=1024, le=10_737_418_240)
    max_file_bytes: int = Field(default=16_777_216, ge=1024, le=134_217_728)
    max_depth: int = Field(default=32, ge=1, le=64)
    per_file_seconds: float = Field(default=2.0, gt=0.0, le=60.0)
    job_deadline_seconds: int = Field(default=300, ge=1, le=3600)
    execution_per_org_active_limit: int = Field(default=2, ge=1, le=16)
    execution_global_active_limit: int = Field(default=8, ge=1, le=64)
    execution_per_org_queued_limit: int = Field(default=4, ge=1, le=64)
    execution_global_queued_limit: int = Field(default=16, ge=1, le=256)
    execution_max_queue_wait_seconds: int = Field(default=900, ge=1, le=86_400)
    execution_operation_timeout_seconds: float = Field(default=60.0, ge=0.5, le=600.0)
    execution_shutdown_grace_seconds: float = Field(default=5.0, ge=0.1, le=120.0)
    archive_max_entries: int = Field(default=10_000, ge=1, le=100_000)
    archive_max_nesting: int = Field(default=4, ge=1, le=16)
    archive_max_decompressed_bytes: int = Field(default=268_435_456, ge=1024, le=2_147_483_648)
    parser_max_output_bytes: int = Field(default=4_194_304, ge=1024, le=33_554_432)
    max_findings_per_job: int = Field(default=5_000, ge=1, le=50_000)
    subprocess_timeout_seconds: float = Field(default=60.0, ge=0.5, le=600.0)
    subprocess_max_output_bytes: int = Field(default=4_194_304, ge=1024, le=33_554_432)
    network_connect_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    network_read_timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    network_max_response_bytes: int = Field(default=1_048_576, ge=256, le=16_777_216)
    safe_retry_max_attempts: int = Field(default=2, ge=0, le=5)
    safe_retry_delay_seconds: float = Field(default=0.5, ge=0.0, le=30.0)
    code_excluded_paths: list[str] = Field(default_factory=list)
    malware_max_files: int = 50_000
    malware_max_total_bytes: int = 1_073_741_824
    malware_max_file_bytes: int = 16_777_216
    malware_max_depth: int = 32
    malware_per_file_seconds: float = 2.0
    malware_job_deadline_seconds: int = 300
    repository_snapshot_max_bytes: int = Field(default=5_368_709_120, ge=1, le=10_737_418_240)
    repository_snapshot_org_quota_bytes: int = Field(
        default=10_737_418_240, ge=1, le=107_374_182_400
    )
    log_evidence_max_bytes: int = Field(default=250_000_000, ge=1, le=250_000_000)
    log_evidence_org_quota_bytes: int = Field(default=2_000_000_000, ge=1, le=20_000_000_000)
    malware_known_bad_hashes: Path | None = None
    malware_rules_directory: Path | None = None
    data_source: Literal["real", "simulation"] = "real"
    integrations: IntegrationsSettings = Field(default_factory=IntegrationsSettings)
    _allowed_root_validation: list[object] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def validate_repository_snapshot_limits(self) -> Settings:
        if self.repository_snapshot_org_quota_bytes < self.repository_snapshot_max_bytes:
            raise ValueError(
                "repository organization quota must be at least the per-snapshot limit"
            )
        return self

    @model_validator(mode="after")
    def validate_log_evidence_limits(self) -> Settings:
        if self.log_evidence_org_quota_bytes < self.log_evidence_max_bytes:
            raise ValueError(
                "log evidence organization quota must be at least the per-snapshot limit"
            )
        return self

    @model_validator(mode="after")
    def validate_configured_roots(self) -> Settings:
        from chinescan.core.fs_policy import (
            policy_paths,
            storage_paths,
            validate_allowed_roots,
        )

        hard, soft = policy_paths(self)
        roots, statuses = validate_allowed_roots(
            list(self.allowed_roots),
            hard_denied=hard,
            soft_denied=soft,
            allow_soft_denied=self.allow_soft_denied,
            storage_paths=storage_paths(self),
        )
        self.allowed_roots = roots
        self._allowed_root_validation = cast(list[object], statuses)
        return self

    @model_validator(mode="after")
    def validate_resource_governance_limits(self) -> Settings:
        from chinescan.core.resource_governance import ResourceLimits

        ResourceLimits.from_settings(self)
        return self

    @property
    def allowed_root_validation(self) -> list[object]:
        """Path-free validation statuses for roots supplied at configuration load."""
        return list(self._allowed_root_validation)
