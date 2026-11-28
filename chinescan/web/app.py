"""Same-origin authenticated API and production frontend serving."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import secrets
import shutil
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Match

from chinescan.chain_trace.export import export_graph
from chinescan.chain_trace.registry import load_registry, normalize_address
from chinescan.core.capabilities import module_capabilities
from chinescan.core.cases import (
    CaseNotFoundError,
    CaseRecordNotFoundError,
    CaseWorkflow,
    CaseWorkflowError,
)
from chinescan.core.chain_trace_execution import (
    GovernedChainImportAdapter,
    GovernedChainProviderAdapter,
)
from chinescan.core.config.settings import Settings
from chinescan.core.dashboard_alerts import AlertStateError, DashboardAlerts
from chinescan.core.dashboard_intelligence import DashboardIntelligence
from chinescan.core.diagnostics import build_report, health_report
from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.errors import StorageError
from chinescan.core.execution_adapters import (
    GovernedLogAnalysisAdapter,
    GovernedMalwareStaticTriageAdapter,
    GovernedNmapAdapter,
    GovernedNucleiAdapter,
    RepositoryCodeAssessmentAdapter,
    build_default_adapter_registry,
)
from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker
from chinescan.core.execution_isolation import IsolationProfile, isolation_status
from chinescan.core.external_reports import (
    MAX_EXTERNAL_REPORT_BYTES,
    ExternalReportError,
    parse_scanity_export,
)
from chinescan.core.first_superuser import (
    FIRST_SUPERUSER_EMAIL,
    FirstSuperuserBootstrapError,
    complete_first_superuser_setup,
)
from chinescan.core.fs_policy import (
    FilesystemBrowserService,
    folder_approval_error,
    policy_paths,
)
from chinescan.core.github_import import GitHubImportError, GitHubImportService, session_binding
from chinescan.core.identity import IdentityError, IdentityService
from chinescan.core.log_evidence import LogEvidenceStore
from chinescan.core.log_locations import LogLocationService
from chinescan.core.logging.redaction import redact
from chinescan.core.logging.structured import configure_logging
from chinescan.core.malware_ack import MalwareAcknowledgementError, MalwareAcknowledgements
from chinescan.core.malware_evidence import MalwareEvidenceStore
from chinescan.core.malware_project_scan import ProjectMalwareJobs, ProjectMalwareScanner
from chinescan.core.models.common import (
    Confidence,
    EvidenceKind,
    FindingCategory,
    FindingVerdict,
    ScanVerdict,
    Severity,
)
from chinescan.core.models.finding import EvidenceLocation, Finding, FindingExplanation
from chinescan.core.models.investigation import (
    Alert,
    Case,
    CaseStatus,
    CodeAssessmentSummary,
    CoverageReport,
    Event,
    Scan,
    TimelineEntry,
)
from chinescan.core.orchestration.code_scan import ScanBounds
from chinescan.core.organizations import OrganizationService
from chinescan.core.projects import ProjectError, ProjectService
from chinescan.core.report_store import ReportStoreError, save_scan_reports
from chinescan.core.reporting import (
    ReportingError,
    redact_finding_payload,
    render_case_report,
    render_report,
    scan_data,
)
from chinescan.core.repository_assessment import (
    RepositoryAssessmentService,
    RepositorySnapshotStore,
)
from chinescan.core.storage.postgres import PostgresRepository
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.integrations.artex.client import ArtexHealthClient, ArtexIntegrationError
from chinescan.integrations.artex.models import ArtexAuditEvent, ArtexSyncState
from chinescan.integrations.nmap.executor import NmapExecutor
from chinescan.integrations.nuclei.executor import NucleiExecutor
from chinescan.integrations.nuclei.profiles import profile_listing as nuclei_profile_listing
from chinescan.malware_analysis.managed import (
    ManagedSampleError,
    SampleRegistry,
    create_backend,
    safe_display_name,
)
from chinescan.web.auth import (
    CredentialError,
    LoginThrottle,
    ProgressiveLockout,
    Session,
    SessionStore,
    create_operator,
    ensure_operator_identity_id,
    migrate_legacy_operator,
    normalize_email,
    operator_auth_epoch,
    operator_email,
    operator_identity_id,
    operator_status,
    perform_dummy_verification,
    reset_operator_password,
)
from chinescan.web.chain_trace_jobs import ChainTraceJobManager
from chinescan.web.code_jobs import CodeJobManager, ProjectConfigurationError, ProjectRegistry
from chinescan.web.engagement_security_api import create_engagement_security_router
from chinescan.web.execution_api import create_chain_execution_router, create_execution_router
from chinescan.web.log_evidence_api import create_log_evidence_router
from chinescan.web.log_jobs import LogJobManager, LogSourceError, LogSourceRegistry
from chinescan.web.malware_evidence_api import create_malware_evidence_router
from chinescan.web.malware_jobs import MalwareDashboardManager
from chinescan.web.nmap_api import create_nmap_router
from chinescan.web.nuclei_api import create_nuclei_router
from chinescan.web.organization_api import create_organization_router
from chinescan.web.phase6_api import create_phase6_router
from chinescan.web.rate_limit import InProcessRateLimiter
from chinescan.web.repository_execution_api import create_repository_router

COOKIE_NAME = "chinescan_session"
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
MAX_SCAN_REPORT_FINDINGS = 10_000
MAX_SCAN_REPORT_BYTES = 20 * 1024 * 1024
PROJECT_OPERATION_RATE_LIMIT = 20
PROJECT_OPERATION_RATE_WINDOW_SECONDS = 60


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)
    totp_code: str | None = Field(default=None, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class InvitationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=16, max_length=256)
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    display_name: str | None = Field(default=None, min_length=1, max_length=120)


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=128)


class TotpCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=64)


class AccountStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["active", "disabled", "revoked", "suspended"]


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class ResetPasswordRequest(ForgotPasswordRequest):
    token: str = Field(min_length=32, max_length=256)
    password: str = Field(min_length=12, max_length=1024)


class FirstSuperuserSetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    token: str = Field(min_length=32, max_length=256)
    password: str = Field(min_length=12, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class AuthSessionResponse(BaseModel):
    """Authenticated operator identity and in-memory CSRF token."""

    model_config = ConfigDict(extra="forbid")
    email: str
    csrf_token: str = Field(description="Keep in memory and send in X-CSRF-Token for writes.")


class AuthStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authenticated: bool
    email_masked: str | None
    signup_available: bool


class ScanSummaryResponse(BaseModel):
    """Path-free persisted scan summary identified by its stable scan ID."""

    model_config = ConfigDict(extra="forbid")
    scan_id: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    scanner: str
    project_types: list[str]
    finding_count: int
    verdict: ScanVerdict | None = None
    coverage_gap_count: int = 0


class ScanDetailResponse(ScanSummaryResponse):
    finding_ids: list[str]
    coverage: CoverageReport | None = None
    failures: dict[str, str] = Field(default_factory=dict)
    code_assessment: CodeAssessmentSummary | None = None


class FindingSummaryResponse(BaseModel):
    """Reviewed, redacted finding fields approved for dashboard display."""

    model_config = ConfigDict(extra="forbid")
    finding_id: str
    title: str
    severity: Severity
    category: FindingCategory
    confidence: Confidence
    verdict: FindingVerdict
    scanner: str
    rule_id: str
    contributing_rule_ids: list[str] = Field(default_factory=list)
    entry_point: EvidenceLocation | None = None
    source_location: EvidenceLocation | None = None
    sink_location: EvidenceLocation | None = None
    controls_considered: list[str] = Field(default_factory=list)
    exploitability_conditions: list[str] = Field(default_factory=list)
    project_impact: str | None = None
    remediation_before: str | None = None
    remediation_after: str | None = None
    verification_step: str | None = None
    why_not_higher: str | None = None
    what_would_raise_it: str | None = None


class FindingDetailResponse(FindingSummaryResponse):
    description: str = ""
    location: str | None = None
    tags: list[str] = Field(default_factory=list)
    evidence: EvidenceKind | None = None
    line_numbers: list[int] = Field(default_factory=list)
    code_excerpt: str | None = None
    remediation: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    exposure: str = "unknown"
    explanation: FindingExplanation | None = None


class OverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_count: int
    finding_count: int
    findings_by_severity: dict[Severity, int]
    findings_by_verdict: dict[str, int]
    top_fix_first: list[dict[str, str]]
    recent_scans: list[ScanSummaryResponse]


class ScanPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[ScanSummaryResponse]
    total: int
    limit: int
    offset: int


class FindingPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[FindingSummaryResponse]
    total: int
    total_stored: int
    limit: int
    offset: int


class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=1, max_length=255)
    title: str | None = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=8000)
    severity: Severity = Severity.MEDIUM


class CaseNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=8000)


class CaseLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_type: str = Field(min_length=1, max_length=80)
    record_id: str = Field(min_length=1, max_length=255)


class AlertSnoozeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    until: datetime


class CaseStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: CaseStatus


class GitHubPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=300)
    ref: str | None = Field(default=None, max_length=100)


class GitHubImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview_id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    replace_project_id: str | None = Field(default=None, max_length=80)
    replace_confirmation: str | None = Field(default=None, max_length=120)


class CodeJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(min_length=1, max_length=80)


class ProjectCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    directory_id: str = Field(min_length=32, max_length=128)


class FolderApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    directory_id: str = Field(min_length=32, max_length=128)
    approved: bool
    name: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: Literal["project", "logs", "malware"] = "project"


class ProjectRemoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(min_length=1, max_length=120)


class LogJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(min_length=1, max_length=80)


class ProjectLogLocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    directory_id: str = Field(min_length=32, max_length=128)
    scope: Literal["project", "external"] = "project"


class ProjectLogLocationRemoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(min_length=1, max_length=120)


class ProjectLogJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    location_ids: list[str] | None = Field(default=None, max_length=20)


class LogSuggestionConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suggestion_id: str = Field(min_length=16, max_length=128)
    name: str = Field(min_length=1, max_length=120)


class MalwareJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registry_id: str | None = Field(default=None, min_length=1, max_length=80)
    sample_id: str | None = Field(default=None, min_length=1, max_length=255)
    profile: Literal["builtin_static"] = "builtin_static"


class MalwareAcknowledgementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(min_length=1, max_length=80)
    confirmed: bool = False
    typed_phrase: str | None = Field(default=None, max_length=80)


class ProjectMalwareJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acknowledgement_token: str | None = Field(default=None, min_length=32, max_length=128)
    profile: Literal["builtin_static"]


class MalwareSampleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registry_id: str | None
    display_name: str
    state: Literal["registered", "managed", "unavailable"]
    source_available: bool
    source_size_bytes: int | None
    sample_id: str | None
    sha256: str | None
    managed_size_bytes: int | None
    availability: str | None


class MalwareJobResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    sample_id: str
    status: Literal["queued", "running", "succeeded", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    analysis_id: str | None
    warning: str | None
    analysis_status: Literal["complete", "partial"] | None = None


class MalwareJobPageResponse(BaseModel):
    items: list[MalwareJobResponse]
    total: int
    limit: int
    offset: int


class MalwareAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: str
    sample_id: str
    profile: str
    status: Literal["complete", "partial"]
    created_at: str
    size_bytes: int
    hashes: dict[str, str]
    file_type: str
    architecture: str | None
    printable_string_count: int
    indicator_count: int
    indicators: list[dict[str, str]]
    warnings: list[str]
    archive_findings: list[dict[str, Any]] = Field(default_factory=list)
    engines: dict[str, dict[str, Any]]
    entropy_bits_per_byte: float | None = None
    section_entropy: list[dict[str, Any]] = Field(default_factory=list)
    timestamp_utc: str | None = None
    imports: list[str] = Field(default_factory=list)
    suspicious_api_combinations: list[str] = Field(default_factory=list)
    verdict: Literal["clean-no-indicators", "suspicious", "likely-malicious"] = "suspicious"
    verdict_evidence: list[str] = Field(default_factory=list)
    verdict_caveat: str = "Static analysis cannot establish that a sample is safe."
    evidence_note: str


class CodeProjectResponse(BaseModel):
    project_id: str
    display_name: str


class CodeJobResponse(BaseModel):
    job_id: str
    project_id: str
    project_name: str
    status: Literal["queued", "running", "succeeded", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    scan_id: str | None
    error: str | None
    warning: str | None = None


class CodeJobPageResponse(BaseModel):
    items: list[CodeJobResponse]
    total: int
    limit: int
    offset: int


class LogSourceResponse(BaseModel):
    source_id: str
    display_name: str


class LogJobResponse(BaseModel):
    job_id: str
    source_id: str
    source_name: str
    status: Literal["queued", "running", "succeeded", "partial", "failed", "interrupted"]
    created_at: str
    started_at: str | None
    finished_at: str | None
    scan_id: str | None
    event_count: int
    alert_count: int
    error_count: int
    error: str | None
    diagnostics: list[str] = Field(default_factory=list)
    project_id: str | None = None
    location_ids: list[str] = Field(default_factory=list)
    skipped_counts: dict[str, int] = Field(default_factory=dict)
    error_code: str | None = None


class LogJobPageResponse(BaseModel):
    items: list[LogJobResponse]
    total: int
    limit: int
    offset: int


class AlertResponse(BaseModel):
    alert_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    rule_id: str
    event_ids: list[str]
    indicator_ids: list[str]
    mitre_attack_techniques: list[str]


class EventResponse(BaseModel):
    event_id: str
    occurred_at: datetime
    kind: str
    summary: str
    source: str
    source_ip: str | None
    destination_ip: str | None
    user: str | None
    host: str | None
    process: str | None
    url: str | None
    event_outcome: str | None
    mitre_attack_techniques: list[str]


class TimelineResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class AlertPageResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int


class EventPageResponse(BaseModel):
    items: list[EventResponse]
    total: int
    limit: int
    offset: int


def _loopback_host(host: str) -> bool:
    value = host.strip().lower()
    hostname = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    return hostname in {"127.0.0.1", "localhost"}


def create_app(
    database_path: Path | str,
    credential_path: Path | str,
    *,
    session_ttl_seconds: int | None = None,
    secure_cookie: bool = False,
    serve_frontend: bool = True,
    projects_path: Path | str | None = None,
    log_sources_path: Path | str | None = None,
    malware_registry_path: Path | str | None = None,
    settings: Settings | None = None,
    github_import_test_file_transport: bool = False,
    test_only_project_operation_rate_limit: int | None = None,
    start_governed_worker: bool = True,
) -> FastAPI:
    """Create an app; the optional project-limit override is only for isolated tests."""
    configure_logging()
    active_settings = settings or Settings(_env_file=None)
    repository: SQLiteRepository
    if active_settings.database_url:
        repository = PostgresRepository(
            active_settings.database_url,
            storage_root=Path(database_path).expanduser().resolve(strict=False).parent,
        )
    else:
        repository = SQLiteRepository(database_path)
    organization_service = OrganizationService(repository)
    identity_service = IdentityService(organization_service)
    engagement_security_service = EngagementSecurityService(repository, organization_service)
    from chinescan.core.resource_governance import ResourceLimits

    resource_limits = ResourceLimits.from_settings(active_settings)
    execution_governance = ExecutionGovernanceService(
        engagement_security_service,
        resource_limits=resource_limits,
    )
    governed_domain_worker = GovernedDomainWorker(
        repository,
        execution_governance,
        shutdown_grace_seconds=resource_limits.shutdown_grace_seconds,
    )
    dashboard_alerts = DashboardAlerts(repository)
    dashboard_intelligence = DashboardIntelligence(repository, dashboard_alerts)
    auth_failure_windows: dict[str, deque[float]] = {}
    db_lock = threading.RLock()
    absolute_ttl_seconds = (
        session_ttl_seconds
        if session_ttl_seconds is not None
        else active_settings.session_absolute_ttl_seconds
    )
    idle_ttl_seconds = active_settings.session_idle_ttl_seconds
    sessions = SessionStore(absolute_ttl_seconds, idle_ttl_seconds, engine=repository.engine)
    credentials = Path(credential_path)
    try:
        migrate_legacy_operator(credentials)
    except CredentialError:
        logging.getLogger("chinescan.auth").warning("operator_credentials_need_recovery")
    if operator_status(credentials) == "active":
        try:
            stored_operator_email = operator_email(credentials)
            if stored_operator_email:
                stable_identity = operator_identity_id(credentials)
                if stable_identity is None:
                    stable_identity = organization_service.user_id_for_email(stored_operator_email)
                    stable_identity = ensure_operator_identity_id(
                        credentials, stable_identity or str(uuid4())
                    )
                op_epoch = operator_auth_epoch(credentials)
                effective_epoch = identity_service.active_auth_epoch_for_operator(
                    stable_identity, op_epoch
                )
                _op_user, _op_org = organization_service.ensure_operator(
                    stored_operator_email, effective_epoch, stable_identity
                )
                identity_service.migrate_operator_credentials(credentials, _op_user["id"])
        except Exception:
            # Authentication remains closed until the idempotent identity and
            # ownership bootstrap succeeds on a later retry.
            logging.getLogger("chinescan.auth").error("operator_identity_bootstrap_failed")
    registry = ProjectRegistry(
        projects_path,
        [
            Path(database_path).parent,
            credentials,
            Path(projects_path)
            if projects_path
            else Path.home() / ".config" / "chinescan" / "projects.toml",
        ],
    )
    log_registry = LogSourceRegistry(
        log_sources_path,
        [
            Path(database_path).parent,
            credentials,
            Path(projects_path)
            if projects_path
            else Path.home() / ".config" / "chinescan" / "projects.toml",
            Path(log_sources_path)
            if log_sources_path
            else Path.home() / ".config" / "chinescan" / "log-sources.toml",
        ],
    )
    malware_jobs: MalwareDashboardManager | None = None
    sample_registry: SampleRegistry | None = None
    malware_evidence_store: MalwareEvidenceStore | None = None
    malware_diagnostic = (
        "Execution unavailable: configure managed storage and an operator registry."
    )
    rate_limiter = InProcessRateLimiter(
        {
            "auth": (active_settings.auth_rate_limit, active_settings.rate_limit_window_seconds),
            "job_start": (
                active_settings.job_start_rate_limit,
                active_settings.rate_limit_window_seconds,
            ),
            "exports": (
                active_settings.export_rate_limit,
                active_settings.rate_limit_window_seconds,
            ),
            "reads": (
                active_settings.read_rate_limit,
                active_settings.rate_limit_window_seconds,
            ),
            "artex": (active_settings.integrations.artex.requests_per_minute, 60),
        }
    )
    hard_denied, soft_denied = policy_paths(active_settings)
    fs_browser = FilesystemBrowserService(
        list(active_settings.allowed_roots),
        hard_denied,
        soft_denied,
        active_settings.allow_soft_denied,
    )
    github_managed_directory = Path(database_path).expanduser().resolve(strict=False).parent / "gh"
    project_service = ProjectService(
        repository,
        fs_browser,
        registry,
        allowed_roots=list(active_settings.allowed_roots),
        hard_denied=hard_denied,
        soft_denied=soft_denied,
        allow_soft_denied=active_settings.allow_soft_denied,
        managed_import_directory=github_managed_directory,
    )
    repository_snapshot_store = RepositorySnapshotStore(
        repository,
        Path(database_path).expanduser().resolve(strict=False).parent / "repository-snapshots",
        max_snapshot_bytes=active_settings.repository_snapshot_max_bytes,
        organization_quota_bytes=active_settings.repository_snapshot_org_quota_bytes,
        max_files=active_settings.max_files,
        max_depth=active_settings.max_depth,
    )
    repository_assessment_service = RepositoryAssessmentService(
        repository, engagement_security_service, project_service, repository_snapshot_store
    )
    repository_adapter = RepositoryCodeAssessmentAdapter(
        repository,
        repository_snapshot_store,
        ScanBounds(
            max_files=active_settings.max_files,
            max_total_bytes=active_settings.max_total_bytes,
            max_file_bytes=active_settings.max_file_bytes,
            max_depth=active_settings.max_depth,
            per_file_seconds=active_settings.per_file_seconds,
            job_deadline_seconds=active_settings.job_deadline_seconds,
            excluded_paths=tuple(active_settings.code_excluded_paths),
        ),
    )
    log_evidence_store = LogEvidenceStore(
        repository,
        Path(database_path).expanduser().resolve(strict=False).parent / "log-evidence-snapshots",
        allowed_roots=list(active_settings.allowed_roots),
        max_snapshot_bytes=active_settings.log_evidence_max_bytes,
        organization_quota_bytes=active_settings.log_evidence_org_quota_bytes,
    )
    log_analysis_adapter = GovernedLogAnalysisAdapter(repository, log_evidence_store)
    chain_label_paths = (
        (str(active_settings.chain_labels_path),) if active_settings.chain_labels_path else ()
    )
    chain_import_adapter = GovernedChainImportAdapter(
        repository, log_evidence_store, tuple(chain_label_paths)
    )
    chain_provider_adapter = GovernedChainProviderAdapter(
        repository,
        max_requests=active_settings.chain_trace_max_requests,
        deadline_seconds=active_settings.chain_trace_deadline_seconds,
        label_paths=tuple(chain_label_paths),
    )
    nmap_adapter = (
        GovernedNmapAdapter(
            repository,
            NmapExecutor(
                binary=active_settings.integrations.nmap.binary,
                timeout_seconds=active_settings.integrations.nmap.timeout_seconds,
                max_output_bytes=active_settings.integrations.nmap.max_output_bytes,
                expected_major=active_settings.integrations.nmap.expected_major,
                isolation_profile=IsolationProfile(
                    cpu_seconds=resource_limits.scanner_cpu_seconds,
                    memory_bytes=resource_limits.scanner_memory_bytes,
                    max_processes=resource_limits.scanner_process_count,
                    max_open_files=resource_limits.scanner_open_files,
                    max_file_bytes=resource_limits.scanner_temp_bytes,
                    network_isolation_required=True,
                    linux_namespaces_required=True,
                    linux_cgroup_required=True,
                    linux_seccomp_required=True,
                    filesystem_isolation_required=True,
                ),
                require_hardened_isolation=active_settings.integrations.nmap.require_hardened_isolation,
            ),
        )
        if active_settings.integrations.nmap.enabled
        else None
    )
    nuclei_adapter = (
        GovernedNucleiAdapter(
            repository,
            NucleiExecutor(
                binary=active_settings.integrations.nuclei.binary,
                template_directory=active_settings.integrations.nuclei.template_directory,
                approved_templates=active_settings.integrations.nuclei.approved_templates,
                timeout_seconds=active_settings.integrations.nuclei.timeout_seconds,
                max_output_bytes=active_settings.integrations.nuclei.max_output_bytes,
                expected_major=active_settings.integrations.nuclei.expected_major,
                isolation_profile=IsolationProfile(
                    cpu_seconds=resource_limits.scanner_cpu_seconds,
                    memory_bytes=resource_limits.scanner_memory_bytes,
                    max_processes=resource_limits.scanner_process_count,
                    max_open_files=resource_limits.scanner_open_files,
                    max_file_bytes=resource_limits.scanner_temp_bytes,
                    network_isolation_required=True,
                    linux_namespaces_required=True,
                    linux_cgroup_required=True,
                    linux_seccomp_required=True,
                    filesystem_isolation_required=True,
                ),
                require_hardened_isolation=active_settings.integrations.nuclei.require_hardened_isolation,
            ),
        )
        if active_settings.integrations.nuclei.enabled
        else None
    )
    execution_governance.adapters = build_default_adapter_registry(
        repository,
        repository_adapter,
        log_analysis_adapter,
        chain_import_adapter=chain_import_adapter,
        chain_provider_adapter=chain_provider_adapter,
        nmap_adapter=nmap_adapter,
        nuclei_adapter=nuclei_adapter,
    )
    execution_governance.repository_scan_bounds = {
        "max_files": active_settings.max_files,
        "max_total_bytes": active_settings.max_total_bytes,
        "max_file_bytes": active_settings.max_file_bytes,
        "max_depth": active_settings.max_depth,
        "per_file_seconds": active_settings.per_file_seconds,
        "job_deadline_seconds": active_settings.job_deadline_seconds,
        "excluded_paths": list(active_settings.code_excluded_paths),
    }
    governed_domain_worker.adapters = execution_governance.adapters
    log_location_service = LogLocationService(repository, project_service)
    log_jobs = LogJobManager(
        repository, db_lock, log_registry, project_locations=log_location_service
    )
    malware_acknowledgements = MalwareAcknowledgements(repository)
    project_malware_jobs = ProjectMalwareJobs(
        repository, ProjectMalwareScanner(repository, project_service, active_settings)
    )
    github_imports = GitHubImportService(
        repository,
        active_settings,
        github_managed_directory,
        test_file_transport=github_import_test_file_transport,
        project_service=project_service,
    )
    jobs = CodeJobManager(
        repository,
        db_lock,
        project_service,
        reports_dir=active_settings.reports_dir,
        bounds=ScanBounds(
            max_files=active_settings.max_files,
            max_total_bytes=active_settings.max_total_bytes,
            max_file_bytes=active_settings.max_file_bytes,
            max_depth=active_settings.max_depth,
            per_file_seconds=active_settings.per_file_seconds,
            job_deadline_seconds=active_settings.job_deadline_seconds,
            excluded_paths=tuple(active_settings.code_excluded_paths),
        ),
    )
    chain_jobs = ChainTraceJobManager(repository, active_settings)
    project_throttle = LoginThrottle(
        limit=(
            PROJECT_OPERATION_RATE_LIMIT
            if test_only_project_operation_rate_limit is None
            else test_only_project_operation_rate_limit
        ),
        window_seconds=PROJECT_OPERATION_RATE_WINDOW_SECONDS,
    )
    fs_browse_throttle = LoginThrottle(limit=60, window_seconds=60)
    malware_config = (
        Path(malware_registry_path)
        if malware_registry_path
        else Path.home() / ".config" / "chinescan" / "malware-samples.toml"
    )
    try:
        backend, sample_registry = create_backend(
            repository,
            active_settings,
            malware_config,
            additional_protected_paths=[
                credentials,
                Path(projects_path)
                if projects_path
                else Path.home() / ".config" / "chinescan" / "projects.toml",
                Path(log_sources_path)
                if log_sources_path
                else Path.home() / ".config" / "chinescan" / "log-sources.toml",
            ],
        )
        malware_jobs = MalwareDashboardManager(repository, backend, sample_registry)
        malware_diagnostic = (
            "Execution unavailable: Windows Job Object containment is required."
            if not malware_jobs.execution_available
            else ""
        )
    except (ManagedSampleError, OSError, ValueError):
        malware_diagnostic = "Managed storage or operator registry configuration is unavailable."
    if malware_jobs is not None and sample_registry is not None:
        malware_evidence_store = MalwareEvidenceStore(
            repository,
            malware_jobs.manager.store,
            engagement_security_service,
            organization_quota_bytes=active_settings.malware_evidence_org_quota_bytes,
        )
        execution_governance.adapters.register(
            GovernedMalwareStaticTriageAdapter(repository, malware_evidence_store)
        )

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        local_worker_managers = (
            jobs,
            chain_jobs,
            log_jobs,
            project_malware_jobs,
        )
        started_local_workers: list[Any] = []
        for manager in local_worker_managers:
            try:
                manager.start()
            except StorageError:
                # A local worker is unavailable until operator bootstrap has established
                # the personal organization. Keep diagnostic/auth endpoints available.
                logging.getLogger("chinescan.worker").warning(
                    "local_worker_start_denied", extra={"worker": type(manager).__name__}
                )
            else:
                started_local_workers.append(manager)
        if start_governed_worker and os.environ.get("CHINESCAN_STANDALONE_WORKER") != "1":
            governed_domain_worker.start()
        github_imports.start_worker()
        if malware_jobs is not None:
            try:
                malware_jobs.start()
                started_local_workers.append(malware_jobs)
            except StorageError:
                logging.getLogger("chinescan.worker").warning(
                    "local_worker_start_denied",
                    extra={"worker": type(malware_jobs).__name__},
                )
        try:
            yield
        finally:
            governed_domain_worker.stop()
            github_imports.stop_worker()
            for manager in reversed(started_local_workers):
                stop = getattr(manager, "stop", None) or getattr(manager, "stop_worker", None)
                if stop is not None:
                    stop()
        repository.close()

    application = FastAPI(
        title="ChiNeScan local dashboard", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    allowed_origins = tuple(active_settings.cors_allowed_origins)
    if allowed_origins:
        # Credentials are required for the existing HttpOnly session cookie.
        # Never combine credentialed CORS with a wildcard origin.
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
            expose_headers=[],
        )
    application.state.repository = repository
    application.state.project_registry = registry
    application.state.chain_job_manager = chain_jobs
    application.state.project_service = project_service
    application.state.repository_assessment_service = repository_assessment_service
    application.state.repository_snapshot_store = repository_snapshot_store
    application.state.log_evidence_store = log_evidence_store
    application.state.log_location_service = log_location_service
    application.state.log_source_registry = log_registry
    application.state.log_job_manager = log_jobs
    application.state.malware_job_manager = malware_jobs
    application.state.malware_evidence_store = malware_evidence_store
    application.state.project_malware_job_manager = project_malware_jobs
    application.state.github_import_manager = github_imports
    application.state.dashboard_alerts = dashboard_alerts
    application.state.dashboard_intelligence = dashboard_intelligence
    application.state.organization_service = organization_service
    application.state.identity_service = identity_service
    application.state.engagement_security_service = engagement_security_service
    application.state.execution_governance = execution_governance
    application.state.governed_domain_worker = governed_domain_worker
    application.state.nmap_adapter = nmap_adapter
    application.state.session_store = sessions
    application.state.local_operator_user_id = organization_service.operator_user_id
    application.state.started_at = time.monotonic()
    application.state.diagnostic_errors = []

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> Response:
        # Pydantic errors may contain submitted values (including login passwords).
        details = [
            {
                "type": item.get("type", "invalid_request"),
                "loc": item.get("loc", []),
                "msg": redact(item.get("msg", "Invalid request.")),
            }
            for item in exc.errors()
        ]
        return Response(
            content=json.dumps({"detail": details}),
            status_code=422,
            media_type="application/json",
        )

    @application.exception_handler(HTTPException)
    async def safe_http_error_handler(_request: Request, exc: HTTPException) -> Response:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": redact(exc.detail)},
            headers=exc.headers,
        )

    @application.exception_handler(Exception)
    async def safe_internal_error_handler(request: Request, _exc: Exception) -> Response:
        route = request.scope.get("route")
        logging.getLogger("chinescan.errors").error(
            "request_failed",
            extra={
                "request_id": getattr(request.state, "request_id", "unknown"),
                "route": getattr(route, "path", "unmatched"),
            },
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "The request could not be completed."},
        )

    @application.middleware("http")
    async def loopback_and_origin_guard(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # The version prefix is an alias only; all existing route dependencies,
        # authentication checks, and response filtering remain shared.
        if request.url.path.startswith("/api/v1/"):
            rewritten = "/api/" + request.url.path[len("/api/v1/") :]
            request.scope["path"] = rewritten
            request.scope["raw_path"] = rewritten.encode("ascii", errors="ignore")
        request_id = str(uuid4())
        request.state.request_id = request_id
        started = time.monotonic()
        host = request.headers.get("host", "")
        client_ip = request.client.host if request.client else ""
        if not _loopback_host(host) or not _loopback_host(client_ip):
            result = Response("Local loopback access required.", status_code=400)
            result.headers["X-Request-ID"] = request_id
            return result

        def origin_matches_request(origin: str) -> bool:
            parsed_origin = urlsplit(origin)
            if (
                parsed_origin.path not in {"", "/"}
                or parsed_origin.query
                or parsed_origin.fragment
                or parsed_origin.username
                or parsed_origin.password
            ):
                return False
            if (
                parsed_origin.scheme == request.url.scheme
                and parsed_origin.netloc.lower() == host.lower()
            ):
                return True
            if not active_settings.trusted_proxy:
                return False
            forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
            forwarded_host = request.headers.get("x-forwarded-host", "").split(",", 1)[0].strip()
            if forwarded_proto != "https" or not forwarded_host:
                return False
            forwarded_origin = f"{forwarded_proto}://{forwarded_host.lower()}"
            configured_origins = {
                configured.rstrip("/").lower()
                for configured in active_settings.cors_allowed_origins
            }
            return (
                origin.rstrip("/").lower() in configured_origins
                and origin.rstrip("/").lower() == forwarded_origin
            )

        if request.url.path.startswith("/api/fs/"):
            origin = request.headers.get("origin")
            if origin and not origin_matches_request(origin):
                result = Response("Same-origin request required.", status_code=403)
                result.headers["X-Request-ID"] = request_id
                return result
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                maximum_body = (
                    2_100_000
                    if request.url.path == "/api/chain/jobs"
                    else MAX_EXTERNAL_REPORT_BYTES
                    if request.url.path.endswith("/external-reports")
                    else 8192
                )
                if int(content_length) > maximum_body:
                    result = Response("Request body is too large.", status_code=413)
                    result.headers["X-Request-ID"] = request_id
                    return result
            except ValueError:
                result = Response("Invalid request framing.", status_code=400)
                result.headers["X-Request-ID"] = request_id
                return result
        if request.headers.get("transfer-encoding"):
            result = Response("Chunked request bodies are not accepted.", status_code=400)
            result.headers["X-Request-ID"] = request_id
            return result
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if not origin:
                result = Response("Same-origin request required.", status_code=403)
                result.headers["X-Request-ID"] = request_id
                return result
            if not origin_matches_request(origin):
                result = Response("Same-origin request required.", status_code=403)
                result.headers["X-Request-ID"] = request_id
                return result
        if request.url.path.startswith("/api/"):
            path = request.url.path
            if path in {
                "/api/auth/login",
                "/api/auth/signup",
                "/api/auth/forgot-password",
                "/api/auth/reset-password",
                "/api/auth/first-superuser/setup",
            }:
                category = "auth"
            elif "/report/" in path or "/export/" in path or "/exports/" in path:
                category = "exports"
            elif request.method == "GET":
                category = "reads"
            else:
                category = "job_start"
            client_key = request.client.host if request.client else "unknown"
            if active_settings.trusted_proxy:
                forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
                if forwarded:
                    client_key = forwarded[:64]
            retry = rate_limiter.check(category, client_key)
            if retry:
                limited = JSONResponse(
                    status_code=429,
                    content={
                        "detail": {
                            "code": "rate_limited",
                            "message": "Request limit reached; retry shortly.",
                        }
                    },
                    headers={"Retry-After": str(retry)},
                )
                limited.headers["X-Request-ID"] = request_id
                limited.headers["X-API-Version"] = "1"
                limited.headers["X-Content-Type-Options"] = "nosniff"
                limited.headers["X-Frame-Options"] = "DENY"
                limited.headers["Referrer-Policy"] = "no-referrer"
                limited.headers["Content-Security-Policy"] = (
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none'"
                )
                return limited
        path = request.url.path
        organization_api = path.startswith("/api/organizations/") or path == "/api/organizations"
        identity_api = (
            path == "/api/auth/me"
            or path
            in {
                "/api/auth/session",
                "/api/auth/csrf",
                "/api/auth/password/change",
                "/api/auth/totp",
                "/api/auth/totp/enroll",
                "/api/auth/totp/confirm",
                "/api/auth/totp/disable",
                "/api/auth/totp/recovery-codes",
                "/api/ready",
                "/api/diagnostics",
            }
            or path.startswith("/api/auth/users/")
        )
        public_auth_api = path in {
            "/api/auth/login",
            "/api/auth/signup",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/invitations/accept",
        } or (path == "/api/auth/first-superuser/setup" and request.method == "POST")
        unsupported_version_alias = path.startswith("/api/v") and not path.startswith("/api/v1/")
        has_matching_api_route = any(
            route.matches(request.scope)[0] is not Match.NONE for route in application.router.routes
        )
        if (
            path.startswith("/api/")
            and has_matching_api_route
            and path != "/api/health"
            and not unsupported_version_alias
            and not (organization_api or identity_api or public_auth_api)
        ):
            opaque = request.cookies.get(COOKIE_NAME)
            session = sessions.get(opaque)
            if session is None:
                denied = JSONResponse(
                    status_code=401, content={"detail": "Authentication required."}
                )
                denied.headers["X-Request-ID"] = request_id
                denied.headers["X-API-Version"] = "1"
                return denied
            if not session.user_id:
                denied = JSONResponse(
                    status_code=401, content={"detail": "Authentication required."}
                )
                denied.headers["X-Request-ID"] = request_id
                denied.headers["X-API-Version"] = "1"
                return denied
            organization_member_resource = path in {
                "/api/scans",
                "/api/cases",
                "/api/findings",
                "/api/reports",
            } or any(
                path.startswith(prefix)
                for prefix in ("/api/scans/", "/api/cases/", "/api/findings/", "/api/reports/")
            )
            operator_only_prefixes = (
                "/api/projects",
                "/api/code",
                "/api/log",
                "/api/malware",
                "/api/chain",
                "/api/alerts",
                "/api/dashboard",
                "/api/github",
                "/api/fs",
                "/api/organization-migration-report",
                "/api/organization-bootstrap-report",
            )
            if not organization_member_resource and (
                not organization_service.operator_user_id
                or session.user_id != organization_service.operator_user_id
            ):
                denied = JSONResponse(
                    status_code=403, content={"detail": "Local operator access required."}
                )
                denied.headers["X-Request-ID"] = request_id
                denied.headers["X-API-Version"] = "1"
                return denied
            selected = request.headers.get("x-chinescan-organization-id")
            organization_id = organization_service.membership_context(session.user_id, selected)
            if organization_id is None:
                denied = JSONResponse(status_code=404, content={"detail": "Resource not found."})
                denied.headers["X-Request-ID"] = request_id
                denied.headers["X-API-Version"] = "1"
                return denied
            if path.startswith(operator_only_prefixes):
                personal_id = organization_service.personal_organization_id(session.user_id)
                if not personal_id or organization_id != personal_id:
                    denied = JSONResponse(
                        status_code=404, content={"detail": "Resource not found."}
                    )
                    denied.headers["X-Request-ID"] = request_id
                    denied.headers["X-API-Version"] = "1"
                    return denied
            request.state.organization_id = organization_id
            organization_scoped_resource = organization_member_resource or path.startswith(
                operator_only_prefixes
            )
            if organization_scoped_resource:
                membership_role = organization_service.membership_role(
                    session.user_id, organization_id
                )
                if request.method in {"POST", "PUT", "PATCH", "DELETE"} and membership_role not in {
                    "owner",
                    "admin",
                    "member",
                }:
                    denied = JSONResponse(
                        status_code=403,
                        content={"detail": "Organization role does not allow this action."},
                    )
                    denied.headers["X-Request-ID"] = request_id
                    denied.headers["X-API-Version"] = "1"
                    return denied
                authorization_scope = repository.member_context(
                    organization_id,
                    session.user_id,
                    write=request.method in {"POST", "PUT", "PATCH", "DELETE"},
                )
            else:
                authorization_scope = repository.organization_context(organization_id)
            with authorization_scope:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-API-Version"] = "1"
        route = request.scope.get("route")
        if response.status_code >= 400 and request.url.path.startswith("/api/"):
            error_ring = application.state.diagnostic_errors
            error_ring.append(
                {
                    "error_code": f"http_{response.status_code}",
                    "route": str(getattr(route, "path", "unmatched"))[:120],
                    "request_id": request_id,
                    "timestamp": datetime.now().astimezone().isoformat(),
                    "message": "Request could not be completed."
                    if response.status_code >= 500
                    else "Request was rejected.",
                }
            )
            del error_ring[:-50]
        duration_ms = round((time.monotonic() - started) * 1000, 2)
        access_logger = logging.getLogger("chinescan.access")
        access_logger.info(
            "request_complete",
            extra={
                "request_id": request_id,
                "method": request.method,
                "route": getattr(route, "path", request.url.path),
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        if duration_ms >= 1000:
            access_logger.warning(
                "slow_request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "route": getattr(route, "path", request.url.path),
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "private, no-store"
        return response

    def current_session(token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> Session:
        session = sessions.get(token)
        if session is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        if (
            session.user_id
            and organization_service.operator_user_id
            and session.user_id == organization_service.operator_user_id
            and operator_status(credentials) == "active"
        ):
            identity_service.migrate_operator_credentials(credentials, session.user_id)
        persistent_user = (
            organization_service.get_active_user(session.user_id) if session.user_id else None
        )
        if not persistent_user or not secrets.compare_digest(
            persistent_user["auth_epoch"], session.auth_epoch
        ):
            sessions.revoke(token)
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session

    diagnostics_throttle = LoginThrottle(limit=12, window_seconds=60)

    def allow_diagnostics(request: Request) -> None:
        key = "diagnostics:" + (request.client.host if request.client else "unknown")
        if not diagnostics_throttle.allowed(key):
            raise HTTPException(
                status_code=429, detail="Diagnostics rate limit reached; retry shortly."
            )

    def require_local_operator_diagnostics(session: Session) -> None:
        if (
            not organization_service.operator_user_id
            or session.user_id != organization_service.operator_user_id
        ):
            raise HTTPException(status_code=404, detail="Resource not found.")

    @application.get("/api/health")
    def health() -> dict[str, Any]:
        return health_report(started_at=application.state.started_at, bind_address="127.0.0.1")

    @application.get("/api/ready")
    def ready(request: Request, session: Session = Depends(current_session)) -> Response:  # noqa: B008
        require_local_operator_diagnostics(session)
        allow_diagnostics(request)
        report = build_report(
            settings=active_settings,
            database_path=database_path,
            credential_path=credentials,
            frontend_dist=FRONTEND_DIST,
            errors=application.state.diagnostic_errors,
        )
        readiness_ids = {
            "config",
            "credentials",
            "database",
            "directories",
            "frontend",
            "filesystem-policy",
            "managed-malware",
        }
        checks = [dict(item) for item in report["checks"] if item["id"] in readiness_ids]
        if report["operator_state"] != "active":
            for item in checks:
                if item["id"] == "credentials":
                    item["state"] = "FAIL"
                    item["detail"] = "Credential store is not active and schema-valid."
                    item["action_hint"] = "Create or migrate the local operator credential store."
        failures = any(item["state"] == "FAIL" for item in checks)
        warnings = any(item["state"] == "WARN" for item in checks)
        state = "failed" if failures else "degraded" if warnings else "ok"
        response = JSONResponse(
            {"state": state, "checks": checks, "allowed_roots": report["allowed_roots"]},
            status_code=503 if failures else 200,
        )
        return response

    @application.get("/api/diagnostics")
    def diagnostics(
        request: Request,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        require_local_operator_diagnostics(session)
        allow_diagnostics(request)
        return build_report(
            settings=active_settings,
            database_path=database_path,
            credential_path=credentials,
            frontend_dist=FRONTEND_DIST,
            errors=application.state.diagnostic_errors,
        )

    @application.get("/api/diagnostics/execution-resources")
    def execution_resource_diagnostics(
        request: Request,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        require_local_operator_diagnostics(session)
        allow_diagnostics(request)
        return execution_governance.get_global_resource_diagnostics()

    def require_csrf(
        request: Request,
        session: Session = Depends(current_session),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
        csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> Session:
        import secrets

        if not csrf_header or not secrets.compare_digest(session.csrf_token, csrf_header):
            if not session.user_id:
                raise HTTPException(status_code=401, detail="Authentication required.")
            dashboard_intelligence.record_security_signal(
                {
                    "key": "csrf-block:" + str(getattr(request.state, "request_id", uuid4())),
                    "kind": "authorization_block",
                    "summary": "A same-origin request failed the CSRF authorization check.",
                    "module": "Security Dashboard",
                }
            )
            raise HTTPException(status_code=403, detail="CSRF validation failed.")
        return session

    organization_router = create_organization_router(
        organization_service, current_session, require_csrf, identity=identity_service
    )
    application.router.routes.extend(organization_router.routes)

    engagement_security_router = create_engagement_security_router(
        engagement_security_service, current_session, require_csrf
    )
    application.router.routes.extend(engagement_security_router.routes)

    execution_router = create_execution_router(
        execution_governance, governed_domain_worker, current_session, require_csrf
    )
    application.router.routes.extend(execution_router.routes)

    nmap_router = create_nmap_router(
        execution_governance,
        governed_domain_worker,
        repository,
        active_settings.integrations.nmap,
        current_session,
        require_csrf,
    )
    application.router.routes.extend(nmap_router.routes)

    nuclei_router = create_nuclei_router(
        execution_governance,
        repository,
        active_settings.integrations.nuclei,
        current_session,
        require_csrf,
    )
    application.router.routes.extend(nuclei_router.routes)

    chain_execution_router = create_chain_execution_router(
        execution_governance, governed_domain_worker, current_session, require_csrf
    )
    application.router.routes.extend(chain_execution_router.routes)

    log_evidence_router = create_log_evidence_router(
        log_evidence_store,
        engagement_security_service,
        log_registry,
        execution_governance,
        current_session,
        require_csrf,
    )
    application.router.routes.extend(log_evidence_router.routes)

    repository_router = create_repository_router(
        repository_assessment_service,
        execution_governance,
        governed_domain_worker,
        current_session,
        require_csrf,
    )
    application.router.routes.extend(repository_router.routes)
    phase6_router = create_phase6_router(repository, current_session, require_csrf)
    application.router.routes.extend(phase6_router.routes)
    if malware_evidence_store is not None and sample_registry is not None:
        malware_evidence_router = create_malware_evidence_router(
            malware_evidence_store,
            engagement_security_service,
            sample_registry,
            execution_governance,
            current_session,
            require_csrf,
        )
        application.router.routes.extend(malware_evidence_router.routes)

    @application.get("/api/integrations/artex/status")
    def artex_status(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        """Return local bridge state without exposing configuration secrets or upstream data."""
        profile = active_settings.integrations.artex
        raw = repository.get("artex_sync_state", "artex:sync:health")
        try:
            state = (
                ArtexSyncState.model_validate(raw)
                if raw
                else ArtexSyncState(state="disabled" if not profile.enabled else "unknown")
            )
        except ValidationError:
            state = ArtexSyncState(state="unknown", error_code="invalid_local_state")
        return {
            "integration": "ARTEX",
            "mode": profile.mode,
            "enabled": profile.enabled and profile.health_enabled,
            "configuration_ready": bool(
                profile.enabled
                and profile.health_enabled
                and profile.release_id
                and profile.base_url
            ),
            "authentication": "unsupported_health_only",
            "capabilities": ["health"] if profile.enabled and profile.health_enabled else [],
            "active_operations": False,
            "state": state.state,
            "checked_at": state.checked_at,
            "version": state.health.version if state.health else None,
            "error_code": state.error_code,
        }

    @application.get("/api/integrations/nmap/status")
    def nmap_status(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        """Return non-sensitive Nmap readiness without probing the local binary."""
        profile = active_settings.integrations.nmap
        isolation = isolation_status()
        isolation_ready = bool(
            not profile.require_hardened_isolation
            or (isolation["hardened_supported"] and isolation["network_isolation"])
        )
        return {
            "integration": "Nmap",
            "enabled": profile.enabled,
            "configuration_ready": bool(profile.enabled and profile.binary and isolation_ready),
            "readiness_code": (
                None
                if isolation_ready
                else (
                    "hardened_isolation_unavailable"
                    if not isolation["hardened_supported"]
                    else "network_isolation_unavailable"
                )
            ),
            "profiles": [
                "host_discovery",
                "basic_port_assessment",
                "service_identification",
            ],
            "target_types": ["ip", "cidr"],
            "hostname_targets_supported": False,
            "isolation": isolation,
        }

    @application.get("/api/integrations/nuclei/status")
    def nuclei_status(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        """Return non-sensitive Nuclei readiness and approved-template metadata."""
        profile = active_settings.integrations.nuclei
        isolation = isolation_status()
        isolation_ready = bool(
            not profile.require_hardened_isolation
            or (isolation["hardened_supported"] and isolation["network_isolation"])
        )
        return {
            "integration": "Nuclei",
            "enabled": profile.enabled,
            "configuration_ready": bool(
                profile.enabled
                and profile.binary
                and profile.template_directory
                and isolation_ready
            ),
            "readiness_code": (
                None
                if isolation_ready
                else (
                    "hardened_isolation_unavailable"
                    if not isolation["hardened_supported"]
                    else "network_isolation_unavailable"
                )
            ),
            "profiles": nuclei_profile_listing(),
            "approved_templates": sorted(profile.approved_templates),
            "target_types": ["ip", "cidr"],
            "isolation": isolation,
        }

    @application.get("/api/integrations/artex/health")
    def artex_health(
        request: Request,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        """Perform exactly one read-only health request after explicit config enablement."""
        profile = active_settings.integrations.artex
        if not profile.enabled or not profile.health_enabled:
            raise HTTPException(status_code=403, detail={"code": "integration_disabled"})
        host = request.client.host if request.client else "unknown"
        retry_after = rate_limiter.check("artex", host)
        if retry_after:
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited"},
                headers={"Retry-After": str(retry_after)},
            )
        correlation_id = str(getattr(request.state, "request_id", uuid4()))

        def save_record(record_type: str, record_id: str, payload: dict[str, Any]) -> None:
            org_id = repository._current_organization_id()
            if org_id and session.user_id:
                with repository.member_context(org_id, session.user_id, write=True):
                    repository.save(record_type, record_id, payload)
            else:
                repository.save(record_type, record_id, payload)

        def audit(event: ArtexAuditEvent) -> None:
            save_record("artex_audit_event", event.event_id, event.model_dump(mode="json"))

        audit(
            ArtexAuditEvent(
                event_type="health_requested",
                outcome="started",
                correlation_id=correlation_id,
                operator_id=session.email,
                configured_release_id=profile.release_id,
            )
        )
        try:
            health = ArtexHealthClient(profile).get_health(correlation_id=correlation_id)
        except ArtexIntegrationError as exc:
            unavailable = exc.code == "upstream_unavailable"
            state = ArtexSyncState(
                state="unavailable" if unavailable else "invalid", error_code=exc.code
            )
            save_record("artex_sync_state", state.record_id, state.model_dump(mode="json"))
            audit(
                ArtexAuditEvent(
                    event_type="health_failed",
                    outcome="unavailable" if unavailable else "invalid",
                    correlation_id=correlation_id,
                    operator_id=session.email,
                    configured_release_id=profile.release_id,
                    error_code=exc.code,
                )
            )
            raise HTTPException(
                status_code=503, detail={"code": exc.code, "state": state.state}
            ) from None
        state = ArtexSyncState(
            state="available", checked_at=datetime.now().astimezone(), health=health
        )
        save_record("artex_sync_state", state.record_id, state.model_dump(mode="json"))
        audit(
            ArtexAuditEvent(
                event_type="health_succeeded",
                outcome="success",
                correlation_id=correlation_id,
                operator_id=session.email,
                configured_release_id=profile.release_id,
                upstream_version=health.version,
            )
        )
        return {
            "integration": "ARTEX",
            "state": "available",
            "health": health.model_dump(),
            "read_only": True,
        }

    def github_import_enabled() -> None:
        if not active_settings.github_import_enabled:
            raise HTTPException(
                status_code=403,
                detail={"code": "feature_disabled", "message": "GitHub import is disabled."},
            )

    github_import_throttle = LoginThrottle(limit=10, window_seconds=60)

    def github_import_error(exc: GitHubImportError) -> HTTPException:
        status_code = (
            422
            if exc.code in {"invalid_url", "invalid_ref", "invalid_name"}
            else 429
            if exc.code in {"queue_full", "rate_limited"}
            else 404
            if exc.code == "job_not_found"
            else 409
            if exc.code.startswith("preview_")
            else 503
            if exc.code == "git_missing"
            else 400
        )
        return HTTPException(status_code, detail={"code": exc.code, "message": str(exc)})

    def allow_github_import(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        if not github_import_throttle.allowed("github-import:" + client_ip):
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "GitHub import rate limit reached."},
            )

    @application.get("/api/github/status")
    def github_import_status_info(
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        return {
            "enabled": active_settings.github_import_enabled,
            "git_available": shutil.which("git") is not None,
            "max_bytes": active_settings.github_import_max_bytes,
            "max_files": active_settings.github_import_max_files,
            "max_projects": active_settings.github_import_max_projects,
            "timeout_seconds": active_settings.github_import_timeout_seconds,
        }

    @application.post("/api/github/previews")
    def github_preview(
        payload: GitHubPreviewRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        allow_github_import(request)
        try:
            return github_imports.preview(
                session_binding(session.csrf_token), payload.url, payload.ref
            )
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    @application.post("/api/github/imports", status_code=202)
    def github_import(
        payload: GitHubImportRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        allow_github_import(request)
        try:
            return github_imports.start(
                session_binding(session.csrf_token),
                payload.preview_id,
                payload.name,
                replace_project_id=payload.replace_project_id,
                replace_confirmation=payload.replace_confirmation,
            )
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    @application.get("/api/github/imports/{job_id}")
    def github_import_status(
        job_id: str,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        try:
            return github_imports.get(session_binding(session.csrf_token), job_id)
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    @application.post("/api/github/imports/{job_id}/cancel")
    def github_import_cancel(
        job_id: str,
        _request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        github_import_enabled()
        allow_github_import(_request)
        try:
            return github_imports.cancel(session_binding(session.csrf_token), job_id)
        except GitHubImportError as exc:
            raise github_import_error(exc) from exc

    auth_lockout = ProgressiveLockout(engine=repository.engine)

    def lockout_keys(request: Request, email: str) -> list[str]:
        ip = request.client.host if request.client else "unknown"
        return [f"ip:{ip}", f"email:{email.casefold()}"]

    def lockout_response(retry: int) -> HTTPException:
        return HTTPException(
            status_code=429,
            detail="Authentication request could not be completed. Try again later.",
            headers={"Retry-After": str(max(1, retry))},
        )

    @application.get("/api/auth/session", response_model=AuthStatusResponse)
    def auth_session(token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> dict[str, Any]:
        session = sessions.get(token)
        if session is not None:
            if (
                session.user_id
                and organization_service.operator_user_id
                and session.user_id == organization_service.operator_user_id
                and operator_status(credentials) == "active"
            ):
                identity_service.migrate_operator_credentials(credentials, session.user_id)
            persistent_user = (
                organization_service.get_active_user(session.user_id) if session.user_id else None
            )
            if not persistent_user or not secrets.compare_digest(
                persistent_user["auth_epoch"], session.auth_epoch
            ):
                sessions.revoke(token)
                session = None
        email = session.email if session else None
        local, separator, domain = email.partition("@") if email else ("", "", "")
        masked = f"{local[:1]}***{separator}{domain}" if separator else None
        return {
            "authenticated": session is not None,
            "email_masked": masked,
            "signup_available": operator_status(credentials) == "none",
        }

    @application.get("/api/auth/csrf")
    def auth_csrf(session: Session = Depends(current_session)) -> dict[str, str]:  # noqa: B008
        return {"csrf_token": session.csrf_token}

    @application.post("/api/auth/login", response_model=AuthSessionResponse)
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        if operator_status(credentials) == "active":
            try:
                op_email = operator_email(credentials)
                if op_email and normalize_email(payload.email) == op_email:
                    stable_identity = operator_identity_id(credentials)
                    if stable_identity is None:
                        stable_identity = ensure_operator_identity_id(
                            credentials,
                            organization_service.user_id_for_email(op_email) or str(uuid4()),
                        )
                    op_epoch = operator_auth_epoch(credentials)
                    effective_epoch = identity_service.active_auth_epoch_for_operator(
                        stable_identity, op_epoch
                    )
                    op_user, _op_org = organization_service.ensure_operator(
                        op_email, effective_epoch, stable_identity
                    )
                    identity_service.migrate_operator_credentials(credentials, op_user["id"])
            except Exception:
                pass
        user = identity_service.authenticate(payload.email, payload.password, payload.totp_code)
        if user is None:
            retry = auth_lockout.fail(keys)
            now = time.monotonic()
            scope = hashlib.sha256("|".join(keys).encode("utf-8", errors="replace")).hexdigest()
            failures = auth_failure_windows.setdefault(scope, deque())
            while failures and failures[0] <= now - 300:
                failures.popleft()
            failures.append(now)
            if len(failures) >= 5:
                dashboard_intelligence.record_security_signal(
                    dashboard_intelligence.repeated_auth_signal(scope)
                )
            if retry:
                raise lockout_response(retry)
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        auth_lockout.succeed(keys)
        sessions.revoke(request.cookies.get(COOKIE_NAME))
        opaque, session = sessions.create(
            user["email_normalized"], user["auth_epoch"], user_id=user["id"]
        )
        if (
            organization_service.operator_user_id is None
            and operator_status(credentials) == "active"
            and operator_email(credentials) == user["email_normalized"]
        ):
            application.state.local_operator_user_id = user["id"]
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        return {"email": session.email, "csrf_token": session.csrf_token}

    @application.post("/api/auth/signup", response_model=AuthSessionResponse, status_code=201)
    def signup(payload: SignupRequest, request: Request, response: Response) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        try:
            create_operator(credentials, payload.email, payload.password)
        except CredentialError:
            retry = auth_lockout.fail(keys)
            if retry:
                raise lockout_response(retry) from None
            raise HTTPException(
                status_code=400, detail="Account cannot be created with these details."
            ) from None
        auth_lockout.succeed(keys)
        try:
            stored_email = normalize_email(payload.email)
            stable_identity = operator_identity_id(credentials)
            if stable_identity is None:
                stable_identity = ensure_operator_identity_id(credentials, str(uuid4()))
            user, _personal_org = organization_service.ensure_operator(
                stored_email, operator_auth_epoch(credentials), stable_identity
            )
            identity_service.migrate_operator_credentials(credentials, user["id"])
        except Exception:
            # The credential source remains intact; application startup/login
            # retries the idempotent identity bootstrap and never rolls it back.
            raise HTTPException(
                status_code=503, detail="Account identity is temporarily unavailable."
            ) from None
        opaque, session = sessions.create(
            stored_email, operator_auth_epoch(credentials), user_id=user["id"]
        )
        application.state.local_operator_user_id = user["id"]
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        return {"email": session.email, "csrf_token": session.csrf_token}

    @application.post("/api/auth/forgot-password", response_model=dict[str, str], status_code=202)
    def forgot_password(payload: ForgotPasswordRequest, request: Request) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        perform_dummy_verification(payload.email)
        auth_lockout.fail(keys)
        return {
            "status": (
                "If the account exists, reset instructions are prepared. Run "
                "`uv run chinescan web reset-password --email <email>` on this machine."
            )
        }

    @application.post("/api/auth/reset-password", response_model=dict[str, str])
    def reset_password(payload: ResetPasswordRequest, request: Request) -> dict[str, str]:
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        if not reset_operator_password(credentials, payload.email, payload.token, payload.password):
            retry = auth_lockout.fail(keys)
            if retry:
                raise lockout_response(retry)
            raise HTTPException(
                status_code=400, detail="Reset could not be completed. Request a new local token."
            )
        auth_lockout.succeed(keys)
        if organization_service.operator_user_id:
            identity_service.migrate_operator_credentials(
                credentials, organization_service.operator_user_id
            )
        sessions.revoke_all()
        return {"status": "Password reset. Sign in with your new password."}

    @application.post(
        "/api/auth/first-superuser/setup",
        response_model=AuthSessionResponse,
        status_code=201,
    )
    def first_superuser_setup(
        payload: FirstSuperuserSetupRequest, request: Request, response: Response
    ) -> dict[str, str]:
        """Consume the one-time deployment bootstrap token exactly once."""
        if not isinstance(repository, PostgresRepository):
            raise HTTPException(
                status_code=503,
                detail="First administrator setup requires the reviewed PostgreSQL deployment.",
            )
        keys = lockout_keys(request, payload.email)
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        if payload.email != FIRST_SUPERUSER_EMAIL:
            perform_dummy_verification(payload.password)
            auth_lockout.fail(keys)
            raise HTTPException(status_code=400, detail="Account setup cannot be completed.")
        try:
            user_id = complete_first_superuser_setup(
                repository.engine, payload.token, payload.password
            )
            user = organization_service.get_active_user(user_id)
            if not user or user.get("platform_role") != "superuser":
                raise FirstSuperuserBootstrapError("Administrator identity is unavailable.")
        except FirstSuperuserBootstrapError:
            auth_lockout.fail(keys)
            raise HTTPException(
                status_code=400, detail="Account setup cannot be completed."
            ) from None
        auth_lockout.succeed(keys)
        sessions.revoke_user_sessions(user_id)
        opaque, session = sessions.create(
            user["email_normalized"], user["auth_epoch"], user_id=user_id
        )
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        application.state.local_operator_user_id = user_id
        organization_service.operator_user_id = user_id
        return {"email": session.email, "csrf_token": session.csrf_token}

    @application.post("/api/auth/logout", response_model=dict[str, str])
    def logout(
        response: Response,
        _session: Session = Depends(require_csrf),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> dict[str, str]:
        sessions.revoke(token)
        response.delete_cookie(
            COOKIE_NAME, path="/", secure=secure_cookie, httponly=True, samesite="strict"
        )
        return {"status": "logged_out"}

    @application.post("/api/auth/invitations/accept", status_code=200)
    def accept_invitation(
        payload: InvitationAcceptRequest,
        request: Request,
        response: Response,
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> dict[str, Any]:
        ip = request.client.host if request.client else "unknown"
        keys = [f"invite-ip:{ip}"]
        retry = auth_lockout.retry_after(keys)
        if retry:
            raise lockout_response(retry)
        authenticated_user_id: str | None = None
        existing_session = sessions.get(token)
        if existing_session and existing_session.user_id:
            active = organization_service.get_active_user(existing_session.user_id)
            if active and secrets.compare_digest(active["auth_epoch"], existing_session.auth_epoch):
                authenticated_user_id = active["id"]
        try:
            accepted = identity_service.accept_invitation(
                payload.token,
                password=payload.password,
                display_name=payload.display_name,
                authenticated_user_id=authenticated_user_id,
            )
        except IdentityError as exc:
            retry = auth_lockout.fail(keys)
            if retry:
                raise lockout_response(retry) from None
            raise HTTPException(status_code=400, detail=str(exc)) from None
        auth_lockout.succeed(keys)
        user = accepted["user"]
        opaque, session = sessions.rotate(
            token, user["email_normalized"], user["auth_epoch"], user_id=user["id"]
        )
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        return {
            "email": session.email,
            "csrf_token": session.csrf_token,
            "organization_id": accepted["organization_id"],
            "role": accepted["role"],
        }

    @application.post("/api/auth/password/change")
    def change_password(
        payload: PasswordChangeRequest,
        response: Response,
        session: Session = Depends(current_session),  # noqa: B008
        _csrf: Session = Depends(require_csrf),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> dict[str, str]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            new_epoch = identity_service.change_password(
                session.user_id, payload.current_password, payload.new_password
            )
        except IdentityError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if new_epoch is None:
            raise HTTPException(status_code=401, detail="Current password is invalid.")
        sessions.revoke_user_sessions(session.user_id)
        opaque, rotated = sessions.create(session.email, new_epoch, user_id=session.user_id)
        response.set_cookie(
            COOKIE_NAME,
            opaque,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
            max_age=absolute_ttl_seconds,
            path="/",
        )
        return {"status": "password_changed", "csrf_token": rotated.csrf_token}

    @application.get("/api/auth/totp")
    def totp_status(session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return identity_service.totp_status(session.user_id)

    @application.post("/api/auth/totp/enroll")
    def totp_enroll(
        session: Session = Depends(current_session),  # noqa: B008
        _csrf: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            secret = identity_service.start_totp_enrollment(session.user_id)
        except IdentityError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        from urllib.parse import quote

        label = quote(session.email)
        uri = f"otpauth://totp/ChiNeScan:{label}?secret={secret}&issuer=ChiNeScan"
        return {"secret": secret, "otpauth_uri": uri}

    @application.post("/api/auth/totp/confirm")
    def totp_confirm(
        payload: TotpCodeRequest,
        session: Session = Depends(current_session),  # noqa: B008
        _csrf: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        codes = identity_service.confirm_totp_enrollment(session.user_id, payload.code)
        if codes is None:
            raise HTTPException(status_code=400, detail="Authenticator verification failed.")
        return {"totp_enabled": True, "recovery_codes": codes}

    @application.post("/api/auth/totp/disable")
    def totp_disable(
        payload: TotpCodeRequest,
        session: Session = Depends(current_session),  # noqa: B008
        _csrf: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        if not identity_service.disable_totp(session.user_id, payload.code):
            raise HTTPException(status_code=400, detail="Authenticator verification failed.")
        return {"totp_enabled": False}

    @application.post("/api/auth/totp/recovery-codes")
    def totp_regenerate_recovery_codes(
        payload: TotpCodeRequest,
        session: Session = Depends(current_session),  # noqa: B008
        _csrf: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        codes = identity_service.regenerate_recovery_codes(session.user_id, payload.code)
        if codes is None:
            raise HTTPException(status_code=400, detail="Authenticator verification failed.")
        return {"recovery_codes": codes}

    @application.patch("/api/auth/users/{user_id}/status")
    def update_user_status(
        user_id: str,
        payload: AccountStatusRequest,
        session: Session = Depends(current_session),  # noqa: B008
        _csrf: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            updated = identity_service.set_account_status(session.user_id, user_id, payload.status)
        except IdentityError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if updated is None:
            raise HTTPException(status_code=404, detail="Resource not found.")
        return {
            key: updated[key]
            for key in ("id", "email_normalized", "display_name", "status", "updated_at")
        }

    @application.get("/api/overview", response_model=OverviewResponse)
    def overview(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        with db_lock:
            scan_page, scan_count = repository.page_records(
                "scan", limit=5, offset=0, sort_by="started_at", descending=True
            )
            finding_count = repository.count_records("finding")
            grouped = repository.count_records("finding", group_by="severity")
            grouped_verdict = repository.count_records("finding", group_by="verdict")
            top_findings, _ = repository.page_records(
                "finding", limit=100, offset=0, sort_by="severity", descending=True
            )
        counts = {severity.value: int(grouped.get(severity.value, 0)) for severity in Severity}
        verdict_counts = {
            name: int(grouped_verdict.get(name, 0)) for name in ("confirmed", "likely", "lead")
        }
        top_fix_first = [
            {
                "title": str(item.get("title", "Finding"))[:160],
                "severity": str(item.get("severity", "info")),
                "location": str(item.get("location") or "unspecified")[:240],
            }
            for item in top_findings
            if item.get("verdict", "lead") in {"confirmed", "likely"}
        ][:5]
        recent = [Scan.model_validate(item) for item in scan_page]
        return {
            "scan_count": scan_count,
            "finding_count": finding_count,
            "findings_by_severity": counts,
            "findings_by_verdict": verdict_counts,
            "top_fix_first": top_fix_first,
            "recent_scans": [_scan_summary(scan) for scan in recent],
        }

    @application.get("/api/projects")
    def list_projects(_session: Session = Depends(current_session)) -> list[dict[str, Any]]:  # noqa: B008
        return project_service.list()

    @application.get("/api/projects/{project_id}")
    def get_project(
        project_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return project_service.get(project_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.get("/api/projects/{project_id}/browse")
    def browse_project_directory(
        project_id: str,
        request: Request,
        directory_id: Annotated[str | None, Query(min_length=32, max_length=128)] = None,
        session: Session = Depends(current_session),  # noqa: B008
        cursor: Annotated[str | None, Query(max_length=128)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            if directory_id is None:
                _, root = project_service.resolve(project_id)
                return fs_browser.project_root_view(session.csrf_token, root)
            selection = fs_browser.resolve_selection(
                session.csrf_token, "project_directory", directory_id
            )
            _, root = project_service.resolve(project_id)
            try:
                selection.relative_to(root)
            except ValueError as exc:
                raise ValueError("directory_unavailable") from exc
            return fs_browser.list_view(
                session.csrf_token, "project_directory", directory_id, cursor=cursor, limit=limit
            )
        except (ProjectError, ValueError) as exc:
            raise HTTPException(
                status_code=404, detail="Directory selection is unavailable."
            ) from exc

    @application.get("/api/projects/{project_id}/log-locations")
    def list_project_log_locations(
        project_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> list[dict[str, Any]]:  # noqa: B008
        try:
            return log_location_service.list(project_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.post("/api/projects/{project_id}/log-locations", status_code=201)
    def add_project_log_location(
        project_id: str,
        payload: ProjectLogLocationRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            capability: Literal["project_directory", "log_location"] = (
                "project_directory" if payload.scope == "project" else "log_location"
            )
            selected = fs_browser.resolve_selection(
                session.csrf_token, capability, payload.directory_id
            )
            return log_location_service.add(project_id, payload.name, selected, payload.scope)
        except (ProjectError, ValueError) as exc:
            code = exc.code if isinstance(exc, ProjectError) else "directory_unavailable"
            raise HTTPException(
                status_code=422,
                detail={
                    "code": code,
                    "message": str(exc)
                    if isinstance(exc, ProjectError)
                    else "The selected folder is unavailable.",
                },
            ) from exc

    @application.delete("/api/projects/{project_id}/log-locations/{location_id}")
    def remove_project_log_location(
        project_id: str,
        location_id: str,
        payload: ProjectLogLocationRemoveRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            location = next(
                item
                for item in log_location_service.list(project_id)
                if item["location_id"] == location_id
            )
            if payload.confirmation != location["name"]:
                raise ProjectError(
                    "confirmation_mismatch",
                    "Type the log location name exactly to confirm removal.",
                )
            log_location_service.remove(project_id, location_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=409 if exc.code == "confirmation_mismatch" else 404,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        except StopIteration as exc:
            raise HTTPException(status_code=404, detail="Log location not found.") from exc
        return {"status": "removed"}

    @application.post("/api/projects/{project_id}/log-suggestions")
    def project_log_suggestions(
        project_id: str,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return log_location_service.suggestions(project_id, _session.csrf_token)
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.post("/api/projects/{project_id}/log-suggestions/confirm", status_code=201)
    def confirm_project_log_suggestion(
        project_id: str,
        payload: LogSuggestionConfirmRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return log_location_service.confirm(
                project_id, payload.suggestion_id, payload.name, _session.csrf_token
            )
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.post(
        "/api/projects/{project_id}/log-jobs",
        response_model=LogJobResponse,
        status_code=202,
    )
    def create_project_log_job(
        project_id: str,
        payload: ProjectLogJobRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return log_jobs.submit_project(project_id, payload.location_ids)
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except LogSourceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="The log analysis queue is full.") from exc

    @application.post("/api/malware/acknowledgements", status_code=201)
    def issue_malware_acknowledgement(
        payload: MalwareAcknowledgementRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("malware-ack:" + client_ip):
            raise HTTPException(
                status_code=429, detail={"code": "rate_limited", "message": "Try again shortly."}
            )
        try:
            project_service.resolve(payload.project_id)
            return malware_acknowledgements.issue(
                payload.project_id, session.csrf_token, payload.confirmed
            )
        except ProjectError as exc:
            raise HTTPException(
                status_code=404, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except MalwareAcknowledgementError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc

    @application.get("/api/malware/host-hint")
    def malware_host_hint(_session: Session = Depends(current_session)) -> dict[str, str | bool]:  # noqa: B008
        import os
        import platform

        signals = " ".join(
            (
                platform.platform(),
                os.environ.get("PROCESSOR_IDENTIFIER", ""),
                os.environ.get("COMPUTERNAME", ""),
            )
        ).casefold()
        virtualized: bool | str = (
            True
            if any(
                token in signals for token in ("virtual", "vmware", "hyper-v", "kvm", "qemu", "xen")
            )
            else "unknown"
        )
        return {"virtualized": virtualized, "confidence": "low"}

    @application.post("/api/projects/{project_id}/malware-jobs", status_code=202)
    def start_project_malware_job(
        project_id: str,
        payload: ProjectMalwareJobRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("malware-job:" + client_ip):
            raise HTTPException(
                status_code=429, detail={"code": "rate_limited", "message": "Try again shortly."}
            )
        if not payload.acknowledgement_token:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "invalid_acknowledgement",
                    "message": "A valid project VM-risk acknowledgement is required.",
                },
            )
        try:
            malware_acknowledgements.consume(
                payload.acknowledgement_token, project_id, session.csrf_token
            )
            job = project_malware_jobs.submit(project_id)
            return _safe_project_malware_job(job)
        except MalwareAcknowledgementError as exc:
            raise HTTPException(
                status_code=403, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429,
                detail={"code": "queue_full", "message": "The project scan queue is full."},
            ) from exc

    @application.get("/api/projects/{project_id}/malware-jobs/{job_id}")
    def get_project_malware_job(
        project_id: str,
        job_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        job = project_malware_jobs.get(job_id)
        if job is None or job.get("project_id") != project_id:
            raise HTTPException(
                status_code=404,
                detail={"code": "job_not_found", "message": "Project malware job not found."},
            )
        return _safe_project_malware_job(job)

    @application.post("/api/projects", status_code=201)
    def add_project(
        payload: ProjectCreateRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return project_service.create_from_selection(
                payload.name, session.csrf_token, payload.directory_id
            )
        except (ProjectError, ValueError) as exc:
            code = exc.code if isinstance(exc, ProjectError) else "directory_unavailable"
            raise HTTPException(
                status_code=422,
                detail={
                    "code": code,
                    "message": str(exc)
                    if isinstance(exc, ProjectError)
                    else "The selected folder is unavailable.",
                },
            ) from exc

    @application.post("/api/projects/approve-folder", status_code=201)
    def approve_project_folder(
        payload: FolderApprovalRequest,
        request: Request,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        if payload.approved is not True:
            raise HTTPException(
                status_code=400,
                detail={"code": "approval_required", "message": "Explicit approval is required."},
            )
        try:
            project = project_service.create_from_folder_approval(
                session.csrf_token, payload.directory_id, payload.name
            )
            if payload.purpose == "logs":
                location = log_location_service.add_approved_root(str(project["project_id"]))
                return {**project, "log_location_id": location["location_id"]}
            return project
        except ProjectError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        except ValueError as exc:
            code = str(exc)
            raise HTTPException(
                status_code=422,
                detail={"code": code, "message": folder_approval_error(code)},
            ) from exc

    @application.delete("/api/projects/{project_id}")
    def remove_project(
        project_id: str,
        payload: ProjectRemoveRequest,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, str]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            project_service.remove(project_id, payload.confirmation)
        except ProjectError as exc:
            raise HTTPException(
                status_code=409, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        return {"status": "removed"}

    @application.post(
        "/api/projects/{project_id}/code-jobs", response_model=CodeJobResponse, status_code=202
    )
    def create_project_code_job(
        project_id: str,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        client_ip = request.client.host if request.client else ""
        if not project_throttle.allowed("projects:" + client_ip):
            raise HTTPException(status_code=429, detail="Project operation rate limit reached.")
        try:
            return jobs.submit(project_id)
        except ProjectError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429, detail="The code assessment queue is full."
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409, detail="An assessment is already queued or running."
            ) from exc

    @application.get("/api/code/projects", response_model=list[CodeProjectResponse])
    def code_projects(_session: Session = Depends(current_session)) -> list[dict[str, str]]:  # noqa: B008
        return project_service.code_projects()

    @application.post("/api/code/jobs", response_model=CodeJobResponse, status_code=202)
    def create_code_job(
        payload: CodeJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return jobs.submit(payload.project_id)
        except ProjectConfigurationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(
                status_code=429, detail="The code assessment queue is full."
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409,
                detail="An assessment for this project is already queued or running.",
            ) from exc

    @application.get("/api/code/jobs", response_model=CodeJobPageResponse)
    def list_code_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        items, total = jobs.list(limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/code/jobs/{job_id}", response_model=CodeJobResponse)
    def get_code_job(job_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        item = jobs.get(job_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Code assessment job not found.")
        return item

    @application.get("/api/malware/capability")
    def malware_capability(_session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        return {
            "execution_available": bool(malware_jobs and malware_jobs.execution_available),
            "diagnostic": (
                malware_jobs.execution_diagnostic if malware_jobs else malware_diagnostic
            ),
            "historical_views_available": True,
        }

    @application.get("/api/modules")
    def list_modules(_session: Session = Depends(current_session)) -> list[dict[str, object]]:  # noqa: B008
        return module_capabilities()

    @application.get("/api/dashboard/scores")
    def dashboard_scores(_session: Session = Depends(current_session)) -> list[dict[str, Any]]:  # noqa: B008
        return dashboard_intelligence.score_modules()

    @application.get("/api/alerts")
    def dashboard_alert_list(
        limit: int = Query(default=100, ge=1, le=200),
        include_resolved: bool = False,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> list[dict[str, Any]]:
        dashboard_intelligence.refresh_alerts()
        return dashboard_alerts.list_alerts(limit=limit, include_resolved=include_resolved)

    @application.get("/api/alerts/{alert_id}/audit")
    def dashboard_alert_audit(
        alert_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> list[dict[str, Any]]:
        if dashboard_alerts.get(alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return dashboard_alerts.audit(alert_id)

    @application.post("/api/alerts/{alert_id}/acknowledge")
    def acknowledge_dashboard_alert(
        alert_id: str,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return dashboard_alerts.transition(alert_id, "acknowledge", session.email)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Alert not found.") from exc
        except AlertStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/alerts/{alert_id}/snooze")
    def snooze_dashboard_alert(
        alert_id: str,
        payload: AlertSnoozeRequest,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return dashboard_alerts.transition(
                alert_id, "snooze", session.email, snoozed_until=payload.until.isoformat()
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Alert not found.") from exc
        except AlertStateError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/alerts/{alert_id}/resolve")
    def resolve_dashboard_alert(
        alert_id: str,
        session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            return dashboard_alerts.transition(alert_id, "resolve", session.email)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Alert not found.") from exc
        except AlertStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.get("/api/alerts/events")
    def dashboard_alert_events(
        request: Request,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
        after: int = Query(default=0, ge=0),
        session: Session = Depends(current_session),  # noqa: B008
        token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> StreamingResponse:
        try:
            cursor = max(after, int(last_event_id or "0"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid event cursor.") from None
        organization_id = getattr(request.state, "organization_id", None)
        user_id = session.user_id

        async def stream() -> AsyncIterator[str]:
            nonlocal cursor
            last_refresh = 0.0
            while not await request.is_disconnected():
                if sessions.get(token) is None:
                    yield "event: session-expired\ndata: {}\n\n"
                    return
                now_mono = time.monotonic()
                if now_mono - last_refresh >= 15:
                    if organization_id and user_id:
                        with repository.member_context(organization_id, user_id, write=False):
                            dashboard_intelligence.refresh_alerts()
                    last_refresh = now_mono
                items = dashboard_alerts.events_after(cursor)
                for item in items:
                    cursor = int(item["audit_id"])
                    payload = json.dumps(item, separators=(",", ":"))
                    yield f"id: {cursor}\nevent: alert\ndata: {payload}\n\n"
                if not items:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(5)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "private, no-store", "X-Accel-Buffering": "no"},
        )

    @application.get("/api/malware/samples", response_model=list[MalwareSampleResponse])
    def malware_samples(_session: Session = Depends(current_session)) -> list[dict[str, Any]]:  # noqa: B008
        if malware_jobs is None:
            raise HTTPException(status_code=503, detail="Sample registry is unavailable.")
        try:
            entries = malware_jobs.entries()
        except ManagedSampleError as exc:
            raise HTTPException(status_code=503, detail="Sample registry is unavailable.") from exc
        return [
            {**entry, "display_name": safe_display_name(str(entry["display_name"]))}
            for entry in entries
        ]

    @application.get("/api/malware/samples/{sample_id}", response_model=MalwareSampleResponse)
    def malware_sample_detail(
        sample_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        if len(sample_id) > 255:
            raise HTTPException(status_code=404, detail="Managed sample not found.")
        raw = repository.get("malware_sample", sample_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Managed sample not found.")
        availability = str(raw.get("availability", "unavailable"))
        if malware_jobs is None:
            availability = "unavailable"
        elif availability == "available":
            try:
                malware_jobs.manager.store.verify(
                    str(raw.get("object_key", "")), str(raw.get("sha256", ""))
                )
            except ManagedSampleError:
                availability = "unavailable"
                raw["availability"] = availability
                repository.save("malware_sample", sample_id, raw)
        return {
            "registry_id": str(raw.get("registry_id", ""))[:80],
            "display_name": safe_display_name(str(raw.get("display_name", "Sample"))),
            "state": "managed" if availability == "available" else "unavailable",
            "source_available": False,
            "source_size_bytes": None,
            "sample_id": str(raw.get("sample_id", "")),
            "sha256": str(raw.get("sha256", "")),
            "managed_size_bytes": raw.get("size_bytes")
            if isinstance(raw.get("size_bytes"), int)
            else None,
            "availability": availability,
        }

    @application.post("/api/malware/jobs", response_model=MalwareJobResponse, status_code=202)
    def create_malware_job(
        _payload: MalwareJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        raise HTTPException(
            status_code=410,
            detail={
                "code": "sample_workflow_deprecated",
                "message": (
                    "New sample-based jobs are deprecated. Scan an approved project after "
                    "acknowledging VM risk."
                ),
            },
        )

    @application.get("/api/malware/jobs", response_model=MalwareJobPageResponse)
    def list_malware_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:  # noqa: B008
        rows, total = repository.page_records(
            "malware_job", limit=limit, offset=offset, sort_by="created_at", descending=True
        )
        return {
            "items": [_malware_job_view(row, repository) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/malware/jobs/{job_id}", response_model=MalwareJobResponse)
    def get_malware_job(
        job_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        row = repository.get("malware_job", job_id) if len(job_id) <= 255 else None
        if row is None:
            raise HTTPException(status_code=404, detail="Malware job not found.")
        return _malware_job_view(row, repository)

    @application.get("/api/malware/analyses/{analysis_id}", response_model=MalwareAnalysisResponse)
    def get_malware_analysis(
        analysis_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        raw = repository.get("malware_analysis", analysis_id) if len(analysis_id) <= 255 else None
        if raw is None:
            raise HTTPException(status_code=404, detail="Malware analysis not found.")
        return _malware_analysis_view(raw)

    @application.get("/api/log/sources", response_model=list[LogSourceResponse])
    def log_sources(_session: Session = Depends(current_session)) -> list[dict[str, str]]:  # noqa: B008
        return log_registry.entries()

    @application.get("/api/log/sources/status")
    def log_sources_status(_session: Session = Depends(current_session)) -> dict[str, str]:  # noqa: B008
        status = log_registry.status()
        return {"status": status["status"], "reason": status["reason"]}

    @application.post("/api/log/jobs", response_model=LogJobResponse, status_code=202)
    def create_log_job(
        payload: LogJobCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            return log_jobs.submit(payload.source_id)
        except LogSourceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="The log analysis queue is full.") from exc

    @application.get("/api/log/jobs", response_model=LogJobPageResponse)
    def list_log_jobs(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        items, total = log_jobs.list(limit, offset)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @application.get("/api/log/jobs/{job_id}", response_model=LogJobResponse)
    def get_log_job(job_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        item = log_jobs.get(job_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Log analysis job not found.")
        return item

    def log_scan(scan_id: str) -> Scan:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        with db_lock:
            raw = repository.get("scan", scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        scan = Scan.model_validate(raw)
        if scan.scanner != "chinescan-log-analysis":
            raise HTTPException(status_code=404, detail="Log analysis not found.")
        return scan

    @application.get("/api/log/analyses/{scan_id}/alerts", response_model=AlertPageResponse)
    def log_alerts(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        severity: Annotated[str | None, Query(max_length=20)] = None,
    ) -> dict[str, Any]:
        if severity and severity not in {item.value for item in Severity}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("alert", scan.alert_ids)
        alerts = [Alert.model_validate(records[item]) for item in scan.alert_ids if item in records]
        if severity:
            alerts = [x for x in alerts if x.severity.value == severity]
        alerts.sort(key=lambda x: (x.severity.value, x.title.casefold(), x.alert_id))
        page = alerts[offset : offset + limit]
        return {
            "items": [_alert_summary(x) for x in page],
            "total": len(alerts),
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/log/analyses/{scan_id}/alerts/{alert_id}", response_model=AlertResponse)
    def log_alert_detail(
        scan_id: str,
        alert_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        scan = log_scan(scan_id)
        if alert_id not in scan.alert_ids:
            raise HTTPException(status_code=404, detail="Alert not found.")
        with db_lock:
            raw = repository.get("alert", alert_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return _alert_summary(Alert.model_validate(raw))

    @application.get("/api/log/analyses/{scan_id}/events", response_model=EventPageResponse)
    def log_events(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        source: Annotated[str | None, Query(max_length=100)] = None,
    ) -> dict[str, Any]:
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("event", scan.event_ids)
        events = [Event.model_validate(records[item]) for item in scan.event_ids if item in records]
        if source:
            events = [x for x in events if x.source.casefold() == source.casefold()]
        events.sort(key=lambda x: (x.occurred_at, x.event_id), reverse=True)
        page = events[offset : offset + limit]
        return {
            "items": [_event_summary(x) for x in page],
            "total": len(events),
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/log/analyses/{scan_id}/events/{event_id}", response_model=EventResponse)
    def log_event_detail(
        scan_id: str,
        event_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        scan = log_scan(scan_id)
        if event_id not in scan.event_ids:
            raise HTTPException(status_code=404, detail="Event not found.")
        with db_lock:
            raw = repository.get("event", event_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Event not found.")
        return _event_summary(Event.model_validate(raw))

    @application.get("/api/log/analyses/{scan_id}/timeline", response_model=TimelineResponse)
    def log_timeline(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> dict[str, Any]:
        scan = log_scan(scan_id)
        with db_lock:
            records = repository.get_many("timeline_entry", scan.timeline_entry_ids)
        timeline = [
            TimelineEntry.model_validate(records[item])
            for item in scan.timeline_entry_ids
            if item in records
        ]
        timeline.sort(key=lambda x: (x.occurred_at, x.entry_id), reverse=True)
        page = timeline[offset : offset + limit]
        values = [x.model_dump(mode="json") for x in page]
        return {"items": values, "total": len(timeline), "limit": limit, "offset": offset}

    @application.get("/api/scans", response_model=ScanPageResponse)
    def list_scans(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        status: Literal["complete", "partial", "failed", "running"] | None = None,
        scanner: Annotated[str | None, Query(max_length=100)] = None,
        sort: Literal["started_at", "status", "scanner"] = "started_at",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        filters = {
            key: value for key, value in {"status": status, "scanner": scanner}.items() if value
        }
        with db_lock:
            page, total = repository.page_records(
                "scan",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        scans = [Scan.model_validate(item) for item in page]
        return {
            "items": [_scan_summary(scan) for scan in scans],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/scans/{scan_id}", response_model=ScanDetailResponse)
    def get_scan(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Scan not found.")
        with db_lock:
            raw = repository.get("scan", scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        scan = Scan.model_validate(raw)
        return _scan_summary(scan) | {
            "finding_ids": scan.finding_ids,
            "coverage": scan.coverage.model_dump(mode="json") if scan.coverage else None,
            "failures": scan.failures,
            "code_assessment": scan.code_assessment.model_dump(mode="json")
            if scan.code_assessment
            else None,
        }

    @application.get("/api/findings", response_model=FindingPageResponse)
    def list_findings(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        severity: Annotated[str | None, Query(max_length=20)] = None,
        category: Annotated[str | None, Query(max_length=80)] = None,
        scanner: Annotated[str | None, Query(max_length=100)] = None,
        sort: Literal["severity", "title", "scanner", "category"] = "severity",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        if severity and severity not in {item.value for item in Severity}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        filters = {
            key: value
            for key, value in {
                "severity": severity,
                "category": category,
                "scanner": scanner,
            }.items()
            if value
        }
        with db_lock:
            page, total = repository.page_records(
                "finding",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
            _all_rows, total_stored = repository.page_records(
                "finding", limit=1, offset=0, sort_by="severity", descending=True
            )
        return {
            "items": [_finding_summary(Finding.model_validate(item)) for item in page],
            "total": total,
            "total_stored": total_stored,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/findings/{finding_id}", response_model=FindingDetailResponse)
    def get_finding(
        finding_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if len(finding_id) > 255:
            raise HTTPException(status_code=404, detail="Finding not found.")
        with db_lock:
            raw = repository.get("finding", finding_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        return _finding_summary(Finding.model_validate(raw), detail=True)

    def case_view(case_id: str) -> dict[str, Any]:
        workflow = CaseWorkflow(repository)
        stored_case = workflow.get_case(case_id)
        _enforce_case_limits(stored_case)
        context = workflow.context(stored_case)
        case = context.case
        _, timeline, warnings = workflow.timeline(case)
        severities = {item.value: 0 for item in Severity}
        linked = []
        for (record_type, record_id), record in sorted(context.records.items()):
            raw_severity = getattr(record, "severity", None)
            if raw_severity is not None and raw_severity.value in severities:
                severities[raw_severity.value] += 1
            linked.append(
                {
                    "record_type": record_type,
                    "record_id": record_id,
                    "source": str(
                        getattr(record, "source", None)
                        or getattr(record, "scanner", None)
                        or record_type
                    ),
                    "title": str(getattr(record, "title", "")),
                    "severity": raw_severity.value if raw_severity is not None else None,
                    "sample_id": getattr(record, "sample_id", None),
                    "completeness": getattr(record, "status", None)
                    if record_type == "malware_analysis"
                    else None,
                }
            )
        view = {
            "case": case.model_dump(mode="json"),
            "links": [item.model_dump(mode="json") for item in context.links],
            "records": linked,
            "timeline": [item.model_dump(mode="json") for item in timeline],
            "warnings": list(dict.fromkeys([*context.warnings, *warnings])),
            "counts_by_severity": severities,
        }
        return view

    @application.get("/api/cases")
    def list_cases(
        _session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
        status: CaseStatus | None = None,
        severity: Severity | None = None,
        sort: Literal["created_at", "updated_at", "status", "severity", "title"] = "updated_at",
        order: Literal["asc", "desc"] = "desc",
    ) -> dict[str, Any]:
        filters = {
            key: value.value
            for key, value in {"status": status, "severity": severity}.items()
            if value
        }
        with db_lock:
            page, total = repository.page_records(
                "case",
                limit=limit,
                offset=offset,
                sort_by=sort,
                descending=order == "desc",
                filters=filters,
            )
        case_items = [
            {
                "case_id": item["case_id"],
                "title": item["title"],
                "description": item["description"],
                "status": item["status"],
                "severity": item["severity"],
                "created_at": item["created_at"],
                "updated_at": item["updated_at"],
                "note_count": len(item.get("notes", [])),
                "linked_record_count": len(item.get("links", [])),
            }
            for item in page
        ]
        return {
            "items": case_items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.post("/api/cases", status_code=201)
    def create_case(
        payload: CaseCreateRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                case, warnings = CaseWorkflow(repository).create_from_scan(
                    payload.scan_id,
                    title=payload.title,
                    description=payload.description,
                    severity=payload.severity.value,
                )
                result = case_view(case.case_id)
            result["warnings"] = list(dict.fromkeys([*result["warnings"], *warnings]))
            return result
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/cases/{case_id}")
    def get_case(case_id: str, _session: Session = Depends(current_session)) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/status")
    def update_case_status(
        case_id: str,
        payload: CaseStatusRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                CaseWorkflow(repository).update_status(case_id, payload.status)
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/notes", status_code=201)
    def add_case_note(
        case_id: str,
        payload: CaseNoteRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                # The session identity is deliberately not stored as a legacy author label.
                CaseWorkflow(repository).add_note(case_id, payload.body)
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.post("/api/cases/{case_id}/links")
    def link_case_record(
        case_id: str,
        payload: CaseLinkRequest,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            with db_lock:
                CaseWorkflow(repository).link_record(
                    case_id, payload.record_type, payload.record_id
                )
                return case_view(case_id)
        except CaseWorkflowError as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/cases/{case_id}/report/{output_format}")
    def case_report(
        case_id: str,
        output_format: Literal["json", "markdown", "html"],
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        try:
            with db_lock:
                case = CaseWorkflow(repository).get_case(case_id)
                _enforce_case_limits(case)
                body = render_case_report(repository, case_id, output_format)
            return _download_response(body, f"case-report.{output_format}", output_format)
        except (CaseWorkflowError, ReportingError) as exc:
            raise _case_http_error(exc) from exc

    @application.get("/api/reports/{scan_id}/{output_format}")
    @application.get("/api/scans/{scan_id}/report/{output_format}")
    def scan_report(
        scan_id: str,
        output_format: Literal[
            "json", "full-json", "detail", "markdown", "html", "csv", "sarif", "share-summary"
        ],
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        try:
            with db_lock:
                scan, findings = scan_data(repository, scan_id)
                if len(findings) > MAX_SCAN_REPORT_FINDINGS:
                    raise HTTPException(
                        status_code=413, detail="Scan report exceeds configured finding limits."
                    )
                body = render_report(scan, findings, output_format)
                if len(body.encode("utf-8")) > MAX_SCAN_REPORT_BYTES:
                    raise HTTPException(
                        status_code=413, detail="Complete report exceeds the 20 MB export limit."
                    )
            return _download_response(
                body,
                f"scan-report.{output_format}",
                output_format,
                max_bytes=MAX_SCAN_REPORT_BYTES if output_format == "full-json" else 2_000_000,
            )
        except ReportingError as exc:
            if output_format == "full-json" and "Complete JSON report exceeds" in str(exc):
                raise HTTPException(
                    status_code=413,
                    detail="Complete JSON report exceeds the configured count or byte limit.",
                ) from exc
            if str(exc).startswith("Scan not found:"):
                raise HTTPException(status_code=404, detail="Scan not found.") from exc
            raise _case_http_error(exc) from exc

    @application.get("/api/scans/{scan_id}/findings.jsonl")
    def scan_findings_jsonl(
        scan_id: str,
        request: Request,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> StreamingResponse:
        if len(scan_id) > 255:
            raise HTTPException(status_code=404, detail="Scan not found.")
        with db_lock:
            stored = repository.get("scan", scan_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        scan = Scan.model_validate(stored)
        finding_ids = list(scan.finding_ids)
        if len(finding_ids) != len(set(finding_ids)):
            raise HTTPException(
                status_code=409,
                detail="Scan contains duplicate finding IDs; export was not started.",
            )
        chain_scan = "chain" in scan.project_types or scan.scanner == "chain_trace"
        organization_id = getattr(request.state, "organization_id", None)
        principal_id = _session.user_id
        if not organization_id or not principal_id:
            raise HTTPException(status_code=404, detail="Scan not found.")

        def stream() -> Iterator[str]:
            manifest = {
                "type": "manifest",
                "schema": "chinescan.findings/1",
                "scan_id": scan_id,
                "total_findings": len(finding_ids),
                "ordering": "scan.finding_ids order",
                "consistency": "scan ID list captured at request start",
                "processing_failure_count": len(scan.failures),
            }
            yield json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n"
            digest = hashlib.sha256()
            returned = 0
            for start in range(0, len(finding_ids), 100):
                ids = finding_ids[start : start + 100]
                try:
                    with (
                        repository.member_context(organization_id, principal_id, write=False),
                        db_lock,
                    ):
                        records = repository.get_many("finding", ids)
                except StorageError:
                    yield (
                        json.dumps(
                            {"type": "error", "code": "record_unavailable_or_unsafe"},
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    return
                try:
                    if len(records) != len(ids):
                        raise ValueError("finding unavailable")
                    for finding_id in ids:
                        finding = Finding.model_validate(records[finding_id])
                        row = {
                            "type": "finding",
                            "finding": redact_finding_payload(finding, chain_scan=chain_scan),
                        }
                        line = json.dumps(row, ensure_ascii=False, sort_keys=True)
                        digest.update((line + "\n").encode("utf-8"))
                        returned += 1
                        yield line + "\n"
                except Exception:
                    yield (
                        json.dumps(
                            {"type": "error", "code": "record_unavailable_or_unsafe"},
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    return
            yield (
                json.dumps(
                    {
                        "type": "complete",
                        "returned_findings": returned,
                        "sha256": digest.hexdigest(),
                    },
                    sort_keys=True,
                )
                + "\n"
            )

        return StreamingResponse(
            stream(),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}-findings.jsonl"',
                "Cache-Control": "no-store",
            },
        )

    @application.post("/api/scans/{scan_id}/external-reports", status_code=201)
    async def import_scanity_report(
        scan_id: str,
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_EXTERNAL_REPORT_BYTES:
            raise HTTPException(status_code=413, detail="Report exceeds the 2 MB import limit.")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_EXTERNAL_REPORT_BYTES:
                raise HTTPException(status_code=413, detail="Report exceeds the 2 MB import limit.")
        try:
            with db_lock:
                scan_payload = repository.get("scan", scan_id)
                if scan_payload is None:
                    raise HTTPException(status_code=404, detail="Scan not found.")
                scan_record = Scan.model_validate(scan_payload)
                if not scan_record.code_assessment and not (
                    {kind.casefold() for kind in scan_record.project_types or []}
                    & {"python", "node"}
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="External reports can only be imported into code assessments.",
                    )
                if scan_record.code_assessment is None:
                    scan_record.code_assessment = CodeAssessmentSummary()
                target_record = repository.get("target", scan_record.target_id)
                target_root = Path(str(target_record["value"])) if target_record else Path.cwd()
                imported = parse_scanity_export(
                    bytes(body), target=target_root, project_id=scan_record.project_id
                )
                existing_ids = set(scan_record.finding_ids)
                existing_fingerprints = {
                    str(item.get("fingerprint"))
                    for item in repository.list_records("finding")
                    if item.get("source") == "scanity" and item.get("finding_id") in existing_ids
                }
                added = [item for item in imported if item.fingerprint not in existing_fingerprints]
                for item in added:
                    repository.save("finding", item.finding_id, item.model_dump(mode="json"))
                scan_record.finding_ids = list(
                    dict.fromkeys([*scan_record.finding_ids, *(item.finding_id for item in added)])
                )
                repository.save("scan", scan_id, scan_record.model_dump(mode="json"))
                try:
                    save_scan_reports(repository, scan_id, active_settings.reports_dir)
                except ReportStoreError:
                    pass
            return {"scan_id": scan_id, "imported": len(added), "source": "scanity"}
        except ExternalReportError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/fs/roots")
    def filesystem_roots(
        request: Request,
        capability: Literal["project_directory", "log_location"] = Query(...),
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        return fs_browser.roots_view(session.csrf_token, capability)

    @application.get("/api/fs/picker-roots")
    def folder_picker_roots(
        request: Request,
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, object]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        return fs_browser.picker_roots_view(session.csrf_token)

    @application.get("/api/fs/picker-list")
    def folder_picker_list(
        request: Request,
        directory_id: Annotated[str, Query(min_length=32, max_length=128)],
        session: Session = Depends(current_session),  # noqa: B008
        cursor: Annotated[str | None, Query(max_length=128)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, object]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            return fs_browser.list_view(
                session.csrf_token,
                "folder_approval",
                directory_id,
                cursor=cursor,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail={"code": "directory_unavailable", "message": "Folder is unavailable."},
            ) from exc

    @application.get("/api/fs/picker-preview")
    def folder_picker_preview(
        request: Request,
        directory_id: Annotated[str, Query(min_length=32, max_length=128)],
        session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, str]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            return fs_browser.preview_folder_approval(session.csrf_token, directory_id)
        except ValueError as exc:
            code = str(exc)
            raise HTTPException(
                status_code=422,
                detail={"code": code, "message": folder_approval_error(code)},
            ) from exc

    @application.get("/api/fs/list")
    def filesystem_list(
        request: Request,
        directory_id: Annotated[str, Query(min_length=32, max_length=128)],
        capability: Literal["project_directory", "log_location"] = Query(...),
        session: Session = Depends(current_session),  # noqa: B008
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[str | None, Query(max_length=128)] = None,
    ) -> dict[str, object]:
        if not fs_browse_throttle.allowed("fs:" + (request.client.host if request.client else "")):
            raise HTTPException(status_code=429, detail="Browse rate limit reached; retry shortly.")
        try:
            return fs_browser.list_view(
                session.csrf_token,
                capability,
                directory_id,
                cursor=cursor,
                limit=limit,
            )
        except ValueError as exc:
            code = str(exc)
            raise HTTPException(
                status_code=400 if code == "invalid_page_size" else 404,
                detail="Directory selection is unavailable.",
            ) from exc

    if serve_frontend and FRONTEND_DIST.is_dir():

        @application.get("/signup", include_in_schema=False)
        def signup_page() -> FileResponse:
            return FileResponse(FRONTEND_DIST / "index.html")

        @application.get("/forgot-password", include_in_schema=False)
        def forgot_password_page() -> FileResponse:
            return FileResponse(FRONTEND_DIST / "index.html")

        @application.get("/reset-password", include_in_schema=False)
        def reset_password_page() -> FileResponse:
            return FileResponse(FRONTEND_DIST / "index.html")

    @application.post("/api/chain/jobs", status_code=202)
    async def start_chain_job(
        request: Request,
        _session: Session = Depends(require_csrf),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        try:
            body = await request.json()
            if len(json.dumps(body).encode()) > 2_000_000:
                raise HTTPException(
                    413, detail={"code": "import_too_large", "message": "Import text exceeds 2 MB."}
                )
            chain = str(body["chain"]).lower()
            selected_chain = load_registry().get(chain)
            if selected_chain is None:
                raise HTTPException(
                    422, detail={"code": "unknown_chain", "message": "Unknown chain."}
                )
            try:
                normalize_address(selected_chain, str(body["address"]))
            except ValueError:
                raise HTTPException(
                    422,
                    detail={
                        "code": "invalid_address",
                        "message": "Wallet address is invalid for the selected chain.",
                    },
                ) from None
            try:
                depth = int(body.get("depth", 3))
                if not 1 <= depth <= 6:
                    raise ValueError
            except (TypeError, ValueError):
                raise HTTPException(
                    422,
                    detail={"code": "invalid_depth", "message": "Depth must be between 1 and 6."},
                ) from None
            try:
                minimum = Decimal(str(body.get("min_amount", "0")))
                if not minimum.is_finite() or minimum < 0:
                    raise ValueError
            except (InvalidOperation, TypeError, ValueError):
                raise HTTPException(
                    422,
                    detail={
                        "code": "invalid_min_amount",
                        "message": "Minimum amount must be a non-negative decimal.",
                    },
                ) from None
            if body.get("allow_network") and not active_settings.chain_network_enabled:
                raise HTTPException(
                    403,
                    detail={
                        "code": "chain_network_disabled",
                        "message": "Network chain lookups are disabled by server settings.",
                    },
                )
            if not body.get("import_text") and not body.get("allow_network"):
                raise HTTPException(
                    422,
                    detail={
                        "code": "offline_import_required",
                        "message": "Provide an explorer export or explicitly allow network lookup.",
                    },
                )
            job = chain_jobs.submit(
                {
                    "address": str(body["address"]),
                    "chain": chain,
                    "depth": depth,
                    "min_amount": str(minimum),
                    "allow_network": bool(body.get("allow_network")),
                    "import_text": body.get("import_text"),
                    "import_format": body.get("import_format", "csv"),
                }
            )
            return _safe_chain_job(job)
        except HTTPException:
            raise
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                422,
                detail={"code": "invalid_chain_request", "message": "Invalid chain job request."},
            ) from None
        except OverflowError:
            raise HTTPException(
                429, detail={"code": "chain_queue_full", "message": "Chain job queue is full."}
            ) from None

    @application.get("/api/chain/jobs")
    def list_chain_jobs(
        limit: int = 50,
        offset: int = 0,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:  # noqa: B008
        items, total = chain_jobs.list(max(1, min(100, limit)), max(0, offset))
        return {
            "items": [_safe_chain_job(item) for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/chain/jobs/{job_id}")
    def get_chain_job(
        job_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        item = chain_jobs.get(job_id)
        if item is None:
            raise HTTPException(404, detail="Chain job not found.")
        return _safe_chain_job(item)

    @application.get("/api/chain/chains")
    def list_chains(
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> list[dict[str, Any]]:
        return [
            {
                "name": item.name,
                "family": item.family,
                "native_asset": item.native_asset,
                "credential_configured": bool(
                    item.api_key_env and __import__("os").getenv(item.api_key_env)
                ),
            }
            for item in load_registry().values()
        ]

    @application.get("/api/chain/traces/{scan_id}/graph")
    def chain_graph(
        scan_id: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> dict[str, Any]:
        graph = repository.get("chain_graph", scan_id)
        if graph is None:
            raise HTTPException(404, detail="Chain graph not found.")
        return graph

    @application.get("/api/chain/traces/{scan_id}/export/{fmt}")
    def chain_export(
        scan_id: str,
        fmt: str,
        _session: Session = Depends(current_session),  # noqa: B008
    ) -> Response:  # noqa: B008
        graph = repository.get("chain_graph", scan_id)
        if graph is None:
            raise HTTPException(404, detail="Chain graph not found.")
        if fmt not in {"graph-json", "graphml", "transfers-csv", "indicators"}:
            raise HTTPException(404, detail="Unknown export format.")
        media = (
            "application/json"
            if fmt in {"graph-json", "indicators"}
            else "text/csv"
            if fmt == "transfers-csv"
            else "application/graphml+xml"
        )
        return Response(export_graph(graph, fmt), media_type=media)

    if serve_frontend and FRONTEND_DIST.is_dir():
        application.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

    return application


def _safe_chain_job(raw: dict[str, Any]) -> dict[str, Any]:
    return {key: raw.get(key) for key in ("job_id", "status", "created_at", "scan_id", "error")}


def _safe_project_malware_job(raw: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "job_id",
        "project_id",
        "status",
        "profile",
        "created_at",
        "started_at",
        "finished_at",
        "scan_id",
        "finding_count",
        "files_seen",
        "skipped_counts",
        "coverage_notes",
        "error_code",
        "error",
    )
    return {key: raw.get(key) for key in keys if key in raw}


def _malware_job_view(raw: dict[str, Any], repository: SQLiteRepository) -> dict[str, Any]:
    analysis_id = raw.get("analysis_id")
    analysis = repository.get("malware_analysis", str(analysis_id)) if analysis_id else None
    return {
        "job_id": str(raw.get("job_id", "")),
        "sample_id": str(raw.get("sample_id", "")),
        "status": raw.get("status", "failed"),
        "created_at": str(raw.get("created_at", "")),
        "started_at": raw.get("started_at"),
        "finished_at": raw.get("finished_at"),
        "analysis_id": raw.get("analysis_id"),
        "warning": str(raw.get("warning"))[:500] if raw.get("warning") else None,
        "analysis_status": analysis.get("status") if analysis else None,
    }


def _malware_analysis_view(raw: dict[str, Any]) -> dict[str, Any]:
    raw_result = raw.get("result")
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_hashes = result.get("hashes")
    hashes: dict[str, Any] = raw_hashes if isinstance(raw_hashes, dict) else {}
    raw_indicators = result.get("indicators")
    indicators: list[Any] = raw_indicators if isinstance(raw_indicators, list) else []
    raw_warnings = result.get("warnings")
    warnings: list[Any] = raw_warnings if isinstance(raw_warnings, list) else []
    raw_engines = raw.get("engines")
    engines: dict[str, Any] = raw_engines if isinstance(raw_engines, dict) else {}
    safe_indicators = []
    for item in indicators[:500]:
        if (
            isinstance(item, dict)
            and isinstance(item.get("kind"), str)
            and isinstance(item.get("value"), str)
        ):
            safe_indicators.append({"kind": item["kind"][:40], "value": item["value"][:2048]})
    safe_engines = {}
    for name in ("yara", "clamav"):
        state = engines.get(name, {})
        if isinstance(state, dict):
            safe_engines[name] = {
                key: str(state.get(key, "not_checked"))[:40]
                for key in (
                    "requested",
                    "installation",
                    "configuration",
                    "real_binary_verification",
                )
            }
    return {
        "analysis_id": str(raw.get("analysis_id", "")),
        "sample_id": str(raw.get("sample_id", "")),
        "profile": str(raw.get("profile", "builtin_static"))[:40],
        "status": raw.get("status", "partial"),
        "created_at": str(raw.get("created_at", "")),
        "size_bytes": result.get("size_bytes", 0),
        "hashes": {
            key: str(hashes[key])
            for key in ("md5", "sha1", "sha256")
            if isinstance(hashes.get(key), str)
            and len(hashes[key]) == {"md5": 32, "sha1": 40, "sha256": 64}[key]
            and all(character in "0123456789abcdef" for character in hashes[key].lower())
        },
        "file_type": str(result.get("file_type", "unknown"))[:120],
        "architecture": str(result["architecture"])[:80]
        if isinstance(result.get("architecture"), str)
        else None,
        "printable_string_count": result.get("printable_string_count", 0),
        "indicator_count": result.get("indicator_count", len(safe_indicators)),
        "indicators": safe_indicators,
        "warnings": [str(item)[:500] for item in warnings[:50]],
        "engines": safe_engines,
        "entropy_bits_per_byte": _finite_number(
            result.get("entropy_bits_per_byte"), minimum=0, maximum=8
        ),
        "section_entropy": _safe_section_entropy(result.get("section_entropy")),
        "timestamp_utc": (
            str(result["timestamp_utc"])[:40]
            if isinstance(result.get("timestamp_utc"), str)
            else None
        ),
        "imports": _safe_malware_strings(result.get("imports"), 200, 180),
        "suspicious_api_combinations": _safe_malware_strings(
            result.get("suspicious_api_combinations"), 20, 80
        ),
        "verdict": (
            result.get("verdict")
            if result.get("verdict") in {"clean-no-indicators", "suspicious", "likely-malicious"}
            else "suspicious"
        ),
        "verdict_evidence": _safe_malware_strings(result.get("verdict_evidence"), 40, 100),
        "verdict_caveat": str(
            result.get("verdict_caveat")
            or "Static analysis cannot establish that a sample is safe."
        )[:500],
        "evidence_note": (
            "Indicators are untrusted candidate evidence, not confirmed maliciousness. "
            "URLs and HTML-like values are inert text. Sample bytes, printable strings, "
            "archive names, paths, and raw worker output are withheld."
        ),
    }


def _finite_number(value: Any, *, minimum: float, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and minimum <= number <= maximum else None


def _safe_section_entropy(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output: list[dict[str, Any]] = []
    for item in value[:100]:
        if not isinstance(item, dict):
            continue
        name = item.get("section")
        entropy = _finite_number(item.get("entropy_bits_per_byte"), minimum=0, maximum=8)
        if isinstance(name, str) and entropy is not None:
            output.append({"name": redact(name[:80]), "entropy_bits_per_byte": entropy})
    return output


def _safe_malware_strings(value: Any, maximum: int, length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [redact(item[:length]) for item in value[:maximum] if isinstance(item, str)]


def _scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "status": scan.status,
        "scanner": scan.scanner,
        "project_types": scan.project_types,
        "finding_count": len(scan.finding_ids),
        "verdict": scan.verdict,
        "coverage_gap_count": len(scan.coverage.gaps) if scan.coverage else 0,
    }


def _finding_summary(finding: Finding, *, detail: bool = False) -> dict[str, Any]:
    # Explicit schema allowlist: never send raw evidence or arbitrary persisted JSON to the browser.
    value: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "title": redact(finding.title),
        "severity": finding.severity.value,
        "category": finding.category.value,
        "confidence": finding.confidence.value,
        "verdict": finding.verdict.value,
        "scanner": finding.scanner,
        "rule_id": redact(finding.rule_id),
        "contributing_rule_ids": finding.contributing_rule_ids or [finding.rule_id],
        "entry_point": _safe_evidence_location(finding.entry_point),
        "source_location": _safe_evidence_location(finding.source_location),
        "sink_location": _safe_evidence_location(finding.sink_location),
        "controls_considered": [redact(item) for item in finding.controls_considered],
        "exploitability_conditions": [redact(item) for item in finding.exploitability_conditions],
        "project_impact": redact(finding.project_impact) if finding.project_impact else None,
        "remediation_before": (
            redact(finding.remediation_before) if finding.remediation_before else None
        ),
        "remediation_after": (
            redact(finding.remediation_after) if finding.remediation_after else None
        ),
        "verification_step": (
            redact(finding.verification_step) if finding.verification_step else None
        ),
        "why_not_higher": redact(finding.why_not_higher) if finding.why_not_higher else None,
        "what_would_raise_it": (
            redact(finding.what_would_raise_it) if finding.what_would_raise_it else None
        ),
    }
    if detail:
        value["description"] = redact(finding.description)
        value["location"] = safe_display_name(finding.location) if finding.location else None
        value["tags"] = finding.tags
        value["evidence"] = finding.evidence.value if finding.evidence else None
        value["line_numbers"] = finding.line_numbers
        value["code_excerpt"] = redact(finding.code_excerpt) if finding.code_excerpt else None
        value["remediation"] = redact(finding.remediation) if finding.remediation else None
        value["cwe_ids"] = finding.cwe_ids
        value["exposure"] = finding.exposure
        value["explanation"] = (
            redact(finding.explanation.model_dump(mode="json")) if finding.explanation else None
        )
    return value


def _safe_evidence_location(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    file_name = safe_display_name(value.file)
    excerpt = redact(value.excerpt) if value.excerpt else None
    return {"file": file_name, "line": value.line, "excerpt": excerpt}


def _alert_summary(alert: Alert) -> dict[str, Any]:
    value = {
        "alert_id": alert.alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "confidence": alert.confidence.value,
        "rule_id": alert.rule_id,
        "event_ids": alert.event_ids,
        "indicator_ids": alert.indicator_ids,
        "mitre_attack_techniques": alert.mitre_attack_techniques,
        "verdict": alert.verdict.value,
        "matching_refs": alert.matching_refs,
        "first_match_ref": alert.first_match_ref,
        "last_match_ref": alert.last_match_ref,
        "match_count": alert.match_count,
        "log_limitations": alert.log_limitations,
        "project_impact": alert.project_impact,
        "exploitability_conditions": alert.exploitability_conditions,
        "controls_considered": alert.controls_considered,
        "remediation": alert.remediation,
        "verification_step": alert.verification_step,
        "why_not_higher": alert.why_not_higher,
        "what_would_raise_it": alert.what_would_raise_it,
    }
    return value


def _event_summary(event: Event) -> dict[str, Any]:
    # Raw refs may contain full local paths; browser schemas intentionally omit them.
    value = {
        "event_id": event.event_id,
        "occurred_at": event.occurred_at,
        "kind": event.kind,
        "summary": event.summary,
        "source": event.source,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "user": event.user,
        "host": event.host,
        "process": event.process,
        "url": event.url,
        "event_outcome": event.event_outcome,
        "mitre_attack_techniques": event.mitre_attack_techniques,
    }
    return value


def _case_http_error(exc: ValueError) -> HTTPException:
    if isinstance(exc, (CaseNotFoundError, CaseRecordNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


def _enforce_case_limits(case: Case) -> None:
    if len(case.links) > 2_000 or len(case.notes) > 1_000 or len(case.activities) > 5_000:
        raise HTTPException(status_code=413, detail="Case exceeds configured record limits.")


def _download_response(
    body: str, filename: str, output_format: str, *, max_bytes: int = 2_000_000
) -> Response:
    # Reports are generated in memory from bounded stored records, never via a user path.
    encoded = body.encode("utf-8")
    if len(encoded) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Generated report exceeds the {max_bytes // (1024 * 1024)} MB limit.",
        )
    media_type = {
        "json": "application/json; charset=utf-8",
        "full-json": "application/json; charset=utf-8",
        "detail": "text/markdown; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
        "sarif": "application/sarif+json; charset=utf-8",
    }[output_format]
    safe_name = filename.replace('"', "")
    disposition = "attachment"
    return Response(
        content=encoded,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )
