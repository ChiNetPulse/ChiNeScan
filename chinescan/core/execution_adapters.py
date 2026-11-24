"""Typed contract for trusted assessment adapters under execution governance.

Adapters receive only a server-created context and a control object. External
operations must pass through the control object's target-bound policy check.
This is an internal extension boundary, not a sandbox for untrusted plugins.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from threading import Event
from typing import Any, Literal, Protocol
from uuid import NAMESPACE_URL, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update

from chinescan.core.engagement_security import _utc
from chinescan.core.log_evidence import LogEvidenceStore
from chinescan.core.malware_evidence import (
    ANALYSIS_VERSION as MALWARE_ANALYSIS_VERSION,
    MalwareEvidenceStore,
)
from chinescan.core.models.common import ScanVerdict
from chinescan.core.models.investigation import Scan, Target
from chinescan.core.orchestration.code_scan import BuiltinRuleScanner, CodeScanService, ScanBounds
from chinescan.core.repository_assessment import (
    REPOSITORY_TECHNIQUE,
    SCANNER_VERSION,
    RepositorySnapshotStore,
)
from chinescan.core.storage.repository import Repository
from chinescan.core.storage.sqlite import SQLiteRepository, assessment_audit_events, execution_jobs
from chinescan.domain_assessment.authorization import AuthorizationGrant
from chinescan.domain_assessment.probe import (
    ExecutionCancelled,
    ExecutionStopped,
    NetworkDomainProbe,
)
from chinescan.domain_assessment.service import DomainAssessmentService
from chinescan.log_analysis.service import (
    LOG_ANALYSIS_VERSION,
    LOG_RULESET_VERSION,
    LogAnalysisService,
)
from chinescan.malware_analysis.analyzer import AnalysisError, analyze_file

ActionClass = Literal["passive", "controlled_active", "sensitive"]
AdapterStatus = Literal["complete", "partial"]


class ExecutionContext(BaseModel):
    """Immutable, database-derived identity and authorization snapshot for one job."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    job_id: str = Field(min_length=36, max_length=36)
    organization_id: str = Field(min_length=36, max_length=36)
    requester_user_id: str = Field(min_length=36, max_length=36)
    engagement_id: str = Field(min_length=36, max_length=36)
    assignment_roles: tuple[str, ...]
    asset_id: str = Field(min_length=36, max_length=36)
    target: str = Field(min_length=1, max_length=2048)
    asset_type: str = Field(min_length=1, max_length=20)
    technique: str = Field(min_length=1, max_length=80)
    action_class: ActionClass
    scope_revision_id: str = Field(min_length=36, max_length=36)
    authorization_id: str = Field(min_length=36, max_length=36)
    authorization_document_sha256: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    approval_id: str | None = Field(default=None, min_length=36, max_length=36)
    policy_decision_id: str = Field(min_length=36, max_length=36)
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_request_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    repository_binding_id: str | None = Field(default=None, min_length=36, max_length=36)
    repository_snapshot_id: str | None = Field(default=None, min_length=36, max_length=36)
    repository_snapshot_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    repository_manifest_version: int | None = None
    repository_attestation_id: str | None = Field(default=None, min_length=36, max_length=36)
    repository_attestation_version: str | None = None
    adapter_id: str | None = None
    adapter_version: str | None = None
    scanner_version: str | None = None
    scan_bounds: dict[str, Any] | None = None
    exclusion_policy_version: str | None = None
    log_evidence_snapshot_id: str | None = Field(default=None, min_length=36, max_length=36)
    log_evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    log_evidence_manifest_version: int | None = None
    log_evidence_source_format: str | None = None
    log_analysis_version: str | None = None
    log_ruleset_version: str | None = None
    malware_evidence_snapshot_id: str | None = Field(default=None, min_length=36, max_length=36)
    malware_evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    malware_evidence_manifest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    malware_evidence_manifest_version: int | None = None
    malware_analysis_version: str | None = None
    chain_context: dict[str, Any] | None = None
    created_at: str
    expires_at: str

    @classmethod
    def from_job(cls, job: dict[str, Any]) -> ExecutionContext:
        raw = job.get("execution_context")
        if not isinstance(raw, dict):
            raise ValueError("Execution context is missing.")
        context = cls.model_validate(raw)
        if context.chain_context != raw.get("chain_context"):
            raise ValueError("Execution context chain binding is invalid.")
        fields = (
            "organization_id",
            "requester_user_id",
            "engagement_id",
            "asset_id",
            "target",
            "asset_type",
            "technique",
            "action_class",
            "scope_revision_id",
            "authorization_id",
            "authorization_document_sha256",
            "approval_id",
            "policy_decision_id",
            "request_digest",
            "policy_request_digest",
            "repository_binding_id",
            "repository_snapshot_id",
            "repository_snapshot_sha256",
            "repository_manifest_version",
            "repository_attestation_id",
            "repository_attestation_version",
            "adapter_id",
            "adapter_version",
            "exclusion_policy_version",
            "log_evidence_snapshot_id",
            "log_evidence_sha256",
            "log_evidence_manifest_version",
            "log_evidence_source_format",
            "log_analysis_version",
            "log_ruleset_version",
            "malware_evidence_snapshot_id",
            "malware_evidence_sha256",
            "malware_evidence_manifest_sha256",
            "malware_evidence_manifest_version",
            "malware_analysis_version",
            "created_at",
            "expires_at",
        )
        if any(getattr(context, name) != job.get(name) for name in fields):
            raise ValueError("Execution context does not match its durable job row.")
        if context.job_id != job.get("id"):
            raise ValueError("Execution context job identifier does not match its durable row.")
        if context.repository_attestation_version != job.get("repository_attestation_version"):
            raise ValueError("Execution context attestation version does not match its durable row.")
        if context.adapter_id != job.get("adapter_id") or context.adapter_version != job.get("adapter_version"):
            raise ValueError("Execution context adapter identity does not match its durable row.")
        if context.scanner_version != job.get("repository_scanner_version"):
            raise ValueError("Execution context scanner identity does not match its durable row.")
        if context.scan_bounds != job.get("repository_scan_bounds"):
            raise ValueError("Execution context scan bounds do not match its durable row.")
        if context.exclusion_policy_version != job.get("exclusion_policy_version"):
            raise ValueError("Execution context exclusion policy does not match its durable row.")
        if context.asset_type == "log_evidence" and context.technique == "log_analysis" and (
            not context.log_evidence_snapshot_id
            or not context.log_evidence_sha256
            or context.log_evidence_manifest_version != 1
            or context.log_analysis_version != LOG_ANALYSIS_VERSION
            or context.log_ruleset_version != LOG_RULESET_VERSION
            or context.technique != "log_analysis"
            or context.action_class != "passive"
        ):
            raise ValueError("Execution context does not contain a valid log evidence binding.")
        if context.asset_type == "malware_evidence" and (
            not context.malware_evidence_snapshot_id
            or not context.malware_evidence_sha256
            or not context.malware_evidence_manifest_sha256
            or context.malware_evidence_manifest_version != 1
            or context.malware_analysis_version != MALWARE_ANALYSIS_VERSION
            or context.technique != "malware_static_triage"
            or context.action_class != "passive"
        ):
            raise ValueError("Execution context does not contain a valid malware evidence binding.")
        if context.technique == "chain_trace_import" and (
            context.asset_type != "log_evidence"
            or context.action_class != "passive"
            or context.chain_context is None
            or set(context.chain_context) != {"chain", "seed", "depth"}
            or not context.log_evidence_snapshot_id
            or not context.log_evidence_sha256
            or context.log_evidence_manifest_version != 1
            or context.adapter_id != "builtin.governed-chain-import"
            or context.adapter_version != "1"
        ):
            raise ValueError("Execution context does not contain a valid chain import binding.")
        if context.technique == "chain_provider_lookup" and (
            context.asset_type != "chain_address"
            or context.action_class != "sensitive"
            or context.chain_context is None
            or set(context.chain_context) != {"chain", "address", "provider"}
            or context.adapter_id != "builtin.governed-chain-provider"
            or context.adapter_version != "1"
        ):
            raise ValueError("Execution context does not contain a valid provider lookup binding.")
        if tuple(sorted(context.assignment_roles)) != context.assignment_roles:
            raise ValueError("Execution context assignment roles are not canonical.")
        return context


class AdapterCapabilities(BaseModel):
    """Static declaration used to reject unsupported requests before dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,79}$")
    techniques: tuple[str, ...] = Field(min_length=1)
    target_types: tuple[str, ...] = Field(min_length=1)
    action_class: ActionClass
    enabled: bool
    performs_external_operations: bool


class AdapterResult(BaseModel):
    """Safe structured outcome returned by a trusted adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_id: str
    status: AdapterStatus
    result_id: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)


class AdapterFailure(RuntimeError):
    """Expected safe failure with a stable code and no exception-text disclosure."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code):
            raise ValueError("Adapter failure code must be a stable uppercase identifier.")
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class AdapterControl(Protocol):
    """Worker-provided control plane; adapters cannot self-authorize destinations."""

    def check_cancelled(self) -> None: ...

    def authorize_external_action(self, target: str, technique: str) -> None: ...

    def report_progress(self, percent: int, phase: str) -> None: ...


class GovernedAssessmentAdapter(Protocol):
    """Execution interface implemented by trusted, explicitly registered adapters."""

    @property
    def capabilities(self) -> AdapterCapabilities: ...

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]: ...

    def execute(
        self,
        context: ExecutionContext,
        parameters: dict[str, Any],
        control: AdapterControl,
    ) -> AdapterResult: ...


class UnsupportedAdapterError(ValueError):
    """No enabled adapter declares the requested target and technique pair."""


class AdapterRegistry:
    """Small explicit registry; it is not a plugin loader or job framework."""

    def __init__(self, adapters: tuple[GovernedAssessmentAdapter, ...] = ()) -> None:
        self._by_id: dict[str, GovernedAssessmentAdapter] = {}
        self._by_operation: dict[tuple[str, str], GovernedAssessmentAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: GovernedAssessmentAdapter) -> None:
        capabilities = adapter.capabilities
        if capabilities.adapter_id in self._by_id:
            raise ValueError("Duplicate assessment adapter identifier.")
        if not capabilities.enabled:
            raise ValueError("Disabled assessment adapters cannot be registered.")
        for target_type in capabilities.target_types:
            for technique in capabilities.techniques:
                key = (target_type, technique)
                if key in self._by_operation:
                    raise ValueError("Duplicate adapter operation capability.")
                self._by_operation[key] = adapter
        self._by_id[capabilities.adapter_id] = adapter

    def resolve(self, target_type: str, technique: str) -> GovernedAssessmentAdapter:
        adapter = self._by_operation.get((target_type, technique))
        if adapter is None:
            raise UnsupportedAdapterError("Assessment technique is not supported.")
        return adapter

    def validate_parameters(
        self,
        target_type: str,
        technique: str,
        parameters: dict[str, Any],
    ) -> tuple[GovernedAssessmentAdapter, dict[str, Any]]:
        adapter = self.resolve(target_type, technique)
        try:
            validated = adapter.validate_parameters(parameters)
        except (TypeError, ValueError) as exc:
            raise ValueError("Assessment parameters are invalid.") from exc
        if not isinstance(validated, dict):
            raise ValueError("Adapter parameter validation returned an invalid result.")
        return adapter, validated


class ExecutionControl:
    """Per-job policy, cancellation, and progress callbacks supplied by the worker."""

    def __init__(
        self,
        *,
        context: ExecutionContext,
        cancellation: Event,
        external_operations_enabled: bool,
        revalidate: Any,
        progress: Any,
        cancellation_check: Any = None,
    ) -> None:
        self.context = context
        self._cancellation = cancellation
        self._external_operations_enabled = external_operations_enabled
        self._revalidate = revalidate
        self._progress = progress
        self._cancellation_check = cancellation_check

    def check_cancelled(self) -> None:
        if self._cancellation_check is not None and self._cancellation_check():
            raise ExecutionCancelled("Execution was cancelled.")
        if self._cancellation.is_set():
            raise ExecutionCancelled("Execution was cancelled.")

    def authorize_external_action(self, target: str, technique: str) -> None:
        self.check_cancelled()
        if not self._external_operations_enabled:
            raise AdapterFailure("ADAPTER_EXTERNAL_OPERATION_DISABLED")
        if target != self.context.target or technique != self.context.technique:
            raise AdapterFailure("ADAPTER_TARGET_OR_TECHNIQUE_MISMATCH")
        if not self._revalidate():
            raise AdapterFailure("POLICY_REVALIDATION_DENIED")
        self.check_cancelled()

    def report_progress(self, percent: int, phase: str) -> None:
        self.check_cancelled()
        if not 0 <= percent <= 100:
            raise ValueError("Progress percent must be between 0 and 100.")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,39}", phase):
            raise ValueError("Progress phase must be a safe identifier.")
        self._progress(percent, phase)


class DomainPostureAdapter:
    """Adapter for the existing bounded, single-domain posture assessment."""

    def __init__(self, repository: Repository) -> None:
        self.repository = repository
        self._capabilities = AdapterCapabilities(
            adapter_id="builtin.domain-posture",
            techniques=("service_fingerprint",),
            target_types=("domain",),
            action_class="controlled_active",
            enabled=True,
            performs_external_operations=True,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if parameters:
            raise ValueError("The domain posture adapter accepts no caller parameters.")
        return {}

    def execute(
        self,
        context: ExecutionContext,
        parameters: dict[str, Any],
        control: AdapterControl,
    ) -> AdapterResult:
        self.validate_parameters(parameters)
        control.report_progress(5, "revalidating")
        grant = AuthorizationGrant(
            target=context.target,
            method="engagement_policy",
            operator=context.requester_user_id,
            authorized_at=_utc(context.created_at),
            valid_until=_utc(context.expires_at),
            profile="light",
        )
        probe = NetworkDomainProbe(
            before_external_action=lambda: _run_control_action(
                control, context.target, context.technique
            )
        )
        control.authorize_external_action(context.target, context.technique)
        control.report_progress(10, "assessment_started")
        result = DomainAssessmentService(self.repository, probe).assess(grant)
        control.report_progress(95, "persisting_results")
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="partial" if result.status != "complete" else "complete",
            result_id=result.scan_id,
            summary={"finding_count": len(result.findings), "scan_status": result.status},
        )


class RepositoryCodeAssessmentAdapter:
    """Read-only local assessment of one verified managed repository snapshot."""

    def __init__(self, repository: SQLiteRepository, snapshots: RepositorySnapshotStore, bounds: ScanBounds) -> None:
        self.repository = repository
        self.snapshots = snapshots
        self.bounds = bounds
        self.bounds_document = {
            "max_files": bounds.max_files,
            "max_total_bytes": bounds.max_total_bytes,
            "max_file_bytes": bounds.max_file_bytes,
            "max_depth": bounds.max_depth,
            "per_file_seconds": bounds.per_file_seconds,
            "job_deadline_seconds": bounds.job_deadline_seconds,
            "excluded_paths": list(bounds.excluded_paths),
        }
        self._capabilities = AdapterCapabilities(
            adapter_id="builtin.repository-code-assessment",
            techniques=(REPOSITORY_TECHNIQUE,),
            target_types=("repository",),
            action_class="passive",
            enabled=True,
            performs_external_operations=False,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if parameters:
            raise ValueError("Repository code assessment accepts no caller parameters.")
        return {}

    def execute(self, context: ExecutionContext, parameters: dict[str, Any], control: AdapterControl) -> AdapterResult:
        self.validate_parameters(parameters)
        if (
            context.asset_type != "repository"
            or context.technique != REPOSITORY_TECHNIQUE
            or context.action_class != "passive"
            or not context.repository_binding_id
            or not context.repository_snapshot_id
            or not context.repository_snapshot_sha256
            or not context.repository_attestation_id
            or not context.repository_manifest_version
            or context.adapter_id != self.capabilities.adapter_id
            or context.adapter_version != "1"
            or context.scanner_version != SCANNER_VERSION
            or context.exclusion_policy_version != "repository-exclusions-v1"
            or context.scan_bounds != self.bounds_document
        ):
            raise AdapterFailure("REPOSITORY_EXECUTION_CONTEXT_INVALID")
        snapshot, path = self.snapshots.verify(context.organization_id, context.repository_snapshot_id)
        if (
            snapshot is None or path is None
            or snapshot["sha256"] != context.repository_snapshot_sha256
            or snapshot["manifest_version"] != context.repository_manifest_version
            or snapshot["scanner_version"] != context.scanner_version
        ):
            raise AdapterFailure("REPOSITORY_SNAPSHOT_INTEGRITY_FAILED")
        with self.repository.engine.connect() as connection:
            from chinescan.core.storage.sqlite import (
                repository_asset_bindings,
                repository_attestations,
            )
            binding = connection.execute(select(repository_asset_bindings).where(
                repository_asset_bindings.c.id == context.repository_binding_id,
                repository_asset_bindings.c.organization_id == context.organization_id,
                repository_asset_bindings.c.engagement_id == context.engagement_id,
                repository_asset_bindings.c.asset_id == context.asset_id,
                repository_asset_bindings.c.snapshot_id == context.repository_snapshot_id,
                repository_asset_bindings.c.snapshot_sha256 == context.repository_snapshot_sha256,
            )).first()
            attestation = connection.execute(select(repository_attestations).where(
                repository_attestations.c.id == context.repository_attestation_id,
                repository_attestations.c.organization_id == context.organization_id,
                repository_attestations.c.engagement_id == context.engagement_id,
                repository_attestations.c.asset_id == context.asset_id,
                repository_attestations.c.authorization_id == context.authorization_id,
                repository_attestations.c.scope_revision_id == context.scope_revision_id,
            )).first()
        if not binding or not attestation or attestation.attestation_version != context.repository_attestation_version:
            raise AdapterFailure("REPOSITORY_BINDING_OR_ATTESTATION_INVALID")

        control.report_progress(5, "snapshot_verified")
        scan_id = str(uuid5(NAMESPACE_URL, f"chinescan-execution:{context.job_id}"))
        target_id = context.asset_id
        target = Target(value=context.target, kind="repository")
        started = datetime.now(UTC)
        saved_findings: set[str] = set()

        def persist_partial(findings: list[Any]) -> None:
            with self.repository.organization_context(context.organization_id):
                with self.repository.execution_provenance_context(context.model_dump(mode="json")):
                    self.repository.save("target", target_id, target.model_dump(mode="json"))
                    for finding in findings:
                        if finding.finding_id not in saved_findings:
                            self.repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
                            saved_findings.add(finding.finding_id)
                    partial = Scan(
                        scan_id=scan_id, target_id=target_id, scanner=SCANNER_VERSION,
                        started_at=started, status="partial",
                        finding_ids=sorted(saved_findings), verdict=ScanVerdict.NO_MATCHES_WITH_GAPS,
                    )
                    self.repository.save("scan", scan_id, partial.model_dump(mode="json"))
            summary = {"status": "partial", "finding_count": len(saved_findings), "snapshot_sha256": context.repository_snapshot_sha256}
            with self.repository.engine.begin() as connection:
                changed = connection.execute(update(execution_jobs).where(
                    execution_jobs.c.id == context.job_id,
                    execution_jobs.c.organization_id == context.organization_id,
                    execution_jobs.c.engagement_id == context.engagement_id,
                    execution_jobs.c.status == "running",
                ).values(scan_id=scan_id, result_summary=summary))
                if changed.rowcount:
                    connection.execute(assessment_audit_events.insert().values(
                        id=str(uuid4()),
                        organization_id=context.organization_id,
                        engagement_id=context.engagement_id,
                        actor_user_id=context.requester_user_id,
                        action="execution.partial_result_persisted",
                        resource_type="execution_job", resource_id=context.job_id,
                        decision="ALLOW", reason_code="PARTIAL_RESULT_PERSISTED",
                        occurred_at=datetime.now(UTC).isoformat(),
                        details={"scan_id": scan_id, "finding_count": len(saved_findings)},
                    ))

        control.report_progress(10, "code_assessment_started")
        result = CodeScanService(
            [BuiltinRuleScanner(self.bounds)], repository=None, bounds=self.bounds,
        ).scan(path, control=control, scan_id=scan_id, on_partial=persist_partial)
        control.check_cancelled()
        verified_snapshot, verified_path = self.snapshots.verify(
            context.organization_id, context.repository_snapshot_id
        )
        if (
            verified_snapshot is None
            or verified_path != path
            or verified_snapshot["sha256"] != context.repository_snapshot_sha256
        ):
            raise AdapterFailure("REPOSITORY_SNAPSHOT_CHANGED_DURING_ASSESSMENT")
        with self.repository.organization_context(context.organization_id):
            with self.repository.execution_provenance_context(context.model_dump(mode="json")):
                for finding in result.findings:
                    control.check_cancelled()
                    if finding.finding_id not in saved_findings:
                        self.repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
                        saved_findings.add(finding.finding_id)
                final_scan = Scan(
                    scan_id=scan_id, target_id=target_id, scanner=SCANNER_VERSION,
                    started_at=result.started_at, finished_at=result.finished_at,
                    status="partial" if result.failures or (result.coverage and result.coverage.gaps) else "complete",
                    finding_ids=sorted(saved_findings), failures=result.failures,
                    coverage=result.coverage, code_assessment=result.code_assessment,
                    verdict=result.verdict,
                    scan_options={"repository_snapshot_sha256": context.repository_snapshot_sha256 or "", "offline_advisory_snapshot": "bundled"},
                )
                self.repository.save("scan", scan_id, final_scan.model_dump(mode="json"))
        control.report_progress(95, "results_persisted")
        partial = result.failures or bool(result.coverage and result.coverage.gaps)
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="partial" if partial else "complete",
            result_id=scan_id,
            summary={
                "finding_count": len(saved_findings),
                "scan_status": "partial" if partial else "complete",
                "project_types": result.project_types,
                "coverage": result.coverage.model_dump(mode="json") if result.coverage else None,
                "scanner_version": SCANNER_VERSION,
                "snapshot_sha256": context.repository_snapshot_sha256,
            },
        )


class GovernedLogAnalysisAdapter:
    """Analyze only a verified immutable, engagement-owned log evidence snapshot."""

    def __init__(self, repository: SQLiteRepository, evidence: LogEvidenceStore) -> None:
        self.repository = repository
        self.evidence = evidence
        self._capabilities = AdapterCapabilities(
            adapter_id="builtin.governed-log-analysis",
            techniques=("log_analysis",),
            target_types=("log_evidence",),
            action_class="passive",
            enabled=True,
            performs_external_operations=False,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if parameters:
            raise ValueError("Governed log analysis does not accept caller parameters.")
        return {}

    def execute(
        self,
        context: ExecutionContext,
        parameters: dict[str, Any],
        control: AdapterControl,
    ) -> AdapterResult:
        self.validate_parameters(parameters)
        if (
            context.asset_type != "log_evidence"
            or context.technique != "log_analysis"
            or context.action_class != "passive"
            or context.target != f"log:{context.asset_id}"
            or not context.log_evidence_snapshot_id
            or not context.log_evidence_sha256
            or context.log_evidence_manifest_version != 1
            or context.log_analysis_version != LOG_ANALYSIS_VERSION
            or context.log_ruleset_version != LOG_RULESET_VERSION
            or context.adapter_id != self.capabilities.adapter_id
            or context.adapter_version != "1"
        ):
            raise AdapterFailure("LOG_EXECUTION_CONTEXT_INVALID")
        snapshot, root = self.evidence.verify(
            context.organization_id, context.engagement_id, context.asset_id,
            context.log_evidence_snapshot_id,
        )
        if (
            snapshot is None or root is None
            or snapshot["sha256"] != context.log_evidence_sha256
            or snapshot["manifest_version"] != context.log_evidence_manifest_version
            or snapshot["source_format"] != context.log_evidence_source_format
        ):
            raise AdapterFailure("LOG_EVIDENCE_INTEGRITY_FAILED")
        control.report_progress(10, "log_evidence_verified")
        control.check_cancelled()
        try:
            result = LogAnalysisService(self.repository).analyze(
                root,
                safe_target=context.target,
                sanitize_output=True,
                control=control,
            )
        except ExecutionCancelled:
            raise
        except Exception as exc:
            raise AdapterFailure("LOG_ANALYSIS_FAILED") from exc
        control.check_cancelled()
        verified, verified_root = self.evidence.verify(
            context.organization_id, context.engagement_id, context.asset_id,
            context.log_evidence_snapshot_id,
        )
        if (
            verified is None or verified_root != root
            or verified["sha256"] != context.log_evidence_sha256
        ):
            raise AdapterFailure("LOG_EVIDENCE_CHANGED_DURING_ANALYSIS")
        control.report_progress(95, "log_results_persisted")
        partial = bool(result.errors)
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="partial" if partial else "complete",
            result_id=result.scan_id,
            summary={
                "event_count": result.events,
                "alert_count": len(result.alerts),
                "source_count": result.source_count,
                "parse_error_count": len(result.errors),
                "evidence_sha256": context.log_evidence_sha256,
                "analysis_version": LOG_ANALYSIS_VERSION,
                "ruleset_version": LOG_RULESET_VERSION,
            },
        )


class GovernedMalwareStaticTriageAdapter:
    """Perform bounded in-process static parsing of one verified evidence snapshot."""

    def __init__(self, repository: SQLiteRepository, evidence: MalwareEvidenceStore) -> None:
        self.repository = repository
        self.evidence = evidence
        self._capabilities = AdapterCapabilities(
            adapter_id="builtin.malware-static-triage",
            techniques=("malware_static_triage",),
            target_types=("malware_evidence",),
            action_class="passive",
            enabled=True,
            performs_external_operations=False,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if parameters:
            raise ValueError("Static malware triage does not accept caller parameters.")
        return {}

    def execute(
        self,
        context: ExecutionContext,
        parameters: dict[str, Any],
        control: AdapterControl,
    ) -> AdapterResult:
        self.validate_parameters(parameters)
        if (
            context.asset_type != "malware_evidence"
            or context.technique != "malware_static_triage"
            or context.action_class != "passive"
            or context.adapter_id != self.capabilities.adapter_id
            or context.adapter_version != "1"
            or context.malware_analysis_version != MALWARE_ANALYSIS_VERSION
            or not context.malware_evidence_snapshot_id
            or not context.malware_evidence_sha256
            or not context.malware_evidence_manifest_sha256
            or context.malware_evidence_manifest_version != 1
        ):
            raise AdapterFailure("MALWARE_EXECUTION_CONTEXT_INVALID")
        snapshot, sample_path = self.evidence.verify(
            context.organization_id,
            context.engagement_id,
            context.asset_id,
            context.malware_evidence_snapshot_id,
        )
        if (
            snapshot is None
            or sample_path is None
            or snapshot["sha256"] != context.malware_evidence_sha256
            or snapshot["manifest_sha256"] != context.malware_evidence_manifest_sha256
            or snapshot["manifest_version"] != context.malware_evidence_manifest_version
        ):
            raise AdapterFailure("MALWARE_EVIDENCE_INTEGRITY_FAILED")
        control.report_progress(10, "malware_evidence_verified")
        control.check_cancelled()
        try:
            result = analyze_file(
                sample_path,
                use_native_parser=False,
                control=control,
                deadline_seconds=60,
                filename_hint=snapshot["original_filename"],
            )
        except ExecutionCancelled:
            raise
        except AnalysisError as exc:
            raise AdapterFailure("MALWARE_STATIC_ANALYSIS_FAILED") from exc
        except Exception as exc:
            raise AdapterFailure("MALWARE_STATIC_ANALYSIS_FAILED") from exc
        control.check_cancelled()
        verified, verified_path = self.evidence.verify(
            context.organization_id,
            context.engagement_id,
            context.asset_id,
            context.malware_evidence_snapshot_id,
        )
        if (
            verified is None
            or verified_path != sample_path
            or verified["sha256"] != context.malware_evidence_sha256
        ):
            raise AdapterFailure("MALWARE_EVIDENCE_CHANGED_DURING_ANALYSIS")
        analysis_id = str(uuid4())
        safe_result = _safe_malware_result(result)
        record = {
            "analysis_id": analysis_id,
            "sample_id": context.asset_id,
            "status": "complete",
            "created_at": datetime.now(UTC).isoformat(),
            "result": safe_result,
            "evidence_snapshot_id": context.malware_evidence_snapshot_id,
            "evidence_sha256": context.malware_evidence_sha256,
            "manifest_sha256": context.malware_evidence_manifest_sha256,
            "adapter_id": self.capabilities.adapter_id,
            "adapter_version": "1",
            "analysis_version": MALWARE_ANALYSIS_VERSION,
        }
        control.check_cancelled()
        with self.repository.organization_context(context.organization_id):
            self.repository.save("malware_analysis", analysis_id, record)
        control.report_progress(95, "malware_analysis_persisted")
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="complete",
            result_id=analysis_id,
            summary={
                "analysis_id": analysis_id,
                "evidence_sha256": context.malware_evidence_sha256,
                "file_type": result.file_type,
                "size_bytes": result.size_bytes,
                "verdict": result.verdict,
                "verdict_caveat": result.verdict_caveat,
                "indicator_count": result.indicator_count,
                "warning_count": len(result.warnings),
                "interpretation": "Static heuristic observations are not proof of maliciousness or safety.",
            },
        )


def _safe_malware_result(result: Any) -> dict[str, Any]:
    """Persist bounded file identity and measurements, not sample-derived text."""
    return {
        "size_bytes": int(result.size_bytes),
        "hashes": {
            "md5": str(result.md5)[:32],
            "sha1": str(result.sha1)[:40],
            "sha256": str(result.sha256)[:64],
        },
        "file_type": str(result.file_type)[:120],
        "entropy_bits_per_byte": float(result.entropy_bits_per_byte),
        "timestamp_utc": result.timestamp_utc,
        "verdict": str(result.verdict)[:80],
        "verdict_caveat": str(result.verdict_caveat)[:240],
        "printable_string_count": int(result.printable_string_count),
        "architecture": str(result.architecture)[:80] if result.architecture else None,
        "indicator_count": int(result.indicator_count),
        "indicator_types": sorted({str(kind)[:32] for kind, _ in result.indicators})[:32],
        "archive_member_count": result.archive_member_count,
        "characteristic_count": len(result.characteristics),
        "warning_count": len(result.warnings),
    }


def _run_control_action(control: AdapterControl, target: str, technique: str) -> bool:
    try:
        control.authorize_external_action(target, technique)
    except AdapterFailure as exc:
        if exc.code == "POLICY_REVALIDATION_DENIED":
            raise ExecutionStopped(
                "Execution authorization changed before network activity."
            ) from exc
        raise
    return True


def build_default_adapter_registry(
    repository: Repository,
    repository_adapter: GovernedAssessmentAdapter | None = None,
    log_adapter: GovernedAssessmentAdapter | None = None,
    malware_adapter: GovernedAssessmentAdapter | None = None,
    chain_import_adapter: GovernedAssessmentAdapter | None = None,
    chain_provider_adapter: GovernedAssessmentAdapter | None = None,
) -> AdapterRegistry:
    """Build the explicit allowlist of currently operational governed adapters."""

    adapters: tuple[GovernedAssessmentAdapter, ...] = (DomainPostureAdapter(repository),)
    if repository_adapter is not None:
        adapters += (repository_adapter,)
    if log_adapter is not None:
        adapters += (log_adapter,)
    if malware_adapter is not None:
        adapters += (malware_adapter,)
    if chain_import_adapter is not None:
        adapters += (chain_import_adapter,)
    if chain_provider_adapter is not None:
        adapters += (chain_provider_adapter,)
    return AdapterRegistry(adapters)
