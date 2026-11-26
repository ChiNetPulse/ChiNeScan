"""Server-side execution admission and revalidation for engagement jobs.

This module admits the explicitly registered domain, repository, log-evidence,
and malware-evidence adapters. Standalone local workflows remain separate.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any
from uuid import uuid4

from sqlalchemy import func, or_, select, update

from chinescan.chain_trace.registry import CHAINS, normalize_address
from chinescan.core.chain_trace_execution import (
    CHAIN_IMPORT_TECHNIQUE,
    CHAIN_PROVIDER_TECHNIQUE,
)
from chinescan.core.engagement_security import (
    EngagementSecurityService,
    _stamp,
    _utc,
    normalize_target,
)
from chinescan.core.execution_adapters import (
    AdapterFailure,
    AdapterRegistry,
    ExecutionContext,
    ExecutionControl,
    build_default_adapter_registry,
)
from chinescan.core.organizations import now_iso
from chinescan.core.repository_assessment import REPOSITORY_TECHNIQUE
from chinescan.core.resource_governance import (
    ExecutionDeadlineExceeded,
    ResourceLimitError,
    ResourceLimits,
)
from chinescan.core.storage.sqlite import (
    approval_requests,
    authorization_documents,
    engagement_assets,
    execution_action_attempts,
    execution_jobs,
    execution_result_provenance,
    log_evidence_snapshots,
    malware_evidence_snapshots,
    repository_asset_bindings,
    repository_attestations,
    repository_snapshots,
    worker_leases,
)
from chinescan.domain_assessment.probe import ExecutionCancelled, ExecutionStopped

JOB_CONTEXT_TTL = timedelta(minutes=10)
ACTIVE_JOB_LIMIT = 4
GLOBAL_ACTIVE_JOB_LIMIT = 16
DEFAULT_LEASE_DURATION_SECONDS = 30.0
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 10.0
MIN_LEASE_DURATION_SECONDS = 5.0
MAX_LEASE_DURATION_SECONDS = 3600.0
DEFAULT_SHUTDOWN_GRACE_SECONDS = 5.0


class ExecutionGovernanceService:
    """Create, claim, revalidate, and finish durable governed execution jobs."""

    def __init__(
        self,
        security: EngagementSecurityService,
        adapters: AdapterRegistry | None = None,
        repository_scan_bounds: dict[str, Any] | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> None:
        self.security = security
        self.engine = security.engine
        self.adapters = adapters or build_default_adapter_registry(security.repository)
        self.repository_scan_bounds = dict(repository_scan_bounds or {})
        self.resource_limits = resource_limits or ResourceLimits()

    def create_domain_job(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        *,
        approval_id: str | None,
        idempotency_key: str,
        requested_target: str | None = None,
    ) -> dict[str, Any]:
        return self.create_governed_job(
            user_id,
            organization_id,
            engagement_id,
            asset_id,
            technique="service_fingerprint",
            approval_id=approval_id,
            idempotency_key=idempotency_key,
            requested_target=requested_target,
        )

    def create_governed_job(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        *,
        technique: str,
        approval_id: str | None,
        idempotency_key: str,
        requested_target: str | None = None,
        repository_binding_id: str | None = None,
        repository_attestation_id: str | None = None,
        chain_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create an adapter-backed job without consuming its approval at admission."""
        if not idempotency_key or len(idempotency_key) > 80:
            raise ValueError("A valid idempotency key is required.")
        now = datetime.now(UTC)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.organization_id == organization_id,
                        execution_jobs.c.engagement_id == engagement_id,
                        execution_jobs.c.requester_user_id == user_id,
                        execution_jobs.c.idempotency_key == idempotency_key,
                    )
                ).first()
                if existing:
                    item = dict(existing._mapping)
                    if (
                        item["asset_id"] != asset_id
                        or item["approval_id"] != approval_id
                        or item["technique"] != technique
                        or item.get("repository_binding_id") != repository_binding_id
                        or item.get("repository_attestation_id") != repository_attestation_id
                    ):
                        raise ValueError("Idempotency key was already used for another request.")
                    if chain_request is not None:
                        try:
                            requested_context = self.adapters.resolve(
                                item["asset_type"], item["technique"]
                            ).validate_parameters(chain_request)
                        except (TypeError, ValueError):
                            raise ValueError("Assessment parameters are invalid.") from None
                        if (
                            item.get("execution_context", {}).get("chain_context")
                            != requested_context
                        ):
                            raise ValueError(
                                "Idempotency key was already used for another request."
                            )
                    if (
                        requested_target is not None
                        and normalize_target(item["asset_type"], requested_target) != item["target"]
                    ):
                        raise ValueError("Idempotency key was already used for another target.")
                    connection.commit()
                    return item

                asset = connection.execute(
                    select(engagement_assets).where(
                        engagement_assets.c.id == asset_id,
                        engagement_assets.c.organization_id == organization_id,
                        engagement_assets.c.engagement_id == engagement_id,
                        engagement_assets.c.status == "active",
                    )
                ).first()
                if not asset:
                    connection.rollback()
                    return {
                        "decision": "DENY",
                        "reason_code": "ASSET_UNAVAILABLE",
                        "explanation": "The active domain asset is unavailable.",
                    }
                try:
                    adapter, parameters = self.adapters.validate_parameters(
                        asset.asset_type, technique, chain_request or {}
                    )
                except (ValueError, TypeError):
                    connection.rollback()
                    return {
                        "decision": "DENY",
                        "reason_code": "TECHNIQUE_UNSUPPORTED",
                        "explanation": "No enabled adapter supports this operation.",
                    }
                if parameters and technique != CHAIN_IMPORT_TECHNIQUE:
                    connection.rollback()
                    return {
                        "decision": "DENY",
                        "reason_code": "ADAPTER_PARAMETERS_UNSUPPORTED",
                        "explanation": "This operation does not accept caller parameters.",
                    }
                if (
                    requested_target is not None
                    and normalize_target(asset.asset_type, requested_target) != asset.target
                ):
                    connection.rollback()
                    return {
                        "decision": "DENY",
                        "reason_code": "ASSET_TARGET_MISMATCH",
                        "explanation": "The supplied target does not match the registered asset.",
                    }
                decision = self.security._decision(
                    connection,
                    user_id,
                    organization_id,
                    engagement_id,
                    asset.asset_type,
                    asset.target,
                    technique,
                    approval_id,
                    False,
                    now,
                )
                if (
                    decision.get("action_class") is not None
                    and decision["action_class"] != adapter.capabilities.action_class
                ):
                    decision = {
                        **decision,
                        "decision": "DENY",
                        "reason_code": "ADAPTER_CLASSIFICATION_MISMATCH",
                        "explanation": "Adapter classification does not match centralized policy.",
                    }
                if decision["decision"] != "ALLOW":
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "execution.approval_required"
                        if decision["decision"] == "REQUIRE_APPROVAL"
                        else "execution.admission_denied",
                        "execution_job",
                        None,
                        decision=decision["decision"],
                        reason_code=decision["reason_code"],
                        details={
                            "asset_id": asset_id,
                            "technique": technique,
                            "target_sha256": hashlib.sha256(asset.target.encode()).hexdigest(),
                        },
                    )
                    connection.commit()
                    return decision

                repository_context: dict[str, Any] = {}
                log_context: dict[str, Any] = {}
                malware_context: dict[str, Any] = {}
                chain_context: dict[str, Any] = {}
                chain_adapter_context: dict[str, Any] = {}
                policy_request_digest = decision["request_digest"]
                request_digest = policy_request_digest
                if asset.asset_type == "repository":
                    binding = connection.execute(
                        select(repository_asset_bindings).where(
                            repository_asset_bindings.c.id == repository_binding_id,
                            repository_asset_bindings.c.organization_id == organization_id,
                            repository_asset_bindings.c.engagement_id == engagement_id,
                            repository_asset_bindings.c.asset_id == asset_id,
                        )
                    ).first()
                    if not binding:
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "REPOSITORY_BINDING_UNAVAILABLE",
                            "explanation": "The repository binding is unavailable.",
                        }
                    binding_data = dict(binding._mapping)
                    snapshot = connection.execute(
                        select(repository_snapshots).where(
                            repository_snapshots.c.id == binding_data["snapshot_id"],
                            repository_snapshots.c.organization_id == organization_id,
                            repository_snapshots.c.status == "available",
                        )
                    ).first()
                    attestation = connection.execute(
                        select(repository_attestations).where(
                            repository_attestations.c.id == repository_attestation_id,
                            repository_attestations.c.organization_id == organization_id,
                            repository_attestations.c.engagement_id == engagement_id,
                            repository_attestations.c.asset_id == asset_id,
                            repository_attestations.c.authorization_id
                            == decision["authorization_id"],
                            repository_attestations.c.scope_revision_id
                            == decision["scope_revision_id"],
                        )
                    ).first()
                    if not snapshot or not attestation or technique != REPOSITORY_TECHNIQUE:
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "REPOSITORY_ATTESTATION_OR_SNAPSHOT_INVALID",
                            "explanation": "The repository attestation or snapshot is unavailable.",
                        }
                    snapshot_data = dict(snapshot._mapping)
                    attestation_data = dict(attestation._mapping)
                    repository_context = {
                        "repository_binding_id": binding_data["id"],
                        "repository_snapshot_id": snapshot_data["id"],
                        "repository_snapshot_sha256": snapshot_data["sha256"],
                        "repository_manifest_version": snapshot_data["manifest_version"],
                        "repository_attestation_id": attestation_data["id"],
                        "repository_attestation_version": attestation_data["attestation_version"],
                        "adapter_id": adapter.capabilities.adapter_id,
                        "adapter_version": "1",
                        "scanner_version": snapshot_data["scanner_version"],
                        "scan_bounds": self.repository_scan_bounds,
                        "exclusion_policy_version": snapshot_data["manifest"].get(
                            "exclusion_policy"
                        ),
                    }
                    digest_context = {
                        "policy_request_digest": policy_request_digest,
                        "organization_id": organization_id,
                        "engagement_id": engagement_id,
                        "requester_user_id": user_id,
                        "asset_id": asset_id,
                        "target": decision["target"],
                        "technique": technique,
                        "action_class": decision["action_class"],
                        "scope_revision_id": decision["scope_revision_id"],
                        "authorization_id": decision["authorization_id"],
                        "authorization_document_sha256": connection.execute(
                            select(authorization_documents.c.sha256).where(
                                authorization_documents.c.organization_id == organization_id,
                                authorization_documents.c.authorization_id
                                == decision["authorization_id"],
                            )
                        ).scalar_one_or_none(),
                        **repository_context,
                    }
                    request_digest = hashlib.sha256(
                        json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()

                if asset.asset_type == "log_evidence":
                    evidence_snapshot = connection.execute(
                        select(log_evidence_snapshots).where(
                            log_evidence_snapshots.c.organization_id == organization_id,
                            log_evidence_snapshots.c.engagement_id == engagement_id,
                            log_evidence_snapshots.c.asset_id == asset_id,
                            log_evidence_snapshots.c.status == "available",
                        )
                    ).first()
                    if not evidence_snapshot or technique not in {
                        "log_analysis",
                        CHAIN_IMPORT_TECHNIQUE,
                    }:
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "LOG_EVIDENCE_UNAVAILABLE",
                            "explanation": "Registered log evidence is unavailable.",
                        }
                    evidence_data = dict(evidence_snapshot._mapping)
                    log_context = {
                        "log_evidence_snapshot_id": evidence_data["id"],
                        "log_evidence_sha256": evidence_data["sha256"],
                        "log_evidence_manifest_version": evidence_data["manifest_version"],
                        "log_evidence_source_format": evidence_data["source_format"],
                        "log_analysis_version": "chinescan-log-analysis-v1"
                        if technique == "log_analysis"
                        else None,
                        "log_ruleset_version": "builtin-detections-v1"
                        if technique == "log_analysis"
                        else None,
                        "adapter_id": "builtin.governed-log-analysis"
                        if technique == "log_analysis"
                        else "builtin.governed-chain-import",
                        "adapter_version": "1",
                    }
                    if technique == CHAIN_IMPORT_TECHNIQUE:
                        chain_context = parameters
                    digest_context = {
                        "policy_request_digest": policy_request_digest,
                        "organization_id": organization_id,
                        "engagement_id": engagement_id,
                        "requester_user_id": user_id,
                        "asset_id": asset_id,
                        "target": decision["target"],
                        "technique": technique,
                        "action_class": decision["action_class"],
                        "scope_revision_id": decision["scope_revision_id"],
                        "authorization_id": decision["authorization_id"],
                        "authorization_document_sha256": connection.execute(
                            select(authorization_documents.c.sha256).where(
                                authorization_documents.c.organization_id == organization_id,
                                authorization_documents.c.authorization_id
                                == decision["authorization_id"],
                            )
                        ).scalar_one_or_none(),
                        **log_context,
                        **({"chain_context": chain_context} if chain_context else {}),
                    }
                    request_digest = hashlib.sha256(
                        json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()

                if asset.asset_type == "chain_address":
                    if technique != CHAIN_PROVIDER_TECHNIQUE:
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "CHAIN_PROVIDER_UNSUPPORTED",
                            "explanation": "No enabled adapter supports this chain operation.",
                        }
                    parts = asset.target.split(":")
                    if len(parts) != 4 or parts[0] != "chain" or parts[2] != "etherscan-v2":
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "CHAIN_TARGET_INVALID",
                            "explanation": "The registered chain target is invalid.",
                        }
                    chain = CHAINS.get(parts[1])
                    if not chain or chain.family != "evm" or not chain.chain_id:
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "CHAIN_PROVIDER_UNSUPPORTED",
                            "explanation": "No configured provider supports this chain.",
                        }
                    chain_context = {
                        "chain": chain.name,
                        "address": normalize_address(chain, parts[3]),
                        "provider": "etherscan-v2",
                    }
                    chain_adapter_context = {
                        "adapter_id": adapter.capabilities.adapter_id,
                        "adapter_version": "1",
                    }
                    digest_context = {
                        "policy_request_digest": policy_request_digest,
                        "organization_id": organization_id,
                        "engagement_id": engagement_id,
                        "requester_user_id": user_id,
                        "asset_id": asset_id,
                        "target": decision["target"],
                        "technique": technique,
                        "action_class": decision["action_class"],
                        "scope_revision_id": decision["scope_revision_id"],
                        "authorization_id": decision["authorization_id"],
                        "authorization_document_sha256": connection.execute(
                            select(authorization_documents.c.sha256).where(
                                authorization_documents.c.organization_id == organization_id,
                                authorization_documents.c.authorization_id
                                == decision["authorization_id"],
                            )
                        ).scalar_one_or_none(),
                        "chain_context": chain_context,
                        **chain_adapter_context,
                    }
                    request_digest = hashlib.sha256(
                        json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()

                if asset.asset_type == "malware_evidence":
                    malware_snapshot = connection.execute(
                        select(malware_evidence_snapshots).where(
                            malware_evidence_snapshots.c.organization_id == organization_id,
                            malware_evidence_snapshots.c.engagement_id == engagement_id,
                            malware_evidence_snapshots.c.asset_id == asset_id,
                            malware_evidence_snapshots.c.status == "available",
                        )
                    ).first()
                    if not malware_snapshot or technique != "malware_static_triage":
                        connection.rollback()
                        return {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "MALWARE_EVIDENCE_UNAVAILABLE",
                            "explanation": "Registered malware evidence is unavailable.",
                        }
                    evidence_data = dict(malware_snapshot._mapping)
                    malware_context = {
                        "malware_evidence_snapshot_id": evidence_data["id"],
                        "malware_evidence_sha256": evidence_data["sha256"],
                        "malware_evidence_manifest_sha256": evidence_data["manifest_sha256"],
                        "malware_evidence_manifest_version": evidence_data["manifest_version"],
                        "malware_analysis_version": "chinescan-static-malware-v1",
                        "adapter_id": "builtin.malware-static-triage",
                        "adapter_version": "1",
                    }
                    digest_context = {
                        "policy_request_digest": policy_request_digest,
                        "organization_id": organization_id,
                        "engagement_id": engagement_id,
                        "requester_user_id": user_id,
                        "asset_id": asset_id,
                        "target": decision["target"],
                        "technique": technique,
                        "action_class": decision["action_class"],
                        "scope_revision_id": decision["scope_revision_id"],
                        "authorization_id": decision["authorization_id"],
                        "authorization_document_sha256": connection.execute(
                            select(authorization_documents.c.sha256).where(
                                authorization_documents.c.organization_id == organization_id,
                                authorization_documents.c.authorization_id
                                == decision["authorization_id"],
                            )
                        ).scalar_one_or_none(),
                        **malware_context,
                    }
                    request_digest = hashlib.sha256(
                        json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()

                authorization_document_sha256 = connection.execute(
                    select(authorization_documents.c.sha256).where(
                        authorization_documents.c.organization_id == organization_id,
                        authorization_documents.c.authorization_id == decision["authorization_id"],
                    )
                ).scalar_one_or_none()

                if approval_id:
                    existing_binding = connection.execute(
                        select(execution_jobs.c.id).where(
                            execution_jobs.c.approval_id == approval_id
                        )
                    ).first()
                    if existing_binding:
                        denied = {
                            **decision,
                            "decision": "DENY",
                            "reason_code": "APPROVAL_ALREADY_BOUND",
                            "explanation": "This approval is already bound to an execution job.",
                        }
                        self.security._audit(
                            connection,
                            organization_id,
                            engagement_id,
                            user_id,
                            "execution.admission_denied",
                            "execution_job",
                            None,
                            decision="DENY",
                            reason_code="APPROVAL_ALREADY_BOUND",
                            details={"approval_id": approval_id},
                        )
                        connection.commit()
                        return denied

                job_id = str(uuid4())
                decision_id = str(uuid4())
                context = {
                    "version": 1,
                    "job_id": job_id,
                    "organization_id": organization_id,
                    "requester_user_id": user_id,
                    "engagement_id": engagement_id,
                    "assignment_roles": sorted(
                        self.security._assignment_roles(
                            connection, user_id, organization_id, engagement_id
                        )
                    ),
                    "asset_id": asset_id,
                    "target": decision["target"],
                    "asset_type": asset.asset_type,
                    "technique": technique,
                    "action_class": decision["action_class"],
                    "scope_revision_id": decision["scope_revision_id"],
                    "authorization_id": decision["authorization_id"],
                    "authorization_document_sha256": authorization_document_sha256,
                    "approval_id": approval_id,
                    "policy_decision_id": decision_id,
                    "request_digest": request_digest,
                    "policy_request_digest": policy_request_digest
                    if (repository_context or log_context or malware_context or chain_context)
                    else None,
                    **repository_context,
                    **log_context,
                    **malware_context,
                    **chain_adapter_context,
                    **({"chain_context": chain_context} if chain_context else {}),
                    "created_at": _stamp(now),
                    "expires_at": _stamp(now + JOB_CONTEXT_TTL),
                }
                item = {
                    "id": job_id,
                    "organization_id": organization_id,
                    "engagement_id": engagement_id,
                    "requester_user_id": user_id,
                    "asset_id": asset_id,
                    "target": decision["target"],
                    "asset_type": asset.asset_type,
                    "technique": technique,
                    "action_class": decision["action_class"],
                    "scope_revision_id": decision["scope_revision_id"],
                    "authorization_id": decision["authorization_id"],
                    "authorization_document_sha256": authorization_document_sha256,
                    "approval_id": approval_id,
                    "policy_decision_id": decision_id,
                    "request_digest": request_digest,
                    "policy_request_digest": policy_request_digest
                    if (repository_context or log_context or malware_context or chain_context)
                    else None,
                    "repository_binding_id": repository_context.get("repository_binding_id"),
                    "repository_snapshot_id": repository_context.get("repository_snapshot_id"),
                    "repository_snapshot_sha256": repository_context.get(
                        "repository_snapshot_sha256"
                    ),
                    "repository_manifest_version": repository_context.get(
                        "repository_manifest_version"
                    ),
                    "repository_attestation_id": repository_context.get(
                        "repository_attestation_id"
                    ),
                    "repository_attestation_version": repository_context.get(
                        "repository_attestation_version"
                    ),
                    "repository_scanner_version": repository_context.get("scanner_version"),
                    "repository_scan_bounds": repository_context.get("scan_bounds"),
                    "adapter_id": (
                        repository_context
                        or log_context
                        or malware_context
                        or chain_adapter_context
                    ).get("adapter_id"),
                    "adapter_version": (
                        repository_context
                        or log_context
                        or malware_context
                        or chain_adapter_context
                    ).get("adapter_version"),
                    "exclusion_policy_version": repository_context.get("exclusion_policy_version"),
                    "log_evidence_snapshot_id": log_context.get("log_evidence_snapshot_id"),
                    "log_evidence_sha256": log_context.get("log_evidence_sha256"),
                    "log_evidence_manifest_version": log_context.get(
                        "log_evidence_manifest_version"
                    ),
                    "log_evidence_source_format": log_context.get("log_evidence_source_format"),
                    "log_analysis_version": log_context.get("log_analysis_version"),
                    "log_ruleset_version": log_context.get("log_ruleset_version"),
                    "malware_evidence_snapshot_id": malware_context.get(
                        "malware_evidence_snapshot_id"
                    ),
                    "malware_evidence_sha256": malware_context.get("malware_evidence_sha256"),
                    "malware_evidence_manifest_sha256": malware_context.get(
                        "malware_evidence_manifest_sha256"
                    ),
                    "malware_evidence_manifest_version": malware_context.get(
                        "malware_evidence_manifest_version"
                    ),
                    "malware_analysis_version": malware_context.get("malware_analysis_version"),
                    "execution_context": context,
                    "idempotency_key": idempotency_key,
                    "status": "queued",
                    "created_at": _stamp(now),
                    "expires_at": context["expires_at"],
                    "started_at": None,
                    "finished_at": None,
                    "scan_id": None,
                    "result_summary": None,
                    "approval_consumed_at": None,
                    "error_code": None,
                }
                active_count = connection.execute(
                    select(execution_jobs.c.id).where(
                        execution_jobs.c.organization_id == organization_id,
                        execution_jobs.c.status.in_(["queued", "claimed", "running"]),
                    )
                ).fetchall()
                global_active_count = connection.execute(
                    select(execution_jobs.c.id).where(
                        execution_jobs.c.status.in_(["queued", "claimed", "running"])
                    )
                ).fetchall()
                if len(active_count) >= self.resource_limits.per_org_queued_limit:
                    connection.rollback()
                    raise ResourceLimitError(
                        "org_quota_exceeded",
                        "Organization governed execution queue limit exceeded.",
                        status_code=429,
                        details={
                            "limit": self.resource_limits.per_org_queued_limit,
                            "current": len(active_count),
                        },
                    )
                if len(global_active_count) >= self.resource_limits.global_queued_limit:
                    connection.rollback()
                    raise ResourceLimitError(
                        "execution_queue_full",
                        "The governed execution queue is full.",
                        status_code=429,
                        details={
                            "limit": self.resource_limits.global_queued_limit,
                            "current": len(global_active_count),
                        },
                    )
                connection.execute(execution_jobs.insert().values(**item))
                if item["action_class"] == "sensitive":
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "execution.approval_admitted",
                        "execution_job",
                        job_id,
                        decision="ALLOW",
                        reason_code="APPROVAL_BOUND_TO_EXECUTION_JOB",
                        details={
                            "policy_decision_id": decision_id,
                            "request_digest": decision["request_digest"],
                            "scope_revision_id": decision["scope_revision_id"],
                            "authorization_id": decision["authorization_id"],
                            "approval_id": approval_id,
                            "technique": technique,
                        },
                    )
                self.security._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "execution.job_queued",
                    "execution_job",
                    job_id,
                    decision="ALLOW",
                    reason_code="AUTHORIZED_WITHIN_SCOPE",
                    details={
                        "policy_decision_id": decision_id,
                        "request_digest": decision["request_digest"],
                        "scope_revision_id": decision["scope_revision_id"],
                        "authorization_id": decision["authorization_id"],
                        "approval_id": approval_id,
                        "technique": technique,
                    },
                )
                connection.commit()
                return item
            except Exception:
                connection.rollback()
                raise

    def get_job(self, user_id: str, organization_id: str, job_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            item = connection.execute(
                select(execution_jobs).where(
                    execution_jobs.c.id == job_id,
                    execution_jobs.c.organization_id == organization_id,
                )
            ).first()
            if not item:
                return None
            row = dict(item._mapping)
            if self.security._can_read(connection, user_id, organization_id, row["engagement_id"]):
                return row
            return None

    def get_job_provenance(
        self, user_id: str, organization_id: str, engagement_id: str, job_id: str
    ) -> dict[str, Any] | None:
        """Return immutable job context and only its tenant-scoped result references."""
        with self.engine.connect() as connection:
            job_result = connection.execute(
                select(execution_jobs).where(
                    execution_jobs.c.id == job_id,
                    execution_jobs.c.organization_id == organization_id,
                    execution_jobs.c.engagement_id == engagement_id,
                )
            ).first()
            if not job_result:
                return None
            job = dict(job_result._mapping)
            if not self.security._can_read(connection, user_id, organization_id, engagement_id):
                return None
            try:
                context = ExecutionContext.from_job(job).model_dump(mode="json", exclude_unset=True)
            except (TypeError, ValueError):
                return None
            links = connection.execute(
                select(
                    execution_result_provenance.c.record_type,
                    execution_result_provenance.c.record_id,
                    execution_result_provenance.c.created_at,
                )
                .where(
                    execution_result_provenance.c.job_id == job_id,
                    execution_result_provenance.c.organization_id == organization_id,
                    execution_result_provenance.c.engagement_id == engagement_id,
                )
                .order_by(
                    execution_result_provenance.c.record_type,
                    execution_result_provenance.c.record_id,
                )
            ).all()
            approval_outcome = (
                "not_required"
                if not job["approval_id"]
                else "consumed"
                if job["approval_consumed_at"]
                else "not_consumed"
            )
            return {
                "execution": {
                    "job_id": job["id"],
                    "organization_id": job["organization_id"],
                    "engagement_id": job["engagement_id"],
                    "requester_user_id": job["requester_user_id"],
                    "target": job["target"],
                    "target_type": job["asset_type"],
                    "technique": job["technique"],
                    "action_class": job["action_class"],
                    "scope_revision_id": job["scope_revision_id"],
                    "authorization_id": job["authorization_id"],
                    "authorization_document_sha256": job["authorization_document_sha256"],
                    "request_digest": job["request_digest"],
                    "approval_id": job["approval_id"],
                    "approval_consumption_outcome": approval_outcome,
                    "approval_consumed_at": job["approval_consumed_at"],
                    "created_at": job["created_at"],
                    "started_at": job["started_at"],
                    "finished_at": job["finished_at"],
                    "outcome": job["status"],
                    "scan_id": job["scan_id"],
                },
                "execution_context": context,
                "results": [
                    {
                        "record_type": row.record_type,
                        "record_id": row.record_id,
                        "linked_at": row.created_at,
                    }
                    for row in links
                ],
            }

    def list_jobs(
        self, user_id: str, organization_id: str, engagement_id: str, limit: int = 50
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self.security._can_read(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(execution_jobs)
                .where(
                    execution_jobs.c.organization_id == organization_id,
                    execution_jobs.c.engagement_id == engagement_id,
                )
                .order_by(execution_jobs.c.created_at.desc())
                .limit(max(1, min(limit, 100)))
            ).all()
            return [dict(row._mapping) for row in rows]

    def request_cancellation(
        self, user_id: str, organization_id: str, engagement_id: str, job_id: str
    ) -> dict[str, Any] | None:
        """Persist an authorized cancellation request; return None for inaccessible jobs."""
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.organization_id == organization_id,
                        execution_jobs.c.engagement_id == engagement_id,
                    )
                ).first()
                if not row:
                    connection.rollback()
                    return None
                item = dict(row._mapping)
                membership = self.security._membership(connection, user_id, organization_id)
                can_cancel = membership is not None and (
                    user_id == item["requester_user_id"]
                    or self.security._can_manage(
                        connection, user_id, organization_id, engagement_id
                    )
                )
                if not can_cancel:
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "execution.cancellation_rejected",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="CANCELLATION_FORBIDDEN",
                        details={"job_status": item["status"]},
                    )
                    connection.commit()
                    return {"outcome": "forbidden"}
                if item["status"] not in {"queued", "claimed", "running"}:
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "execution.cancellation_rejected",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="JOB_TERMINAL",
                        details={"job_status": item["status"]},
                    )
                    connection.commit()
                    return {"outcome": "terminal", "job": item}

                if item["cancellation_requested_at"] is not None:
                    connection.commit()
                    return {"outcome": "requested", "job": item, "idempotent": True}

                stamp = now_iso()
                new_status = "cancelled" if item["status"] == "queued" else item["status"]
                changes: dict[str, Any] = {
                    "cancellation_requested_at": stamp,
                    "cancellation_requested_by": user_id,
                    "error_code": (
                        "CANCELLATION_REQUESTED"
                        if new_status != "cancelled"
                        else "EXECUTION_CANCELLED"
                    ),
                }
                if new_status != item["status"]:
                    changes.update(
                        status=new_status,
                        finished_at=stamp,
                        cancellation_observed_at=None,
                    )
                connection.execute(
                    update(execution_jobs)
                    .where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.organization_id == organization_id,
                        execution_jobs.c.status == item["status"],
                        execution_jobs.c.cancellation_requested_at.is_(None),
                    )
                    .values(**changes)
                )
                self.security._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "execution.cancellation_requested",
                    "execution_job",
                    job_id,
                    decision="ALLOW",
                    reason_code="CANCELLATION_ACCEPTED",
                    details={"job_status": item["status"]},
                )
                if new_status == "cancelled":
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "execution.cancellation_completed",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="CANCELLED_BEFORE_CLAIM",
                        details={"job_status": "cancelled"},
                    )
                connection.commit()
                updated = dict(item)
                updated.update(
                    cancellation_requested_at=stamp,
                    cancellation_requested_by=user_id,
                    cancellation_observed_at=None,
                    status=new_status,
                    finished_at=stamp if new_status == "cancelled" else item["finished_at"],
                    error_code=(
                        "CANCELLATION_REQUESTED"
                        if new_status != "cancelled"
                        else "EXECUTION_CANCELLED"
                    ),
                )
                return {
                    "outcome": "completed" if new_status == "cancelled" else "requested",
                    "job": updated,
                    "idempotent": False,
                }
            except Exception:
                connection.rollback()
                raise

    def observe_cancellation(
        self,
        job_id: str,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
    ) -> bool:
        """Atomically record worker observation and complete a persisted cancellation."""
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status.in_(["claimed", "running"]),
                        execution_jobs.c.cancellation_requested_at.is_not(None),
                    )
                ).first()
                if not row:
                    connection.rollback()
                    return False
                item = dict(row._mapping)
                if not self._lease_fenced(
                    item, worker_id, lease_generation, time.time(), check_expiry=False
                ):
                    connection.rollback()
                    return False
                in_progress = connection.execute(
                    select(execution_action_attempts).where(
                        execution_action_attempts.c.job_id == job_id,
                        execution_action_attempts.c.state.in_(
                            ["in_progress", "outcome_uncertain", "reconciliation_required"]
                        ),
                    )
                ).first()
                stamp = item["cancellation_observed_at"] or now_iso()
                if in_progress is not None:
                    if in_progress.state == "in_progress":
                        connection.execute(
                            update(execution_action_attempts)
                            .where(
                                execution_action_attempts.c.id == in_progress.id,
                                execution_action_attempts.c.state == "in_progress",
                            )
                            .values(
                                state="outcome_uncertain",
                                outcome_classification="cancelled_during_in_progress",
                                updated_at=stamp,
                            )
                        )
                    connection.execute(
                        update(execution_jobs)
                        .where(
                            execution_jobs.c.id == job_id,
                            execution_jobs.c.status == item["status"],
                        )
                        .values(
                            status="reconciliation_required",
                            cancellation_observed_at=stamp,
                            finished_at=stamp,
                            error_code="CANCELLATION_OUTCOME_UNCERTAIN",
                        )
                    )
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["cancellation_requested_by"] or item["requester_user_id"],
                        "execution.cancellation_outcome_uncertain",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="CANCELLATION_DURING_EXTERNAL_ACTION",
                        details={"action_id": in_progress.id},
                    )
                    connection.commit()
                    return True
                connection.execute(
                    update(execution_action_attempts)
                    .where(
                        execution_action_attempts.c.job_id == job_id,
                        execution_action_attempts.c.state.in_(["not_started", "authorized"]),
                    )
                    .values(
                        state="failed_before_dispatch",
                        outcome_classification="cancelled_before_dispatch",
                        completed_at=stamp,
                        updated_at=stamp,
                    )
                )
                connection.execute(
                    update(execution_jobs)
                    .where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status == item["status"],
                        execution_jobs.c.cancellation_requested_at.is_not(None),
                        execution_jobs.c.cancellation_observed_at.is_(None),
                    )
                    .values(
                        status="cancelled",
                        cancellation_observed_at=stamp,
                        finished_at=stamp,
                        error_code="EXECUTION_CANCELLED",
                    )
                )
                if item["cancellation_observed_at"] is None:
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["cancellation_requested_by"] or item["requester_user_id"],
                        "execution.cancellation_observed",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="WORKER_OBSERVED_CANCELLATION",
                        details={"job_status": item["status"]},
                    )
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["cancellation_requested_by"] or item["requester_user_id"],
                        "execution.cancellation_completed",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="CANCELLATION_OBSERVED_AT_SAFE_BOUNDARY",
                        details={"job_status": "cancelled"},
                    )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def _validate_context(
        self,
        connection: Any,
        item: dict[str, Any],
        *,
        require_approval_consumed: bool = False,
    ) -> tuple[bool, str]:
        now = datetime.now(UTC)
        if _utc(item["expires_at"]) <= now:
            return False, "EXECUTION_CONTEXT_EXPIRED"
        asset = connection.execute(
            select(engagement_assets).where(
                engagement_assets.c.id == item["asset_id"],
                engagement_assets.c.organization_id == item["organization_id"],
                engagement_assets.c.engagement_id == item["engagement_id"],
                engagement_assets.c.status == "active",
                engagement_assets.c.target == item["target"],
            )
        ).first()
        if not asset:
            return False, "ASSET_CONTEXT_CHANGED"
        result = self.security._decision(
            connection,
            item["requester_user_id"],
            item["organization_id"],
            item["engagement_id"],
            item["asset_type"],
            item["target"],
            item["technique"],
            None,
            False,
            now,
        )
        expected = "REQUIRE_APPROVAL" if item["action_class"] == "sensitive" else "ALLOW"
        expected_policy_digest = item.get("policy_request_digest") or item["request_digest"]
        if result["decision"] != expected or result.get("request_digest") != expected_policy_digest:
            return False, result.get("reason_code", "POLICY_CONTEXT_CHANGED")
        if (
            result.get("scope_revision_id") != item["scope_revision_id"]
            or result.get("authorization_id") != item["authorization_id"]
        ):
            return False, "POLICY_CONTEXT_CHANGED"
        current_authorization_document_sha256 = connection.execute(
            select(authorization_documents.c.sha256).where(
                authorization_documents.c.organization_id == item["organization_id"],
                authorization_documents.c.authorization_id == item["authorization_id"],
            )
        ).scalar_one_or_none()
        if current_authorization_document_sha256 != item["authorization_document_sha256"]:
            return False, "AUTHORIZATION_DOCUMENT_CHANGED"
        if item["asset_type"] == "repository":
            digest_context = {
                "policy_request_digest": item["policy_request_digest"],
                "organization_id": item["organization_id"],
                "engagement_id": item["engagement_id"],
                "requester_user_id": item["requester_user_id"],
                "asset_id": item["asset_id"],
                "target": item["target"],
                "technique": item["technique"],
                "action_class": item["action_class"],
                "scope_revision_id": item["scope_revision_id"],
                "authorization_id": item["authorization_id"],
                "authorization_document_sha256": item["authorization_document_sha256"],
                "repository_binding_id": item.get("repository_binding_id"),
                "repository_snapshot_id": item.get("repository_snapshot_id"),
                "repository_snapshot_sha256": item.get("repository_snapshot_sha256"),
                "repository_manifest_version": item.get("repository_manifest_version"),
                "repository_attestation_id": item.get("repository_attestation_id"),
                "repository_attestation_version": item.get("repository_attestation_version"),
                "scanner_version": item.get("repository_scanner_version"),
                "scan_bounds": item.get("repository_scan_bounds"),
                "adapter_id": item.get("adapter_id"),
                "adapter_version": item.get("adapter_version"),
                "exclusion_policy_version": item.get("exclusion_policy_version"),
            }
            digest = hashlib.sha256(
                json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if digest != item["request_digest"]:
                return False, "EXECUTION_CONTEXT_DIGEST_MISMATCH"
            snapshot = connection.execute(
                select(repository_snapshots).where(
                    repository_snapshots.c.id == item["repository_snapshot_id"],
                    repository_snapshots.c.organization_id == item["organization_id"],
                    repository_snapshots.c.sha256 == item["repository_snapshot_sha256"],
                    repository_snapshots.c.manifest_version == item["repository_manifest_version"],
                    repository_snapshots.c.status == "available",
                )
            ).first()
            binding = connection.execute(
                select(repository_asset_bindings).where(
                    repository_asset_bindings.c.id == item["repository_binding_id"],
                    repository_asset_bindings.c.organization_id == item["organization_id"],
                    repository_asset_bindings.c.engagement_id == item["engagement_id"],
                    repository_asset_bindings.c.asset_id == item["asset_id"],
                    repository_asset_bindings.c.snapshot_id == item["repository_snapshot_id"],
                    repository_asset_bindings.c.snapshot_sha256
                    == item["repository_snapshot_sha256"],
                )
            ).first()
            attestation = connection.execute(
                select(repository_attestations).where(
                    repository_attestations.c.id == item["repository_attestation_id"],
                    repository_attestations.c.organization_id == item["organization_id"],
                    repository_attestations.c.engagement_id == item["engagement_id"],
                    repository_attestations.c.asset_id == item["asset_id"],
                    repository_attestations.c.authorization_id == item["authorization_id"],
                    repository_attestations.c.scope_revision_id == item["scope_revision_id"],
                    repository_attestations.c.attestation_version
                    == item["repository_attestation_version"],
                )
            ).first()
            if not snapshot or not binding or not attestation:
                return False, "REPOSITORY_CONTEXT_UNAVAILABLE"
        elif item["asset_type"] == "log_evidence":
            chain_binding = (item.get("execution_context") or {}).get("chain_context")
            digest_context = {
                "policy_request_digest": item["policy_request_digest"],
                "organization_id": item["organization_id"],
                "engagement_id": item["engagement_id"],
                "requester_user_id": item["requester_user_id"],
                "asset_id": item["asset_id"],
                "target": item["target"],
                "technique": item["technique"],
                "action_class": item["action_class"],
                "scope_revision_id": item["scope_revision_id"],
                "authorization_id": item["authorization_id"],
                "authorization_document_sha256": item["authorization_document_sha256"],
                "log_evidence_snapshot_id": item["log_evidence_snapshot_id"],
                "log_evidence_sha256": item["log_evidence_sha256"],
                "log_evidence_manifest_version": item["log_evidence_manifest_version"],
                "log_evidence_source_format": item["log_evidence_source_format"],
                "log_analysis_version": item["log_analysis_version"],
                "log_ruleset_version": item["log_ruleset_version"],
                "adapter_id": item["adapter_id"],
                "adapter_version": item["adapter_version"],
            }
            if item["technique"] == CHAIN_IMPORT_TECHNIQUE:
                if not isinstance(chain_binding, dict) or set(chain_binding) != {
                    "chain",
                    "seed",
                    "depth",
                }:
                    return False, "CHAIN_IMPORT_CONTEXT_INVALID"
                digest_context["chain_context"] = chain_binding
            digest = hashlib.sha256(
                json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if digest != item["request_digest"]:
                return False, "EXECUTION_CONTEXT_DIGEST_MISMATCH"
            snapshot = connection.execute(
                select(log_evidence_snapshots).where(
                    log_evidence_snapshots.c.id == item["log_evidence_snapshot_id"],
                    log_evidence_snapshots.c.organization_id == item["organization_id"],
                    log_evidence_snapshots.c.engagement_id == item["engagement_id"],
                    log_evidence_snapshots.c.asset_id == item["asset_id"],
                    log_evidence_snapshots.c.sha256 == item["log_evidence_sha256"],
                    log_evidence_snapshots.c.manifest_version
                    == item["log_evidence_manifest_version"],
                    log_evidence_snapshots.c.source_format == item["log_evidence_source_format"],
                    log_evidence_snapshots.c.status == "available",
                )
            ).first()
            if not snapshot:
                return False, "LOG_EVIDENCE_CONTEXT_UNAVAILABLE"
        elif item["asset_type"] == "malware_evidence":
            digest_context = {
                "policy_request_digest": item["policy_request_digest"],
                "organization_id": item["organization_id"],
                "engagement_id": item["engagement_id"],
                "requester_user_id": item["requester_user_id"],
                "asset_id": item["asset_id"],
                "target": item["target"],
                "technique": item["technique"],
                "action_class": item["action_class"],
                "scope_revision_id": item["scope_revision_id"],
                "authorization_id": item["authorization_id"],
                "authorization_document_sha256": item["authorization_document_sha256"],
                "malware_evidence_snapshot_id": item["malware_evidence_snapshot_id"],
                "malware_evidence_sha256": item["malware_evidence_sha256"],
                "malware_evidence_manifest_sha256": item["malware_evidence_manifest_sha256"],
                "malware_evidence_manifest_version": item["malware_evidence_manifest_version"],
                "malware_analysis_version": item["malware_analysis_version"],
                "adapter_id": item["adapter_id"],
                "adapter_version": item["adapter_version"],
            }
            digest = hashlib.sha256(
                json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if digest != item["request_digest"]:
                return False, "EXECUTION_CONTEXT_DIGEST_MISMATCH"
            snapshot = connection.execute(
                select(malware_evidence_snapshots).where(
                    malware_evidence_snapshots.c.id == item["malware_evidence_snapshot_id"],
                    malware_evidence_snapshots.c.organization_id == item["organization_id"],
                    malware_evidence_snapshots.c.engagement_id == item["engagement_id"],
                    malware_evidence_snapshots.c.asset_id == item["asset_id"],
                    malware_evidence_snapshots.c.sha256 == item["malware_evidence_sha256"],
                    malware_evidence_snapshots.c.manifest_sha256
                    == item["malware_evidence_manifest_sha256"],
                    malware_evidence_snapshots.c.manifest_version
                    == item["malware_evidence_manifest_version"],
                    malware_evidence_snapshots.c.status == "available",
                )
            ).first()
            if not snapshot:
                return False, "MALWARE_EVIDENCE_CONTEXT_UNAVAILABLE"
        elif item["asset_type"] == "chain_address":
            context = item.get("execution_context") or {}
            chain_binding = context.get("chain_context")
            parts = item["target"].split(":")
            if (
                item["technique"] != CHAIN_PROVIDER_TECHNIQUE
                or item["action_class"] != "sensitive"
                or not isinstance(chain_binding, dict)
                or set(chain_binding) != {"chain", "address", "provider"}
                or len(parts) != 4
                or parts[0] != "chain"
                or parts[2] != "etherscan-v2"
                or chain_binding
                != {"chain": parts[1], "address": parts[3], "provider": "etherscan-v2"}
            ):
                return False, "CHAIN_PROVIDER_CONTEXT_INVALID"
            digest_context = {
                "policy_request_digest": item["policy_request_digest"],
                "organization_id": item["organization_id"],
                "engagement_id": item["engagement_id"],
                "requester_user_id": item["requester_user_id"],
                "asset_id": item["asset_id"],
                "target": item["target"],
                "technique": item["technique"],
                "action_class": item["action_class"],
                "scope_revision_id": item["scope_revision_id"],
                "authorization_id": item["authorization_id"],
                "authorization_document_sha256": item["authorization_document_sha256"],
                "chain_context": chain_binding,
                "adapter_id": item["adapter_id"],
                "adapter_version": item["adapter_version"],
            }
            digest = hashlib.sha256(
                json.dumps(digest_context, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if digest != item["request_digest"]:
                return False, "EXECUTION_CONTEXT_DIGEST_MISMATCH"
        if item["action_class"] == "sensitive":
            if not item["approval_id"]:
                return False, "APPROVAL_CONTEXT_MISSING"
            approval = connection.execute(
                select(approval_requests).where(
                    approval_requests.c.id == item["approval_id"],
                    approval_requests.c.organization_id == item["organization_id"],
                    approval_requests.c.engagement_id == item["engagement_id"],
                )
            ).first()
            if not approval:
                return False, "APPROVAL_CONTEXT_MISSING"
            approval = dict(approval._mapping)
            consumed_at = item["approval_consumed_at"]
            expected_decision = "consumed" if consumed_at else "approved"
            if (
                approval["decision"] != expected_decision
                or approval["requester_user_id"] != item["requester_user_id"]
                or not approval["approver_user_id"]
                or approval["approver_user_id"] == item["requester_user_id"]
                or approval["request_digest"]
                != (item.get("policy_request_digest") or item["request_digest"])
                or approval["scope_revision_id"] != item["scope_revision_id"]
                or approval["authorization_id"] != item["authorization_id"]
                or approval["asset_type"] != item["asset_type"]
                or approval["target"] != item["target"]
                or approval["technique"] != item["technique"]
                or approval["action_class"] != item["action_class"]
                or _utc(approval["expires_at"]) <= now
            ):
                return False, "APPROVAL_CONTEXT_INVALID"
            if consumed_at:
                if (
                    approval["consumed_at"] != consumed_at
                    or approval["consumed_by"] != item["requester_user_id"]
                ):
                    return False, "APPROVAL_CONTEXT_INVALID"
            elif (
                require_approval_consumed
                or approval["consumed_at"] is not None
                or approval["consumed_by"] is not None
            ):
                return False, "APPROVAL_CONTEXT_INVALID"
            approver_role = self.security._membership(
                connection, approval["approver_user_id"], item["organization_id"]
            )
            approver_assignments = self.security._assignment_roles(
                connection,
                approval["approver_user_id"],
                item["organization_id"],
                item["engagement_id"],
            )
            if approver_role not in {"owner", "admin"} and not (
                approver_role == "member"
                and approver_assignments.intersection({"lead", "reviewer"})
            ):
                return False, "APPROVER_NO_LONGER_AUTHORIZED"
        return True, "EXECUTION_CONTEXT_VALID"

    @staticmethod
    def _validate_lease_bounds(
        lease_duration_seconds: float, heartbeat_interval_seconds: float | None = None
    ) -> float:
        if not (MIN_LEASE_DURATION_SECONDS <= lease_duration_seconds <= MAX_LEASE_DURATION_SECONDS):
            raise ValueError("Lease duration must be between 5 and 3600 seconds.")
        if heartbeat_interval_seconds is not None and not (
            0.05 <= heartbeat_interval_seconds <= lease_duration_seconds / 2.0
        ):
            raise ValueError("Heartbeat interval must be <= half of the lease duration.")
        return float(lease_duration_seconds)

    @staticmethod
    def _lease_fenced(
        item: dict[str, Any],
        worker_id: str | None,
        lease_generation: int | None,
        ts: float,
        *,
        check_expiry: bool = True,
    ) -> bool:
        if worker_id is None and lease_generation is None:
            return True
        if worker_id is None or lease_generation is None:
            return False
        if item.get("worker_id") != worker_id:
            return False
        if int(item.get("lease_generation") or 0) != int(lease_generation):
            return False
        if check_expiry:
            exp = item.get("lease_expires_at")
            if exp is None or float(exp) <= ts:
                return False
        return True

    def register_worker(self, worker_id: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        stamp = now_iso()
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    select(worker_leases.c.worker_id).where(worker_leases.c.worker_id == worker_id)
                ).first()
                if existing is None:
                    connection.execute(
                        worker_leases.insert().values(
                            worker_id=worker_id,
                            status="active",
                            started_at=stamp,
                            last_heartbeat_at=ts,
                            stopped_at=None,
                        )
                    )
                else:
                    connection.execute(
                        update(worker_leases)
                        .where(worker_leases.c.worker_id == worker_id)
                        .values(status="active", last_heartbeat_at=ts, stopped_at=None)
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def mark_worker_stopping(self, worker_id: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        with self.engine.begin() as connection:
            connection.execute(
                update(worker_leases)
                .where(worker_leases.c.worker_id == worker_id)
                .values(status="stopping", last_heartbeat_at=ts)
            )

    def unregister_worker(self, worker_id: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        with self.engine.begin() as connection:
            connection.execute(
                update(worker_leases)
                .where(worker_leases.c.worker_id == worker_id)
                .values(status="stopped", last_heartbeat_at=ts, stopped_at=now_iso())
            )

    def authorize_external_action(
        self,
        job_id: str,
        target: str,
        technique: str,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        adapter_id: str | None = None,
        now: float | None = None,
    ) -> bool:
        """Revalidate an action, persist durable intent, and consume sensitive approval."""
        ts = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status == "running",
                    )
                ).first()
                if not row:
                    connection.rollback()
                    return False
                item = dict(row._mapping)
                if not self._lease_fenced(item, worker_id, lease_generation, ts):
                    connection.rollback()
                    return False

                def block(reason: str, *, approval_failure: bool = False) -> bool:
                    now_text = now_iso()
                    connection.execute(
                        update(execution_jobs)
                        .where(
                            execution_jobs.c.id == job_id,
                            execution_jobs.c.status == "running",
                        )
                        .values(status="blocked", finished_at=now_text, error_code=reason)
                    )
                    details = {
                        "policy_decision_id": item["policy_decision_id"],
                        "request_digest": item["request_digest"],
                    }
                    if approval_failure:
                        self.security._audit(
                            connection,
                            item["organization_id"],
                            item["engagement_id"],
                            item["requester_user_id"],
                            "execution.approval_validation_failed",
                            "execution_job",
                            job_id,
                            decision="DENY",
                            reason_code=reason,
                            details=details,
                        )
                        self.security._audit(
                            connection,
                            item["organization_id"],
                            item["engagement_id"],
                            item["requester_user_id"],
                            "execution.blocked_after_approval_validation",
                            "execution_job",
                            job_id,
                            decision="DENY",
                            reason_code=reason,
                            details=details,
                        )
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["requester_user_id"],
                        "execution.job_blocked",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code=reason,
                        details=details,
                    )
                    connection.commit()
                    return False

                if target != item["target"] or technique != item["technique"]:
                    return block("EXECUTION_CONTEXT_MISMATCH")

                eff_worker_id = worker_id or item.get("worker_id") or "local-worker"
                eff_gen = (
                    int(lease_generation)
                    if lease_generation is not None
                    else int(item.get("lease_generation") or 0)
                )
                prior_attempts = connection.execute(
                    select(execution_action_attempts)
                    .where(execution_action_attempts.c.job_id == job_id)
                    .order_by(execution_action_attempts.c.action_sequence.desc())
                ).all()
                same_gen_active = next(
                    (
                        a
                        for a in prior_attempts
                        if int(a.lease_generation) == eff_gen
                        and a.worker_id == eff_worker_id
                        and a.state in {"authorized", "in_progress"}
                    ),
                    None,
                )
                unsafe_prior = next(
                    (
                        a
                        for a in prior_attempts
                        if a is not same_gen_active
                        and a.state
                        in {
                            "authorized",
                            "in_progress",
                            "completed",
                            "outcome_uncertain",
                            "reconciliation_required",
                        }
                    ),
                    None,
                )
                if unsafe_prior is not None:
                    now_text = now_iso()
                    connection.execute(
                        update(execution_jobs)
                        .where(
                            execution_jobs.c.id == job_id,
                            execution_jobs.c.status == "running",
                        )
                        .values(
                            status="reconciliation_required",
                            finished_at=now_text,
                            error_code="DUPLICATE_EXTERNAL_ACTION_BLOCKED",
                        )
                    )
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["requester_user_id"],
                        "execution.duplicate_action_blocked",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="DUPLICATE_EXTERNAL_ACTION_BLOCKED",
                        details={
                            "prior_action_id": unsafe_prior.id,
                            "prior_state": unsafe_prior.state,
                        },
                    )
                    connection.commit()
                    return False

                def _record_action_intent() -> None:
                    stamp = now_iso()
                    if same_gen_active is not None:
                        if same_gen_active.state == "authorized":
                            connection.execute(
                                update(execution_action_attempts)
                                .where(
                                    execution_action_attempts.c.id == same_gen_active.id,
                                    execution_action_attempts.c.state == "authorized",
                                )
                                .values(
                                    state="in_progress",
                                    started_at=stamp,
                                    updated_at=stamp,
                                )
                            )
                        return
                    max_seq = (
                        connection.execute(
                            select(func.max(execution_action_attempts.c.action_sequence)).where(
                                execution_action_attempts.c.job_id == job_id
                            )
                        ).scalar_one_or_none()
                        or 0
                    )
                    connection.execute(
                        execution_action_attempts.insert().values(
                            id=str(uuid4()),
                            job_id=job_id,
                            organization_id=item["organization_id"],
                            engagement_id=item["engagement_id"],
                            action_sequence=int(max_seq) + 1,
                            lease_generation=eff_gen,
                            worker_id=eff_worker_id,
                            adapter_id=adapter_id or item.get("adapter_id") or "governed.adapter",
                            operation=technique,
                            authorization_id=item["authorization_id"],
                            approval_id=item["approval_id"],
                            request_digest=item["request_digest"],
                            state="authorized",
                            started_at=None,
                            completed_at=None,
                            outcome_classification=None,
                            result_reference=None,
                            created_at=stamp,
                            updated_at=stamp,
                        )
                    )

                if item["action_class"] != "sensitive":
                    valid, reason = self._validate_context(connection, item)
                    if not valid:
                        return block(reason)
                    _record_action_intent()
                    connection.commit()
                    return True

                if item["approval_consumed_at"]:
                    valid, reason = self._validate_context(
                        connection, item, require_approval_consumed=True
                    )
                    if not valid:
                        return block(reason, approval_failure=True)
                    _record_action_intent()
                    connection.commit()
                    return True

                approved = self.security._decision(
                    connection,
                    item["requester_user_id"],
                    item["organization_id"],
                    item["engagement_id"],
                    item["asset_type"],
                    item["target"],
                    item["technique"],
                    item["approval_id"],
                    False,
                    datetime.now(UTC),
                )
                if (
                    approved["decision"] != "ALLOW"
                    or approved.get("reason_code") != "APPROVAL_VALID"
                    or approved.get("request_digest")
                    != (item.get("policy_request_digest") or item["request_digest"])
                    or approved.get("scope_revision_id") != item["scope_revision_id"]
                    or approved.get("authorization_id") != item["authorization_id"]
                    or approved.get("action_class") != item["action_class"]
                ):
                    return block(
                        approved.get("reason_code", "APPROVAL_CONTEXT_INVALID"),
                        approval_failure=True,
                    )

                consumed = self.security._decision(
                    connection,
                    item["requester_user_id"],
                    item["organization_id"],
                    item["engagement_id"],
                    item["asset_type"],
                    item["target"],
                    item["technique"],
                    item["approval_id"],
                    True,
                    datetime.now(UTC),
                )
                if (
                    consumed["decision"] != "ALLOW"
                    or consumed.get("reason_code") != "APPROVAL_CONSUMED"
                    or consumed.get("request_digest")
                    != (item.get("policy_request_digest") or item["request_digest"])
                ):
                    return block(
                        consumed.get("reason_code", "APPROVAL_CONSUMPTION_FAILED"),
                        approval_failure=True,
                    )
                consumed_at = connection.execute(
                    select(approval_requests.c.consumed_at).where(
                        approval_requests.c.id == item["approval_id"],
                        approval_requests.c.organization_id == item["organization_id"],
                    )
                ).scalar_one_or_none()
                if not isinstance(consumed_at, str):
                    raise RuntimeError("Consumed approval timestamp is unavailable.")
                updated = connection.execute(
                    update(execution_jobs)
                    .where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status == "running",
                        execution_jobs.c.approval_consumed_at.is_(None),
                    )
                    .values(approval_consumed_at=consumed_at)
                )
                if updated.rowcount != 1:
                    raise RuntimeError("Execution approval marker could not be committed.")
                item["approval_consumed_at"] = consumed_at
                valid, reason = self._validate_context(
                    connection, item, require_approval_consumed=True
                )
                if not valid:
                    # Keep consumption and record the block: approvals are never restored.
                    return block(reason, approval_failure=True)
                _record_action_intent()
                self.security._audit(
                    connection,
                    item["organization_id"],
                    item["engagement_id"],
                    item["requester_user_id"],
                    "execution.approval_consumed",
                    "execution_job",
                    job_id,
                    decision="ALLOW",
                    reason_code="APPROVAL_CONSUMED_AT_ACTION_BOUNDARY",
                    details={
                        "approval_id": item["approval_id"],
                        "request_digest": item["request_digest"],
                        "scope_revision_id": item["scope_revision_id"],
                        "authorization_id": item["authorization_id"],
                    },
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def _claim_on_connection(
        self,
        connection: Any,
        job_id: str,
        worker_id: str,
        lease_duration_seconds: float,
        ts: float,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            select(execution_jobs).where(
                execution_jobs.c.id == job_id,
                execution_jobs.c.status == "queued",
            )
        ).first()
        if not row:
            return None
        item = dict(row._mapping)
        created_at_dt = _utc(item["created_at"])
        queue_wait_seconds = (datetime.now(UTC) - created_at_dt).total_seconds()
        if queue_wait_seconds > self.resource_limits.max_queue_wait_seconds:
            old_gen = int(item.get("lease_generation") or 0)
            res = connection.execute(
                update(execution_jobs)
                .where(
                    execution_jobs.c.id == job_id,
                    execution_jobs.c.status == "queued",
                    execution_jobs.c.lease_generation == old_gen,
                )
                .values(
                    status="blocked",
                    finished_at=now_iso(),
                    error_code="EXECUTION_QUEUE_WAIT_EXPIRED",
                )
            )
            if res.rowcount == 1:
                self.security._audit(
                    connection,
                    item["organization_id"],
                    item["engagement_id"],
                    item["requester_user_id"],
                    "execution.deadline_exceeded",
                    "execution_job",
                    job_id,
                    decision="DENY",
                    reason_code="EXECUTION_QUEUE_WAIT_EXPIRED",
                    details={"queue_wait_ms": int(max(0.0, queue_wait_seconds) * 1000)},
                )
            return None
        valid, reason = self._validate_context(connection, item)
        status = "claimed" if valid else "blocked"
        old_gen = int(item.get("lease_generation") or 0)
        new_gen = old_gen + 1 if valid else old_gen
        new_attempt = int(item.get("attempt_number") or 0) + (1 if valid else 0)
        claimed_iso = now_iso()
        lease_exp = ts + lease_duration_seconds if valid else None
        res = connection.execute(
            update(execution_jobs)
            .where(
                execution_jobs.c.id == job_id,
                execution_jobs.c.status == "queued",
                execution_jobs.c.lease_generation == old_gen,
            )
            .values(
                status=status,
                worker_id=worker_id if valid else None,
                lease_generation=new_gen,
                lease_expires_at=lease_exp,
                heartbeat_at=ts if valid else None,
                claimed_at=claimed_iso if valid else None,
                attempt_number=new_attempt,
                started_at=_stamp(datetime.now(UTC)) if valid else None,
                finished_at=None if valid else now_iso(),
                error_code=None if valid else reason,
            )
        )
        if res.rowcount != 1:
            return None
        self.security._audit(
            connection,
            item["organization_id"],
            item["engagement_id"],
            item["requester_user_id"],
            "execution.job_claimed" if valid else "execution.job_blocked",
            "execution_job",
            job_id,
            decision="ALLOW" if valid else "DENY",
            reason_code=reason,
            details={
                "policy_decision_id": item["policy_decision_id"],
                "worker_id": worker_id if valid else None,
                "lease_generation": new_gen,
                "attempt_number": new_attempt,
            },
        )
        if not valid:
            return None
        return {
            **item,
            "status": status,
            "worker_id": worker_id,
            "lease_generation": new_gen,
            "lease_expires_at": lease_exp,
            "heartbeat_at": ts,
            "claimed_at": claimed_iso,
            "attempt_number": new_attempt,
            "error_code": None,
        }

    def claim_job(
        self,
        job_id: str,
        worker_id: str | None = None,
        *,
        lease_duration_seconds: float = DEFAULT_LEASE_DURATION_SECONDS,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        self._validate_lease_bounds(lease_duration_seconds)
        eff_worker_id = worker_id or f"worker-{secrets.token_hex(8)}"
        ts = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                claimed = self._claim_on_connection(
                    connection, job_id, eff_worker_id, lease_duration_seconds, ts
                )
                connection.commit()
                return claimed
            except Exception:
                connection.rollback()
                raise

    def claim_next_job(
        self,
        worker_id: str,
        *,
        lease_duration_seconds: float = DEFAULT_LEASE_DURATION_SECONDS,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        self._validate_lease_bounds(lease_duration_seconds)
        ts = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                active_rows = connection.execute(
                    select(
                        execution_jobs.c.organization_id,
                        execution_jobs.c.asset_type,
                    ).where(execution_jobs.c.status.in_(["claimed", "running"]))
                ).all()
                global_active = len(active_rows)
                if global_active >= self.resource_limits.global_active_limit:
                    connection.commit()
                    return None
                org_active: dict[str, int] = {}
                workload_active: dict[str, int] = {}
                for active_row in active_rows:
                    org_active[active_row.organization_id] = (
                        org_active.get(active_row.organization_id, 0) + 1
                    )
                    workload_active[active_row.asset_type] = (
                        workload_active.get(active_row.asset_type, 0) + 1
                    )
                queued_rows = connection.execute(
                    select(
                        execution_jobs.c.id,
                        execution_jobs.c.organization_id,
                        execution_jobs.c.asset_type,
                        execution_jobs.c.created_at,
                    )
                    .where(execution_jobs.c.status == "queued")
                    .order_by(execution_jobs.c.created_at)
                ).all()
                if not queued_rows:
                    connection.commit()
                    return None
                eligible = [
                    r
                    for r in queued_rows
                    if org_active.get(r.organization_id, 0)
                    < self.resource_limits.per_org_active_limit
                    and workload_active.get(r.asset_type, 0)
                    < self.resource_limits.workload_limit(r.asset_type)
                ]
                if not eligible:
                    connection.commit()
                    return None
                # Fair scheduling: prioritize organizations with fewer active jobs, then FIFO.
                eligible.sort(key=lambda r: (org_active.get(r.organization_id, 0), r.created_at))
                for candidate in eligible:
                    claimed = self._claim_on_connection(
                        connection, candidate.id, worker_id, lease_duration_seconds, ts
                    )
                    if claimed is not None:
                        connection.commit()
                        return claimed
                connection.commit()
                return None
            except Exception:
                connection.rollback()
                raise

    def heartbeat_job(
        self,
        job_id: str,
        worker_id: str,
        lease_generation: int,
        *,
        lease_duration_seconds: float = DEFAULT_LEASE_DURATION_SECONDS,
        now: float | None = None,
    ) -> bool:
        self._validate_lease_bounds(lease_duration_seconds)
        ts = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(execution_jobs).where(execution_jobs.c.id == job_id)
                ).first()
                if not row:
                    connection.rollback()
                    return False
                item = dict(row._mapping)
                if item["status"] not in {"claimed", "running"}:
                    connection.rollback()
                    return False
                if not self._lease_fenced(item, worker_id, lease_generation, ts):
                    connection.rollback()
                    return False
                res = connection.execute(
                    update(execution_jobs)
                    .where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status.in_(["claimed", "running"]),
                        execution_jobs.c.worker_id == worker_id,
                        execution_jobs.c.lease_generation == lease_generation,
                        execution_jobs.c.lease_expires_at > ts,
                    )
                    .values(
                        heartbeat_at=ts,
                        lease_expires_at=ts + lease_duration_seconds,
                    )
                )
                connection.execute(
                    update(worker_leases)
                    .where(worker_leases.c.worker_id == worker_id)
                    .values(last_heartbeat_at=ts)
                )
                connection.commit()
                return bool(res.rowcount == 1)
            except Exception:
                connection.rollback()
                raise

    def latest_action_attempt(self, job_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(execution_action_attempts)
                .where(execution_action_attempts.c.job_id == job_id)
                .order_by(execution_action_attempts.c.action_sequence.desc())
                .limit(1)
            ).first()
            return dict(row._mapping) if row else None

    def list_reconciliation_jobs(
        self, user_id: str, organization_id: str, engagement_id: str, limit: int = 50
    ) -> list[dict[str, Any]] | None:
        """List unresolved jobs for an operator allowed to manage the engagement.

        Only safe operational metadata is returned; immutable execution payloads and
        upstream response data remain behind the existing provenance boundary.
        """
        with self.engine.connect() as connection:
            if not self.security._can_manage(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(execution_jobs)
                .where(
                    execution_jobs.c.organization_id == organization_id,
                    execution_jobs.c.engagement_id == engagement_id,
                    execution_jobs.c.status == "reconciliation_required",
                )
                .order_by(execution_jobs.c.created_at.asc())
                .limit(max(1, min(limit, 100)))
            ).all()
            items: list[dict[str, Any]] = []
            for row in rows:
                job = dict(row._mapping)
                attempt = connection.execute(
                    select(execution_action_attempts)
                    .where(execution_action_attempts.c.job_id == job["id"])
                    .order_by(execution_action_attempts.c.action_sequence.desc())
                    .limit(1)
                ).first()
                attempt_data = dict(attempt._mapping) if attempt else None
                items.append(
                    {
                        "id": job["id"],
                        "status": job["status"],
                        "error_code": job["error_code"],
                        "organization_id": job["organization_id"],
                        "engagement_id": job["engagement_id"],
                        "requester_user_id": job["requester_user_id"],
                        "target": job["target"],
                        "technique": job["technique"],
                        "action_class": job["action_class"],
                        "request_digest": job["request_digest"],
                        "approval_id": job["approval_id"],
                        "created_at": job["created_at"],
                        "started_at": job["started_at"],
                        "finished_at": job["finished_at"],
                        "attempt": (
                            {
                                "id": attempt_data["id"],
                                "state": attempt_data["state"],
                                "action_sequence": attempt_data["action_sequence"],
                                "outcome_classification": attempt_data["outcome_classification"],
                                "started_at": attempt_data["started_at"],
                                "updated_at": attempt_data["updated_at"],
                            }
                            if attempt_data
                            else None
                        ),
                    }
                )
            return items

    def resolve_reconciliation(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        job_id: str,
        *,
        resolution: str,
        evidence_reference: str,
    ) -> dict[str, Any] | None:
        """Resolve one uncertain action with an authorized, auditable decision."""
        if resolution not in {"confirmed_success", "confirmed_failure"}:
            raise ValueError("Unsupported reconciliation resolution.")
        evidence = evidence_reference.strip()
        if not evidence or len(evidence) > 120:
            raise ValueError("Reconciliation evidence reference is required and bounded.")
        stamp = now_iso()
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.organization_id == organization_id,
                        execution_jobs.c.engagement_id == engagement_id,
                        execution_jobs.c.status == "reconciliation_required",
                    )
                ).first()
                if not row:
                    connection.rollback()
                    return None
                job = dict(row._mapping)
                if not self.security._can_manage(
                    connection, user_id, organization_id, engagement_id
                ):
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "execution.reconciliation_rejected",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code="RECONCILIATION_FORBIDDEN",
                        details={"resolution": resolution},
                    )
                    connection.commit()
                    return {"outcome": "forbidden"}
                attempt = connection.execute(
                    select(execution_action_attempts)
                    .where(
                        execution_action_attempts.c.job_id == job_id,
                        execution_action_attempts.c.state.in_(
                            ["outcome_uncertain", "reconciliation_required"]
                        ),
                    )
                    .order_by(execution_action_attempts.c.action_sequence.desc())
                    .limit(1)
                ).first()
                if not attempt:
                    connection.rollback()
                    return {"outcome": "invalid_state"}
                attempt_values: dict[str, Any] = {
                    "outcome_classification": f"manually_{resolution}",
                    "result_reference": evidence,
                    "updated_at": stamp,
                }
                if resolution == "confirmed_success":
                    attempt_values.update(state="completed", completed_at=stamp)
                connection.execute(
                    update(execution_action_attempts)
                    .where(
                        execution_action_attempts.c.id == attempt.id,
                        execution_action_attempts.c.state.in_(
                            ["outcome_uncertain", "reconciliation_required"]
                        ),
                    )
                    .values(**attempt_values)
                )
                job_values = {
                    "status": "completed" if resolution == "confirmed_success" else "failed",
                    "finished_at": stamp,
                    "error_code": (
                        None
                        if resolution == "confirmed_success"
                        else "EXTERNAL_ACTION_CONFIRMED_FAILED"
                    ),
                }
                connection.execute(
                    update(execution_jobs)
                    .where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status == "reconciliation_required",
                    )
                    .values(**job_values)
                )
                self.security._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "execution.reconciliation_resolved",
                    "execution_job",
                    job_id,
                    decision="ALLOW",
                    reason_code="RECONCILIATION_RESOLVED",
                    details={
                        "resolution": resolution,
                        "evidence_reference": evidence,
                        "action_id": attempt.id,
                    },
                )
                connection.commit()
                return {
                    "outcome": "resolved",
                    "resolution": resolution,
                    "job": {**job, **job_values},
                }
            except Exception:
                connection.rollback()
                raise

    def mark_action_in_progress(
        self,
        job_id: str,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        action_id: str | None = None,
        now: float | None = None,
    ) -> bool:
        stamp = now_iso()
        ts = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                job_row = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status == "running",
                    )
                ).first()
                if not job_row or not self._lease_fenced(
                    dict(job_row._mapping), worker_id, lease_generation, ts
                ):
                    connection.rollback()
                    return False
                query = select(execution_action_attempts).where(
                    execution_action_attempts.c.job_id == job_id,
                    execution_action_attempts.c.state.in_(["not_started", "authorized"]),
                )
                if action_id is not None:
                    query = query.where(execution_action_attempts.c.id == action_id)
                else:
                    query = query.order_by(execution_action_attempts.c.action_sequence.desc())
                attempt = connection.execute(query.limit(1)).first()
                if not attempt:
                    connection.rollback()
                    return False
                if lease_generation is not None and int(attempt.lease_generation) != int(
                    lease_generation
                ):
                    connection.rollback()
                    return False
                res = connection.execute(
                    update(execution_action_attempts)
                    .where(
                        execution_action_attempts.c.id == attempt.id,
                        execution_action_attempts.c.state.in_(["not_started", "authorized"]),
                    )
                    .values(state="in_progress", started_at=stamp, updated_at=stamp)
                )
                connection.commit()
                return bool(res.rowcount == 1)
            except Exception:
                connection.rollback()
                raise

    def complete_action_attempt(
        self,
        job_id: str,
        *,
        state: str,
        outcome_classification: str,
        result_reference: str | None = None,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        action_id: str | None = None,
    ) -> bool:
        if state not in {
            "completed",
            "failed_before_dispatch",
            "outcome_uncertain",
            "reconciliation_required",
        }:
            raise ValueError("Invalid action attempt completion state.")
        stamp = now_iso()
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                job_row = connection.execute(
                    select(execution_jobs).where(execution_jobs.c.id == job_id)
                ).first()
                if not job_row:
                    connection.rollback()
                    return False
                item = dict(job_row._mapping)
                if not self._lease_fenced(
                    item, worker_id, lease_generation, time.time(), check_expiry=False
                ):
                    connection.rollback()
                    return False
                query = select(execution_action_attempts).where(
                    execution_action_attempts.c.job_id == job_id,
                    execution_action_attempts.c.state.in_(["authorized", "in_progress"]),
                )
                if action_id is not None:
                    query = query.where(execution_action_attempts.c.id == action_id)
                else:
                    query = query.order_by(execution_action_attempts.c.action_sequence.desc())
                attempt = connection.execute(query.limit(1)).first()
                if not attempt:
                    connection.rollback()
                    return False
                res = connection.execute(
                    update(execution_action_attempts)
                    .where(
                        execution_action_attempts.c.id == attempt.id,
                        execution_action_attempts.c.state.in_(["authorized", "in_progress"]),
                    )
                    .values(
                        state=state,
                        completed_at=stamp if state == "completed" else None,
                        outcome_classification=outcome_classification,
                        result_reference=result_reference,
                        updated_at=stamp,
                    )
                )
                if (
                    res.rowcount == 1
                    and state in {"outcome_uncertain", "reconciliation_required"}
                    and item["status"] in {"claimed", "running"}
                ):
                    connection.execute(
                        update(execution_jobs)
                        .where(
                            execution_jobs.c.id == job_id,
                            execution_jobs.c.status.in_(["claimed", "running"]),
                        )
                        .values(
                            status="reconciliation_required",
                            finished_at=stamp,
                            error_code="EXTERNAL_OUTCOME_UNCERTAIN",
                        )
                    )
                connection.commit()
                return bool(res.rowcount == 1)
            except Exception:
                connection.rollback()
                raise

    def recover_stale_jobs(
        self, *, now: float | None = None, include_stopped_workers: bool = True
    ) -> list[dict[str, Any]]:
        """Idempotently recover expired or orphaned jobs.

        Separates safe retries from uncertainty.
        """
        ts = time.time() if now is None else float(now)
        stamp = now_iso()
        recovered: list[dict[str, Any]] = []
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                stopped_workers: set[str] = set()
                if include_stopped_workers:
                    stopped_workers = {
                        r.worker_id
                        for r in connection.execute(
                            select(worker_leases.c.worker_id).where(
                                worker_leases.c.status == "stopped"
                            )
                        ).all()
                    }
                conditions = [
                    execution_jobs.c.lease_expires_at.is_(None),
                    execution_jobs.c.lease_expires_at <= ts,
                ]
                if stopped_workers:
                    conditions.append(execution_jobs.c.worker_id.in_(stopped_workers))
                stale_rows = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.status.in_(["claimed", "running"]),
                        or_(*conditions),
                    )
                ).all()
                for row in stale_rows:
                    item = dict(row._mapping)
                    job_id = item["id"]
                    attempts = connection.execute(
                        select(execution_action_attempts)
                        .where(execution_action_attempts.c.job_id == job_id)
                        .order_by(execution_action_attempts.c.action_sequence.desc())
                    ).all()
                    unsafe_attempt = next(
                        (
                            a
                            for a in attempts
                            if a.state
                            in {
                                "in_progress",
                                "outcome_uncertain",
                                "reconciliation_required",
                                "completed",
                            }
                        ),
                        None,
                    )
                    if unsafe_attempt is not None or item["approval_consumed_at"] is not None:
                        if unsafe_attempt is not None and unsafe_attempt.state == "in_progress":
                            connection.execute(
                                update(execution_action_attempts)
                                .where(
                                    execution_action_attempts.c.id == unsafe_attempt.id,
                                    execution_action_attempts.c.state == "in_progress",
                                )
                                .values(
                                    state="outcome_uncertain",
                                    outcome_classification="worker_lease_expired",
                                    updated_at=stamp,
                                )
                            )
                        err = (
                            "CANCELLATION_OUTCOME_UNCERTAIN"
                            if item["cancellation_requested_at"] is not None
                            else "EXTERNAL_OUTCOME_UNCERTAIN"
                        )
                        connection.execute(
                            update(execution_jobs)
                            .where(
                                execution_jobs.c.id == job_id,
                                execution_jobs.c.status.in_(["claimed", "running"]),
                            )
                            .values(
                                status="reconciliation_required",
                                finished_at=stamp,
                                last_recovery_at=stamp,
                                error_code=err,
                            )
                        )
                        self.security._audit(
                            connection,
                            item["organization_id"],
                            item["engagement_id"],
                            item["requester_user_id"],
                            "execution.recovery_reconciliation_required",
                            "execution_job",
                            job_id,
                            decision="DENY",
                            reason_code=err,
                            details={
                                "lease_generation": item.get("lease_generation"),
                                "action_id": unsafe_attempt.id if unsafe_attempt else None,
                            },
                        )
                        recovered.append({"id": job_id, "outcome": "reconciliation_required"})
                        continue

                    connection.execute(
                        update(execution_action_attempts)
                        .where(
                            execution_action_attempts.c.job_id == job_id,
                            execution_action_attempts.c.state.in_(["not_started", "authorized"]),
                        )
                        .values(
                            state="failed_before_dispatch",
                            outcome_classification="worker_crashed_before_dispatch",
                            completed_at=stamp,
                            updated_at=stamp,
                        )
                    )
                    if item["cancellation_requested_at"] is not None:
                        connection.execute(
                            update(execution_jobs)
                            .where(
                                execution_jobs.c.id == job_id,
                                execution_jobs.c.status.in_(["claimed", "running"]),
                            )
                            .values(
                                status="cancelled",
                                cancellation_observed_at=item["cancellation_observed_at"] or stamp,
                                finished_at=stamp,
                                last_recovery_at=stamp,
                                error_code="EXECUTION_CANCELLED",
                            )
                        )
                        self.security._audit(
                            connection,
                            item["organization_id"],
                            item["engagement_id"],
                            item["cancellation_requested_by"] or item["requester_user_id"],
                            "execution.job_recovered_cancelled",
                            "execution_job",
                            job_id,
                            decision="DENY",
                            reason_code="CANCELLED_DURING_RECOVERY",
                            details={"lease_generation": item.get("lease_generation")},
                        )
                        recovered.append({"id": job_id, "outcome": "cancelled"})
                        continue

                    valid, reason = self._validate_context(connection, item)
                    if valid:
                        connection.execute(
                            update(execution_jobs)
                            .where(
                                execution_jobs.c.id == job_id,
                                execution_jobs.c.status.in_(["claimed", "running"]),
                            )
                            .values(
                                status="queued",
                                worker_id=None,
                                lease_expires_at=None,
                                heartbeat_at=None,
                                claimed_at=None,
                                last_recovery_at=stamp,
                                error_code=None,
                            )
                        )
                        self.security._audit(
                            connection,
                            item["organization_id"],
                            item["engagement_id"],
                            item["requester_user_id"],
                            "execution.job_recovered_requeued",
                            "execution_job",
                            job_id,
                            decision="ALLOW",
                            reason_code="SAFE_RECOVERY_REQUEUED",
                            details={"lease_generation": item.get("lease_generation")},
                        )
                        recovered.append({"id": job_id, "outcome": "queued"})
                    else:
                        connection.execute(
                            update(execution_jobs)
                            .where(
                                execution_jobs.c.id == job_id,
                                execution_jobs.c.status.in_(["claimed", "running"]),
                            )
                            .values(
                                status="blocked",
                                finished_at=stamp,
                                last_recovery_at=stamp,
                                error_code=reason,
                            )
                        )
                        self.security._audit(
                            connection,
                            item["organization_id"],
                            item["engagement_id"],
                            item["requester_user_id"],
                            "execution.job_blocked",
                            "execution_job",
                            job_id,
                            decision="DENY",
                            reason_code=reason,
                            details={"lease_generation": item.get("lease_generation")},
                        )
                        recovered.append({"id": job_id, "outcome": "blocked"})
                connection.commit()
                return recovered
            except Exception:
                connection.rollback()
                raise

    def revalidate_job(
        self,
        job_id: str,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        now: float | None = None,
    ) -> bool:
        ts = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    select(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status.in_(["claimed", "running"]),
                    )
                ).first()
                if not row:
                    connection.rollback()
                    return False
                item = dict(row._mapping)
                if not self._lease_fenced(item, worker_id, lease_generation, ts):
                    connection.rollback()
                    return False
                valid, reason = self._validate_context(connection, item)
                if not valid:
                    update_stmt = update(execution_jobs).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status.in_(["claimed", "running"]),
                    )
                    if worker_id is not None and lease_generation is not None:
                        update_stmt = update_stmt.where(
                            execution_jobs.c.worker_id == worker_id,
                            execution_jobs.c.lease_generation == lease_generation,
                        )
                    connection.execute(
                        update_stmt.values(
                            status="blocked", finished_at=now_iso(), error_code=reason
                        )
                    )
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["requester_user_id"],
                        "execution.job_blocked",
                        "execution_job",
                        job_id,
                        decision="DENY",
                        reason_code=reason,
                        details={"policy_decision_id": item["policy_decision_id"]},
                    )
                    connection.commit()
                    return False
                if item["status"] == "claimed":
                    connection.execute(
                        update(execution_jobs)
                        .where(execution_jobs.c.id == job_id, execution_jobs.c.status == "claimed")
                        .values(status="running", started_at=now_iso())
                    )
                    self.security._audit(
                        connection,
                        item["organization_id"],
                        item["engagement_id"],
                        item["requester_user_id"],
                        "execution.job_started",
                        "execution_job",
                        job_id,
                        decision="ALLOW",
                        reason_code="EXECUTION_CONTEXT_VALID",
                        details={"policy_decision_id": item["policy_decision_id"]},
                    )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def record_progress(
        self,
        job_id: str,
        percent: int,
        phase: str,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        now: float | None = None,
    ) -> None:
        ts = time.time() if now is None else float(now)
        with self.engine.begin() as connection:
            row = connection.execute(
                select(execution_jobs).where(
                    execution_jobs.c.id == job_id,
                    execution_jobs.c.status == "running",
                )
            ).first()
            if not row:
                return
            item = dict(row._mapping)
            if not self._lease_fenced(item, worker_id, lease_generation, ts):
                return
            self.security._audit(
                connection,
                item["organization_id"],
                item["engagement_id"],
                item["requester_user_id"],
                "execution.progress",
                "execution_job",
                job_id,
                decision="ALLOW",
                reason_code="ADAPTER_PROGRESS",
                details={"percent": percent, "phase": phase},
            )

    def block_running_job(
        self,
        job_id: str,
        reason: str,
        *,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        now: float | None = None,
    ) -> None:
        """Block a running job without leaking adapter details or consuming approval."""
        ts = time.time() if now is None else float(now)
        with self.engine.begin() as connection:
            row = connection.execute(
                select(execution_jobs).where(
                    execution_jobs.c.id == job_id,
                    execution_jobs.c.status == "running",
                )
            ).first()
            if not row:
                return
            item = dict(row._mapping)
            if not self._lease_fenced(item, worker_id, lease_generation, ts):
                return
            connection.execute(
                update(execution_jobs)
                .where(execution_jobs.c.id == job_id, execution_jobs.c.status == "running")
                .values(status="blocked", finished_at=now_iso(), error_code=reason)
            )
            self.security._audit(
                connection,
                item["organization_id"],
                item["engagement_id"],
                item["requester_user_id"],
                "execution.sensitive_action_not_reached",
                "execution_job",
                job_id,
                decision="DENY",
                reason_code="SENSITIVE_ACTION_NOT_REACHED",
                details={"request_digest": item["request_digest"]},
            )
            self.security._audit(
                connection,
                item["organization_id"],
                item["engagement_id"],
                item["requester_user_id"],
                "execution.job_blocked",
                "execution_job",
                job_id,
                decision="DENY",
                reason_code=reason,
                details={"policy_decision_id": item["policy_decision_id"]},
            )

    def sensitive_approval_consumed(self, job_id: str) -> bool:
        with self.engine.connect() as connection:
            return (
                connection.execute(
                    select(execution_jobs.c.approval_consumed_at).where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.action_class == "sensitive",
                    )
                ).scalar_one_or_none()
                is not None
            )

    def finish_job(
        self,
        job_id: str,
        *,
        scan_id: str | None,
        failed: bool = False,
        cancelled: bool = False,
        error_code: str | None = None,
        result_summary: dict[str, Any] | None = None,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        now: float | None = None,
    ) -> bool:
        ts = time.time() if now is None else float(now)
        with self.engine.begin() as connection:
            row = connection.execute(
                select(execution_jobs).where(
                    execution_jobs.c.id == job_id,
                    execution_jobs.c.status == "running",
                )
            ).first()
            if not row:
                return False
            item = dict(row._mapping)
            if not self._lease_fenced(item, worker_id, lease_generation, ts):
                return False
            status = "cancelled" if cancelled else ("failed" if failed else "completed")
            stmt = update(execution_jobs).where(
                execution_jobs.c.id == job_id,
                execution_jobs.c.status == "running",
            )
            if worker_id is not None and lease_generation is not None:
                stmt = stmt.where(
                    execution_jobs.c.worker_id == worker_id,
                    execution_jobs.c.lease_generation == lease_generation,
                )
            res = connection.execute(
                stmt.values(
                    status=status,
                    scan_id=scan_id,
                    result_summary=result_summary,
                    finished_at=now_iso(),
                    error_code=error_code,
                )
            )
            if res.rowcount != 1:
                return False
            self.security._audit(
                connection,
                item["organization_id"],
                item["engagement_id"],
                item["requester_user_id"],
                "execution.job_cancelled"
                if cancelled
                else ("execution.job_failed" if failed else "execution.job_completed"),
                "execution_job",
                job_id,
                decision="DENY" if failed or cancelled else "ALLOW",
                reason_code=(
                    "ASSESSMENT_CANCELLED"
                    if cancelled
                    else (error_code or "ASSESSMENT_FAILED" if failed else "ASSESSMENT_COMPLETED")
                ),
                details={"scan_id": scan_id, "result_present": result_summary is not None},
            )
            if failed and item["cancellation_requested_at"] is not None:
                self.security._audit(
                    connection,
                    item["organization_id"],
                    item["engagement_id"],
                    item["cancellation_requested_by"] or item["requester_user_id"],
                    "execution.cancellation_interrupted_by_failure",
                    "execution_job",
                    job_id,
                    decision="DENY",
                    reason_code="EXECUTION_FAILED_BEFORE_CANCELLATION_COMPLETED",
                    details={"job_status": "failed"},
                )
            if cancelled:
                stamp = item["cancellation_observed_at"] or now_iso()
                connection.execute(
                    update(execution_jobs)
                    .where(
                        execution_jobs.c.id == job_id,
                        execution_jobs.c.status == "cancelled",
                        execution_jobs.c.cancellation_observed_at.is_(None),
                    )
                    .values(cancellation_observed_at=stamp)
                )
                self.security._audit(
                    connection,
                    item["organization_id"],
                    item["engagement_id"],
                    item["cancellation_requested_by"] or item["requester_user_id"],
                    "execution.cancellation_observed",
                    "execution_job",
                    job_id,
                    decision="DENY",
                    reason_code="WORKER_OBSERVED_LOCAL_CANCELLATION",
                    details={"job_status": item["status"]},
                )
                self.security._audit(
                    connection,
                    item["organization_id"],
                    item["engagement_id"],
                    item["cancellation_requested_by"] or item["requester_user_id"],
                    "execution.cancellation_completed",
                    "execution_job",
                    job_id,
                    decision="DENY",
                    reason_code="CANCELLATION_COMPLETED",
                    details={"job_status": "cancelled"},
                )
            return True

    def partial_result(self, job_id: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(
                    execution_jobs.c.scan_id,
                    execution_jobs.c.result_summary,
                ).where(execution_jobs.c.id == job_id)
            ).first()
            return dict(row._mapping) if row else {"scan_id": None, "result_summary": None}

    def get_organization_resource_usage(self, user_id: str, organization_id: str) -> dict[str, Any]:
        """Return tenant-isolated queue and active execution counts for one organization."""
        with self.engine.connect() as connection:
            from chinescan.core.storage.sqlite import organization_memberships

            membership = connection.execute(
                select(organization_memberships.c.status).where(
                    organization_memberships.c.organization_id == organization_id,
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.status == "active",
                )
            ).first()
            if membership is None:
                raise PermissionError("Organization access denied.")
            rows = connection.execute(
                select(execution_jobs.c.status, execution_jobs.c.asset_type).where(
                    execution_jobs.c.organization_id == organization_id,
                    execution_jobs.c.status.in_(
                        ["queued", "claimed", "running", "reconciliation_required"]
                    ),
                )
            ).all()
        queued = sum(1 for r in rows if r.status == "queued")
        active = sum(1 for r in rows if r.status in {"claimed", "running"})
        reconciliation = sum(1 for r in rows if r.status == "reconciliation_required")
        return {
            "organization_id": organization_id,
            "queued_jobs": queued,
            "active_jobs": active,
            "total_reserved_jobs": queued + active,
            "reconciliation_required_jobs": reconciliation,
            "limits": {
                "per_org_active_limit": self.resource_limits.per_org_active_limit,
                "per_org_queued_limit": self.resource_limits.per_org_queued_limit,
                "default_job_deadline_seconds": self.resource_limits.default_job_deadline_seconds,
                "max_queue_wait_seconds": self.resource_limits.max_queue_wait_seconds,
            },
        }

    def get_global_resource_diagnostics(self) -> dict[str, Any]:
        """Return operator-only global execution capacity and worker lease health."""
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(execution_jobs.c.status, execution_jobs.c.asset_type).where(
                    execution_jobs.c.status.in_(
                        ["queued", "claimed", "running", "reconciliation_required"]
                    )
                )
            ).all()
            workers = connection.execute(
                select(
                    worker_leases.c.worker_id,
                    worker_leases.c.status,
                    worker_leases.c.last_heartbeat_at,
                )
            ).all()
        queued = sum(1 for r in rows if r.status == "queued")
        active = sum(1 for r in rows if r.status in {"claimed", "running"})
        reconciliation = sum(1 for r in rows if r.status == "reconciliation_required")
        by_workload: dict[str, int] = {}
        for r in rows:
            if r.status in {"claimed", "running"}:
                by_workload[r.asset_type] = by_workload.get(r.asset_type, 0) + 1
        return {
            "global_queued_jobs": queued,
            "global_active_jobs": active,
            "global_reserved_jobs": queued + active,
            "reconciliation_required_jobs": reconciliation,
            "active_by_workload": by_workload,
            "workers": [
                {
                    "worker_id": w.worker_id,
                    "status": w.status,
                    "last_heartbeat_at": w.last_heartbeat_at,
                }
                for w in workers
            ],
            "limits": self.resource_limits.model_dump(mode="json"),
        }


class GovernedDomainWorker:
    """Single-process worker dispatching through an explicit adapter registry."""

    def __init__(
        self,
        repository: Any,
        governance: ExecutionGovernanceService,
        adapters: AdapterRegistry | None = None,
        *,
        worker_id: str | None = None,
        lease_duration_seconds: float = DEFAULT_LEASE_DURATION_SECONDS,
        heartbeat_interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS,
    ) -> None:
        ExecutionGovernanceService._validate_lease_bounds(
            lease_duration_seconds, heartbeat_interval_seconds
        )
        self.repository = repository
        self.governance = governance
        self.adapters = adapters or governance.adapters
        self.worker_id = worker_id or f"worker-{secrets.token_hex(8)}"
        self.lease_duration_seconds = float(lease_duration_seconds)
        self.heartbeat_interval_seconds = float(heartbeat_interval_seconds)
        self.shutdown_grace_seconds = float(shutdown_grace_seconds)
        self._condition = threading.Condition()
        self._stopping = False
        self._thread: threading.Thread | None = None
        self._active_lock = threading.Lock()
        self._active_cancellations: dict[str, Event] = {}

    def request_cancellation(
        self, user_id: str, organization_id: str, engagement_id: str, job_id: str
    ) -> dict[str, Any] | None:
        result = self.governance.request_cancellation(
            user_id, organization_id, engagement_id, job_id
        )
        if result and result.get("outcome") == "requested":
            with self._active_lock:
                signal = self._active_cancellations.get(job_id)
                if signal:
                    signal.set()
        return result

    def start(self) -> None:
        with self._condition:
            self._stopping = False
        self.governance.register_worker(self.worker_id)
        self.governance.recover_stale_jobs()
        self._thread = threading.Thread(
            target=self._run, name="chinescan-governed-domain-jobs", daemon=True
        )
        self._thread.start()

    def stop(self, grace_seconds: float | None = None) -> None:
        grace = self.shutdown_grace_seconds if grace_seconds is None else float(grace_seconds)
        self.governance.mark_worker_stopping(self.worker_id)
        with self._condition:
            self._stopping = True
            self._condition.notify_all()
        with self._active_lock:
            for cancellation in self._active_cancellations.values():
                cancellation.set()
        if self._thread:
            self._thread.join(timeout=max(0.1, grace))
            if not self._thread.is_alive():
                self.governance.unregister_worker(self.worker_id)
                self._thread = None
        else:
            self.governance.unregister_worker(self.worker_id)

    def _next_job_id(self) -> str | None:
        with self.repository.engine.connect() as connection:
            result = connection.execute(
                select(execution_jobs.c.id)
                .where(execution_jobs.c.status == "queued")
                .order_by(execution_jobs.c.created_at)
                .limit(1)
            ).scalar_one_or_none()
            return result if isinstance(result, str) else None

    def run_one(self, requested_job_id: str | None = None) -> dict[str, Any] | None:
        with self._condition:
            if self._stopping:
                return None
        if requested_job_id is not None:
            job = self.governance.claim_job(
                requested_job_id,
                self.worker_id,
                lease_duration_seconds=self.lease_duration_seconds,
            )
            job_id = requested_job_id
        else:
            job = self.governance.claim_next_job(
                self.worker_id,
                lease_duration_seconds=self.lease_duration_seconds,
            )
            if job is None:
                return None
            job_id = job["id"]
        if job is None:
            with self.repository.engine.connect() as connection:
                status = connection.execute(
                    select(execution_jobs.c.status).where(execution_jobs.c.id == job_id)
                ).scalar_one_or_none()
            if status == "cancelled":
                return {"id": job_id, "status": "cancelled"}
            return {"id": job_id, "status": "blocked"}
        lease_generation = int(job["lease_generation"])
        if not self.governance.revalidate_job(
            job_id, worker_id=self.worker_id, lease_generation=lease_generation
        ):
            return {"id": job_id, "status": "blocked"}
        try:
            context = ExecutionContext.from_job(job)
            adapter_parameters = {}
            if context.technique == CHAIN_IMPORT_TECHNIQUE:
                if context.chain_context is None:
                    raise AdapterFailure("CHAIN_IMPORT_CONTEXT_INVALID")
                adapter_parameters = context.chain_context
            adapter, parameters = self.adapters.validate_parameters(
                context.asset_type,
                context.technique,
                adapter_parameters,
            )
            if adapter.capabilities.action_class != context.action_class:
                raise AdapterFailure("ADAPTER_CLASSIFICATION_MISMATCH")
        except (ValueError, AdapterFailure):
            self.governance.finish_job(
                job_id,
                scan_id=None,
                failed=True,
                error_code="ADAPTER_CONTEXT_REJECTED",
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            return {"id": job_id, "status": "failed"}
        cancellation = Event()
        heartbeat_stop = Event()
        lease_lost = Event()
        deadline_exceeded = Event()
        limits = self.governance.resource_limits
        expires_remaining = max(0.0, (_utc(context.expires_at) - datetime.now(UTC)).total_seconds())
        effective_deadline_seconds = min(limits.default_job_deadline_seconds, expires_remaining)
        deadline_monotonic = time.monotonic() + effective_deadline_seconds
        with self._active_lock:
            self._active_cancellations[job_id] = cancellation

        def _heartbeat_loop() -> None:
            wait_step = min(self.heartbeat_interval_seconds, max(0.05, effective_deadline_seconds))
            while not heartbeat_stop.wait(timeout=wait_step):
                if time.monotonic() >= deadline_monotonic:
                    deadline_exceeded.set()
                    cancellation.set()
                    return
                if not self.governance.heartbeat_job(
                    job_id,
                    self.worker_id,
                    lease_generation,
                    lease_duration_seconds=self.lease_duration_seconds,
                ):
                    lease_lost.set()
                    cancellation.set()
                    return

        hb_thread = threading.Thread(
            target=_heartbeat_loop,
            name=f"chinescan-hb-{job_id[:8]}",
            daemon=True,
        )
        hb_thread.start()

        def _authorize_and_mark() -> bool:
            if lease_lost.is_set():
                return False
            ok = self.governance.authorize_external_action(
                job_id,
                context.target,
                context.technique,
                worker_id=self.worker_id,
                lease_generation=lease_generation,
                adapter_id=adapter.capabilities.adapter_id,
            )
            if ok:
                self.governance.mark_action_in_progress(
                    job_id,
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
            return ok

        control = ExecutionControl(
            context=context,
            cancellation=cancellation,
            external_operations_enabled=adapter.capabilities.performs_external_operations,
            revalidate=_authorize_and_mark,
            progress=lambda percent, phase: self.governance.record_progress(
                job_id,
                percent,
                phase,
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            ),
            cancellation_check=lambda: self.governance.observe_cancellation(
                job_id,
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            ),
            deadline_monotonic=deadline_monotonic,
            operation_timeout_seconds=limits.default_operation_timeout_seconds,
            max_findings_per_job=limits.max_findings_per_job,
        )
        try:
            control.check_cancelled()
            # Reconstruct repository authority from the persisted, revalidated job.
            # The requester must still have active membership; worker threads do
            # not inherit the web request or local-operator principal.
            with self.repository.member_context(
                context.organization_id, context.requester_user_id, write=True
            ):
                with self.repository.execution_provenance_context(context.model_dump(mode="json")):
                    result = adapter.execute(context, parameters, control)
            if lease_lost.is_set():
                self.governance.complete_action_attempt(
                    job_id,
                    state="outcome_uncertain",
                    outcome_classification="lease_lost_during_execution",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {"id": job_id, "status": "reconciliation_required"}
            if (
                context.action_class == "sensitive"
                and not self.governance.sensitive_approval_consumed(job_id)
            ):
                self.governance.complete_action_attempt(
                    job_id,
                    state="failed_before_dispatch",
                    outcome_classification="sensitive_action_not_reached",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                self.governance.block_running_job(
                    job_id,
                    "SENSITIVE_ACTION_NOT_REACHED",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {"id": job_id, "status": "blocked"}
            if not self.governance.revalidate_job(
                job_id, worker_id=self.worker_id, lease_generation=lease_generation
            ):
                self.governance.complete_action_attempt(
                    job_id,
                    state="outcome_uncertain",
                    outcome_classification="revalidation_failed_post_execute",
                    result_reference=result.result_id,
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                outcome = {"id": job_id, "status": "blocked"}
                if result.result_id:
                    outcome["scan_id"] = result.result_id
                return outcome
            self.governance.complete_action_attempt(
                job_id,
                state="completed",
                outcome_classification="succeeded" if result.status == "complete" else "partial",
                result_reference=result.result_id,
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            failed = result.status != "complete"
            self.governance.finish_job(
                job_id,
                scan_id=result.result_id,
                failed=failed,
                error_code="ADAPTER_PARTIAL_RESULT" if failed else None,
                result_summary=result.model_dump(mode="json"),
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            return {
                "id": job_id,
                "status": "failed" if failed else "completed",
                "scan_id": result.result_id,
                "adapter_id": result.adapter_id,
                "result": result.summary,
            }
        except ExecutionDeadlineExceeded:
            latest = self.governance.latest_action_attempt(job_id)
            if latest and latest.get("state") in {"in_progress", "outcome_uncertain"}:
                self.governance.complete_action_attempt(
                    job_id,
                    state="outcome_uncertain",
                    outcome_classification="deadline_exceeded_in_progress",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {
                    "id": job_id,
                    "status": "reconciliation_required",
                    "error_code": "EXTERNAL_OUTCOME_UNCERTAIN",
                }
            self.governance.complete_action_attempt(
                job_id,
                state="failed_before_dispatch",
                outcome_classification="deadline_exceeded_before_dispatch",
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            partial = self.governance.partial_result(job_id)
            self.governance.finish_job(
                job_id,
                scan_id=partial["scan_id"],
                failed=True,
                error_code="EXECUTION_DEADLINE_EXCEEDED",
                result_summary=partial["result_summary"],
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            outcome = {
                "id": job_id,
                "status": "failed",
                "error_code": "EXECUTION_DEADLINE_EXCEEDED",
            }
            if partial["scan_id"]:
                outcome["scan_id"] = partial["scan_id"]
            return outcome
        except ExecutionCancelled:
            latest = self.governance.latest_action_attempt(job_id)
            if deadline_exceeded.is_set():
                if latest and latest.get("state") in {"in_progress", "outcome_uncertain"}:
                    self.governance.complete_action_attempt(
                        job_id,
                        state="outcome_uncertain",
                        outcome_classification="deadline_exceeded_in_progress",
                        worker_id=self.worker_id,
                        lease_generation=lease_generation,
                    )
                    return {
                        "id": job_id,
                        "status": "reconciliation_required",
                        "error_code": "EXTERNAL_OUTCOME_UNCERTAIN",
                    }
                self.governance.complete_action_attempt(
                    job_id,
                    state="failed_before_dispatch",
                    outcome_classification="deadline_exceeded_before_dispatch",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                partial = self.governance.partial_result(job_id)
                self.governance.finish_job(
                    job_id,
                    scan_id=partial["scan_id"],
                    failed=True,
                    error_code="EXECUTION_DEADLINE_EXCEEDED",
                    result_summary=partial["result_summary"],
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {
                    "id": job_id,
                    "status": "failed",
                    "error_code": "EXECUTION_DEADLINE_EXCEEDED",
                }
            if latest and latest.get("state") in {"in_progress", "outcome_uncertain"}:
                self.governance.complete_action_attempt(
                    job_id,
                    state="outcome_uncertain",
                    outcome_classification="cancelled_during_in_progress",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {"id": job_id, "status": "reconciliation_required"}
            self.governance.complete_action_attempt(
                job_id,
                state="failed_before_dispatch",
                outcome_classification="cancelled_before_dispatch",
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            partial = self.governance.partial_result(job_id)
            self.governance.finish_job(
                job_id,
                scan_id=partial["scan_id"],
                cancelled=True,
                error_code="EXECUTION_CANCELLED",
                result_summary=partial["result_summary"],
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            outcome = {"id": job_id, "status": "cancelled"}
            if partial["scan_id"]:
                outcome["scan_id"] = partial["scan_id"]
            return outcome
        except ExecutionStopped:
            self.governance.complete_action_attempt(
                job_id,
                state="outcome_uncertain",
                outcome_classification="execution_stopped",
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            return {"id": job_id, "status": "blocked"}
        except AdapterFailure as exc:
            if exc.code == "POLICY_REVALIDATION_DENIED":
                return {"id": job_id, "status": "blocked"}
            latest = self.governance.latest_action_attempt(job_id)
            if latest and latest.get("state") == "in_progress":
                self.governance.complete_action_attempt(
                    job_id,
                    state="outcome_uncertain",
                    outcome_classification=f"adapter_failure:{exc.code}",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {
                    "id": job_id,
                    "status": "reconciliation_required",
                    "error_code": "EXTERNAL_OUTCOME_UNCERTAIN",
                }
            self.governance.complete_action_attempt(
                job_id,
                state="failed_before_dispatch",
                outcome_classification=exc.code,
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            partial = self.governance.partial_result(job_id)
            self.governance.finish_job(
                job_id,
                scan_id=partial["scan_id"],
                failed=True,
                error_code=exc.code,
                result_summary=partial["result_summary"],
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            outcome = {"id": job_id, "status": "failed", "error_code": exc.code}
            if partial["scan_id"]:
                outcome["scan_id"] = partial["scan_id"]
            return outcome
        except Exception:
            # Authorization failures already transition the job to BLOCKED. All other
            # failures have a generic durable code; internal exception text is withheld.
            latest = self.governance.latest_action_attempt(job_id)
            if latest and latest.get("state") == "in_progress":
                self.governance.complete_action_attempt(
                    job_id,
                    state="outcome_uncertain",
                    outcome_classification="unexpected_exception_in_progress",
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                )
                return {"id": job_id, "status": "reconciliation_required"}
            self.governance.complete_action_attempt(
                job_id,
                state="failed_before_dispatch",
                outcome_classification="unexpected_exception_before_dispatch",
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            partial = self.governance.partial_result(job_id)
            self.governance.finish_job(
                job_id,
                scan_id=partial["scan_id"],
                failed=True,
                result_summary=partial["result_summary"],
                worker_id=self.worker_id,
                lease_generation=lease_generation,
            )
            outcome = {"id": job_id, "status": "failed"}
            if partial["scan_id"]:
                outcome["scan_id"] = partial["scan_id"]
            return outcome
        finally:
            heartbeat_stop.set()
            hb_thread.join(timeout=1.0)
            with self._active_lock:
                self._active_cancellations.pop(job_id, None)

    def _run(self) -> None:
        idle_ticks = 0
        while True:
            with self._condition:
                if self._stopping:
                    return
            if self.run_one() is None:
                idle_ticks += 1
                if idle_ticks >= 10:
                    idle_ticks = 0
                    self.governance.recover_stale_jobs(include_stopped_workers=False)
                with self._condition:
                    self._condition.wait(timeout=0.5)
            else:
                idle_ticks = 0
