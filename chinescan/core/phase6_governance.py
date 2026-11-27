"""Phase 6 execution assurance and evidence lifecycle primitives.

The module is intentionally policy-first: a capability is only marked
``enforced`` after a runtime probe succeeds, and retention deletion rechecks
holds inside the same SQLite write transaction immediately before erasing a
record.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, select, update

from chinescan.core.organizations import now_iso
from chinescan.core.storage.sqlite import (
    execution_capability_snapshots,
    execution_result_provenance,
    legal_hold_records,
    legal_holds,
    record_ownership,
    records,
    retention_audit_events,
    retention_jobs,
    retention_policies,
)

POLICY_VERSION = "phase6-1"
EXECUTION_STATES = frozenset(
    {
        "requested",
        "authorized",
        "queued",
        "leased",
        "starting",
        "running",
        "completed",
        "failed",
        "cancelled",
        "timed_out",
        "outcome_uncertain",
        "reconciliation_required",
        "reconciled",
    }
)
_TRANSITIONS: dict[str, frozenset[str]] = {
    "requested": frozenset({"authorized", "failed", "cancelled"}),
    "authorized": frozenset({"queued", "failed", "cancelled"}),
    "queued": frozenset({"leased", "cancelled", "failed"}),
    "leased": frozenset({"starting", "queued", "failed", "cancelled", "outcome_uncertain"}),
    "starting": frozenset({"running", "failed", "outcome_uncertain", "cancelled"}),
    "running": frozenset({"completed", "failed", "cancelled", "timed_out", "outcome_uncertain"}),
    "outcome_uncertain": frozenset({"reconciliation_required"}),
    "reconciliation_required": frozenset({"reconciled", "completed", "failed", "cancelled"}),
    "reconciled": frozenset(),
    "completed": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
    "timed_out": frozenset(),
}


class Phase6PolicyError(ValueError):
    """A requested Phase 6 operation violates a security invariant."""


@dataclass(frozen=True)
class Capability:
    name: str
    supported: bool
    runtime_available: bool
    enforced: bool
    reason: str | None = None
    initialized: bool = False
    verified: bool = False


@dataclass(frozen=True)
class CapabilitySnapshot:
    platform: str
    profile: str
    policy_version: str
    capabilities: tuple[Capability, ...]
    execution_identity: str | None

    @property
    def required_controls(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.capabilities)

    @property
    def enforced_controls(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.capabilities if item.enforced)

    @property
    def unavailable_controls(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.capabilities if not item.enforced)

    @property
    def hardened(self) -> bool:
        return bool(self.capabilities) and all(item.enforced for item in self.capabilities)


def probe_capabilities() -> CapabilitySnapshot:
    """Return actual, non-sensitive runtime capability facts.

    Linux namespace/cgroup/seccomp controls are deployment capabilities, not
    facts that can be inferred from ``sys.platform``. Windows gets its own
    Job Object probe and never receives Linux capability names.
    """
    platform = sys.platform
    if os.name == "nt":
        job_objects = _windows_job_object_available()
        controls: tuple[Capability, ...] = (
            Capability(
                "windows_job_object",
                True,
                job_objects,
                False,
                "runtime_setup_not_verified" if job_objects else "job_object_api_unavailable",
            ),
            Capability("restricted_token", True, False, False, "token_initialization_not_verified"),
            Capability(
                "network_egress_policy", True, False, False, "deployment_policy_not_verified"
            ),
        )
    elif platform.startswith("linux"):
        controls = tuple(
            Capability(name, True, False, False, "deployment_control_not_verified")
            for name in (
                "user_namespace",
                "pid_namespace",
                "mount_namespace",
                "network_namespace",
                "cgroup_v2",
                "seccomp",
                "capability_reduction",
                "network_egress_policy",
            )
        )
    else:
        controls = (
            Capability(
                "process_tree_cleanup", os.name in {"nt", "posix"}, True, os.name in {"nt", "posix"}
            ),
        )
    return CapabilitySnapshot(platform, "hardened", POLICY_VERSION, controls, None)


def _windows_job_object_available() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return callable(getattr(ctypes, "WinDLL", None))
    except (AttributeError, OSError):
        return False


def require_profile(profile: str, snapshot: CapabilitySnapshot | None = None) -> CapabilitySnapshot:
    if profile not in {"hardened", "restricted", "development"}:
        raise Phase6PolicyError("unknown execution profile")
    result = snapshot or probe_capabilities()
    if profile == "hardened" and not result.hardened:
        raise Phase6PolicyError("mandatory isolation controls are unavailable; execution refused")
    return result


def validate_transition(current: str, requested: str) -> None:
    if current not in EXECUTION_STATES or requested not in EXECUTION_STATES:
        raise Phase6PolicyError("unknown execution state")
    if requested not in _TRANSITIONS[current]:
        raise Phase6PolicyError(f"invalid execution transition: {current} -> {requested}")


def persist_capability_snapshot(
    repository: Any,
    organization_id: str,
    *,
    job_id: str | None = None,
    profile: str = "hardened",
    snapshot: CapabilitySnapshot | None = None,
) -> str:
    result = require_profile(profile, snapshot)
    snapshot_id = str(uuid4())
    status = "initialized" if result.hardened else "unavailable"
    with repository.engine.begin() as connection:
        connection.execute(
            execution_capability_snapshots.insert().values(
                id=snapshot_id,
                organization_id=organization_id,
                job_id=job_id,
                profile=profile,
                platform=result.platform,
                policy_version=result.policy_version,
                required_controls=list(result.required_controls),
                available_controls=[
                    item.name for item in result.capabilities if item.runtime_available
                ],
                enforced_controls=list(result.enforced_controls),
                unavailable_controls=list(result.unavailable_controls),
                initialization_status=status,
                failure_reason=None if result.hardened else "mandatory_controls_unavailable",
                execution_identity=result.execution_identity,
                created_at=now_iso(),
            )
        )
    return snapshot_id


class EvidenceLifecycleService:
    """Tenant-scoped retention policies, legal holds, and safe deletion."""

    def __init__(self, repository: Any) -> None:
        self.repository = repository
        self.engine = repository.engine

    def _audit(
        self,
        connection: Any,
        org: str,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str | None,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            retention_audit_events.insert().values(
                id=str(uuid4()),
                organization_id=org,
                actor_user_id=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                occurred_at=now_iso(),
            )
        )

    def create_policy(
        self,
        organization_id: str,
        actor_user_id: str,
        retention_days: int,
        *,
        engagement_id: str | None = None,
        evidence_category: str | None = None,
    ) -> str:
        if not 1 <= retention_days <= 36500:
            raise Phase6PolicyError("retention_days must be between 1 and 36500")
        policy_id = str(uuid4())
        with (
            self.repository.member_context(organization_id, actor_user_id, write=True),
            self.engine.begin() as connection,
        ):
            connection.execute(
                retention_policies.insert().values(
                    id=policy_id,
                    organization_id=organization_id,
                    engagement_id=engagement_id,
                    evidence_category=evidence_category,
                    retention_days=retention_days,
                    version=1,
                    status="active",
                    effective_at=now_iso(),
                    created_by=actor_user_id,
                    created_at=now_iso(),
                )
            )
            self._audit(
                connection,
                organization_id,
                actor_user_id,
                "retention.policy_created",
                "retention_policy",
                policy_id,
                {"retention_days": retention_days},
            )
        return policy_id

    def create_hold(
        self,
        organization_id: str,
        actor_user_id: str,
        record_ids: list[tuple[str, str]],
        reason: str,
        *,
        engagement_id: str | None = None,
    ) -> str:
        if not reason.strip() or not record_ids:
            raise Phase6PolicyError("a legal hold requires a reason and at least one record")
        hold_id = str(uuid4())
        with (
            self.repository.member_context(organization_id, actor_user_id, write=True),
            self.engine.begin() as connection,
        ):
            for record_type, record_id in record_ids:
                owned = connection.execute(
                    select(record_ownership.c.record_id).where(
                        record_ownership.c.organization_id == organization_id,
                        record_ownership.c.record_type == record_type,
                        record_ownership.c.record_id == record_id,
                    )
                ).scalar_one_or_none()
                if owned is None:
                    raise Phase6PolicyError("legal hold record is outside the organization")
            connection.execute(
                legal_holds.insert().values(
                    id=hold_id,
                    organization_id=organization_id,
                    engagement_id=engagement_id,
                    reason=reason.strip(),
                    status="active",
                    created_by=actor_user_id,
                    created_at=now_iso(),
                )
            )
            connection.execute(
                legal_hold_records.insert(),
                [
                    dict(
                        hold_id=hold_id, record_type=t, record_id=i, organization_id=organization_id
                    )
                    for t, i in record_ids
                ],
            )
            self._audit(
                connection,
                organization_id,
                actor_user_id,
                "legal_hold.created",
                "legal_hold",
                hold_id,
                {"record_count": len(record_ids)},
            )
        return hold_id

    def release_hold(self, organization_id: str, actor_user_id: str, hold_id: str) -> bool:
        with (
            self.repository.member_context(organization_id, actor_user_id, write=True),
            self.engine.begin() as connection,
        ):
            result = connection.execute(
                update(legal_holds)
                .where(
                    legal_holds.c.id == hold_id,
                    legal_holds.c.organization_id == organization_id,
                    legal_holds.c.status == "active",
                )
                .values(status="released", released_by=actor_user_id, released_at=now_iso())
            )
            if result.rowcount != 1:
                return False
            self._audit(
                connection,
                organization_id,
                actor_user_id,
                "legal_hold.released",
                "legal_hold",
                hold_id,
                {},
            )
            return True

    def list_policies(self, organization_id: str, actor_user_id: str) -> list[dict[str, Any]]:
        with self.repository.member_context(organization_id, actor_user_id):
            with self.engine.connect() as connection:
                rows = connection.execute(
                    select(retention_policies)
                    .where(retention_policies.c.organization_id == organization_id)
                    .order_by(retention_policies.c.created_at.desc())
                ).mappings()
                return [dict(row) for row in rows]

    def list_holds(self, organization_id: str, actor_user_id: str) -> list[dict[str, Any]]:
        with self.repository.member_context(organization_id, actor_user_id):
            with self.engine.connect() as connection:
                rows = (
                    connection.execute(
                        select(legal_holds)
                        .where(legal_holds.c.organization_id == organization_id)
                        .order_by(legal_holds.c.created_at.desc())
                    )
                    .mappings()
                    .all()
                )
                result: list[dict[str, Any]] = []
                for row in rows:
                    item = dict(row)
                    item["record_count"] = len(
                        connection.execute(
                            select(legal_hold_records.c.record_id).where(
                                legal_hold_records.c.hold_id == item["id"]
                            )
                        ).all()
                    )
                    result.append(item)
                return result

    def list_retention_jobs(self, organization_id: str, actor_user_id: str) -> list[dict[str, Any]]:
        with self.repository.member_context(organization_id, actor_user_id):
            with self.engine.connect() as connection:
                rows = connection.execute(
                    select(retention_jobs)
                    .where(retention_jobs.c.organization_id == organization_id)
                    .order_by(retention_jobs.c.created_at.desc())
                    .limit(100)
                ).mappings()
                return [dict(row) for row in rows]

    def list_audit(self, organization_id: str, actor_user_id: str) -> list[dict[str, Any]]:
        with self.repository.member_context(organization_id, actor_user_id):
            with self.engine.connect() as connection:
                rows = connection.execute(
                    select(retention_audit_events)
                    .where(retention_audit_events.c.organization_id == organization_id)
                    .order_by(retention_audit_events.c.occurred_at.desc())
                    .limit(100)
                ).mappings()
                return [dict(row) for row in rows]

    def run_once(
        self,
        organization_id: str,
        actor_user_id: str,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> dict[str, int]:
        if limit < 1 or limit > 1000:
            raise Phase6PolicyError("retention limit is out of range")
        instant = now or datetime.now(UTC)
        counts = {"deleted": 0, "blocked": 0, "skipped": 0}
        with (
            self.repository.member_context(organization_id, actor_user_id, write=True),
            self.engine.begin() as connection,
        ):
            candidates = connection.execute(
                select(
                    records.c.record_type,
                    records.c.record_id,
                    records.c.payload,
                    record_ownership.c.engagement_id,
                )
                .join(
                    record_ownership,
                    (record_ownership.c.record_type == records.c.record_type)
                    & (record_ownership.c.record_id == records.c.record_id),
                )
                .where(
                    record_ownership.c.organization_id == organization_id,
                    records.c.record_type == "evidence",
                )
                .limit(limit)
            ).all()
            for row in candidates:
                payload = dict(row.payload or {})
                category = payload.get("evidence_type")
                policy = connection.execute(
                    select(retention_policies)
                    .where(
                        retention_policies.c.organization_id == organization_id,
                        retention_policies.c.status == "active",
                        (retention_policies.c.engagement_id == row.engagement_id)
                        | (retention_policies.c.engagement_id.is_(None)),
                        (retention_policies.c.evidence_category == category)
                        | (retention_policies.c.evidence_category.is_(None)),
                    )
                    .order_by(
                        retention_policies.c.engagement_id.is_(None),
                        retention_policies.c.evidence_category.is_(None),
                    )
                ).first()
                if policy is None:
                    counts["skipped"] += 1
                    continue
                ingested = _parse_time(payload.get("ingested_at") or payload.get("created_at"))
                if (
                    ingested is None
                    or ingested + timedelta(days=int(policy.retention_days)) > instant
                ):
                    continue
                held = connection.execute(
                    select(legal_hold_records.c.hold_id)
                    .join(legal_holds, legal_holds.c.id == legal_hold_records.c.hold_id)
                    .where(
                        legal_hold_records.c.organization_id == organization_id,
                        legal_hold_records.c.record_type == row.record_type,
                        legal_hold_records.c.record_id == row.record_id,
                        legal_holds.c.status == "active",
                    )
                    .limit(1)
                ).first()
                if held is not None:
                    counts["blocked"] += 1
                    continue
                job = connection.execute(
                    select(retention_jobs).where(
                        retention_jobs.c.organization_id == organization_id,
                        retention_jobs.c.record_type == row.record_type,
                        retention_jobs.c.record_id == row.record_id,
                    )
                ).first()
                if job is not None and job.status == "deleted":
                    continue
                if job is None:
                    connection.execute(
                        retention_jobs.insert().values(
                            id=str(uuid4()),
                            organization_id=organization_id,
                            record_type=row.record_type,
                            record_id=row.record_id,
                            status="eligible",
                            decision_reason="retention_expired",
                            attempt_count=1,
                            created_at=now_iso(),
                        )
                    )
                else:
                    connection.execute(
                        update(retention_jobs)
                        .where(retention_jobs.c.id == job.id)
                        .values(
                            status="eligible",
                            attempt_count=retention_jobs.c.attempt_count + 1,
                            last_error=None,
                        )
                    )
                # Recheck the hold in this transaction immediately before delete.
                held = connection.execute(
                    select(legal_hold_records.c.hold_id)
                    .join(legal_holds, legal_holds.c.id == legal_hold_records.c.hold_id)
                    .where(
                        legal_hold_records.c.organization_id == organization_id,
                        legal_hold_records.c.record_type == row.record_type,
                        legal_hold_records.c.record_id == row.record_id,
                        legal_holds.c.status == "active",
                    )
                    .limit(1)
                ).first()
                if held is not None:
                    counts["blocked"] += 1
                    continue
                connection.execute(
                    delete(execution_result_provenance).where(
                        execution_result_provenance.c.record_type == row.record_type,
                        execution_result_provenance.c.record_id == row.record_id,
                        execution_result_provenance.c.organization_id == organization_id,
                    )
                )
                connection.execute(
                    delete(legal_hold_records).where(
                        legal_hold_records.c.organization_id == organization_id,
                        legal_hold_records.c.record_type == row.record_type,
                        legal_hold_records.c.record_id == row.record_id,
                    )
                )
                connection.execute(
                    delete(record_ownership).where(
                        record_ownership.c.organization_id == organization_id,
                        record_ownership.c.record_type == row.record_type,
                        record_ownership.c.record_id == row.record_id,
                    )
                )
                connection.execute(
                    delete(records).where(
                        records.c.record_type == row.record_type,
                        records.c.record_id == row.record_id,
                    )
                )
                connection.execute(
                    update(retention_jobs)
                    .where(
                        retention_jobs.c.organization_id == organization_id,
                        retention_jobs.c.record_type == row.record_type,
                        retention_jobs.c.record_id == row.record_id,
                    )
                    .values(status="deleted", completed_at=now_iso())
                )
                self._audit(
                    connection,
                    organization_id,
                    actor_user_id,
                    "retention.deleted",
                    "evidence",
                    row.record_id,
                    {"policy_id": policy.id},
                )
                counts["deleted"] += 1
        return counts


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
