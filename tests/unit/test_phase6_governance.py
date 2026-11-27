from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from chinescan.core.phase6_governance import (
    EvidenceLifecycleService,
    Phase6PolicyError,
    probe_capabilities,
    validate_transition,
)
from chinescan.core.storage.sqlite import organizations


def test_execution_state_machine_rejects_unsafe_retry() -> None:
    validate_transition("running", "outcome_uncertain")
    validate_transition("outcome_uncertain", "reconciliation_required")
    try:
        validate_transition("outcome_uncertain", "queued")
    except Phase6PolicyError:
        pass
    else:
        raise AssertionError("uncertain external work must not be automatically retried")


def test_capability_probe_never_claims_unverified_controls() -> None:
    snapshot = probe_capabilities()
    assert set(snapshot.enforced_controls).isdisjoint(snapshot.unavailable_controls)
    assert snapshot.hardened is False
    assert all(not item.verified or item.enforced for item in snapshot.capabilities)
    assert all(not item.initialized or item.runtime_available for item in snapshot.capabilities)
    assert "network_egress_policy" in snapshot.unavailable_controls or snapshot.platform not in {
        "linux",
        "win32",
    }


def test_active_hold_blocks_retention_until_release(repository) -> None:
    organization_id = repository._local_operator_organization_id
    assert organization_id is not None
    with repository.engine.connect() as connection:
        actor_id = connection.execute(
            select(organizations.c.owner_user_id).where(organizations.c.id == organization_id)
        ).scalar_one()
    record_id = "phase6-evidence"
    old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    repository.save(
        "evidence",
        record_id,
        {"evidence_type": "scanner.raw", "ingested_at": old, "content_sha256": "a" * 64},
    )
    service = EvidenceLifecycleService(repository)
    service.create_policy(organization_id, actor_id, 1)
    hold_id = service.create_hold(
        organization_id, actor_id, [("evidence", record_id)], "active investigation"
    )
    result = service.run_once(organization_id, actor_id)
    assert result["blocked"] == 1
    assert repository.get("evidence", record_id) is not None
    assert service.release_hold(organization_id, actor_id, hold_id)
    result = service.run_once(organization_id, actor_id)
    assert result["deleted"] == 1
    assert repository.get("evidence", record_id) is None
