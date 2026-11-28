from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from chinescan.core.accounts import Session
from chinescan.core.phase6_governance import (
    Capability,
    CapabilitySnapshot,
    EvidenceLifecycleService,
    Phase6PolicyError,
    _parse_time,
    persist_capability_snapshot,
    probe_capabilities,
    require_profile,
    validate_transition,
)
from chinescan.core.storage.sqlite import (
    execution_capability_snapshots,
    organizations,
    retention_jobs,
)
from chinescan.web.phase6_api import create_phase6_router


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


def test_retention_service_lists_audit_and_handles_eligibility_edges(repository) -> None:
    organization_id = repository._local_operator_organization_id
    assert organization_id is not None
    with repository.engine.connect() as connection:
        actor_id = connection.execute(
            select(organizations.c.owner_user_id).where(organizations.c.id == organization_id)
        ).scalar_one()
    service = EvidenceLifecycleService(repository)

    with pytest.raises(Phase6PolicyError, match="retention_days"):
        service.create_policy(organization_id, actor_id, 0)
    with pytest.raises(Phase6PolicyError, match="retention limit"):
        service.run_once(organization_id, actor_id, limit=0)
    with pytest.raises(Phase6PolicyError, match="reason"):
        service.create_hold(organization_id, actor_id, [], "")

    policy_id = service.create_policy(organization_id, actor_id, 1, evidence_category="scanner.raw")
    assert service.list_policies(organization_id, actor_id)[0]["id"] == policy_id
    assert service.list_holds(organization_id, actor_id) == []
    assert service.list_retention_jobs(organization_id, actor_id) == []
    assert len(service.list_audit(organization_id, actor_id)) == 1

    repository.save(
        "evidence",
        "no-policy",
        {"evidence_type": "other.category", "ingested_at": "not-a-timestamp"},
    )
    assert service.run_once(organization_id, actor_id)["skipped"] == 1


def test_capability_profiles_and_snapshot_persistence(repository) -> None:
    organization_id = repository._local_operator_organization_id
    assert organization_id is not None

    with pytest.raises(Phase6PolicyError, match="unknown execution profile"):
        require_profile("unknown")
    with pytest.raises(Phase6PolicyError, match="unknown execution state"):
        validate_transition("nonexistent", "queued")

    unhardened = CapabilitySnapshot(
        platform="linux",
        profile="restricted",
        policy_version="phase6-1",
        capabilities=(Capability("seccomp", True, True, False, "unverified"),),
        execution_identity=None,
    )
    with pytest.raises(Phase6PolicyError, match="mandatory isolation controls"):
        require_profile("hardened", unhardened)
    assert require_profile("restricted", unhardened) is unhardened

    unavail_id = persist_capability_snapshot(
        repository, organization_id, profile="restricted", snapshot=unhardened
    )
    hardened = CapabilitySnapshot(
        platform="linux",
        profile="hardened",
        policy_version="phase6-1",
        capabilities=(Capability("seccomp", True, True, True, None, True, True),),
        execution_identity="worker-1",
    )
    init_id = persist_capability_snapshot(
        repository, organization_id, profile="hardened", snapshot=hardened
    )

    with repository.engine.connect() as connection:
        rows = {
            row.id: row
            for row in connection.execute(
                select(execution_capability_snapshots).where(
                    execution_capability_snapshots.c.id.in_([unavail_id, init_id])
                )
            ).mappings()
        }
    assert rows[unavail_id]["initialization_status"] == "unavailable"
    assert rows[unavail_id]["failure_reason"] == "mandatory_controls_unavailable"
    assert rows[init_id]["initialization_status"] == "initialized"
    assert rows[init_id]["failure_reason"] is None


def test_retention_hold_and_retry_edges(repository) -> None:
    organization_id = repository._local_operator_organization_id
    assert organization_id is not None
    with repository.engine.connect() as connection:
        actor_id = connection.execute(
            select(organizations.c.owner_user_id).where(organizations.c.id == organization_id)
        ).scalar_one()

    service = EvidenceLifecycleService(repository)
    service.create_policy(organization_id, actor_id, 7)

    with pytest.raises(Phase6PolicyError, match="outside the organization"):
        service.create_hold(organization_id, actor_id, [("evidence", "missing-id")], "audit")
    assert service.release_hold(organization_id, actor_id, "missing-hold") is False

    fresh_id = "fresh-evidence"
    repository.save(
        "evidence",
        fresh_id,
        {"evidence_type": "scanner.raw", "ingested_at": datetime.now(UTC).isoformat()},
    )
    hold_id = service.create_hold(
        organization_id, actor_id, [("evidence", fresh_id)], "active review"
    )
    holds = service.list_holds(organization_id, actor_id)
    assert len(holds) == 1
    assert holds[0]["id"] == hold_id
    assert holds[0]["record_count"] == 1
    assert service.run_once(organization_id, actor_id) == {"deleted": 0, "blocked": 0, "skipped": 0}
    assert service.release_hold(organization_id, actor_id, hold_id) is True

    retry_id = "retry-evidence"
    old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    repository.save("evidence", retry_id, {"evidence_type": "scanner.raw", "ingested_at": old})
    with repository.engine.begin() as connection:
        connection.execute(
            retention_jobs.insert().values(
                id="preexisting-eligible-job",
                organization_id=organization_id,
                record_type="evidence",
                record_id=retry_id,
                status="eligible",
                decision_reason="retention_expired",
                attempt_count=1,
                created_at=old,
            )
        )
    assert service.run_once(organization_id, actor_id)["deleted"] == 1
    jobs = {j["record_id"]: j for j in service.list_retention_jobs(organization_id, actor_id)}
    assert jobs[retry_id]["attempt_count"] == 2
    assert jobs[retry_id]["status"] == "deleted"
    assert _parse_time(123) is None
    assert _parse_time("not-iso") is None


def test_phase6_api_error_paths(repository) -> None:
    organization_id = repository._local_operator_organization_id
    assert organization_id is not None
    with repository.engine.connect() as connection:
        actor_id = connection.execute(
            select(organizations.c.owner_user_id).where(organizations.c.id == organization_id)
        ).scalar_one()

    current_user: dict[str, str] = {"user_id": actor_id}

    def current_session() -> Session:
        return Session(
            email="operator@local.test",
            csrf_token="csrf",
            expires_at=9999999999,
            auth_epoch=1,
            user_id=current_user["user_id"],
            created_at=1,
            last_seen_at=1,
        )

    app = FastAPI()
    app.include_router(create_phase6_router(repository, current_session, lambda: None))
    client = TestClient(app)

    assert client.get(f"/api/organizations/{organization_id}/phase6/status").status_code == 200
    for path in (
        "status",
        "retention/policies",
        "legal-holds",
        "retention/jobs",
        "retention/audit",
    ):
        resp = client.get(f"/api/organizations/00000000-0000-0000-0000-000000000000/phase6/{path}")
        assert resp.status_code == 404

    bad_hold = client.post(
        f"/api/organizations/{organization_id}/phase6/legal-holds",
        json={"reason": "audit", "records": [["evidence", "missing-id"]]},
    )
    assert bad_hold.status_code == 422

    missing_release = client.post(
        f"/api/organizations/{organization_id}/phase6/legal-holds/missing-hold/release"
    )
    assert missing_release.status_code == 404

    policy_resp = client.post(
        f"/api/organizations/{organization_id}/phase6/retention/policies",
        json={"retention_days": 30},
    )
    assert policy_resp.status_code == 201
    assert "id" in policy_resp.json()

    repository.save(
        "evidence",
        "api-hold-evidence",
        {"evidence_type": "scanner.raw", "ingested_at": datetime.now(UTC).isoformat()},
    )
    hold_resp = client.post(
        f"/api/organizations/{organization_id}/phase6/legal-holds",
        json={"reason": "api hold", "records": [["evidence", "api-hold-evidence"]]},
    )
    assert hold_resp.status_code == 201
    hold_id = hold_resp.json()["id"]
    rel_resp = client.post(
        f"/api/organizations/{organization_id}/phase6/legal-holds/{hold_id}/release"
    )
    assert rel_resp.status_code == 200
    assert rel_resp.json()["status"] == "released"

    current_user["user_id"] = ""
    unauth = client.get(f"/api/organizations/{organization_id}/phase6/status")
    assert unauth.status_code == 401
