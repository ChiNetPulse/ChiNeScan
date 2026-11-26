"""Phase 2D regression tests: durable worker leases, fencing, action boundary, and recovery."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import insert, select, text

from chinescan.core.accounts import create_operator
from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.execution_governance import ExecutionGovernanceService
from chinescan.core.organizations import OrganizationService
from chinescan.core.storage.recovery import backup_database, restore_backup, verify_backup
from chinescan.core.storage.sqlite import (
    SQLiteRepository,
    execution_action_attempts,
    execution_jobs,
    users,
    worker_leases,
)
from chinescan.web.app import create_app


def _seed_governed_job(
    tmp_path: Path,
    *,
    technique: str = "service_fingerprint",
) -> tuple[
    SQLiteRepository,
    OrganizationService,
    EngagementSecurityService,
    ExecutionGovernanceService,
    str,
    str,
    str,
    str,
]:
    db_path = tmp_path / "phase2d.sqlite3"
    repo = SQLiteRepository(db_path)
    orgs = OrganizationService(repo)
    sec = EngagementSecurityService(repo, orgs)
    gov = ExecutionGovernanceService(sec)
    op_user, org = orgs.ensure_operator(
        "op@example.test", "epoch-1", "11111111-1111-4111-8111-111111111111"
    )
    user_id = op_user["id"]
    org_id = org["id"]
    client = orgs.create_client(user_id, org_id, "Acme", "Phase 2D client")
    eng = orgs.create_engagement(
        user_id, org_id, client["id"], "Phase 2D Eng", "Phase 2D eng", "active"
    )
    eng_id = eng["id"]
    reviewer_id = "22222222-2222-4222-8222-222222222222"
    now = datetime.now(UTC)
    stamp = now.isoformat()
    with repo.engine.begin() as conn:
        conn.execute(
            insert(users).values(
                id=reviewer_id,
                email_normalized="reviewer@example.test",
                display_name="Reviewer",
                status="active",
                auth_epoch="epoch-r",
                created_at=stamp,
                updated_at=stamp,
            )
        )
    orgs.add_member(user_id, org_id, reviewer_id, "member")
    orgs.change_assignment(user_id, org_id, eng_id, reviewer_id, role="reviewer")
    asset = sec.create_asset(user_id, org_id, eng_id, "domain", "app.example.test")
    assert asset is not None
    rev = sec.create_scope_revision(
        user_id,
        org_id,
        eng_id,
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": [technique],
            }
        ],
        "Phase 2D scope",
    )
    assert rev is not None
    published = sec.publish_scope_revision(reviewer_id, org_id, eng_id, rev["id"])
    assert published is not None
    sec.create_authorization(
        user_id,
        org_id,
        eng_id,
        published["id"],
        "AUTH-2D",
        "Acme",
        [technique],
        (now - timedelta(minutes=5)).isoformat(),
        (now + timedelta(hours=2)).isoformat(),
    )
    job = gov.create_governed_job(
        user_id,
        org_id,
        eng_id,
        asset["id"],
        technique=technique,
        approval_id=None,
        idempotency_key=f"idem-{technique}",
    )
    return repo, orgs, sec, gov, user_id, org_id, eng_id, job["id"]


def test_atomic_concurrent_claim_with_independent_connections(tmp_path: Path) -> None:
    repo, _orgs, _sec, gov, _uid, _oid, _eid, job_id = _seed_governed_job(tmp_path)
    repo2 = SQLiteRepository(repo.path)
    try:
        gov2 = ExecutionGovernanceService(
            EngagementSecurityService(repo2, OrganizationService(repo2))
        )
        barrier = Barrier(2)

        def _claim(idx: int) -> dict | None:
            barrier.wait()
            service = gov if idx == 0 else gov2
            return service.claim_job(job_id, f"worker-{idx}", lease_duration_seconds=30.0)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(_claim, range(2)))

        winners = [r for r in results if r is not None]
        losers = [r for r in results if r is None]
        assert len(winners) == 1
        assert len(losers) == 1
        winner = winners[0]
        assert winner["lease_generation"] == 1
        assert winner["attempt_number"] == 1

        with repo.engine.connect() as conn:
            row = conn.execute(select(execution_jobs).where(execution_jobs.c.id == job_id)).first()
            assert row is not None
            assert row.worker_id == winner["worker_id"]
            assert row.lease_generation == 1
    finally:
        repo2.close()
        repo.close()


def test_lease_heartbeat_expiry_and_stale_worker_fencing(tmp_path: Path) -> None:
    repo, _orgs, _sec, gov, _uid, _oid, _eid, job_id = _seed_governed_job(tmp_path)
    try:
        t0 = 1_764_000_000.0
        claimed = gov.claim_job(job_id, "worker-a", lease_duration_seconds=10.0, now=t0)
        assert claimed is not None
        gen1 = claimed["lease_generation"]
        assert gov.revalidate_job(job_id, worker_id="worker-a", lease_generation=gen1, now=t0 + 1)

        # Wrong owner cannot heartbeat
        assert (
            gov.heartbeat_job(job_id, "worker-b", gen1, lease_duration_seconds=10.0, now=t0 + 2)
            is False
        )
        # Current owner can heartbeat before expiry
        assert (
            gov.heartbeat_job(job_id, "worker-a", gen1, lease_duration_seconds=10.0, now=t0 + 2)
            is True
        )

        # After expiry, renewal is rejected (never silently resurrected)
        assert (
            gov.heartbeat_job(job_id, "worker-a", gen1, lease_duration_seconds=10.0, now=t0 + 15)
            is False
        )

        # Safe recovery returns job to queued, preserving lease_generation=1
        recovered = gov.recover_stale_jobs(now=t0 + 15)
        assert recovered == [{"id": job_id, "outcome": "queued"}]

        # Worker B claims with lease_generation=2
        claimed2 = gov.claim_job(job_id, "worker-b", lease_duration_seconds=10.0, now=t0 + 16)
        assert claimed2 is not None
        assert claimed2["lease_generation"] == 2
        assert gov.revalidate_job(job_id, worker_id="worker-b", lease_generation=2, now=t0 + 16)

        # Stale worker-a (gen 1) is fenced out of all mutations
        assert (
            gov.revalidate_job(job_id, worker_id="worker-a", lease_generation=gen1, now=t0 + 17)
            is False
        )
        assert (
            gov.authorize_external_action(
                job_id,
                "app.example.test",
                "service_fingerprint",
                worker_id="worker-a",
                lease_generation=gen1,
                now=t0 + 17,
            )
            is False
        )
        assert (
            gov.finish_job(
                job_id, scan_id="fake", worker_id="worker-a", lease_generation=gen1, now=t0 + 17
            )
            is False
        )
        with repo.engine.connect() as conn:
            row = conn.execute(select(execution_jobs).where(execution_jobs.c.id == job_id)).first()
            assert row is not None
            assert row.status == "running"
            assert row.worker_id == "worker-b"
            assert row.lease_generation == 2
    finally:
        repo.close()


def test_crash_recovery_separates_safe_retry_from_uncertain_external_actions(
    tmp_path: Path,
) -> None:
    # 1. Crash after authorization but before dispatch -> safe retry
    repo, _orgs, _sec, gov, _uid, _oid, _eid, job_id = _seed_governed_job(tmp_path)
    try:
        t0 = 1_764_000_000.0
        c1 = gov.claim_job(job_id, "worker-1", lease_duration_seconds=10.0, now=t0)
        assert c1 is not None
        assert gov.revalidate_job(job_id, worker_id="worker-1", lease_generation=1, now=t0 + 1)
        assert gov.authorize_external_action(
            job_id,
            "app.example.test",
            "service_fingerprint",
            worker_id="worker-1",
            lease_generation=1,
            now=t0 + 1,
        )
        # Crash before mark_action_in_progress
        rec1 = gov.recover_stale_jobs(now=t0 + 20)
        assert rec1 == [{"id": job_id, "outcome": "queued"}]
        # Idempotent second recovery pass does nothing
        assert gov.recover_stale_jobs(now=t0 + 21) == []
        attempt1 = gov.latest_action_attempt(job_id)
        assert attempt1 is not None
        assert attempt1["state"] == "failed_before_dispatch"

        # 2. Worker 2 claims, starts external action (in_progress),
        #    and crashes -> reconciliation_required
        c2 = gov.claim_job(job_id, "worker-2", lease_duration_seconds=10.0, now=t0 + 22)
        assert c2 is not None and c2["lease_generation"] == 2
        assert gov.revalidate_job(job_id, worker_id="worker-2", lease_generation=2, now=t0 + 22)
        assert gov.authorize_external_action(
            job_id,
            "app.example.test",
            "service_fingerprint",
            worker_id="worker-2",
            lease_generation=2,
            now=t0 + 22,
        )
        assert gov.mark_action_in_progress(
            job_id, worker_id="worker-2", lease_generation=2, now=t0 + 22
        )
        rec2 = gov.recover_stale_jobs(now=t0 + 40)
        assert rec2 == [{"id": job_id, "outcome": "reconciliation_required"}]
        assert gov.recover_stale_jobs(now=t0 + 41) == []

        with repo.engine.connect() as conn:
            job_row = conn.execute(
                select(execution_jobs).where(execution_jobs.c.id == job_id)
            ).first()
            assert job_row is not None
            assert job_row.status == "reconciliation_required"
            assert job_row.error_code == "EXTERNAL_OUTCOME_UNCERTAIN"
        attempt2 = gov.latest_action_attempt(job_id)
        assert attempt2 is not None
        assert attempt2["state"] == "outcome_uncertain"

        # Backup and restore preserves reconciliation_required and action history
        bundle = tmp_path / "backup-bundle"
        assert backup_database(repo.path, bundle).verification.verified
        assert verify_backup(bundle).migration_revision == "0015_durable_job_leases_actions"
        restored_db = tmp_path / "restored.sqlite3"
        restored = restore_backup(bundle, restored_db)
        assert restored.resulting_revision == "0015_durable_job_leases_actions"
        restored_repo = SQLiteRepository(restored_db)
        try:
            with restored_repo.engine.connect() as rconn:
                rjob = rconn.execute(
                    select(execution_jobs).where(execution_jobs.c.id == job_id)
                ).first()
                assert rjob is not None
                assert rjob.status == "reconciliation_required"
                rattempts = rconn.execute(
                    select(execution_action_attempts).where(
                        execution_action_attempts.c.job_id == job_id
                    )
                ).all()
                assert len(rattempts) == 2
        finally:
            restored_repo.close()
    finally:
        repo.close()


def test_reconciliation_is_authorized_audited_and_requires_evidence(tmp_path: Path) -> None:
    repo, _orgs, _sec, gov, operator_id, org_id, eng_id, job_id = _seed_governed_job(tmp_path)
    try:
        claimed = gov.claim_job(job_id, "worker-reconcile", lease_duration_seconds=5.0, now=100.0)
        assert claimed is not None
        generation = int(claimed["lease_generation"])
        assert gov.revalidate_job(
            job_id, worker_id="worker-reconcile", lease_generation=generation, now=100.0
        )
        assert gov.authorize_external_action(
            job_id,
            "app.example.test",
            "service_fingerprint",
            worker_id="worker-reconcile",
            lease_generation=generation,
            now=100.0,
        )
        assert gov.mark_action_in_progress(
            job_id, worker_id="worker-reconcile", lease_generation=generation, now=100.0
        )
        assert gov.recover_stale_jobs(now=200.0) == [
            {"id": job_id, "outcome": "reconciliation_required"}
        ]

        unresolved = gov.list_reconciliation_jobs(operator_id, org_id, eng_id)
        assert unresolved is not None and len(unresolved) == 1
        assert unresolved[0]["error_code"] == "EXTERNAL_OUTCOME_UNCERTAIN"
        assert unresolved[0]["attempt"]["state"] == "outcome_uncertain"

        # The seeded reviewer assignment is read-only and cannot resolve an action.
        forbidden = gov.resolve_reconciliation(
            "22222222-2222-4222-8222-222222222222",
            org_id,
            eng_id,
            job_id,
            resolution="confirmed_success",
            evidence_reference="ticket:unauthorized",
        )
        assert forbidden == {"outcome": "forbidden"}

        resolved = gov.resolve_reconciliation(
            operator_id,
            org_id,
            eng_id,
            job_id,
            resolution="confirmed_success",
            evidence_reference="ticket:reconcile-001",
        )
        assert resolved is not None and resolved["outcome"] == "resolved"
        assert resolved["resolution"] == "confirmed_success"
        with repo.engine.connect() as connection:
            job = connection.execute(
                select(execution_jobs).where(execution_jobs.c.id == job_id)
            ).one()
            attempt = connection.execute(
                select(execution_action_attempts).where(
                    execution_action_attempts.c.job_id == job_id
                )
            ).one()
        assert job.status == "completed"
        assert attempt.state == "completed"
        assert attempt.result_reference == "ticket:reconcile-001"
        assert attempt.outcome_classification == "manually_confirmed_success"
    finally:
        repo.close()


def test_action_attempt_immutability_and_duplicate_action_blocked(tmp_path: Path) -> None:
    repo, _orgs, _sec, gov, _uid, _oid, _eid, job_id = _seed_governed_job(tmp_path)
    try:
        t0 = 1_764_000_000.0
        assert gov.claim_job(job_id, "worker-1", lease_duration_seconds=30.0, now=t0) is not None
        assert gov.revalidate_job(job_id, worker_id="worker-1", lease_generation=1, now=t0)
        assert gov.authorize_external_action(
            job_id,
            "app.example.test",
            "service_fingerprint",
            worker_id="worker-1",
            lease_generation=1,
            now=t0,
        )
        assert gov.mark_action_in_progress(job_id, worker_id="worker-1", lease_generation=1, now=t0)

        # Action request_digest is immutable via SQLite trigger
        with pytest.raises(Exception, match="immutable"):
            with repo.engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execution_action_attempts "
                        "SET request_digest = 'tampered' WHERE job_id = :jid"
                    ),
                    {"jid": job_id},
                )

        # A different lease generation cannot authorize a duplicate action
        assert (
            gov.authorize_external_action(
                job_id,
                "app.example.test",
                "service_fingerprint",
                worker_id="worker-1",
                lease_generation=99,
                now=t0,
            )
            is False
        )
    finally:
        repo.close()


def test_cancellation_during_in_progress_preserves_uncertainty_and_worker_shutdown(
    tmp_path: Path,
) -> None:
    repo, _orgs, _sec, gov, uid, oid, eid, job_id = _seed_governed_job(tmp_path)
    try:
        t0 = 1_764_000_000.0
        assert gov.claim_job(job_id, "worker-1", lease_duration_seconds=30.0, now=t0) is not None
        assert gov.revalidate_job(job_id, worker_id="worker-1", lease_generation=1, now=t0)
        assert gov.authorize_external_action(
            job_id,
            "app.example.test",
            "service_fingerprint",
            worker_id="worker-1",
            lease_generation=1,
            now=t0,
        )
        assert gov.mark_action_in_progress(job_id, worker_id="worker-1", lease_generation=1, now=t0)

        req = gov.request_cancellation(uid, oid, eid, job_id)
        assert req is not None and req["outcome"] == "requested"
        assert gov.observe_cancellation(job_id, worker_id="worker-1", lease_generation=1) is True
        with repo.engine.connect() as conn:
            row = conn.execute(select(execution_jobs).where(execution_jobs.c.id == job_id)).first()
            assert row is not None
            assert row.status == "reconciliation_required"
            assert row.error_code == "CANCELLATION_OUTCOME_UNCERTAIN"
    finally:
        repo.close()

    # Standalone worker option in create_app does not auto-start background thread
    cred = tmp_path / "operator.json"
    create_operator(cred, "operator@example.test", "Operator-Secure-Passphrase-99!")
    app = create_app(
        tmp_path / "web.sqlite3", cred, serve_frontend=False, start_governed_worker=False
    )
    try:
        worker = app.state.governed_domain_worker
        assert worker._thread is None
        worker.start()
        assert worker._thread is not None
        worker.stop(grace_seconds=2.0)
        with app.state.repository.engine.connect() as conn:
            lease = conn.execute(
                select(worker_leases).where(worker_leases.c.worker_id == worker.worker_id)
            ).first()
            assert lease is not None
            assert lease.status == "stopped"
    finally:
        app.state.repository.close()
