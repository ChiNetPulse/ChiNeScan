"""Phase 2E acceptance closure tests: shutdown safety, accounting, and limit enforcement."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import insert, select

from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.execution_adapters import (
    AdapterCapabilities,
    AdapterRegistry,
    AdapterResult,
    RepositoryCodeAssessmentAdapter,
)
from chinescan.core.execution_governance import (
    ExecutionGovernanceService,
    GovernedDomainWorker,
)
from chinescan.core.organizations import OrganizationService
from chinescan.core.repository_assessment import (
    ATTESTATION_TEXT,
    REPOSITORY_TECHNIQUE,
    RepositorySnapshotStore,
)
from chinescan.core.resource_governance import ResourceLimitError, ResourceLimits
from chinescan.core.storage.sqlite import (
    SQLiteRepository,
    users,
    worker_leases,
)


def _seed(tmp_path: Path, *, limits: ResourceLimits | None = None, registry: AdapterRegistry | None = None):
    repo = SQLiteRepository(tmp_path / "closure.sqlite3")
    orgs = OrganizationService(repo)
    sec = EngagementSecurityService(repo, orgs)
    gov = ExecutionGovernanceService(sec, adapters=registry, resource_limits=limits)
    op_user, org = orgs.ensure_operator(
        "op@example.test", "epoch-1", "11111111-1111-4111-8111-111111111111"
    )
    uid = op_user["id"]
    oid = org["id"]
    client = orgs.create_client(uid, oid, "Closure", "Phase 2E closure")
    eng = orgs.create_engagement(uid, oid, client["id"], "Closure Eng", "desc", "active")
    eid = eng["id"]
    rev_id = "22222222-2222-4222-8222-222222222222"
    stamp = datetime.now(UTC).isoformat()
    with repo.engine.begin() as conn:
        conn.execute(
            insert(users).values(
                id=rev_id,
                email_normalized="rev@example.test",
                display_name="Reviewer",
                status="active",
                auth_epoch="epoch-r",
                created_at=stamp,
                updated_at=stamp,
            )
        )
    orgs.add_member(uid, oid, rev_id, "member")
    orgs.change_assignment(uid, oid, eid, rev_id, role="reviewer")
    asset = sec.create_asset(uid, oid, eid, "domain", "app.example.test")
    assert asset is not None
    rev = sec.create_scope_revision(
        uid,
        oid,
        eid,
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": ["service_fingerprint", "exploit_verification"],
            }
        ],
        "scope",
    )
    assert rev is not None
    pub = sec.publish_scope_revision(rev_id, oid, eid, rev["id"])
    assert pub is not None
    now = datetime.now(UTC)
    sec.create_authorization(
        uid,
        oid,
        eid,
        pub["id"],
        "AUTH-2E",
        "Closure",
        ["service_fingerprint", "exploit_verification"],
        (now - timedelta(minutes=5)).isoformat(),
        (now + timedelta(hours=2)).isoformat(),
    )
    return repo, orgs, sec, gov, uid, rev_id, oid, eid, asset["id"]


def test_worker_shutdown_preserves_lease_when_thread_stuck_and_fences_stale_worker(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release_stuck = threading.Event()

    class StuckInProgressAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.stuck-inprogress",
            techniques=("service_fingerprint",),
            target_types=("domain",),
            action_class="controlled_active",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, context, _parameters, control) -> AdapterResult:
            control.authorize_external_action(context.target, context.technique)
            entered.set()
            release_stuck.wait(timeout=10)
            return AdapterResult(adapter_id="test.stuck-inprogress", status="complete", summary={})

    registry = AdapterRegistry((StuckInProgressAdapter(),))
    repo, _orgs, _sec, gov, uid, _rid, oid, eid, aid = _seed(tmp_path, registry=registry)
    try:
        # 1. Shutdown with no active job unregisters lease cleanly
        idle_worker = GovernedDomainWorker(repo, gov, registry, worker_id="idle-w")
        idle_worker.start()
        idle_worker.stop(grace_seconds=0.5)
        with repo.engine.connect() as conn:
            lease = conn.execute(
                select(worker_leases.c.status).where(worker_leases.c.worker_id == "idle-w")
            ).scalar_one()
        assert lease == "stopped"

        # 2. Shutdown while action is in_progress and thread does NOT exit within grace period
        job = gov.create_domain_job(uid, oid, eid, aid, approval_id=None, idempotency_key="stuck-1")
        stuck_worker = GovernedDomainWorker(
            repo,
            gov,
            registry,
            worker_id="stuck-w",
            lease_duration_seconds=5.0,
            heartbeat_interval_seconds=1.0,
            shutdown_grace_seconds=0.1,
        )
        stuck_worker.start()
        assert entered.wait(timeout=5)
        stuck_worker.stop(grace_seconds=0.1)

        # Lease MUST remain 'stopping' (NOT 'stopped') while worker thread is still alive
        with repo.engine.connect() as conn:
            stuck_status = conn.execute(
                select(worker_leases.c.status).where(worker_leases.c.worker_id == "stuck-w")
            ).scalar_one()
        assert stuck_status == "stopping"

        # Stale-worker recovery before lease expiry MUST NOT release the job prematurely
        assert gov.recover_stale_jobs(now=time.time() - 100.0) == []

        # Once lease expires, recovery marks uncertain action reconciliation_required
        rec = gov.recover_stale_jobs(now=time.time() + 60.0)
        assert rec == [{"id": job["id"], "outcome": "reconciliation_required"}]

        # Old worker (lease_generation=1) is fenced from mutating durable state
        assert (
            gov.finish_job(
                job["id"], scan_id=None, failed=False, worker_id="stuck-w", lease_generation=1
            )
            is False
        )
        assert (
            gov.authorize_external_action(
                job["id"], "app.example.test", "service_fingerprint", worker_id="stuck-w", lease_generation=1
            )
            is False
        )
    finally:
        release_stuck.set()
        repo.close()


def test_durable_resource_accounting_release_and_concurrent_recovery(tmp_path: Path) -> None:
    limits = ResourceLimits(
        per_org_active_limit=1,
        global_active_limit=2,
        per_org_queued_limit=2,
        global_queued_limit=4,
    )
    repo, _orgs, _sec, gov, uid, _rid, oid, eid, aid = _seed(tmp_path, limits=limits)
    try:
        # Fill org queue (2)
        j1 = gov.create_domain_job(uid, oid, eid, aid, approval_id=None, idempotency_key="acc-0001")
        j2 = gov.create_domain_job(uid, oid, eid, aid, approval_id=None, idempotency_key="acc-0002")

        # Complete j1 -> releases 1 slot
        c1 = gov.claim_job(j1["id"], "w-acc")
        assert c1 is not None and gov.revalidate_job(j1["id"], worker_id="w-acc", lease_generation=1)
        assert gov.finish_job(j1["id"], scan_id=None, worker_id="w-acc", lease_generation=1)

        # Fail j2 -> releases 2nd slot
        c2 = gov.claim_job(j2["id"], "w-acc")
        assert c2 is not None and gov.revalidate_job(j2["id"], worker_id="w-acc", lease_generation=1)
        assert gov.finish_job(j2["id"], scan_id=None, failed=True, error_code="E", worker_id="w-acc", lease_generation=1)

        # Cancel j3 safely before execution -> releases slot
        j3 = gov.create_domain_job(uid, oid, eid, aid, approval_id=None, idempotency_key="acc-0003")
        cancel_res = gov.request_cancellation(uid, oid, eid, j3["id"])
        assert cancel_res is not None and cancel_res["outcome"] == "completed"
        assert cancel_res["job"]["status"] == "cancelled"
        assert gov.get_organization_resource_usage(uid, oid)["total_reserved_jobs"] == 0

        # Crash + expired lease recovery + concurrent admission cannot exceed per_org_queued_limit=2
        j4 = gov.create_domain_job(uid, oid, eid, aid, approval_id=None, idempotency_key="acc-0004")
        assert gov.claim_job(j4["id"], "w-crash", lease_duration_seconds=5.0, now=100.0) is not None

        def run_recovery() -> list[dict]:
            return gov.recover_stale_jobs(now=200.0)

        def admit(idx: int) -> str:
            try:
                return gov.create_domain_job(
                    uid, oid, eid, aid, approval_id=None, idempotency_key=f"conc-admit-{idx}"
                )["id"]
            except ResourceLimitError as exc:
                return f"rejected:{exc.code}"

        with ThreadPoolExecutor(max_workers=4) as pool:
            f_rec = pool.submit(run_recovery)
            f_ads = [pool.submit(admit, i) for i in range(3)]
            f_rec.result()
            outcomes = [f.result() for f in f_ads]
        # j4 remains reserved (re-queued), so at most 1 of the 3 concurrent admissions can succeed
        admitted = [x for x in outcomes if not x.startswith("rejected:")]
        assert len(admitted) == 1
        assert gov.get_organization_resource_usage(uid, oid)["total_reserved_jobs"] == 2
    finally:
        repo.close()


def test_max_findings_per_job_enforced_by_repository_adapter(tmp_path: Path) -> None:
    from chinescan.web.app import create_app
    from chinescan.web.auth import create_operator

    snap_dir = tmp_path / "repo_src"
    snap_dir.mkdir()
    sample_api_key = "".join(("sk", "_live_", "1234567890abcdef1234567890"))
    (snap_dir / "app.py").write_text(
        "\n".join(
            [
                "eval(user_input)",
                "exec(user_input)",
                f"API_KEY = '{sample_api_key}'",
                "PASSWORD = 'super_secret_password_value_12345'",
                "subprocess.run('ls', shell=True)",
            ]
        ),
        encoding="utf-8",
    )
    cred = tmp_path / "operator.json"
    create_operator(cred, "op@example.test", "Operator-Secure-Passphrase-99!")
    app = create_app(
        tmp_path / "cap.sqlite3",
        cred,
        serve_frontend=False,
        start_governed_worker=False,
    )
    try:
        repo = app.state.repository
        orgs = app.state.organization_service
        sec = app.state.engagement_security_service
        ras = app.state.repository_assessment_service
        uid = orgs.operator_user_id
        oid = orgs.accessible_organizations(uid)[0]["id"]
        client = orgs.create_client(uid, oid, "Cap", "Cap")
        eng = orgs.create_engagement(uid, oid, client["id"], "Cap Eng", "desc", "active")
        eid = eng["id"]
        rev_id = "22222222-2222-4222-8222-222222222222"
        stamp = datetime.now(UTC).isoformat()
        with repo.engine.begin() as conn:
            conn.execute(
                insert(users).values(
                    id=rev_id,
                    email_normalized="r@example.test",
                    display_name="Rev",
                    status="active",
                    auth_epoch="e",
                    created_at=stamp,
                    updated_at=stamp,
                )
            )
        orgs.add_member(uid, oid, rev_id, "member")
        orgs.change_assignment(uid, oid, eid, rev_id, role="reviewer")
        with repo.local_operator_context():
            project = app.state.project_service.create("Cap source", snap_dir)
        asset = ras.create_asset(uid, oid, eid, "Cap source")
        assert asset is not None
        scope = sec.create_scope_revision(
            uid,
            oid,
            eid,
            [
                {
                    "asset_id": asset["id"],
                    "effect": "include",
                    "match_mode": "exact",
                    "techniques": [REPOSITORY_TECHNIQUE],
                }
            ],
            "scope",
        )
        assert scope is not None
        pub = sec.publish_scope_revision(rev_id, oid, eid, scope["id"])
        assert pub is not None
        now = datetime.now(UTC)
        auth = sec.create_authorization(
            uid,
            oid,
            eid,
            pub["id"],
            "AUTH-CAP",
            "Cap",
            [REPOSITORY_TECHNIQUE],
            (now - timedelta(minutes=5)).isoformat(),
            (now + timedelta(hours=2)).isoformat(),
        )
        assert auth is not None
        bound = ras.bind(
            uid,
            oid,
            eid,
            asset["id"],
            project["project_id"],
            auth["id"],
            pub["id"],
            ATTESTATION_TEXT,
        )
        assert bound is not None
        gov = app.state.execution_governance
        gov.resource_limits = ResourceLimits(max_findings_per_job=2)
        job = gov.create_governed_job(
            uid,
            oid,
            eid,
            asset["id"],
            technique=REPOSITORY_TECHNIQUE,
            approval_id=None,
            idempotency_key="cap-findings-0001",
            repository_binding_id=bound["binding_id"],
            repository_attestation_id=bound["attestation_id"],
        )
        assert "id" in job, f"Job denied: {job}"
        res = app.state.governed_domain_worker.run_one(job["id"])
        assert res is not None
        assert res["result"]["finding_count"] <= 2
        assert res["status"] == "failed"  # partial scan -> ADAPTER_PARTIAL_RESULT
    finally:
        app.state.repository.close()
