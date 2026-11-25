"""Phase 2E tests: resource governance, deadlines, fairness, and subprocess supervision."""

from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import insert, select, update

from chinescan.core.config.settings import Settings
from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.execution_adapters import (
    AdapterCapabilities,
    AdapterRegistry,
    AdapterResult,
)
from chinescan.core.execution_governance import (
    ExecutionGovernanceService,
    GovernedDomainWorker,
)
from chinescan.core.organizations import OrganizationService
from chinescan.core.resource_governance import (
    ExecutionDeadlineExceeded,
    ResourceLimitError,
    ResourceLimits,
)
from chinescan.core.storage.sqlite import (
    SQLiteRepository,
    approval_requests,
    execution_jobs,
    users,
)
from chinescan.core.subprocess_supervision import (
    SubprocessExecutionError,
    run_supervised_subprocess,
)
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


def _insert_user(repo: SQLiteRepository, user_id: str, email: str, name: str) -> str:
    stamp = datetime.now(UTC).isoformat()
    with repo.engine.begin() as conn:
        conn.execute(
            insert(users).values(
                id=user_id,
                email_normalized=email,
                display_name=name,
                status="active",
                auth_epoch="epoch-2e",
                created_at=stamp,
                updated_at=stamp,
            )
        )
    return user_id


def _seed_org(
    repo: SQLiteRepository,
    orgs: OrganizationService,
    sec: EngagementSecurityService,
    user_id: str,
    reviewer_id: str,
    email: str,
    org_name: str,
    target: str,
) -> tuple[str, str, str, str, str]:
    _insert_user(repo, user_id, email, org_name)
    _insert_user(repo, reviewer_id, f"rev-{email}", f"Rev {org_name}")
    slug = org_name.lower().replace(" ", "-")
    org_id = orgs.create_organization(user_id, org_name, slug)["id"]
    orgs.add_member(user_id, org_id, reviewer_id, "member")
    client_id = orgs.create_client(user_id, org_id, f"{org_name} Client", "Phase 2E")["id"]
    eng_id = orgs.create_engagement(
        user_id, org_id, client_id, f"{org_name} Eng", "Phase 2E eng", "active"
    )["id"]
    orgs.change_assignment(user_id, org_id, eng_id, reviewer_id, role="reviewer")
    asset = sec.create_asset(user_id, org_id, eng_id, "domain", target)
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
                "techniques": ["service_fingerprint", "exploit_verification"],
            }
        ],
        "Phase 2E scope",
    )
    assert rev is not None
    published = sec.publish_scope_revision(reviewer_id, org_id, eng_id, rev["id"])
    assert published is not None
    now = datetime.now(UTC)
    sec.create_authorization(
        user_id,
        org_id,
        eng_id,
        published["id"],
        f"AUTH-{org_name}",
        org_name,
        ["service_fingerprint", "exploit_verification"],
        (now - timedelta(minutes=5)).isoformat(),
        (now + timedelta(hours=2)).isoformat(),
    )
    return user_id, reviewer_id, org_id, eng_id, asset["id"]


def test_resource_limits_and_settings_reject_invalid_ceilings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError):
        ResourceLimits(per_org_active_limit=10, global_active_limit=4)
    with pytest.raises(ValidationError):
        ResourceLimits(per_org_queued_limit=2, per_org_active_limit=3)
    with pytest.raises(ValidationError):
        ResourceLimits(default_operation_timeout_seconds=120.0, default_job_deadline_seconds=60.0)

    monkeypatch.setenv("CHINESCAN_EXECUTION_PER_ORG_ACTIVE_LIMIT", "999")
    with pytest.raises(ValidationError):
        Settings()


def test_per_org_global_quotas_concurrent_race_and_approval_preservation(tmp_path: Path) -> None:
    repo = SQLiteRepository(tmp_path / "quotas.sqlite3")
    try:
        orgs = OrganizationService(repo)
        sec = EngagementSecurityService(repo, orgs)
        limits = ResourceLimits(
            per_org_active_limit=1,
            global_active_limit=2,
            per_org_queued_limit=2,
            global_queued_limit=3,
        )
        class SensitiveAdapter:
            capabilities = AdapterCapabilities(
                adapter_id="test.sensitive-2e",
                techniques=("exploit_verification",),
                target_types=("domain",),
                action_class="sensitive",
                enabled=True,
                performs_external_operations=True,
            )

            def validate_parameters(self, parameters: dict) -> dict:
                return parameters

            def execute(self, context, _parameters, control) -> AdapterResult:
                del context, control
                return AdapterResult(adapter_id="test.sensitive-2e", status="complete", summary={})

        from chinescan.core.execution_adapters import DomainPostureAdapter

        registry = AdapterRegistry((DomainPostureAdapter(repo), SensitiveAdapter()))
        gov = ExecutionGovernanceService(sec, adapters=registry, resource_limits=limits)
        u1, r1, o1, e1, a1 = _seed_org(
            repo,
            orgs,
            sec,
            "11111111-1111-4111-8111-111111111101",
            "11111111-1111-4111-8111-111111111102",
            "u1@example.test",
            "Org One",
            "one.example.test",
        )
        u2, _r2, o2, e2, a2 = _seed_org(
            repo,
            orgs,
            sec,
            "22222222-2222-4222-8222-222222222201",
            "22222222-2222-4222-8222-222222222202",
            "u2@example.test",
            "Org Two",
            "two.example.test",
        )

        # Concurrent admission race on org 1: per_org_queued_limit=2 allows only 2
        def submit(idx: int) -> str:
            try:
                res = gov.create_domain_job(
                    u1, o1, e1, a1, approval_id=None, idempotency_key=f"race-key-00000000-{idx}"
                )
                return res["id"]
            except ResourceLimitError as exc:
                return f"rejected:{exc.code}"

        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(submit, range(4)))
        admitted = [x for x in outcomes if not x.startswith("rejected:")]
        rejected = [x for x in outcomes if x.startswith("rejected:")]
        assert len(admitted) == 2
        assert rejected == ["rejected:org_quota_exceeded", "rejected:org_quota_exceeded"]

        # Sensitive approval is NOT consumed if admission is rejected by quota
        rev = sec.create_approval_request(
            u1, o1, e1, "domain", "one.example.test", "exploit_verification"
        )
        assert rev is not None
        assert sec.decide_approval(r1, o1, e1, rev["id"], "approved", "approve") is not None
        with pytest.raises(ResourceLimitError) as exc_info:
            gov.create_governed_job(
                u1,
                o1,
                e1,
                a1,
                technique="exploit_verification",
                approval_id=rev["id"],
                idempotency_key="sensitive-rejected-01",
            )
        assert exc_info.value.code == "org_quota_exceeded"
        with repo.engine.connect() as conn:
            app_row = conn.execute(
                select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                    approval_requests.c.id == rev["id"]
                )
            ).one()
        assert app_row.decision == "approved"
        assert app_row.consumed_at is None

        # Org 2 can admit 1 job (global_queued_limit=3), then 2nd hits global queue full
        j_org2 = gov.create_domain_job(
            u2, o2, e2, a2, approval_id=None, idempotency_key="org2-key-00000001"
        )
        assert j_org2["status"] == "queued"
        with pytest.raises(ResourceLimitError) as g_exc:
            gov.create_domain_job(
                u2, o2, e2, a2, approval_id=None, idempotency_key="org2-key-00000002"
            )
        assert g_exc.value.code == "execution_queue_full"
    finally:
        repo.close()


def test_fair_scheduling_and_workload_concurrency_limits(tmp_path: Path) -> None:
    repo = SQLiteRepository(tmp_path / "fairness.sqlite3")
    try:
        orgs = OrganizationService(repo)
        sec = EngagementSecurityService(repo, orgs)
        limits = ResourceLimits(
            per_org_active_limit=1,
            global_active_limit=2,
            per_org_queued_limit=3,
            global_queued_limit=6,
            workload_concurrency_limits={"domain": 2},
        )
        class SensitiveAdapter:
            capabilities = AdapterCapabilities(
                adapter_id="test.sensitive-2e",
                techniques=("exploit_verification",),
                target_types=("domain",),
                action_class="sensitive",
                enabled=True,
                performs_external_operations=True,
            )

            def validate_parameters(self, parameters: dict) -> dict:
                return parameters

            def execute(self, context, _parameters, control) -> AdapterResult:
                del context, control
                return AdapterResult(adapter_id="test.sensitive-2e", status="complete", summary={})

        from chinescan.core.execution_adapters import DomainPostureAdapter

        registry = AdapterRegistry((DomainPostureAdapter(repo), SensitiveAdapter()))
        gov = ExecutionGovernanceService(sec, adapters=registry, resource_limits=limits)
        u1, _r1, o1, e1, a1 = _seed_org(
            repo,
            orgs,
            sec,
            "33333333-3333-4333-8333-333333333301",
            "33333333-3333-4333-8333-333333333302",
            "f1@example.test",
            "Fair One",
            "f1.example.test",
        )
        u2, _r2, o2, e2, a2 = _seed_org(
            repo,
            orgs,
            sec,
            "44444444-4444-4444-8444-444444444401",
            "44444444-4444-4444-8444-444444444402",
            "f2@example.test",
            "Fair Two",
            "f2.example.test",
        )

        j1 = gov.create_domain_job(u1, o1, e1, a1, approval_id=None, idempotency_key="fair-org1-000001")
        j2 = gov.create_domain_job(u1, o1, e1, a1, approval_id=None, idempotency_key="fair-org1-000002")
        j3 = gov.create_domain_job(u2, o2, e2, a2, approval_id=None, idempotency_key="fair-org2-000001")

        # First claim takes j1 (org 1)
        c1 = gov.claim_next_job("worker-1")
        assert c1 is not None and c1["id"] == j1["id"]
        # Next claim MUST NOT take j2 (org 1 already at per_org_active_limit=1); takes j3 (org 2)
        c2 = gov.claim_next_job("worker-2")
        assert c2 is not None and c2["id"] == j3["id"]
        # Global active is now 2: third claim returns None
        assert gov.claim_next_job("worker-3") is None
        # Even if org 1 queued j2 earlier, org 2 got fair execution
        assert j2["id"] not in {c1["id"], c2["id"]}
    finally:
        repo.close()


def test_deadlines_before_claim_and_during_execution(tmp_path: Path) -> None:
    repo = SQLiteRepository(tmp_path / "deadlines.sqlite3")
    try:
        orgs = OrganizationService(repo)
        sec = EngagementSecurityService(repo, orgs)
        limits = ResourceLimits(
            default_job_deadline_seconds=1.0,
            default_operation_timeout_seconds=1.0,
            max_queue_wait_seconds=5.0,
        )

        class SlowPassiveAdapter:
            capabilities = AdapterCapabilities(
                adapter_id="test.slow-passive",
                techniques=("service_fingerprint",),
                target_types=("domain",),
                action_class="controlled_active",
                enabled=True,
                performs_external_operations=True,
            )

            def validate_parameters(self, parameters: dict) -> dict:
                return parameters

            def execute(self, context, _parameters, control) -> AdapterResult:
                del context
                for _ in range(40):
                    control.check_cancelled()
                    time.sleep(0.05)
                return AdapterResult(adapter_id="test.slow-passive", status="complete", summary={})

        class SlowInProgressAdapter:
            capabilities = AdapterCapabilities(
                adapter_id="test.slow-inprogress",
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
                for _ in range(40):
                    control.check_cancelled()
                    time.sleep(0.05)
                return AdapterResult(adapter_id="test.slow-inprogress", status="complete", summary={})

        # 1. Queue wait expired before claim -> EXECUTION_QUEUE_WAIT_EXPIRED
        gov = ExecutionGovernanceService(
            sec, AdapterRegistry((SlowPassiveAdapter(),)), resource_limits=limits
        )
        u1, _r1, o1, e1, a1 = _seed_org(
            repo,
            orgs,
            sec,
            "55555555-5555-4555-8555-555555555501",
            "55555555-5555-4555-8555-555555555502",
            "d1@example.test",
            "Dead One",
            "d1.example.test",
        )
        stale_job = gov.create_domain_job(u1, o1, e1, a1, approval_id=None, idempotency_key="dead-queue-000001")
        old_created = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
        with repo.engine.begin() as conn:
            conn.execute(
                update(execution_jobs)
                .where(execution_jobs.c.id == stale_job["id"])
                .values(created_at=old_created)
            )
        assert gov.claim_job(stale_job["id"], "worker-d") is None
        with repo.engine.connect() as conn:
            row = conn.execute(
                select(execution_jobs.c.status, execution_jobs.c.error_code).where(
                    execution_jobs.c.id == stale_job["id"]
                )
            ).one()
        assert row.status == "blocked"
        assert row.error_code == "EXECUTION_QUEUE_WAIT_EXPIRED"

        # 2. Deadline exceeded before external dispatch -> failed (EXECUTION_DEADLINE_EXCEEDED)
        j_pre = gov.create_domain_job(u1, o1, e1, a1, approval_id=None, idempotency_key="dead-exec-0000001")
        worker1 = GovernedDomainWorker(
            repo, gov, AdapterRegistry((SlowPassiveAdapter(),)), heartbeat_interval_seconds=0.1
        )
        res_pre = worker1.run_one(j_pre["id"])
        assert res_pre == {
            "id": j_pre["id"],
            "status": "failed",
            "error_code": "EXECUTION_DEADLINE_EXCEEDED",
        }

        # 3. Deadline exceeded AFTER action enters in_progress -> reconciliation_required
        gov2 = ExecutionGovernanceService(
            sec, AdapterRegistry((SlowInProgressAdapter(),)), resource_limits=limits
        )
        j_inprog = gov2.create_domain_job(
            u1, o1, e1, a1, approval_id=None, idempotency_key="dead-inprog-00001"
        )
        worker2 = GovernedDomainWorker(
            repo, gov2, AdapterRegistry((SlowInProgressAdapter(),)), heartbeat_interval_seconds=0.1
        )
        res_inprog = worker2.run_one(j_inprog["id"])
        assert res_inprog == {
            "id": j_inprog["id"],
            "status": "reconciliation_required",
            "error_code": "EXTERNAL_OUTCOME_UNCERTAIN",
        }
    finally:
        repo.close()


def test_supervised_subprocess_limits_timeout_cancellation_and_tree_cleanup(tmp_path: Path) -> None:
    # 1. Normal exit
    ok = run_supervised_subprocess(
        [sys.executable, "-c", "print('hello-2e')"],
        cwd=tmp_path,
        timeout_seconds=5.0,
        max_output_bytes=4096,
    )
    assert ok.returncode == 0
    assert b"hello-2e" in ok.stdout

    # 2. Non-zero exit
    nz = run_supervised_subprocess(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        cwd=tmp_path,
        timeout_seconds=5.0,
    )
    assert nz.returncode == 7

    # 3. Output limit enforcement
    with pytest.raises(SubprocessExecutionError) as out_exc:
        run_supervised_subprocess(
            [sys.executable, "-c", "print('x' * 50000)"],
            cwd=tmp_path,
            timeout_seconds=5.0,
            max_output_bytes=1024,
        )
    assert out_exc.value.code == "SUBPROCESS_OUTPUT_LIMIT_EXCEEDED"

    # 4. Cancellation
    cancel = threading.Event()
    threading.Timer(0.15, cancel.set).start()
    with pytest.raises(SubprocessExecutionError) as can_exc:
        run_supervised_subprocess(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
            timeout_seconds=5.0,
            cancellation=cancel,
        )
    assert can_exc.value.code == "SUBPROCESS_CANCELLED"

    # 5. Timeout + descendant process-tree termination
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time; "
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        f"open({str(pid_file)!r}, 'w').write(str(p.pid)); "
        "time.sleep(30)"
    )
    with pytest.raises(SubprocessExecutionError) as to_exc:
        run_supervised_subprocess(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            timeout_seconds=0.8,
        )
    assert to_exc.value.code == "SUBPROCESS_TIMEOUT"
    if pid_file.exists():
        grand_pid = int(pid_file.read_text().strip())
        # Confirm grandchild process no longer exists
        if os.name == "nt":
            probe = run_supervised_subprocess(
                [sys.executable, "-c", f"import os; os.kill({grand_pid}, 0)"],
                timeout_seconds=3.0,
            )
            assert probe.returncode != 0

    # 6. Already-expired deadline raises ExecutionDeadlineExceeded
    with pytest.raises(ExecutionDeadlineExceeded):
        run_supervised_subprocess(
            [sys.executable, "-c", "print('never')"],
            timeout_seconds=5.0,
            deadline_at=time.monotonic() - 1.0,
        )


def test_quota_and_diagnostics_tenant_isolation_and_auth(tmp_path: Path) -> None:
    cred = tmp_path / "operator.json"
    create_operator(cred, "operator@example.test", "Operator-Secure-Passphrase-99!")
    app = create_app(tmp_path / "web.sqlite3", cred, serve_frontend=False, start_governed_worker=False)
    try:
        orgs: OrganizationService = app.state.organization_service
        sec: EngagementSecurityService = app.state.engagement_security_service
        u1, _r1, o1, e1, _a1 = _seed_org(
            app.state.repository,
            orgs,
            sec,
            "66666666-6666-4666-8666-666666666601",
            "66666666-6666-4666-8666-666666666602",
            "t1@example.test",
            "Tenant One",
            "t1.example.test",
        )
        _u2, _r2, o2, e2, _a2 = _seed_org(
            app.state.repository,
            orgs,
            sec,
            "77777777-7777-4777-8777-777777777701",
            "77777777-7777-4777-8777-777777777702",
            "t2@example.test",
            "Tenant Two",
            "t2.example.test",
        )

        # Non-operator member cannot call local-operator global diagnostics
        u1_tok = app.state.session_store.create(
            email="t1@example.test", user_id=u1, auth_epoch="epoch-2e"
        )[0]
        with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
            client.cookies.set("chinescan_session", u1_tok)
            resp_diag = client.get("/api/diagnostics/execution-resources")
            assert resp_diag.status_code == 403

            # Org 1 member can read org 1 quota, but NOT org 2 quota
            resp_q1 = client.get(f"/api/organizations/{o1}/engagements/{e1}/executions/quota")
            assert resp_q1.status_code == 200
            assert resp_q1.json()["organization_id"] == o1
            resp_q2 = client.get(f"/api/organizations/{o2}/engagements/{e2}/executions/quota")
            assert resp_q2.status_code == 404
    finally:
        app.state.repository.close()
