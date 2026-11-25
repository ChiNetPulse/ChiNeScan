"""Comprehensive role, assignment, lifecycle, and protected-operation authorization matrix tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, select

from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.core.models.investigation import Scan, ScanVerdict, Target
from chinescan.core.storage.sqlite import (
    approval_requests,
    execution_jobs,
    users,
)
from chinescan.web.app import COOKIE_NAME, create_app
from chinescan.web.auth import operator_auth_epoch


def _login_as(app, client: TestClient, user_id: str, email: str) -> dict[str, str]:
    token, session = app.state.session_store.create(
        email,
        operator_auth_epoch(app.state.credentials_path),
        user_id=user_id,
    )
    client.cookies.set(COOKIE_NAME, token)
    return {
        "Origin": str(client.base_url).rstrip("/"),
        "X-CSRF-Token": session.csrf_token,
    }


def _create_user(app, email: str) -> str:
    user_id = str(uuid4())
    stamp = datetime.now(UTC).isoformat()
    auth_epoch = operator_auth_epoch(app.state.credentials_path)
    with app.state.repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=user_id,
                email_normalized=email.casefold(),
                display_name=email.split("@")[0],
                status="active",
                auth_epoch=auth_epoch,
                created_at=stamp,
                updated_at=stamp,
            )
        )
    return user_id


def _build_matrix_workspace(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir()
    credential = state / "operator.json"
    create_operator(credential, "owner@example.test", "synthetic-secure-passphrase-77!")

    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    sample_dir = allowed_root / "samples"
    sample_dir.mkdir()
    sample_file = sample_dir / "benign.txt"
    sample_file.write_bytes(b"MZ" + b"x" * 64 + b" benign synthetic sample")
    log_dir = allowed_root / "logs"
    log_dir.mkdir()
    log_file = log_dir / "app.log"
    log_file.write_text("2026-11-25T10:00:00Z INFO ok\n", encoding="utf-8")

    registry_toml = state / "malware-samples.toml"
    registry_toml.write_text(
        f'[[samples]]\nid = "sample-1"\nname = "Synthetic"\npath = "{sample_file.as_posix()}"\n',
        encoding="utf-8",
    )
    log_sources_toml = state / "log-sources.toml"
    log_sources_toml.write_text(
        f'[[sources]]\nid = "log-1"\nname = "Synthetic Log"\npath = "{log_file.as_posix()}"\n',
        encoding="utf-8",
    )

    settings = Settings(
        _env_file=None,
        database_path=state / "matrix.sqlite3",
        reports_dir=state / "reports",
        allowed_roots=[allowed_root],
        malware_managed_directory=tmp_path / "managed",
        malware_evidence_org_quota_bytes=67_108_864,
    )
    app = create_app(
        settings.database_path,
        credential,
        settings=settings,
        serve_frontend=False,
        projects_path=state / "projects.toml",
        log_sources_path=log_sources_toml,
        malware_registry_path=registry_toml,
    )
    app.state.credentials_path = credential
    repo = app.state.repository
    orgs = app.state.organization_service
    security = app.state.engagement_security_service
    governance = app.state.execution_governance
    sample_registry = app.state.malware_job_manager.registry

    owner_id = orgs.operator_user_id
    assert owner_id
    org_id = orgs.personal_organization_id(owner_id)
    assert org_id

    # Second isolated org for cross-org negative checks
    other_user = _create_user(app, "other-owner@example.test")
    other_org = orgs.create_organization(other_user, "Other Org", f"other-{uuid4().hex[:8]}")

    client_rec = orgs.create_client(owner_id, org_id, "Acme", None)
    assert client_rec
    engagement = orgs.create_engagement(
        owner_id, org_id, client_rec["id"], "Matrix Engagement", "Scope", "active"
    )
    assert engagement
    eng_id = engagement["id"]

    # Create reviewer for scope publication (separation of duties)
    reviewer_id = _create_user(app, "setup-reviewer@example.test")
    orgs.add_member(owner_id, org_id, reviewer_id, "member")
    orgs.change_assignment(owner_id, org_id, eng_id, reviewer_id, role="reviewer")

    # Register log evidence and malware evidence
    log_ev = app.state.log_evidence_store.register(
        owner_id, org_id, eng_id, log_file, "Matrix Log", security
    )
    assert log_ev
    sample_id = "sample-1"
    mal_ev = app.state.malware_evidence_store.register(
        owner_id, org_id, eng_id, sample_id, sample_registry
    )
    assert mal_ev
    mal_ev_del = app.state.malware_evidence_store.register(
        owner_id, org_id, eng_id, sample_id, sample_registry
    )
    assert mal_ev_del

    # Create domain asset, scope, authorization, and pending approval
    domain_asset = security.create_asset(owner_id, org_id, eng_id, "domain", "example.test")
    assert domain_asset
    scope = security.create_scope_revision(
        owner_id,
        org_id,
        eng_id,
        [
            {
                "asset_id": domain_asset["id"],
                "effect": "include",
                "match_mode": "subdomains",
                "techniques": ["http_metadata", "exploit_verification"],
            },
            {
                "asset_id": log_ev["asset_id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": ["log_analysis"],
            },
            {
                "asset_id": mal_ev["asset_id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": ["malware_static_triage"],
            },
        ],
        "Matrix scope",
    )
    assert scope
    published = security.publish_scope_revision(reviewer_id, org_id, eng_id, scope["id"])
    assert published
    auth = security.create_authorization(
        owner_id,
        org_id,
        eng_id,
        published["id"],
        "AUTH-MATRIX-1",
        "Acme",
        ["http_metadata", "exploit_verification", "log_analysis", "malware_static_triage"],
        datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=2)).isoformat(),
    )
    assert auth
    doc = security.put_authorization_document(
        owner_id, org_id, eng_id, auth["id"], "auth.pdf", "application/pdf", b"%PDF-1.4\nsynthetic"
    )
    assert doc

    # Create a job and an engagement-owned scan/finding/report for report download tests
    job = governance.create_governed_job(
        owner_id,
        org_id,
        eng_id,
        log_ev["asset_id"],
        technique="log_analysis",
        approval_id=None,
        idempotency_key=f"matrix-job-{uuid4()}",
    )
    assert job.get("id"), job
    job_id = job["id"]

    # Persist a scan linked to this engagement
    scan_id = str(uuid4())
    with repo.member_context(org_id, owner_id, write=True):
        with repo.execution_provenance_context(
            {
                "job_id": job_id,
                "organization_id": org_id,
                "engagement_id": eng_id,
                "requester_user_id": owner_id,
                "request_digest": job["request_digest"],
                "authorization_document_sha256": job["authorization_document_sha256"],
            }
        ):
            repo.save(
                "target",
                domain_asset["id"],
                Target(value="example.test", kind="domain").model_dump(mode="json"),
            )
            repo.save(
                "scan",
                scan_id,
                Scan(
                    scan_id=scan_id,
                    target_id=domain_asset["id"],
                    scanner="domain",
                    started_at=datetime.now(UTC),
                    status="complete",
                    finding_ids=[],
                    verdict=ScanVerdict.NO_MATCHES_WITH_GAPS,
                ).model_dump(mode="json"),
            )

    approval = security.create_approval_request(
        owner_id, org_id, eng_id, "domain", "example.test", "exploit_verification"
    )
    assert approval

    return {
        "app": app,
        "client": TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)),
        "owner_id": owner_id,
        "org_id": org_id,
        "other_user": other_user,
        "other_org_id": other_org["id"],
        "eng_id": eng_id,
        "domain_asset_id": domain_asset["id"],
        "job_id": job_id,
        "scan_id": scan_id,
        "log_ev": log_ev,
        "mal_ev": mal_ev,
        "mal_ev_del": mal_ev_del,
        "approval_id": approval["id"],
        "sample_id": sample_id,
    }


@pytest.mark.parametrize(
    ("org_role", "assignment", "expected"),
    [
        # Viewer + every assignment: strictly read-only, assignments do NOT elevate
        ("viewer", "lead", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("viewer", "assessor", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("viewer", "reviewer", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("viewer", "observer", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("viewer", None, {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        # Auditor + every assignment: strictly read-only, assignments do NOT elevate
        ("auditor", "lead", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("auditor", "assessor", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("auditor", "reviewer", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("auditor", "observer", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("auditor", None, {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        # Member + assignments
        ("member", "lead", {"read_org": True, "read_eng": True, "manage": True, "assign_list": True, "assign_write": True, "repo_asset": True, "evidence_read": True, "evidence_write": True, "submit_job": True, "read_job": True, "cancel_job": True, "decide_approval": True, "report": True, "destructive": True}),
        ("member", "assessor", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": True, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": True}),
        ("member", "reviewer", {"read_org": True, "read_eng": True, "manage": False, "assign_list": True, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": True, "report": True, "destructive": False}),
        ("member", "observer", {"read_org": True, "read_eng": True, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": False, "decide_approval": False, "report": True, "destructive": False}),
        ("member", None, {"read_org": True, "read_eng": False, "manage": False, "assign_list": False, "assign_write": False, "repo_asset": False, "evidence_read": False, "evidence_write": False, "submit_job": False, "read_job": False, "cancel_job": False, "decide_approval": False, "report": False, "destructive": False}),
        # Admin without lead assignment: org-wide manage/review, but operate requires lead/assessor
        ("admin", None, {"read_org": True, "read_eng": True, "manage": True, "assign_list": True, "assign_write": True, "repo_asset": False, "evidence_read": True, "evidence_write": False, "submit_job": False, "read_job": True, "cancel_job": True, "decide_approval": True, "report": True, "destructive": False}),
        ("admin", "lead", {"read_org": True, "read_eng": True, "manage": True, "assign_list": True, "assign_write": True, "repo_asset": True, "evidence_read": True, "evidence_write": True, "submit_job": True, "read_job": True, "cancel_job": True, "decide_approval": True, "report": True, "destructive": True}),
    ],
)
def test_role_assignment_operation_matrix(
    tmp_path: Path, org_role: str, assignment: str | None, expected: dict[str, bool]
) -> None:
    ws = _build_matrix_workspace(tmp_path)
    app = ws["app"]
    client = ws["client"]
    orgs = app.state.organization_service
    owner_id = ws["owner_id"]
    org_id = ws["org_id"]
    eng_id = ws["eng_id"]

    try:
        actor_id = _create_user(app, f"{org_role}-{assignment or 'none'}@example.test")
        orgs.add_member(owner_id, org_id, actor_id, org_role)
        if assignment is not None:
            orgs.change_assignment(owner_id, org_id, eng_id, actor_id, role=assignment)

        headers = _login_as(app, client, actor_id, f"{org_role}@example.test")
        org_headers = {**headers, "x-chinescan-organization-id": org_id}

        # 1. Read organization resources
        r_org = client.get(f"/api/organizations/{org_id}", headers=headers)
        assert (r_org.status_code == 200) == expected["read_org"]

        # 2. Read engagement resources
        r_eng = client.get(f"/api/organizations/{org_id}/engagements/{eng_id}", headers=headers)
        assert (r_eng.status_code == 200) == expected["read_eng"]

        # 3. Update engagement
        r_patch = client.patch(
            f"/api/organizations/{org_id}/engagements/{eng_id}",
            json={"description": "Updated"},
            headers=headers,
        )
        assert (r_patch.status_code == 200) == expected["manage"]

        # 4. Manage assignments (list + write)
        r_alist = client.get(
            f"/api/organizations/{org_id}/engagements/{eng_id}/assignments",
            headers=headers,
        )
        assert (r_alist.status_code == 200) == expected["assign_list"]
        r_awrite = client.post(
            f"/api/organizations/{org_id}/engagements/{eng_id}/assignments",
            json={"user_id": ws["owner_id"], "role": "lead"},
            headers=headers,
        )
        assert (r_awrite.status_code in {200, 201}) == expected["assign_write"]

        # 5. Register repository asset (requires lead)
        r_repo = client.post(
            f"/api/organizations/{org_id}/engagements/{eng_id}/repositories",
            json={"description": "Matrix Repo"},
            headers=headers,
        )
        assert (r_repo.status_code == 201) == expected["repo_asset"]

        # 6. Evidence read / write (malware evidence)
        r_mread = client.get(
            f"/api/organizations/{org_id}/engagements/{eng_id}/malware-evidence",
            headers=headers,
        )
        assert (r_mread.status_code == 200) == expected["evidence_read"]
        r_mwrite = client.post(
            f"/api/organizations/{org_id}/engagements/{eng_id}/malware-evidence",
            json={"source_registry_id": ws["sample_id"], "classification": "malware_suspected"},
            headers=headers,
        )
        assert (r_mwrite.status_code == 201) == expected["evidence_write"], r_mwrite.text

        # 7. Submit governed job (malware static triage)
        r_job = client.post(
            f"/api/organizations/{org_id}/engagements/{eng_id}/malware-evidence/{ws['mal_ev']['asset_id']}/executions",
            json={"idempotency_key": f"matrix-submit-{uuid4()}"},
            headers=headers,
        )
        assert (r_job.status_code == 202) == expected["submit_job"]

        # 8. Read jobs & provenance
        r_jread = client.get(
            f"/api/organizations/{org_id}/engagements/{eng_id}/executions/{ws['job_id']}/provenance",
            headers=headers,
        )
        assert (r_jread.status_code == 200) == expected["read_job"]

        # 9. Cancel job (not requester)
        r_cancel = client.post(
            f"/api/organizations/{org_id}/engagements/{eng_id}/executions/{ws['job_id']}/cancel",
            headers=headers,
        )
        assert (r_cancel.status_code in {200, 202}) == expected["cancel_job"]

        # 10. Decide approval (not requester)
        r_app = client.post(
            f"/api/organizations/{org_id}/engagements/{eng_id}/approvals/{ws['approval_id']}/decision",
            json={"decision": "approved", "reason": "Matrix decision"},
            headers=headers,
        )
        assert (r_app.status_code == 200) == expected["decide_approval"]

        # 11. Download report & JSONL findings
        r_rep = client.get(
            f"/api/reports/{ws['scan_id']}/json",
            headers=org_headers,
        )
        assert (r_rep.status_code == 200) == expected["report"]
        r_jsonl = client.get(
            f"/api/scans/{ws['scan_id']}/findings.jsonl",
            headers=org_headers,
        )
        assert (r_jsonl.status_code == 200) == expected["report"]

        # 12. Destructive operation (delete malware evidence on active engagement returns 404 when denied or blocked;
        # close engagement first as owner so eligible deletion succeeds for authorized roles only)
        orgs.update_engagement(owner_id, org_id, eng_id, status="completed")
        r_del = client.delete(
            f"/api/organizations/{org_id}/engagements/{eng_id}/malware-evidence/{ws['mal_ev_del']['asset_id']}",
            headers=headers,
        )
        assert (r_del.status_code == 204) == expected["destructive"]
    finally:
        app.state.repository.close()


def test_membership_revocation_assignment_revocation_and_cross_org_fail_closed(
    tmp_path: Path,
) -> None:
    ws = _build_matrix_workspace(tmp_path)
    app = ws["app"]
    client = ws["client"]
    orgs = app.state.organization_service
    owner_id = ws["owner_id"]
    org_id = ws["org_id"]
    eng_id = ws["eng_id"]

    try:
        # Unauthenticated requests fail closed
        assert client.get(f"/api/organizations/{org_id}").status_code == 401
        assert client.get(f"/api/reports/{ws['scan_id']}/json").status_code == 401

        member_id = _create_user(app, "lifecycle@example.test")
        orgs.add_member(owner_id, org_id, member_id, "member")
        orgs.change_assignment(owner_id, org_id, eng_id, member_id, role="assessor")
        headers = _login_as(app, client, member_id, "lifecycle@example.test")

        # Missing / invalid / foreign x-chinescan-organization-id fails closed (404)
        assert client.get(
            f"/api/reports/{ws['scan_id']}/json",
            headers={**headers, "x-chinescan-organization-id": ws["other_org_id"]},
        ).status_code == 404
        assert client.get(
            f"/api/reports/{ws['scan_id']}/json",
            headers={**headers, "x-chinescan-organization-id": "nonexistent-org"},
        ).status_code == 404

        # Cross-organization engagement ID returns 404
        assert client.get(
            f"/api/organizations/{ws['other_org_id']}/engagements/{eng_id}",
            headers=headers,
        ).status_code == 404

        # Active member+assessor can read engagement and submit job
        assert client.get(
            f"/api/organizations/{org_id}/engagements/{eng_id}", headers=headers
        ).status_code == 200

        # Revoke assignment -> engagement & report access denied
        orgs.change_assignment(owner_id, org_id, eng_id, member_id, status="revoked")
        assert client.get(
            f"/api/organizations/{org_id}/engagements/{eng_id}", headers=headers
        ).status_code == 404
        assert client.get(
            f"/api/reports/{ws['scan_id']}/json",
            headers={**headers, "x-chinescan-organization-id": org_id},
        ).status_code == 404

        # Reactivate assignment then revoke organization membership -> all access denied
        orgs.change_assignment(owner_id, org_id, eng_id, member_id, status="active")
        orgs.update_membership(owner_id, org_id, member_id, status="revoked")
        assert client.get(f"/api/organizations/{org_id}", headers=headers).status_code == 404
        assert client.get(
            f"/api/organizations/{org_id}/engagements/{eng_id}", headers=headers
        ).status_code == 404
    finally:
        app.state.repository.close()


def test_alerts_events_stream_context_and_update_org_inactive_guard(tmp_path: Path) -> None:
    ws = _build_matrix_workspace(tmp_path)
    app = ws["app"]
    orgs = app.state.organization_service
    owner_id = ws["owner_id"]
    org_id = ws["org_id"]

    try:
        # Refresh alerts inside operator member_context works without StorageError
        with app.state.repository.member_context(org_id, owner_id, write=False):
            app.state.dashboard_intelligence.refresh_alerts()

        # Inactive organization cannot be updated even by former owner
        orgs.update_organization(owner_id, org_id, status="archived")
        assert orgs.update_organization(owner_id, org_id, name="Should Fail") is None
    finally:
        app.state.repository.close()
