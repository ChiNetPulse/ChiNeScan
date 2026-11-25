"""Fail-closed access tests for organization-owned generic records."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.core.errors import StorageError
from chinescan.core.models.finding import Finding
from chinescan.core.models.investigation import Scan
from chinescan.core.organizations import OrganizationService
from chinescan.core.storage.sqlite import SQLiteRepository, record_ownership
from chinescan.web.app import COOKIE_NAME, create_app
from chinescan.web.auth import operator_auth_epoch, operator_identity_id


def _principal(repository: SQLiteRepository, label: str) -> tuple[str, str]:
    identity_id = str(uuid4())
    user, organization = OrganizationService(repository).ensure_operator(
        f"{label}-{identity_id[:8]}@example.test",
        f"auth-epoch-{identity_id}",
        identity_id,
    )
    return user["id"], organization["id"]


def test_missing_context_never_turns_owned_query_into_global_access(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "tenant.sqlite3")
    try:
        user_a, org_a = _principal(repository, "owner-a")
        user_b, org_b = _principal(repository, "owner-b")
        with repository.member_context(org_a, user_a, write=True):
            repository.save("scan", "scan-a", {"status": "complete", "scanner": "unit"})
        with repository.member_context(org_b, user_b, write=True):
            repository.save("scan", "scan-b", {"status": "failed", "scanner": "unit"})

        # Before the fix, _owned_record() returned None here and get/list/page/count
        # silently queried both tenants. All entry points now reject missing context.
        with pytest.raises(StorageError, match="authorized organization context"):
            repository.get("scan", "scan-a")
        with pytest.raises(StorageError, match="authorized organization context"):
            repository.list_records("scan")
        with pytest.raises(StorageError, match="authorized organization context"):
            repository.count_records("scan")
        with pytest.raises(StorageError, match="authorized organization context"):
            repository.page_records(
                "scan", limit=10, offset=0, sort_by="status", descending=False
            )
        with pytest.raises(StorageError, match="authorized organization context"):
            repository.save("scan", "unowned", {"status": "complete", "scanner": "unit"})
        with repository.engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT count(*) FROM records WHERE record_id='unowned'"
            ).scalar_one() == 0

        with repository.organization_context(org_a):
            assert repository.get("scan", "scan-a") is not None
            assert repository.get("scan", "scan-b") is None
            items, total = repository.page_records(
                "scan", limit=10, offset=0, sort_by="status", descending=False
            )
            assert [item["status"] for item in items] == ["complete"]
            assert total == repository.count_records("scan") == 1
        with repository.organization_context(org_b):
            assert repository.get("scan", "scan-a") is None
            assert repository.get("scan", "scan-b") is not None
    finally:
        repository.close()


def test_cross_organization_updates_deletes_and_bulk_writes_are_denied(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "tenant-writes.sqlite3")
    try:
        user_a, org_a = _principal(repository, "owner-a")
        user_b, org_b = _principal(repository, "owner-b")
        with repository.member_context(org_a, user_a, write=True):
            repository.save("finding", "finding-a", {"title": "private A", "severity": "high"})
        with repository.member_context(org_b, user_b, write=True):
            repository.save("finding", "finding-b", {"title": "private B", "severity": "low"})
            repository.delete("finding", "finding-a")
            with pytest.raises(IntegrityError):
                repository.save(
                    "finding", "finding-a", {"title": "overwrite attempt", "severity": "critical"}
                )
            with pytest.raises(IntegrityError):
                repository.save_many([
                    ("finding", "new-b", {"title": "new"}),
                    ("finding", "finding-a", {"title": "overwrite attempt"}),
                ])
        with repository.organization_context(org_a):
            record = repository.get("finding", "finding-a")
            assert record == {"title": "private A", "severity": "high"}
            assert repository.get("finding", "new-b") is None
        with repository.organization_context(org_b):
            assert repository.get("finding", "finding-b")["title"] == "private B"
    finally:
        repository.close()


def test_invalid_and_inactive_organization_contexts_are_rejected(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "tenant-context.sqlite3")
    try:
        _user_id, organization_id = _principal(repository, "context-owner")
        with pytest.raises(StorageError, match="valid organization"):
            with repository.organization_context(" "):
                pass
        with pytest.raises(StorageError, match="unavailable"):
            with repository.organization_context(str(uuid4())):
                pass
        with repository.engine.begin() as connection:
            from chinescan.core.storage.sqlite import organizations

            connection.execute(
                organizations.update()
                .where(organizations.c.id == organization_id)
                .values(status="suspended")
            )
        with pytest.raises(StorageError, match="unavailable"):
            with repository.organization_context(organization_id):
                pass
    finally:
        repository.close()


def test_no_general_system_bypass_is_available(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "tenant-no-bypass.sqlite3")
    try:
        assert not hasattr(repository, "system_context")
        with pytest.raises(StorageError, match="authorized organization context"):
            repository.list_records("scan")
    finally:
        repository.close()


def test_nested_same_organization_scope_preserves_verified_principal_only(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "tenant-nested-context.sqlite3")
    try:
        user_id, organization_id = _principal(repository, "nested-context")
        other_user, other_organization = _principal(repository, "nested-other")
        with repository.member_context(organization_id, user_id, write=True):
            with repository.organization_context(organization_id):
                assert repository._organization_principal_id.get() == user_id
                assert repository._organization_write_access.get() is True
            with repository.member_context(other_organization, other_user):
                assert repository._current_organization_id() == other_organization
                assert repository._organization_principal_id.get() == other_user
                assert repository._organization_write_access.get() is False
            assert repository._current_organization_id() == organization_id
            assert repository._organization_principal_id.get() == user_id
        assert repository._current_organization_id() is None
        assert repository._organization_principal_id.get() is None
        assert repository._organization_write_access.get() is False
    finally:
        repository.close()


def test_member_access_is_assignment_scoped_and_writes_require_assignment_role(
    tmp_path,
) -> None:
    repository = SQLiteRepository(tmp_path / "tenant-assignments.sqlite3")
    organizations = OrganizationService(repository)
    try:
        owner_id, organization_id = _principal(repository, "assignment-owner")
        assessor_id, _assessor_personal_org = _principal(repository, "assigned-assessor")
        observer_id, _observer_personal_org = _principal(repository, "assigned-observer")
        unassigned_id, _unassigned_personal_org = _principal(repository, "unassigned-member")
        organizations.add_member(owner_id, organization_id, assessor_id, "member")
        organizations.add_member(owner_id, organization_id, observer_id, "member")
        organizations.add_member(owner_id, organization_id, unassigned_id, "member")
        engagement = organizations.create_engagement(
            owner_id, organization_id, None, "Engagement", "Authorized synthetic scope"
        )
        assert engagement is not None
        organizations.change_assignment(
            owner_id,
            organization_id,
            engagement["id"],
            assessor_id,
            role="assessor",
        )
        organizations.change_assignment(
            owner_id,
            organization_id,
            engagement["id"],
            observer_id,
            role="observer",
        )
        with repository.member_context(organization_id, owner_id, write=True):
            repository.save("scan", "assigned-scan", {"status": "complete"})
        with repository.engine.begin() as connection:
            connection.execute(
                record_ownership.update()
                .where(
                    record_ownership.c.record_type == "scan",
                    record_ownership.c.record_id == "assigned-scan",
                )
                .values(engagement_id=engagement["id"])
            )

        with repository.member_context(organization_id, assessor_id):
            assert repository.get("scan", "assigned-scan") is not None
            with pytest.raises(StorageError, match="write context"):
                repository.save("scan", "read-only-write", {"status": "tampered"})
        with repository.member_context(organization_id, observer_id):
            assert repository.get("scan", "assigned-scan") is not None
        with repository.member_context(organization_id, observer_id, write=True):
            with pytest.raises(IntegrityError):
                repository.save("scan", "assigned-scan", {"status": "tampered"})
        with repository.member_context(organization_id, unassigned_id):
            assert repository.get("scan", "assigned-scan") is None
        with pytest.raises(StorageError, match="membership is unavailable"):
            with repository.member_context(str(uuid4()), assessor_id):
                pass
    finally:
        repository.close()


def test_authenticated_members_access_assigned_scans_without_operator_identity(
    tmp_path,
) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "operator@example.test", "synthetic-operator-password-77!")
    database = tmp_path / "api-assignments.sqlite3"
    app = create_app(
        database,
        credential,
        settings=Settings(_env_file=None, database_path=database),
        serve_frontend=False,
    )
    repository = app.state.repository
    organizations = app.state.organization_service
    owner_id = operator_identity_id(credential)
    assert owner_id is not None
    member_epoch = operator_auth_epoch(credential)
    organization_id = organizations.personal_organization_id(owner_id)
    assert organization_id

    assessor_id = str(uuid4())
    assessor, _assessor_org = organizations.ensure_operator(
        "assessor@example.test", member_epoch, assessor_id
    )
    observer_id = str(uuid4())
    observer, _observer_org = organizations.ensure_operator(
        "observer@example.test", member_epoch, observer_id
    )
    unassigned_id = str(uuid4())
    unassigned, _unassigned_org = organizations.ensure_operator(
        "unassigned@example.test", member_epoch, unassigned_id
    )
    viewer_id = str(uuid4())
    viewer, _viewer_org = organizations.ensure_operator(
        "viewer@example.test", member_epoch, viewer_id
    )
    admin_id = str(uuid4())
    admin, _admin_org = organizations.ensure_operator(
        "admin@example.test", member_epoch, admin_id
    )
    auditor_id = str(uuid4())
    auditor, _auditor_org = organizations.ensure_operator(
        "auditor@example.test", member_epoch, auditor_id
    )
    lead_id = str(uuid4())
    lead, _lead_org = organizations.ensure_operator(
        "lead@example.test", member_epoch, lead_id
    )
    reviewer_id = str(uuid4())
    reviewer, _reviewer_org = organizations.ensure_operator(
        "reviewer@example.test", member_epoch, reviewer_id
    )
    for user, role in (
        (assessor, "member"),
        (observer, "member"),
        (unassigned, "member"),
        (viewer, "viewer"),
        (admin, "admin"),
        (auditor, "auditor"),
        (lead, "member"),
        (reviewer, "member"),
    ):
        organizations.add_member(owner_id, organization_id, user["id"], role)
    engagement = organizations.create_engagement(
        owner_id, organization_id, None, "Assigned scope", "Route authorization fixture"
    )
    assert engagement
    for user_id, assignment_role in (
        (assessor_id, "assessor"),
        (observer_id, "observer"),
        (lead_id, "lead"),
        (reviewer_id, "reviewer"),
    ):
        organizations.change_assignment(
            owner_id,
            organization_id,
            engagement["id"],
            user_id,
            role=assignment_role,
        )
    with repository.member_context(organization_id, owner_id, write=True):
        route_scan = Scan(
            scan_id="assigned-route-scan",
            target_id="synthetic-target",
            scanner="test-fixture",
            started_at=datetime.now(UTC),
            finding_ids=["assigned-route-finding"],
        )
        repository.save("scan", route_scan.scan_id, route_scan.model_dump(mode="json"))
        finding = Finding(
            finding_id="assigned-route-finding",
            title="Synthetic assigned finding",
            fingerprint="assigned-route-finding-fingerprint",
        )
        repository.save("finding", finding.finding_id, finding.model_dump(mode="json"))
    with repository.engine.begin() as connection:
        connection.execute(
            record_ownership.update()
            .where(
                record_ownership.c.record_type == "scan",
                record_ownership.c.record_id == "assigned-route-scan",
            )
            .values(engagement_id=engagement["id"])
        )
        connection.execute(
            record_ownership.update()
            .where(
                record_ownership.c.record_type == "finding",
                record_ownership.c.record_id == "assigned-route-finding",
            )
            .values(engagement_id=engagement["id"])
        )
    foreign_organization = organizations.create_organization(
        owner_id, "Foreign organization", "foreign-route-org"
    )
    with repository.member_context(foreign_organization["id"], owner_id, write=True):
        repository.save(
            "scan",
            "foreign-organization-scan",
            {"scan_id": "foreign-organization-scan", "scanner": "test-fixture"},
        )
        foreign_finding = Finding(
            finding_id="foreign-organization-finding",
            title="Foreign synthetic finding",
            fingerprint="foreign-organization-finding-fingerprint",
        )
        repository.save(
            "finding",
            foreign_finding.finding_id,
            foreign_finding.model_dump(mode="json"),
        )

    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50177))

    def authenticate(user_id: str, email: str, auth_epoch: str) -> None:
        token, _session = app.state.session_store.create(email, auth_epoch, user_id=user_id)
        client.cookies.set(COOKIE_NAME, token)

    authenticate(assessor_id, "assessor@example.test", member_epoch)
    org_headers = {"X-Chinescan-Organization-Id": organization_id}
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 200
    assert client.get(
        "/api/findings/assigned-route-finding", headers=org_headers
    ).status_code == 200
    assert client.get(
        "/api/reports/assigned-route-scan/json", headers=org_headers
    ).status_code == 200
    assert client.get(
        "/api/scans/assigned-route-scan/findings.jsonl", headers=org_headers
    ).status_code == 200
    assert client.get("/api/scans/foreign-scan", headers=org_headers).status_code == 404
    assert client.get(
        "/api/scans/foreign-organization-scan", headers=org_headers
    ).status_code == 404
    assert client.get(
        "/api/findings/foreign-organization-finding", headers=org_headers
    ).status_code == 404
    assert client.get(
        "/api/reports/foreign-organization-scan/json", headers=org_headers
    ).status_code == 404
    created = client.post(
        "/api/cases",
        json={"scan_id": "assigned-route-scan", "title": "Authorized case"},
        headers={
            **org_headers,
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": app.state.session_store.get(
                client.cookies.get(COOKIE_NAME)
            ).csrf_token,
        },
    )
    assert created.status_code == 201, created.text
    case_id = created.json()["case"]["case_id"]

    authenticate(owner_id, "operator@example.test", member_epoch)
    owner_case = client.post(
        "/api/cases",
        json={"scan_id": "assigned-route-scan", "title": "Owner authorized case"},
        headers={
            **org_headers,
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": app.state.session_store.get(
                client.cookies.get(COOKIE_NAME)
            ).csrf_token,
        },
    )
    assert owner_case.status_code == 201
    assert client.get(
        f"/api/cases/{case_id}/report/markdown", headers=org_headers
    ).status_code == 200

    authenticate(admin_id, "admin@example.test", member_epoch)
    admin_case = client.post(
        "/api/cases",
        json={"scan_id": "assigned-route-scan", "title": "Admin authorized case"},
        headers={
            **org_headers,
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": app.state.session_store.get(
                client.cookies.get(COOKIE_NAME)
            ).csrf_token,
        },
    )
    assert admin_case.status_code == 201

    for user_id, email in ((lead_id, "lead@example.test"), (reviewer_id, "reviewer@example.test")):
        authenticate(user_id, email, member_epoch)
        assigned_case = client.post(
            "/api/cases",
            json={"scan_id": "assigned-route-scan", "title": f"{email} authorized case"},
            headers={
                **org_headers,
                "Origin": "http://127.0.0.1",
                "X-CSRF-Token": app.state.session_store.get(
                    client.cookies.get(COOKIE_NAME)
                ).csrf_token,
            },
        )
        assert assigned_case.status_code == 201, assigned_case.text

    authenticate(auditor_id, "auditor@example.test", member_epoch)
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 200
    listed_scans = client.get("/api/scans", headers=org_headers)
    assert listed_scans.status_code == 200
    assert all(
        item["scan_id"] != "foreign-organization-scan"
        for item in listed_scans.json()["items"]
    )
    assert any(
        item["scan_id"] == "assigned-route-scan"
        for item in listed_scans.json()["items"]
    )
    auditor_write = client.post(
        "/api/cases",
        json={"scan_id": "assigned-route-scan", "title": "Forbidden auditor case"},
        headers={
            **org_headers,
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": app.state.session_store.get(
                client.cookies.get(COOKIE_NAME)
            ).csrf_token,
        },
    )
    assert auditor_write.status_code == 403

    authenticate(observer_id, "observer@example.test", member_epoch)
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 200
    assert any(
        item["scan_id"] == "assigned-route-scan"
        for item in client.get("/api/scans", headers=org_headers).json()["items"]
    )
    observer_update = client.post(
        f"/api/cases/{case_id}/status",
        json={"status": "in_progress"},
        headers={
            **org_headers,
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": app.state.session_store.get(
                client.cookies.get(COOKIE_NAME)
            ).csrf_token,
        },
    )
    assert observer_update.status_code == 404

    authenticate(unassigned_id, "unassigned@example.test", member_epoch)
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 404
    assert client.get("/api/scans", headers=org_headers).json()["total"] == 0
    denied_report = client.get("/api/reports/assigned-route-scan/json", headers=org_headers)
    assert denied_report.status_code == 404, denied_report.text
    organizations.change_assignment(
        owner_id,
        organization_id,
        engagement["id"],
        assessor_id,
        status="revoked",
    )
    authenticate(assessor_id, "assessor@example.test", member_epoch)
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 404
    authenticate(viewer_id, "viewer@example.test", member_epoch)
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 200
    assert client.get("/api/scans", headers=org_headers).json()["total"] >= 1
    viewer_write = client.post(
        "/api/cases",
        json={"scan_id": "assigned-route-scan", "title": "Forbidden case"},
        headers={
            **org_headers,
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": app.state.session_store.get(
                client.cookies.get(COOKIE_NAME)
            ).csrf_token,
        },
    )
    assert viewer_write.status_code == 403
    organizations.update_membership(owner_id, organization_id, assessor_id, status="revoked")
    authenticate(assessor_id, "assessor@example.test", member_epoch)
    assert client.get("/api/scans/assigned-route-scan", headers=org_headers).status_code == 404
    revoked_list = client.get("/api/scans", headers=org_headers)
    assert revoked_list.status_code in {401, 403, 404}
    assert "total" not in revoked_list.json()
    client.close()
    repository.close()
