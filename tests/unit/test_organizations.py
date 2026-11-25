import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from chinescan.core.accounts import create_operator, migrate_operator_email_for_reset
from chinescan.core.errors import StorageError
from chinescan.core.organizations import OrganizationError
from chinescan.core.storage.sqlite import (
    organization_memberships,
    organizations,
    record_ownership,
    records,
    users,
)
from chinescan.web.app import create_app


def _client(tmp_path: Path) -> tuple[TestClient, object]:
    credential = tmp_path / "operator.json"
    create_operator(credential, "Owner@Example.test", "synthetic-secure-passphrase-77!")
    app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    response = client.post(
        "/api/auth/login",
        json={
            "email": "owner@example.test",
            "password": "synthetic-secure-passphrase-77!",
        },
        headers={"Origin": "http://127.0.0.1"},
    )
    assert response.status_code == 200
    csrf = response.json()["csrf_token"]
    return client, {"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf}


def test_operator_bootstrap_persists_identity_org_and_legacy_ownership(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "Owner@Example.test", "synthetic-secure-passphrase-77!")
    app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    repository = app.state.repository
    with repository.engine.connect() as connection:
        user_rows = connection.execute(select(users)).all()
        org_rows = connection.execute(select(organizations)).all()
        memberships = connection.execute(select(organization_memberships)).all()
        fk_enabled = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
    assert len(user_rows) == len(org_rows) == len(memberships) == 1
    assert user_rows[0].email_normalized == "owner@example.test"
    assert len(user_rows[0].id) == 36
    assert memberships[0].role == "owner"
    assert fk_enabled == 1
    assert "password_hash" not in app.state.organization_service.current_user(user_rows[0].id)
    report = app.state.organization_service.migration_report()
    assert report is not None
    assert report["total_legacy_records_discovered"] == 0
    assert report["records_with_unresolved_ownership"] == 0
    assert report["records_verified_after_migration"] == 0


def test_identity_bootstrap_preserves_credential_file_and_never_exposes_auth_secrets(
    tmp_path: Path,
) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "owner@example.test", "synthetic-secure-passphrase-77!")
    original = json.loads(credential.read_text(encoding="utf-8"))
    original.update(
        {
            "totp_enabled": True,
            "totp_secret": "SYNTHETIC-TOTP-SECRET",
            "totp_recovery_code_hashes": ["$argon2id$synthetic-recovery-hash"],
            "reset_token_hash": "synthetic-reset-digest",
            "reset_token_expires_at": 4_000_000_000,
        }
    )
    credential.write_text(json.dumps(original), encoding="utf-8")
    before = credential.read_bytes()
    app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    assert credential.read_bytes() == before
    with app.state.repository.engine.connect() as connection:
        user = connection.execute(select(users)).one()
    assert "SYNTHETIC-TOTP-SECRET" not in str(dict(user._mapping))
    assert "synthetic-reset-digest" not in str(dict(user._mapping))
    assert "recovery" not in str(dict(user._mapping)).lower()


def test_bootstrap_is_idempotent_and_preserves_existing_generic_records(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "owner@example.test", "synthetic-secure-passphrase-77!")
    app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    repository = app.state.repository
    with repository.local_operator_context():
        repository.save("finding", "synthetic-finding", {"title": "kept"})
    with repository.engine.connect() as connection:
        user_id = connection.execute(select(users.c.id)).scalar_one()
        org_id = connection.execute(select(organizations.c.id)).scalar_one()
        user_rows_before = connection.execute(select(users.c.id)).all()
    stored_user = app.state.organization_service.current_user(user_id)
    app.state.organization_service.ensure_operator("OWNER@example.test", stored_user["auth_epoch"])
    with repository.engine.connect() as connection:
        user_rows = connection.execute(select(users)).all()
        org_rows = connection.execute(select(organizations)).all()
        owner = connection.execute(
            select(record_ownership).where(
                record_ownership.c.record_type == "finding",
                record_ownership.c.record_id == "synthetic-finding",
            )
        ).one()
    assert len(user_rows_before) == len(user_rows) == len(org_rows) == 1
    assert owner.organization_id == org_id
    with repository.local_operator_context():
        assert repository.get("finding", "synthetic-finding") == {"title": "kept"}
    assert app.state.organization_service.migration_report()["records_successfully_mapped"] >= 1


def test_web_repository_hides_records_owned_by_another_organization(tmp_path: Path) -> None:
    client, _headers = _client(tmp_path)
    repository = client.app.state.repository
    service = client.app.state.organization_service
    user_id = client.get("/api/auth/me").json()["id"]
    personal = next(
        item for item in service.accessible_organizations(user_id) if item["role"] == "owner"
    )
    other = service.create_organization(user_id, "Second Org", "second-org")
    with repository.engine.begin() as connection:
        connection.execute(
            records.insert().values(
                record_type="finding", record_id="other-tenant-finding", payload={"title": "hidden"}
            )
        )
        connection.execute(
            record_ownership.insert().values(
                record_type="finding",
                record_id="other-tenant-finding",
                organization_id=other["id"],
                engagement_id=None,
                created_at=datetime.now(UTC).isoformat(),
            )
        )
    with repository.member_context(personal["id"], user_id, write=True):
        assert repository.get("finding", "other-tenant-finding") is None
        assert repository.get_many("finding", ["other-tenant-finding"]) == {}
        assert all(item.get("title") != "hidden" for item in repository.list_records("finding"))
        with pytest.raises(IntegrityError):
            repository.save("finding", "other-tenant-finding", {"title": "changed"})
    with repository.engine.connect() as connection:
        payload = connection.execute(
            select(records.c.payload).where(records.c.record_id == "other-tenant-finding")
        ).scalar_one()
    assert payload == {"title": "hidden"}


def test_organization_client_engagement_and_assignment_apis_are_tenant_scoped(
    tmp_path: Path,
) -> None:
    client, headers = _client(tmp_path)
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    user_id = me.json()["id"]
    orgs = client.get("/api/organizations").json()["items"]
    personal = next(item for item in orgs if item["role"] == "owner")
    created_org = client.post(
        "/api/organizations",
        json={
            "name": "Client Org",
            "slug": "client-org",
        },
        headers=headers,
    )
    assert created_org.status_code == 201
    org_id = created_org.json()["id"]
    second_user = str(uuid4())
    with client.app.state.repository.engine.begin() as connection:
        connection.execute(
            users.insert().values(
                id=second_user,
                email_normalized="assessor@example.test",
                display_name="assessor@example.test",
                status="active",
                auth_epoch="x" * 32,
                created_at=datetime.now(UTC).isoformat(),
                updated_at=datetime.now(UTC).isoformat(),
            )
        )
    member = client.post(
        f"/api/organizations/{org_id}/members",
        json={
            "user_id": second_user,
            "role": "member",
        },
        headers=headers,
    )
    assert member.status_code == 201
    # Existing active membership cannot be duplicated.
    duplicate = client.post(
        f"/api/organizations/{org_id}/members",
        json={
            "user_id": second_user,
            "role": "member",
        },
        headers=headers,
    )
    assert duplicate.status_code == 409
    client_response = client.post(
        f"/api/organizations/{org_id}/clients",
        json={
            "name": "Example Client",
            "description": "Synthetic",
        },
        headers=headers,
    )
    assert client_response.status_code == 201
    foreign_client = client.post(
        f"/api/organizations/{personal['id']}/engagements",
        json={
            "client_id": client_response.json()["id"],
            "name": "Bad reference",
        },
        headers=headers,
    )
    assert foreign_client.status_code == 409
    engagement = client.post(
        f"/api/organizations/{org_id}/engagements",
        json={
            "client_id": client_response.json()["id"],
            "name": "Assessment",
            "description": "Synthetic engagement",
        },
        headers=headers,
    )
    assert engagement.status_code == 201
    assignments = client.get(
        f"/api/organizations/{org_id}/engagements/{engagement.json()['id']}/assignments"
    )
    assert assignments.status_code == 200
    assert assignments.json()["items"][0]["user_id"] == user_id
    assert assignments.json()["items"][0]["role"] == "lead"
    assigned = client.post(
        f"/api/organizations/{org_id}/engagements/{engagement.json()['id']}/assignments",
        json={"user_id": second_user, "role": "assessor"},
        headers=headers,
    )
    assert assigned.status_code == 201
    assert assigned.json()["user_id"] == second_user
    assert (
        client.get(
            f"/api/organizations/{personal['id']}/clients/{client_response.json()['id']}"
        ).status_code
        == 404
    )


def test_last_active_owner_cannot_be_suspended_and_csrf_is_retained(tmp_path: Path) -> None:
    client, headers = _client(tmp_path)
    user_id = client.get("/api/auth/me").json()["id"]
    org = client.get("/api/organizations").json()["items"][0]
    forbidden = client.patch(
        f"/api/organizations/{org['id']}/members/{user_id}",
        json={"status": "suspended"},
        headers=headers,
    )
    assert forbidden.status_code == 409
    csrf_missing = client.post(
        f"/api/organizations/{org['id']}/clients",
        json={"name": "No CSRF"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert csrf_missing.status_code == 403


def test_unauthenticated_organization_routes_and_cross_tenant_ids_are_denied(
    tmp_path: Path,
) -> None:
    client, headers = _client(tmp_path)
    assert client.get("/api/organizations").status_code == 200
    client.post("/api/auth/logout", headers=headers)
    assert client.get("/api/organizations").status_code == 401
    assert client.get("/api/organizations/not-a-real-org/clients").status_code == 401


def test_existing_artex_health_routes_keep_disabled_profile_behavior(tmp_path: Path) -> None:
    client, _headers = _client(tmp_path)
    status = client.get("/api/integrations/artex/status")
    if status.status_code == 404:
        pytest.skip("ARTEX integration is excluded from the Phase 1/2 release")
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    assert status.json()["active_operations"] is False
    health = client.get("/api/integrations/artex/health")
    assert health.status_code == 403
    assert health.json()["detail"]["code"] == "integration_disabled"


def _add_user(repository, email: str) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC).isoformat()
    with repository.engine.begin() as connection:
        connection.execute(
            users.insert().values(
                id=user_id,
                email_normalized=email,
                display_name=email,
                status="active",
                auth_epoch="a" * 32,
                created_at=now,
                updated_at=now,
            )
        )
    return user_id


def _active_engagement(service, org_id: str, owner_id: str, member_id: str) -> dict:
    service.add_member(owner_id, org_id, member_id, "member")
    item = service.create_engagement(member_id, org_id, None, "Active test", "Synthetic")
    service.update_engagement(owner_id, org_id, item["id"], status="active")
    return item


@pytest.mark.parametrize("membership_status", ["revoked", "suspended"])
def test_inactive_membership_invalidates_active_lead_permissions(
    tmp_path: Path, membership_status: str
) -> None:
    client, _headers = _client(tmp_path)
    service = client.app.state.organization_service
    repository = client.app.state.repository
    owner_id = client.get("/api/auth/me").json()["id"]
    org_id = service.accessible_organizations(owner_id)[0]["id"]
    member_id = _add_user(repository, f"member-{membership_status}@example.test")
    engagement = _active_engagement(service, org_id, owner_id, member_id)
    service.update_membership(owner_id, org_id, member_id, status=membership_status)

    assert service.engagement(member_id, org_id, engagement["id"]) is None
    assert service.update_engagement(member_id, org_id, engagement["id"], name="stolen") is None
    assert service.assignments(member_id, org_id, engagement["id"]) is None
    assert (
        service.change_assignment(member_id, org_id, engagement["id"], owner_id, role="observer")
        is None
    )


def test_revoked_reviewer_is_denied_and_reinstatement_requires_active_assignment(
    tmp_path: Path,
) -> None:
    client, _headers = _client(tmp_path)
    service = client.app.state.organization_service
    repository = client.app.state.repository
    owner_id = client.get("/api/auth/me").json()["id"]
    org_id = service.accessible_organizations(owner_id)[0]["id"]
    reviewer_id = _add_user(repository, "reviewer@example.test")
    engagement = _active_engagement(service, org_id, owner_id, reviewer_id)
    service.change_assignment(
        owner_id, org_id, engagement["id"], reviewer_id, role="reviewer", status="active"
    )
    assert service.engagement(reviewer_id, org_id, engagement["id"]) is not None
    service.update_membership(owner_id, org_id, reviewer_id, status="revoked")
    assert service.engagement(reviewer_id, org_id, engagement["id"]) is None
    assert service.assignments(reviewer_id, org_id, engagement["id"]) is None

    service.update_membership(owner_id, org_id, reviewer_id, status="active")
    assert service.engagement(reviewer_id, org_id, engagement["id"]) is not None
    service.change_assignment(owner_id, org_id, engagement["id"], reviewer_id, status="revoked")
    assert service.engagement(reviewer_id, org_id, engagement["id"]) is None
    service.change_assignment(
        owner_id,
        org_id,
        engagement["id"],
        reviewer_id,
        role="reviewer",
        status="active",
    )
    assert service.engagement(reviewer_id, org_id, engagement["id"]) is not None


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_read_only_role_with_lead_assignment_cannot_manage_engagement_api(
    tmp_path: Path, role: str
) -> None:
    from chinescan.core.accounts import operator_auth_epoch
    from chinescan.core.storage.sqlite import engagement_assignments, engagements

    client, _owner_headers = _client(tmp_path)
    service = client.app.state.organization_service
    repository = client.app.state.repository
    owner_id = client.get("/api/auth/me").json()["id"]
    organization_id = service.accessible_organizations(owner_id)[0]["id"]
    email = f"{role}-lead@example.test"
    user_id = str(uuid4())
    epoch = operator_auth_epoch(tmp_path / "operator.json")
    user, _personal_org = service.ensure_operator(email, epoch, user_id)
    service.add_member(owner_id, organization_id, user_id, role)
    engagement = service.create_engagement(
        owner_id, organization_id, None, f"{role} assignment test", "Synthetic"
    )
    service.update_engagement(owner_id, organization_id, engagement["id"], status="active")
    service.change_assignment(owner_id, organization_id, engagement["id"], user_id, role="lead")

    token, session = client.app.state.session_store.create(
        email, user["auth_epoch"], user_id=user_id
    )
    client.cookies.clear()
    client.cookies.set("chinescan_session", token)
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": session.csrf_token}
    engagement_url = f"/api/organizations/{organization_id}/engagements/{engagement['id']}"
    assignments_url = f"{engagement_url}/assignments"
    try:
        update_response = client.patch(
            engagement_url, json={"name": "Unauthorized rename"}, headers=headers
        )
        assignment_response = client.patch(
            f"{assignments_url}/{owner_id}",
            json={"status": "revoked"},
            headers=headers,
        )
        assert update_response.status_code == 404
        assert assignment_response.status_code == 404
        assert client.get(assignments_url).status_code == 404
        with repository.engine.connect() as connection:
            stored_name = connection.execute(
                select(engagements.c.name).where(engagements.c.id == engagement["id"])
            ).scalar_one()
            owner_assignment = connection.execute(
                select(engagement_assignments.c.status).where(
                    engagement_assignments.c.engagement_id == engagement["id"],
                    engagement_assignments.c.user_id == owner_id,
                )
            ).scalar_one()
        assert stored_name == f"{role} assignment test"
        assert owner_assignment == "active"
    finally:
        client.app.state.repository.close()
        client.close()


def test_assignment_patch_preserves_revocation_and_audits_explicit_reactivation(
    tmp_path: Path,
) -> None:
    client, headers = _client(tmp_path)
    service = client.app.state.organization_service
    repository = client.app.state.repository
    owner_id = client.get("/api/auth/me").json()["id"]
    org_id = service.accessible_organizations(owner_id)[0]["id"]
    member_id = _add_user(repository, "assignment@example.test")
    engagement = _active_engagement(service, org_id, owner_id, member_id)
    base = f"/api/organizations/{org_id}/engagements/{engagement['id']}/assignments/{member_id}"
    revoked = client.patch(base, json={"status": "revoked"}, headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert client.patch(base, json={}, headers=headers).status_code == 422
    role_only = client.patch(base, json={"role": "assessor"}, headers=headers)
    assert role_only.status_code == 200
    assert role_only.json()["status"] == "revoked"
    reactivated = client.patch(base, json={"status": "active"}, headers=headers)
    assert reactivated.status_code == 200
    assert reactivated.json()["status"] == "active"
    from chinescan.core.storage.sqlite import organization_audit_events

    with repository.engine.connect() as connection:
        actions = (
            connection.execute(
                select(organization_audit_events.c.action).where(
                    organization_audit_events.c.resource_id == reactivated.json()["id"]
                )
            )
            .scalars()
            .all()
        )
    assert "assignment.reactivated" in actions


def test_operator_email_recovery_preserves_persistent_identity_and_ownership(
    tmp_path: Path,
) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "old@example.test", "synthetic-secure-passphrase-77!")
    app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    repository = app.state.repository
    with repository.local_operator_context():
        repository.save("finding", "identity-bound", {"title": "still owned"})
    user_before = app.state.local_operator_user_id
    org_before = app.state.organization_service.personal_organization_id(user_before)
    with repository.engine.connect() as connection:
        owner_before = connection.execute(
            select(record_ownership).where(record_ownership.c.record_id == "identity-bound")
        ).one()
    old_credentials = json.loads(credential.read_text(encoding="utf-8"))

    migrate_operator_email_for_reset(credential, "new@example.test")
    next_app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    assert next_app.state.local_operator_user_id == user_before
    assert next_app.state.organization_service.personal_organization_id(user_before) == org_before
    with next_app.state.repository.engine.connect() as connection:
        user = connection.execute(select(users).where(users.c.id == user_before)).one()
        owner_after = connection.execute(
            select(record_ownership).where(record_ownership.c.record_id == "identity-bound")
        ).one()
    assert user.email_normalized == "new@example.test"
    assert owner_after.organization_id == owner_before.organization_id == org_before
    new_credentials = json.loads(credential.read_text(encoding="utf-8"))
    assert new_credentials["identity_id"] == old_credentials["identity_id"] == user_before
    assert new_credentials["password_hash"] == old_credentials["password_hash"]
    assert new_credentials["reset_token_hash"]


def test_operator_email_collision_does_not_move_or_duplicate_identity(tmp_path: Path) -> None:
    credential = tmp_path / "operator.json"
    create_operator(credential, "owner@example.test", "synthetic-secure-passphrase-77!")
    app = create_app(tmp_path / "data.sqlite3", credential, serve_frontend=False)
    service = app.state.organization_service
    identity_id = app.state.local_operator_user_id
    other_id = _add_user(app.state.repository, "taken@example.test")
    with pytest.raises(OrganizationError):
        service.ensure_operator("taken@example.test", "b" * 32, identity_id)
    with app.state.repository.engine.connect() as connection:
        taken_id = connection.execute(
            select(users.c.id).where(users.c.email_normalized == "taken@example.test")
        ).scalar_one()
        retained_email = connection.execute(
            select(users.c.email_normalized).where(users.c.id == identity_id)
        ).scalar_one()
        assert taken_id == other_id
        assert retained_email == "owner@example.test"


def test_request_scoped_tenant_context_isolated_across_concurrent_requests(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    client, _headers = _client(tmp_path)
    repository = client.app.state.repository
    service = client.app.state.organization_service
    owner_id = client.get("/api/auth/me").json()["id"]
    personal_id = service.personal_organization_id(owner_id)
    other = service.create_organization(owner_id, "Concurrent Org", "concurrent-org")
    with repository.engine.begin() as connection:
        for record_id, org_id, title in (
            ("ctx-personal", personal_id, "personal"),
            ("ctx-other", other["id"], "other"),
        ):
            connection.execute(
                records.insert().values(
                    record_type="probe", record_id=record_id, payload={"title": title}
                )
            )
            connection.execute(
                record_ownership.insert().values(
                    record_type="probe",
                    record_id=record_id,
                    organization_id=org_id,
                    engagement_id=None,
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
    barrier = Barrier(2)

    def read_in_context(org_id: str, record_id: str) -> str | None:
        with repository.organization_context(org_id):
            barrier.wait(timeout=5)
            payload = repository.get("probe", record_id)
            other_id = "ctx-other" if record_id == "ctx-personal" else "ctx-personal"
            other_payload = repository.get("probe", other_id)
            return (payload or {}).get("title"), other_payload

    with ThreadPoolExecutor(max_workers=2) as pool:
        personal_future = pool.submit(read_in_context, personal_id, "ctx-personal")
        other_future = pool.submit(read_in_context, other["id"], "ctx-other")
        personal_result = personal_future.result(timeout=10)
        other_result = other_future.result(timeout=10)
    assert personal_result == ("personal", None)
    assert other_result == ("other", None)


def test_legacy_resources_are_restricted_to_local_operator_and_personal_org(tmp_path: Path) -> None:
    client, _headers = _client(tmp_path)
    app = client.app
    service = app.state.organization_service
    repository = app.state.repository
    operator_id = app.state.local_operator_user_id
    personal_id = service.personal_organization_id(operator_id)
    second_org = service.create_organization(operator_id, "Other", "other-operator-org")
    with repository.local_operator_context():
        repository.save("tenant_probe", "personal-only", {"value": "owned"})
    app.add_api_route(
        "/api/tenant-probe/{record_id}",
        lambda record_id: repository.get("tenant_probe", record_id),
    )
    other_user = _add_user(repository, "not-operator@example.test")
    service.add_member(operator_id, second_org["id"], other_user, "member")
    operator_cookie = client.cookies.get("chinescan_session")
    token, _session = app.state.session_store.create(
        "not-operator@example.test", "a" * 32, user_id=other_user
    )
    client.cookies.clear()
    client.cookies.set("chinescan_session", token)
    assert client.get("/api/organizations").status_code == 200
    assert client.get("/api/projects").status_code == 403
    assert client.get("/api/tenant-probe/personal-only").status_code == 403
    client.cookies.clear()
    client.cookies.set("chinescan_session", operator_cookie)
    assert personal_id
    other_org_headers = {"X-ChineScan-Organization-ID": second_org["id"]}
    for path in (
        "/api/projects",
        "/api/code/jobs",
        "/api/log/jobs",
        "/api/malware/jobs",
        "/api/chain/jobs",
        "/api/alerts",
        "/api/dashboard",
        "/api/fs/roots",
        "/api/github/status",
    ):
        assert client.get(path, headers=other_org_headers).status_code == 404, path
    assert client.get("/api/tenant-probe/personal-only").json() == {"value": "owned"}
    assert (
        client.get(
            "/api/tenant-probe/personal-only",
            headers=other_org_headers,
        ).json()
        is None
    )
    for path in ("/api/cases", "/api/scans", "/api/findings"):
        response = client.get(path, headers={"X-ChineScan-Organization-ID": second_org["id"]})
        assert response.status_code == 200
        assert response.json().get("items", []) == []


def test_malware_worker_claims_only_personal_organization_jobs(tmp_path: Path) -> None:
    client, _headers = _client(tmp_path)
    app = client.app
    repository = app.state.repository
    app.state.organization_service.personal_organization_id(app.state.local_operator_user_id)
    other_org = app.state.organization_service.create_organization(
        app.state.local_operator_user_id, "Worker isolation", "worker-isolation"
    )
    now = datetime.now(UTC).isoformat()
    with repository.engine.begin() as connection:
        connection.execute(
            records.insert().values(
                record_type="malware_job",
                record_id="foreign-worker-job",
                payload={
                    "job_id": "foreign-worker-job",
                    "status": "queued",
                    "created_at": now,
                },
            )
        )
        connection.execute(
            record_ownership.insert().values(
                record_type="malware_job",
                record_id="foreign-worker-job",
                organization_id=other_org["id"],
                engagement_id=None,
                created_at=now,
            )
        )
    with pytest.raises(StorageError, match="authorized organization context"):
        repository.claim_next_malware_job(now)
    with repository.local_operator_context():
        assert repository.claim_next_malware_job(now) is None
    with repository.engine.connect() as connection:
        status = connection.execute(
            select(records.c.payload["status"].as_string()).where(
                records.c.record_type == "malware_job",
                records.c.record_id == "foreign-worker-job",
            )
        ).scalar_one()
    assert status == "queued"


def test_migration_report_is_restricted_to_local_operator(tmp_path: Path) -> None:
    client, _headers = _client(tmp_path)
    report_path = "/api/organization-migration-report"
    assert client.get(report_path).status_code == 200
    app = client.app
    other_user = _add_user(app.state.repository, "report-viewer@example.test")
    token, _session = app.state.session_store.create(
        "report-viewer@example.test", "a" * 32, user_id=other_user
    )
    client.cookies.clear()
    client.cookies.set("chinescan_session", token)
    assert client.get(report_path).status_code == 403
