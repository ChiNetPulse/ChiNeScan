"""Regression tests for first-superuser org resolution and device folder upload."""

from __future__ import annotations

import base64
from pathlib import Path
from uuid import uuid4

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import insert

from chinescan.core.organizations import OrganizationService
from chinescan.core.storage.sqlite import (
    SQLiteRepository,
    organization_memberships,
    organizations,
    user_credentials,
    users,
)
from chinescan.web.app import create_app


def _seed_superuser_with_admin_org(
    db_path: Path,
    *,
    email: str = "cipherchi@proton.me",
    password: str = "Superuser-Test-Password-2026!x",
) -> tuple[str, str]:
    """Seed a superuser + chinescan-administration org into an existing schema DB."""
    repo = SQLiteRepository(db_path)
    now = "2026-11-28T00:00:00+00:00"
    user_id = str(uuid4())
    org_id = str(uuid4())
    try:
        with repo.engine.begin() as connection:
            connection.execute(
                insert(users).values(
                    id=user_id,
                    email_normalized=email,
                    display_name="Platform Superuser",
                    platform_role="superuser",
                    status="active",
                    auth_epoch="epoch-1",
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                insert(user_credentials).values(
                    user_id=user_id,
                    password_hash=PasswordHasher().hash(password),
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                insert(organizations).values(
                    id=org_id,
                    slug="chinescan-administration",
                    name="ChiNeScan Administration",
                    owner_user_id=user_id,
                    status="active",
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                insert(organization_memberships).values(
                    id=str(uuid4()),
                    organization_id=org_id,
                    user_id=user_id,
                    role="owner",
                    status="active",
                    created_at=now,
                    updated_at=now,
                )
            )
    finally:
        repo.close()
    return user_id, org_id


def test_superuser_admin_org_resolves_overview_projects_and_worker(
    tmp_path: Path,
) -> None:
    # Seed BEFORE create_app so OrganizationService.__init__ picks up the superuser.
    db_path = tmp_path / "org.sqlite3"
    # First create the schema by calling create_app, then seed, then re-open the app.
    app0 = create_app(db_path, tmp_path / "private0" / "op.json", serve_frontend=False)
    app0.state.repository.close()
    user_id, org_id = _seed_superuser_with_admin_org(db_path)
    application = create_app(db_path, tmp_path / "private" / "op.json", serve_frontend=False)
    repository: SQLiteRepository = application.state.repository

    # OrganizationService should have been loaded at app construction time.
    # Also verify it via a fresh service instance.
    org_service = OrganizationService(repository)
    assert org_service.personal_organization_id(user_id) == org_id
    assert org_service.load_platform_superuser() == user_id
    assert repository._local_operator_organization_id == org_id

    # Non-superuser (plain 'user') must not resolve chinescan-administration as personal.
    other_id = str(uuid4())
    with repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=other_id,
                email_normalized="member@example.test",
                display_name="Member",
                platform_role="user",
                status="active",
                auth_epoch="epoch-2",
                created_at="2026-11-28T00:00:00+00:00",
                updated_at="2026-11-28T00:00:00+00:00",
            )
        )
        connection.execute(
            insert(organization_memberships).values(
                id=str(uuid4()),
                organization_id=org_id,
                user_id=other_id,
                role="owner",
                status="active",
                created_at="2026-11-28T00:00:00+00:00",
                updated_at="2026-11-28T00:00:00+00:00",
            )
        )
    assert org_service.personal_organization_id(other_id) is None

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 50020)
    ) as client:
        resp = client.post(
            "/api/auth/login",
            json={
                "email": "cipherchi@proton.me",
                "password": "Superuser-Test-Password-2026!x",
            },
            headers={"Origin": "http://127.0.0.1"},
        )
        assert resp.status_code == 200, resp.text
        for endpoint in (
            "/api/overview",
            "/api/dashboard/scores",
            "/api/alerts",
            "/api/code/projects",
            "/api/code/jobs?limit=50&offset=0",
            "/api/projects",
        ):
            res = client.get(endpoint)
            assert res.status_code == 200, f"{endpoint} failed: {res.status_code} {res.text}"


def test_upload_folder_filters_secrets_validates_paths_and_cleans_up(
    tmp_path: Path,
) -> None:
    # Create schema via first app instance, then seed, then open app that finds superuser.
    db_path = tmp_path / "upload.sqlite3"
    app0 = create_app(db_path, tmp_path / "private0" / "op.json", serve_frontend=False)
    app0.state.repository.close()
    _seed_superuser_with_admin_org(db_path)
    application = create_app(db_path, tmp_path / "private" / "op.json", serve_frontend=False)

    with TestClient(
        application, base_url="http://127.0.0.1", client=("127.0.0.1", 50021)
    ) as client:
        login = client.post(
            "/api/auth/login",
            json={
                "email": "cipherchi@proton.me",
                "password": "Superuser-Test-Password-2026!x",
            },
            headers={"Origin": "http://127.0.0.1"},
        )
        assert login.status_code == 200, login.text
        csrf = login.json()["csrf_token"]
        headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": csrf}

        # Reject path traversal (approved=True ensures path validation is reached).
        bad_path = client.post(
            "/api/projects/upload-folder",
            json={
                "name": "bad-proj",
                "approved": True,
                "files": [
                    {
                        "path": "../escape.py",
                        "content_base64": base64.b64encode(b"print(1)").decode(),
                    }
                ],
            },
            headers=headers,
        )
        assert bad_path.status_code == 422

        # Reject when only excluded secret files are provided.
        only_secrets = client.post(
            "/api/projects/upload-folder",
            json={
                "name": "secret-only",
                "approved": True,
                "files": [
                    {
                        "path": ".env",
                        "content_base64": base64.b64encode(b"SECRET=1").decode(),
                    },
                    {
                        "path": "certs/private.key",
                        "content_base64": base64.b64encode(b"key").decode(),
                    },
                ],
            },
            headers=headers,
        )
        assert only_secrets.status_code == 422

        # Valid upload mixed with .env / .git / PEM header file — secrets excluded.
        valid = client.post(
            "/api/projects/upload-folder",
            json={
                "name": "my-app",
                "approved": True,
                "files": [
                    {
                        "path": "src/app.py",
                        "content_base64": base64.b64encode(b"def ok(): return 1\n").decode(),
                    },
                    {
                        "path": ".env.local",
                        "content_base64": base64.b64encode(b"API_KEY=secret").decode(),
                    },
                    {
                        "path": ".git/config",
                        "content_base64": base64.b64encode(b"[core]\n").decode(),
                    },
                    {
                        "path": "leaked.txt",
                        "content_base64": base64.b64encode(
                            b"-----BEGIN PRIVATE KEY-----\nabc\n"
                        ).decode(),
                    },
                ],
            },
            headers=headers,
        )
        assert valid.status_code == 201, valid.text
        payload = valid.json()
        assert payload["kind"] == "upload"
        assert payload["origin_label"] == "This device"
        project_id = payload["project_id"]

        # Upload dir is parent(db_path) / "uploads" / project_id
        upload_dir = db_path.parent / "uploads" / project_id
        assert (upload_dir / "src" / "app.py").exists()
        assert not (upload_dir / ".env.local").exists()
        assert not (upload_dir / ".git").exists()
        assert not (upload_dir / "leaked.txt").exists()

        code_projects = client.get("/api/code/projects")
        assert code_projects.status_code == 200
        assert any(p["project_id"] == project_id for p in code_projects.json())

        # DELETE returns 200 {"status": "removed"} and cleans up the upload dir.
        deleted = client.request(
            "DELETE",
            f"/api/projects/{project_id}",
            json={"confirmation": "my-app"},
            headers=headers,
        )
        assert deleted.status_code == 200
        assert deleted.json() == {"status": "removed"}
        assert not upload_dir.exists()
