from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, select, update

from chinescan.core.accounts import create_operator
from chinescan.core.config.settings import Settings
from chinescan.core.repository_assessment import (
    ATTESTATION_TEXT,
    REPOSITORY_TECHNIQUE,
    RepositorySnapshotError,
)
from chinescan.core.storage.recovery import backup_database, restore_backup, verify_backup
from chinescan.core.storage.sqlite import (
    authorization_records,
    engagements,
    execution_jobs,
    execution_result_provenance,
    repository_attestations,
    repository_quota_reservations,
    repository_snapshots,
    users,
)
from chinescan.web.app import create_app


def _workspace(tmp_path: Path):
    work = tmp_path / "operator-projects"
    state = tmp_path / "private-state"
    source = work / "source"
    source.mkdir(parents=True)
    state.mkdir()
    (source / "app.py").write_text(
        "import os\n\ndef example():\n    return os.system('echo unsafe')\n", encoding="utf-8"
    )
    credential = state / "operator.json"
    create_operator(credential, "lead@example.test", "synthetic-passphrase-long-998!secure")
    settings = Settings(_env_file=None, allowed_roots=[work], reports_dir=state / "reports")
    app = create_app(
        state / "test.sqlite3",
        credential,
        serve_frontend=False,
        settings=settings,
        projects_path=state / "projects.toml",
    )
    repository = app.state.repository
    service = app.state.engagement_security_service
    organizations = app.state.organization_service
    with repository.engine.connect() as connection:
        owner_id = connection.execute(select(users.c.id)).scalar_one()
    org_id = organizations.accessible_organizations(owner_id)[0]["id"]
    client = organizations.create_client(owner_id, org_id, "Synthetic client", None)
    engagement = organizations.create_engagement(
        owner_id, org_id, client["id"], "Code review", "Local test", "active"
    )
    reviewer_id = str(uuid4())
    now = datetime.now(UTC).isoformat()
    with repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=reviewer_id,
                email_normalized="reviewer@example.test",
                display_name="Reviewer",
                status="active",
                auth_epoch="test",
                created_at=now,
                updated_at=now,
            )
        )
    organizations.add_member(owner_id, org_id, reviewer_id, "member")
    organizations.change_assignment(
        owner_id, org_id, engagement["id"], reviewer_id, role="reviewer"
    )
    with repository.local_operator_context():
        project = app.state.project_service.create("Local source", source)
    asset = app.state.repository_assessment_service.create_asset(
        owner_id, org_id, engagement["id"], "Synthetic local source"
    )
    scope = service.create_scope_revision(
        owner_id,
        org_id,
        engagement["id"],
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": [REPOSITORY_TECHNIQUE],
            }
        ],
        "Include exact local repository source",
    )
    published = service.publish_scope_revision(reviewer_id, org_id, engagement["id"], scope["id"])
    authorization = service.create_authorization(
        owner_id,
        org_id,
        engagement["id"],
        published["id"],
        "CODE-TEST-1",
        "Synthetic client",
        [REPOSITORY_TECHNIQUE],
        datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )
    return app, owner_id, org_id, engagement["id"], project, asset, published, authorization


def test_repository_binding_attestation_snapshot_and_governed_execution(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        service = app.state.repository_assessment_service
        bound = service.bind(
            owner,
            org,
            engagement,
            asset["id"],
            project["project_id"],
            authorization["id"],
            scope["id"],
            ATTESTATION_TEXT,
        )
        assert bound is not None
        assert bound["snapshot_status"] == "available"
        assert bound["snapshot_sha256"]
        assert (
            bound["attestation_text"]
            if "attestation_text" in bound
            else bound["attestation_version"]
        )
        snapshot, path = app.state.repository_snapshot_store.verify(org, bound["snapshot_id"])
        assert snapshot is not None and path is not None
        assert (path / "app.py").is_file()
        assert not (path / ".git").exists()
        with app.state.repository.engine.connect() as connection:
            attestation = connection.execute(
                select(repository_attestations).where(
                    repository_attestations.c.id == bound["attestation_id"]
                )
            ).first()
        assert attestation is not None
        assert attestation.actor_user_id == owner
        assert attestation.organization_id == org
        assert attestation.engagement_id == engagement
        assert attestation.authorization_id == authorization["id"]
        assert attestation.scope_revision_id == scope["id"]
        assert attestation.attestation_text == ATTESTATION_TEXT
        assert attestation.attestation_version == "repository-code-authorization-v1"
        job = app.state.execution_governance.create_governed_job(
            owner,
            org,
            engagement,
            asset["id"],
            technique=REPOSITORY_TECHNIQUE,
            approval_id=None,
            idempotency_key="repository-assessment-test-001",
            repository_binding_id=bound["binding_id"],
            repository_attestation_id=bound["attestation_id"],
        )
        assert job["status"] == "queued"
        assert job["request_digest"] != job["policy_request_digest"]
        assert job["repository_snapshot_sha256"] == bound["snapshot_sha256"]
        outcome = app.state.governed_domain_worker.run_one(job["id"])
        assert outcome is not None and outcome["status"] in {"completed", "failed"}
        assert outcome.get("scan_id")
        provenance = app.state.execution_governance.get_job_provenance(
            owner, org, engagement, job["id"]
        )
        assert provenance is not None
        assert any(item["record_type"] == "scan" for item in provenance["results"])
    finally:
        app.state.repository.close()


def test_repository_snapshot_is_deterministic_and_excludes_nested_git(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        git = tmp_path / "operator-projects" / "source" / ".git"
        git.mkdir()
        (git / "config").write_text(
            "secret remote credentials do not enter snapshots", encoding="utf-8"
        )
        service = app.state.repository_assessment_service
        first = service.bind(
            owner,
            org,
            engagement,
            asset["id"],
            project["project_id"],
            authorization["id"],
            scope["id"],
            ATTESTATION_TEXT,
        )
        assert first is not None and first["snapshot_id"]
        manifest = app.state.repository_snapshot_store.verify(org, first["snapshot_id"])[0][
            "manifest"
        ]
        assert all(".git" not in item["path"].split("/") for item in manifest["entries"])
        assert manifest["manifest_version"] == 1
        assert first["size_bytes"] > 0
        # Mutating the operator's live source cannot mutate the already-created snapshot.
        (tmp_path / "operator-projects" / "source" / "app.py").write_text(
            "changed", encoding="utf-8"
        )
        snapshot, path = app.state.repository_snapshot_store.verify(org, first["snapshot_id"])
        assert snapshot is not None and path is not None
        assert "os.system" in (path / "app.py").read_text(encoding="utf-8")
    finally:
        app.state.repository.close()


def test_repository_binding_rejects_nonlead_unknown_project_and_raw_path(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        service = app.state.repository_assessment_service
        with app.state.repository.engine.connect() as connection:
            reviewer = connection.execute(
                select(users.c.id).where(users.c.email_normalized == "reviewer@example.test")
            ).scalar_one()
        assert service.projects_for(reviewer, org, engagement) is None
        for untrusted in (
            str(tmp_path / "operator-projects" / "source"),
            "https://example.test/repo.git",
            "unknown-project-id",
        ):
            with pytest.raises(RepositorySnapshotError):
                service.bind(
                    owner,
                    org,
                    engagement,
                    asset["id"],
                    untrusted,
                    authorization["id"],
                    scope["id"],
                    ATTESTATION_TEXT,
                )
        with app.state.repository.engine.connect() as connection:
            assert connection.execute(select(repository_quota_reservations)).first() is None
    finally:
        app.state.repository.close()


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_read_only_lead_assignment_cannot_create_repository_asset_api(
    tmp_path: Path, role: str
) -> None:
    from chinescan.core.accounts import operator_auth_epoch
    from chinescan.core.storage.sqlite import engagement_assets

    app, owner, org, engagement, _project, _asset, _scope, _authorization = _workspace(tmp_path)
    repository = app.state.repository
    email = f"{role}-repository-lead@example.test"
    user_id = str(uuid4())
    epoch = operator_auth_epoch(tmp_path / "private-state" / "operator.json")
    user, _personal_org = app.state.organization_service.ensure_operator(email, epoch, user_id)
    app.state.organization_service.add_member(owner, org, user_id, role)
    app.state.organization_service.change_assignment(owner, org, engagement, user_id, role="lead")
    token, session = app.state.session_store.create(email, user["auth_epoch"], user_id=user_id)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50201))
    try:
        client.cookies.set("chinescan_session", token)
        with repository.engine.connect() as connection:
            before = connection.execute(
                select(engagement_assets.c.id).where(
                    engagement_assets.c.organization_id == org,
                    engagement_assets.c.engagement_id == engagement,
                )
            ).all()
        response = client.post(
            f"/api/organizations/{org}/engagements/{engagement}/repositories",
            json={"description": "Must not be created"},
            headers={
                "Origin": "http://127.0.0.1",
                "X-CSRF-Token": session.csrf_token,
            },
        )
        assert response.status_code == 404
        with repository.engine.connect() as connection:
            after = connection.execute(
                select(engagement_assets.c.id).where(
                    engagement_assets.c.organization_id == org,
                    engagement_assets.c.engagement_id == engagement,
                )
            ).all()
        assert after == before
    finally:
        client.close()
        repository.close()


def test_repository_snapshot_rejects_linked_entries_and_releases_failed_quota_reservation(
    tmp_path: Path,
) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        source = tmp_path / "operator-projects" / "source"
        outside = tmp_path / "outside-secret.txt"
        outside.write_text("must not be copied", encoding="utf-8")
        linked = source / "linked.txt"
        try:
            linked.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("The Windows environment does not permit creating a symlink for this test.")
        store = app.state.repository_snapshot_store
        with pytest.raises(RepositorySnapshotError, match="unsafe"):
            store.create(org, source)
        with app.state.repository.engine.connect() as connection:
            assert connection.execute(select(repository_quota_reservations)).first() is None
        assert (
            not list((store.root / org).glob(".snapshot-*"))
            if (store.root / org).exists()
            else True
        )
    finally:
        app.state.repository.close()


def test_repository_snapshot_limits_are_enforced_and_failed_copy_leaves_no_accounting(
    tmp_path: Path,
) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        store = app.state.repository_snapshot_store
        store.max_snapshot_bytes = 4
        with pytest.raises(RepositorySnapshotError) as error:
            app.state.repository_assessment_service.bind(
                owner,
                org,
                engagement,
                asset["id"],
                project["project_id"],
                authorization["id"],
                scope["id"],
                ATTESTATION_TEXT,
            )
        assert error.value.code == "snapshot_too_large"
        with app.state.repository.engine.connect() as connection:
            assert connection.execute(select(repository_quota_reservations)).first() is None
            assert connection.execute(select(repository_snapshots)).first() is None
    finally:
        app.state.repository.close()


def test_concurrent_snapshot_reservations_cannot_exceed_organization_quota(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        store = app.state.repository_snapshot_store
        store.max_snapshot_bytes = 8
        store.organization_quota_bytes = 10
        roots = [tmp_path / "quota-a", tmp_path / "quota-b"]
        for index, root in enumerate(roots):
            root.mkdir()
            (root / "source.txt").write_text(f"data-{index}", encoding="utf-8")

        def create(root: Path) -> str:
            try:
                store.create(org, root)
                return "created"
            except RepositorySnapshotError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(create, roots))
        assert sorted(outcomes) == ["created", "organization_quota_exceeded"]
        with app.state.repository.engine.connect() as connection:
            committed = (
                connection.execute(
                    select(repository_snapshots.c.size_bytes).where(
                        repository_snapshots.c.organization_id == org,
                        repository_snapshots.c.status != "deleted",
                    )
                )
                .scalars()
                .all()
            )
            reservations = connection.execute(select(repository_quota_reservations)).all()
        assert sum(committed) <= store.organization_quota_bytes
        assert not reservations
    finally:
        app.state.repository.close()


def test_scope_revision_change_denies_existing_repository_binding(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        service = app.state.repository_assessment_service
        bound = service.bind(
            owner,
            org,
            engagement,
            asset["id"],
            project["project_id"],
            authorization["id"],
            scope["id"],
            ATTESTATION_TEXT,
        )
        assert bound is not None
        job = app.state.execution_governance.create_governed_job(
            owner,
            org,
            engagement,
            asset["id"],
            technique=REPOSITORY_TECHNIQUE,
            approval_id=None,
            idempotency_key="repository-stale-scope-001",
            repository_binding_id=bound["binding_id"],
            repository_attestation_id=bound["attestation_id"],
        )
        assert job["status"] == "queued"
        security = app.state.engagement_security_service
        replacement = security.create_scope_revision(
            owner,
            org,
            engagement,
            [
                {
                    "asset_id": asset["id"],
                    "effect": "include",
                    "match_mode": "exact",
                    "techniques": [REPOSITORY_TECHNIQUE],
                },
                {
                    "asset_id": asset["id"],
                    "effect": "exclude",
                    "match_mode": "exact",
                    "techniques": [REPOSITORY_TECHNIQUE],
                },
            ],
            "Exclude repository from scope",
        )
        with app.state.repository.engine.connect() as connection:
            reviewer = connection.execute(
                select(users.c.id).where(users.c.email_normalized == "reviewer@example.test")
            ).scalar_one()
        security.publish_scope_revision(reviewer, org, engagement, replacement["id"])
        outcome = app.state.governed_domain_worker.run_one(job["id"])
        assert outcome is not None and outcome["status"] == "blocked"
    finally:
        app.state.repository.close()


def test_repository_retention_hold_blocks_then_allows_explicit_deletion(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        service = app.state.repository_assessment_service
        bound = service.bind(
            owner,
            org,
            engagement,
            asset["id"],
            project["project_id"],
            authorization["id"],
            scope["id"],
            ATTESTATION_TEXT,
        )
        assert bound is not None
        closed_at = datetime.now(UTC) - timedelta(days=100)
        delete_after = closed_at + timedelta(days=90)
        with app.state.repository.engine.begin() as connection:
            connection.execute(
                update(engagements)
                .where(engagements.c.id == engagement)
                .values(
                    status="completed",
                    closed_at=closed_at.isoformat(),
                )
            )
            connection.execute(
                update(repository_snapshots)
                .where(repository_snapshots.c.id == bound["snapshot_id"])
                .values(closed_at=closed_at.isoformat(), delete_after=delete_after.isoformat())
            )
        assert app.state.repository_snapshot_store.hold(
            owner, org, engagement, bound["snapshot_id"], "Preserve for investigation"
        )
        with pytest.raises(RepositorySnapshotError) as error:
            app.state.repository_snapshot_store.delete_eligible(
                owner, org, engagement, bound["snapshot_id"]
            )
        assert error.value.code == "snapshot_on_hold"
        assert app.state.repository_snapshot_store.release_hold(
            owner, org, engagement, bound["snapshot_id"], "Investigation complete"
        )
        assert app.state.repository_snapshot_store.delete_eligible(
            owner, org, engagement, bound["snapshot_id"]
        )
        with app.state.repository.engine.connect() as connection:
            status = connection.execute(
                select(repository_snapshots.c.status).where(
                    repository_snapshots.c.id == bound["snapshot_id"]
                )
            ).scalar_one()
        assert status == "deleted"
        assert not app.state.repository_snapshot_store._snapshot_path(
            org, bound["snapshot_sha256"]
        ).exists()
    finally:
        app.state.repository.close()


def test_repository_configuration_rejects_quota_smaller_than_snapshot(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least the per-snapshot limit"):
        Settings(
            _env_file=None,
            allowed_roots=[tmp_path],
            repository_snapshot_max_bytes=20,
            repository_snapshot_org_quota_bytes=19,
        )


def test_backup_includes_snapshot_and_database_only_bundle_is_incomplete(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    db_path = Path(app.state.repository.path)
    bound = app.state.repository_assessment_service.bind(
        owner,
        org,
        engagement,
        asset["id"],
        project["project_id"],
        authorization["id"],
        scope["id"],
        ATTESTATION_TEXT,
    )
    assert bound is not None
    app.state.repository.close()
    bundle = tmp_path / "complete-backup"
    result = backup_database(db_path, bundle)
    assert result.verification.verified
    assert (bundle / "repository-snapshots" / org / bound["snapshot_sha256"] / "app.py").is_file()

    destination_dir = tmp_path / "restored-state"
    destination_dir.mkdir()
    restored = restore_backup(bundle, destination_dir / "restored.sqlite3")
    assert restored.resulting_revision == "0016_phase6_governance"
    assert (
        destination_dir / "repository-snapshots" / org / bound["snapshot_sha256"] / "app.py"
    ).is_file()

    database_only = tmp_path / "database-only-copy"
    backup_database(db_path, database_only)
    import shutil

    shutil.rmtree(database_only / "repository-snapshots")
    verification = verify_backup(database_only)
    assert not verification.verified
    assert "repository_snapshot_content_missing_or_corrupt" in verification.structural_errors


def test_repository_api_requires_session_and_never_returns_registered_roots(tmp_path: Path) -> None:
    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        root = f"/api/organizations/{org}/engagements/{engagement}/repositories"
        assert client.get(root + "/projects").status_code == 401
        login = client.post(
            "/api/auth/login",
            json={
                "email": "lead@example.test",
                "password": "synthetic-passphrase-long-998!secure",
            },
            headers={"Origin": "http://127.0.0.1"},
        )
        assert login.status_code == 200
        headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
        projects = client.get(root + "/projects")
        assert projects.status_code == 200
        assert projects.json()["items"][0]["project_registry_id"] == project["project_id"]
        assert str(tmp_path / "operator-projects" / "source") not in projects.text
        assert "repository-snapshots" not in projects.text
        assert client.get(root + "/attestation").status_code == 200
        assert client.get(root + "/retention").status_code == 200
        created = client.post(root, json={"description": "API repository"}, headers=headers)
        assert created.status_code == 201
        assert created.json()["target"].startswith("repo:")
        assert str(tmp_path / "operator-projects" / "source") not in created.text
        rejected = client.post(
            root, json={"target": str(tmp_path), "root": str(tmp_path)}, headers=headers
        )
        assert rejected.status_code == 422
    finally:
        app.state.repository.close()


def test_governed_cli_executes_bound_snapshot_and_records_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from chinescan.cli import commands
    from chinescan.cli.app import app as cli_app

    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        # A synthetic environment file deterministically exercises finding
        # persistence without placing real credentials in the test snapshot.
        (tmp_path / "operator-projects" / "source" / ".env").write_text(
            "EXAMPLE_ONLY=not-a-secret\n", encoding="utf-8"
        )
        bound = app.state.repository_assessment_service.bind(
            owner,
            org,
            engagement,
            asset["id"],
            project["project_id"],
            authorization["id"],
            scope["id"],
            ATTESTATION_TEXT,
        )
        assert bound is not None
        state = tmp_path / "private-state"
        settings = Settings(
            _env_file=None,
            database_path=state / "test.sqlite3",
            reports_dir=state / "reports",
            allowed_roots=[tmp_path / "operator-projects"],
        )
        monkeypatch.setattr(commands, "_settings", lambda: settings)
        monkeypatch.setattr(
            commands, "getpass", lambda _prompt: "synthetic-passphrase-long-998!secure"
        )
        result = CliRunner().invoke(
            cli_app,
            [
                "code-engagement",
                "--organization-id",
                org,
                "--engagement-id",
                engagement,
                "--asset-id",
                asset["id"],
                "--credential-file",
                str(state / "operator.json"),
                "--idempotency-key",
                "governed-cli-test-key",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["status"] == "completed"
        assert payload["asset_id"] == asset["id"]
        assert payload["repository_snapshot_id"] == bound["snapshot_id"]
        assert payload["repository_snapshot_sha256"] == bound["snapshot_sha256"]
        assert "operator-projects" not in result.stdout

        with app.state.repository.engine.connect() as connection:
            job = connection.execute(
                select(execution_jobs).where(execution_jobs.c.id == payload["id"])
            ).one()
            provenance = connection.execute(
                select(execution_result_provenance).where(
                    execution_result_provenance.c.job_id == payload["id"]
                )
            ).all()
        assert job.status == "completed"
        assert provenance
        assert {row.record_type for row in provenance} >= {"scan", "finding"}
    finally:
        app.state.repository.close()


def test_governed_cli_denial_never_falls_back_to_standalone_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from chinescan.cli import commands
    from chinescan.cli.app import app as cli_app

    app, owner, org, engagement, project, asset, scope, authorization = _workspace(tmp_path)
    try:
        bound = app.state.repository_assessment_service.bind(
            owner,
            org,
            engagement,
            asset["id"],
            project["project_id"],
            authorization["id"],
            scope["id"],
            ATTESTATION_TEXT,
        )
        assert bound is not None
        with app.state.repository.engine.begin() as connection:
            connection.execute(
                update(authorization_records)
                .where(authorization_records.c.id == authorization["id"])
                .values(status="revoked")
            )
        state = tmp_path / "private-state"
        settings = Settings(
            _env_file=None,
            database_path=state / "test.sqlite3",
            reports_dir=state / "reports",
            allowed_roots=[tmp_path / "operator-projects"],
        )
        monkeypatch.setattr(commands, "_settings", lambda: settings)
        monkeypatch.setattr(
            commands, "getpass", lambda _prompt: "synthetic-passphrase-long-998!secure"
        )
        legacy_calls: list[Path] = []

        def legacy_scan(_self, target: Path, **_kwargs):
            legacy_calls.append(target)
            raise AssertionError("Governed denial must not invoke the standalone scanner")

        monkeypatch.setattr(commands.CodeScanService, "scan", legacy_scan)
        result = CliRunner().invoke(
            cli_app,
            [
                "code-engagement",
                "--organization-id",
                org,
                "--engagement-id",
                engagement,
                "--asset-id",
                asset["id"],
                "--credential-file",
                str(state / "operator.json"),
            ],
        )
        assert result.exit_code == 2
        assert "authorization_missing_or_invalid" in result.output.lower()
        assert legacy_calls == []
        with app.state.repository.engine.connect() as connection:
            assert connection.execute(select(execution_jobs)).first() is None
    finally:
        app.state.repository.close()
