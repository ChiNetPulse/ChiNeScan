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
from chinescan.core.log_evidence import LogEvidenceError, LogEvidenceStore
from chinescan.core.storage.recovery import backup_database, restore_backup, verify_backup
from chinescan.core.storage.sqlite import (
    approval_requests,
    assessment_audit_events,
    engagements,
    execution_result_provenance,
    log_evidence_quota_reservations,
    log_evidence_snapshots,
    records,
    users,
)
from chinescan.web.app import create_app


def _workspace(tmp_path: Path):
    allowed = tmp_path / "allowed"
    state = tmp_path / "state"
    allowed.mkdir()
    state.mkdir()
    source = allowed / "events.jsonl"
    source.write_text(
        json.dumps({
            "timestamp": "2026-11-24T10:00:00Z",
            "message": (
                "login failed password=LogSecret-998! "
                "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
            ),
            "principalEmail": "alice@example.test",
        }) + "\n",
        encoding="utf-8",
    )
    credential = state / "operator.json"
    create_operator(credential, "lead@example.test", "synthetic-passphrase-long-998!secure")
    log_sources = state / "log-sources.toml"
    log_sources.write_text(
        f'[[sources]]\nid = "synthetic"\nname = "Synthetic logs"\nroot = "{allowed.as_posix()}"\n',
        encoding="utf-8",
    )
    settings = Settings(
        _env_file=None, allowed_roots=[allowed], reports_dir=state / "reports",
        log_evidence_max_bytes=1_000_000, log_evidence_org_quota_bytes=2_000_000,
    )
    app = create_app(
        state / "test.sqlite3", credential, serve_frontend=False,
        settings=settings, projects_path=state / "projects.toml", log_sources_path=log_sources,
    )
    repository = app.state.repository
    organizations = app.state.organization_service
    security = app.state.engagement_security_service
    with repository.engine.connect() as connection:
        owner = connection.execute(select(users.c.id)).scalar_one()
    org = organizations.accessible_organizations(owner)[0]["id"]
    client = organizations.create_client(owner, org, "Synthetic client", None)
    engagement = organizations.create_engagement(
        owner, org, client["id"], "Log review", "Synthetic evidence", "active"
    )
    reviewer = str(uuid4())
    now = datetime.now(UTC).isoformat()
    with repository.engine.begin() as connection:
        connection.execute(insert(users).values(
            id=reviewer, email_normalized="reviewer@example.test", display_name="Reviewer",
            status="active", auth_epoch="test", created_at=now, updated_at=now,
        ))
    organizations.add_member(owner, org, reviewer, "member")
    organizations.change_assignment(owner, org, engagement["id"], reviewer, role="reviewer")
    store = app.state.log_evidence_store
    registered = store.register(
        owner, org, engagement["id"], source, "Synthetic access log", security
    )
    assert registered is not None
    scope = security.create_scope_revision(owner, org, engagement["id"], [{
        "asset_id": registered["asset_id"], "effect": "include", "match_mode": "exact",
        "techniques": ["log_analysis"],
    }], "Include exact registered log evidence")
    published = security.publish_scope_revision(reviewer, org, engagement["id"], scope["id"])
    authorization = security.create_authorization(
        owner, org, engagement["id"], published["id"], "LOG-TEST-1", "Synthetic client",
        ["log_analysis"], datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )
    return app, owner, org, engagement["id"], source, registered, authorization


def test_governed_log_analysis_uses_snapshot_redacts_results_and_records_provenance(
    tmp_path: Path,
) -> None:
    app, owner, org, engagement, source, evidence, _authorization = _workspace(tmp_path)
    try:
        snapshot, snapshot_root = app.state.log_evidence_store.verify(
            org, engagement, evidence["asset_id"], evidence["snapshot_id"]
        )
        assert snapshot and snapshot_root
        original = (snapshot_root / "events.jsonl").read_text(encoding="utf-8")
        source.write_text("changed after evidence registration", encoding="utf-8")
        assert (snapshot_root / "events.jsonl").read_text(encoding="utf-8") == original

        job = app.state.execution_governance.create_governed_job(
            owner, org, engagement, evidence["asset_id"], technique="log_analysis",
            approval_id=None, idempotency_key="governed-log-analysis-test-1",
        )
        assert job["status"] == "queued"
        assert job["log_evidence_snapshot_id"] == evidence["snapshot_id"]
        assert job["log_evidence_sha256"] == evidence["sha256"]
        outcome = app.state.governed_domain_worker.run_one(job["id"])
        assert outcome and outcome["status"] == "completed", (
            outcome,
            app.state.execution_governance.get_job(owner, org, job["id"]),
            len(calls),
        )
        assert outcome["scan_id"]
        provenance = app.state.execution_governance.get_job_provenance(
            owner, org, engagement, job["id"]
        )
        assert provenance and any(row["record_type"] == "scan" for row in provenance["results"])
        with app.state.repository.engine.connect() as connection:
            scan_json = connection.execute(select(records.c.payload).where(
                records.c.record_type == "scan", records.c.record_id == outcome["scan_id"]
            )).scalar_one()
            persisted = json.dumps(scan_json)
            all_payloads = " ".join(
                str(row[0]) for row in connection.execute(select(records.c.payload)).all()
            )
            assert connection.execute(select(execution_result_provenance).where(
                execution_result_provenance.c.job_id == job["id"]
            )).first() is not None
        assert "LogSecret-998" not in persisted + all_payloads
        assert "alice@example.test" not in all_payloads
        assert "abcdefghijklmnopqrstuvwxyz0123456789" not in all_payloads
        assert str(source) not in all_payloads
    finally:
        app.state.repository.close()


def test_governed_chain_import_runs_from_registered_snapshot_with_provenance(tmp_path: Path) -> None:
    app, owner, org, engagement, source, _evidence, _authorization = _workspace(tmp_path)
    try:
        chain_source = source.parent / "chain-export.json"
        chain_source.write_text(json.dumps([{
            "chain": "ethereum",
            "tx_hash": "0x" + "1" * 64,
            "sender": "0x" + "a" * 40,
            "receiver": "0x" + "b" * 40,
            "amount": "1",
            "block_time": 10,
        }]), encoding="utf-8")
        registered = app.state.log_evidence_store.register(
            owner, org, engagement, chain_source, "Synthetic chain export",
            app.state.engagement_security_service,
        )
        assert registered
        scope = app.state.engagement_security_service.create_scope_revision(
            owner, org, engagement, [{
                "asset_id": registered["asset_id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": ["chain_trace_import"],
            }], "Include registered chain-trace input",
        )
        with app.state.repository.engine.connect() as connection:
            reviewer = connection.execute(select(users.c.id).where(
                users.c.email_normalized == "reviewer@example.test"
            )).scalar_one()
        published = app.state.engagement_security_service.publish_scope_revision(
            reviewer, org, engagement, scope["id"]
        )
        app.state.engagement_security_service.create_authorization(
            owner, org, engagement, published["id"], "CHAIN-TEST-1", "Synthetic client",
            ["chain_trace_import"], datetime.now(UTC).isoformat(),
            (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        )
        job = app.state.execution_governance.create_governed_job(
            owner, org, engagement, registered["asset_id"],
            technique="chain_trace_import", approval_id=None,
            idempotency_key="governed-chain-import-test-01",
            chain_request={"chain": "ethereum", "seed": "0x" + "a" * 40, "depth": 2},
        )
        assert job["status"] == "queued"
        outcome = app.state.governed_domain_worker.run_one(job["id"])
        assert outcome and outcome["status"] == "completed", (
            outcome,
            app.state.execution_governance.get_job(owner, org, job["id"]),
            len(calls),
        )
        provenance = app.state.execution_governance.get_job_provenance(
            owner, org, engagement, job["id"]
        )
        assert provenance and any(item["record_type"] == "scan" for item in provenance["results"])
    finally:
        app.state.repository.close()


def test_governed_chain_provider_consumes_approval_before_fixed_root_lookup(tmp_path: Path) -> None:
    from chinescan.core.chain_trace_execution import GovernedChainProviderAdapter
    from chinescan.core.execution_adapters import build_default_adapter_registry

    app, owner, org, engagement, _source, _evidence, _authorization = _workspace(tmp_path)
    try:
        security = app.state.engagement_security_service
        with app.state.repository.engine.connect() as connection:
            reviewer = connection.execute(select(users.c.id).where(
                users.c.email_normalized == "reviewer@example.test"
            )).scalar_one()
        target = "chain:ethereum:etherscan-v2:0x" + "a" * 40
        asset = security.create_asset(owner, org, engagement, "chain_address", target)
        assert asset
        scope = security.create_scope_revision(owner, org, engagement, [{
            "asset_id": asset["id"], "effect": "include", "match_mode": "exact",
            "techniques": ["chain_provider_lookup"],
        }], "Include exact chain address")
        published = security.publish_scope_revision(reviewer, org, engagement, scope["id"])
        security.create_authorization(
            owner, org, engagement, published["id"], "CHAIN-PROVIDER-TEST-1",
            "Synthetic client", ["chain_provider_lookup"], datetime.now(UTC).isoformat(),
            (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        )
        approval = security.create_approval_request(
            owner, org, engagement, "chain_address", asset["target"],
            "chain_provider_lookup",
        )
        assert approval
        assert security.decide_approval(
            reviewer, org, engagement, approval["id"], "approved", "Synthetic approval"
        )
        calls: list[tuple[str, dict[str, object]]] = []

        class Response:
            status_code = 200
            content_type = "application/json"

            @staticmethod
            def json() -> dict[str, object]:
                return {"status": "1", "message": "OK", "result": []}

        def transport(url: str, **kwargs: object) -> Response:
            calls.append((url, kwargs))
            return Response()

        provider = GovernedChainProviderAdapter(
            app.state.repository, api_key="synthetic-key", http_get=transport
        )
        registry = build_default_adapter_registry(
            app.state.repository, chain_provider_adapter=provider
        )
        app.state.execution_governance.adapters = registry
        app.state.governed_domain_worker.adapters = registry
        job = app.state.execution_governance.create_governed_job(
            owner, org, engagement, asset["id"],
            technique="chain_provider_lookup", approval_id=approval["id"],
            idempotency_key="governed-chain-provider-test-01",
        )
        assert job["status"] == "queued"
        outcome = app.state.governed_domain_worker.run_one(job["id"])
        final_job = app.state.execution_governance.get_job(owner, org, job["id"])
        assert outcome and outcome["status"] == "completed", (
            outcome,
            final_job and {key: final_job.get(key) for key in ("status", "error_code", "approval_consumed_at")},
            len(calls),
        )
        assert len(calls) == 3
        assert all(
            call[1]["params"]["address"] == "0x" + "a" * 40
            for call in calls
        )
        with app.state.repository.engine.connect() as connection:
            consumed = connection.execute(select(approval_requests.c.consumed_at).where(
                approval_requests.c.id == approval["id"]
            )).scalar_one()
        assert consumed
        provenance = app.state.execution_governance.get_job_provenance(
            owner, org, engagement, job["id"]
        )
        assert provenance and provenance["execution_context"]["chain_context"]["provider"] == "etherscan-v2"
    finally:
        app.state.repository.close()


def test_corrupt_evidence_blocks_worker_and_records_integrity_failure(tmp_path: Path) -> None:
    app, owner, org, engagement, _source, evidence, _authorization = _workspace(tmp_path)
    try:
        _snapshot, root = app.state.log_evidence_store.verify(
            org, engagement, evidence["asset_id"], evidence["snapshot_id"]
        )
        assert root
        (root / "events.jsonl").write_text("tampered", encoding="utf-8")
        job = app.state.execution_governance.create_governed_job(
            owner, org, engagement, evidence["asset_id"], technique="log_analysis",
            approval_id=None, idempotency_key="governed-log-analysis-corrupt",
        )
        outcome = app.state.governed_domain_worker.run_one(job["id"])
        assert outcome and outcome["status"] == "failed"
        with app.state.repository.engine.connect() as connection:
            status = connection.execute(select(log_evidence_snapshots.c.status).where(
                log_evidence_snapshots.c.id == evidence["snapshot_id"]
            )).scalar_one()
            audit = connection.execute(select(assessment_audit_events).where(
                assessment_audit_events.c.action == "log_evidence.integrity_failed"
            )).first()
        assert status == "corrupt"
        assert audit is not None
    finally:
        app.state.repository.close()


def test_evidence_registration_rejects_outside_roots_and_releases_failed_reservations(
    tmp_path: Path,
) -> None:
    app, owner, org, engagement, _source, _evidence, _authorization = _workspace(tmp_path)
    try:
        outside = tmp_path / "outside.log"
        outside.write_text("synthetic", encoding="utf-8")
        store: LogEvidenceStore = app.state.log_evidence_store
        with pytest.raises(LogEvidenceError, match="outside_allowed_roots"):
            store.register(
                owner, org, engagement, outside, "outside", app.state.engagement_security_service
            )
        store.max_snapshot_bytes = 2
        allowed_source = tmp_path / "allowed" / "large.log"
        allowed_source.write_text("more than two bytes", encoding="utf-8")
        with pytest.raises(LogEvidenceError, match="size_limit"):
            store.register(
                owner, org, engagement, allowed_source, "oversized",
                app.state.engagement_security_service,
            )
        with app.state.repository.engine.connect() as connection:
            assert connection.execute(select(log_evidence_quota_reservations)).first() is None
    finally:
        app.state.repository.close()


def test_log_evidence_registration_rejects_linked_source_paths(tmp_path: Path) -> None:
    app, owner, org, engagement, source, _evidence, _authorization = _workspace(tmp_path)
    linked = source.parent / "linked.jsonl"
    try:
        try:
            linked.symlink_to(source)
        except (OSError, NotImplementedError):
            pytest.skip(
                "The current Windows account cannot create a symlink in the test directory."
            )
        with pytest.raises(LogEvidenceError, match="source_unsafe"):
            app.state.log_evidence_store.register(
                owner, org, engagement, linked, "Linked input",
                app.state.engagement_security_service,
            )
    finally:
        app.state.repository.close()


def test_log_evidence_hold_blocks_deletion_and_explicit_deletion_preserves_metadata(
    tmp_path: Path,
) -> None:
    app, owner, org, engagement, _source, evidence, _authorization = _workspace(tmp_path)
    try:
        with app.state.repository.engine.begin() as connection:
            connection.execute(update(engagements).where(
                engagements.c.id == engagement,
                engagements.c.organization_id == org,
            ).values(status="completed", closed_at=datetime.now(UTC).isoformat()))
        store = app.state.log_evidence_store
        assert store.list_for(owner, org, engagement, app.state.engagement_security_service)[0][
            "deletion_eligible"
        ]
        assert store.place_hold_for_asset(
            owner, org, engagement, evidence["asset_id"], "Preserve for investigation",
            app.state.engagement_security_service,
        )
        held = store.list_for(owner, org, engagement, app.state.engagement_security_service)[0]
        assert held["legal_hold"] is True
        assert held["deletion_eligible"] is False
        assert not store.delete_asset(
            owner, org, engagement, evidence["asset_id"], app.state.engagement_security_service
        )
        with app.state.repository.engine.begin() as connection:
            connection.execute(update(log_evidence_snapshots).where(
                log_evidence_snapshots.c.id == evidence["snapshot_id"]
            ).values(legal_hold=0, hold_reason=None))
        assert store.delete_asset(
            owner, org, engagement, evidence["asset_id"], app.state.engagement_security_service
        )
        with app.state.repository.engine.connect() as connection:
            row = connection.execute(select(log_evidence_snapshots).where(
                log_evidence_snapshots.c.id == evidence["snapshot_id"]
            )).first()
            audit = connection.execute(select(assessment_audit_events).where(
                assessment_audit_events.c.action == "log_evidence.deletion_recorded"
            )).first()
        assert row is not None and row.status == "deleted" and row.sha256 == evidence["sha256"]
        assert audit is not None
        assert not (store.root / org / evidence["sha256"]).exists()
    finally:
        app.state.repository.close()


def test_log_evidence_backup_and_restore_include_snapshot_content(tmp_path: Path) -> None:
    app, _owner, _org, _engagement, _source, evidence, _authorization = _workspace(tmp_path)
    db_path = Path(app.state.repository.path)
    app.state.repository.close()
    bundle = tmp_path / "bundle"
    backup = backup_database(db_path, bundle)
    assert backup.verification.verified
    snapshot_file = bundle / "log-evidence-snapshots" / _org / evidence["sha256"] / "events.jsonl"
    assert snapshot_file.is_file()
    assert verify_backup(bundle).verified

    restore_dir = tmp_path / "restore"
    restore_dir.mkdir()
    restored = restore_backup(bundle, restore_dir / "restored.sqlite3")
    assert restored.resulting_revision == "0015_durable_job_leases_actions"
    restored_snapshot_file = (
        restore_dir / "log-evidence-snapshots" / _org / evidence["sha256"] / "events.jsonl"
    )
    assert restored_snapshot_file.is_file()


def test_governed_log_evidence_api_is_authenticated_tenant_scoped_and_path_free(
    tmp_path: Path,
) -> None:
    app, owner, org, engagement, _source, evidence, _authorization = _workspace(tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    base = f"/api/organizations/{org}/engagements/{engagement}/log-evidence"
    try:
        assert client.get(base).status_code == 401
        login = client.post(
            "/api/auth/login",
            json={"email": "lead@example.test", "password": "synthetic-passphrase-long-998!secure"},
            headers={"Origin": "http://127.0.0.1"},
        )
        assert login.status_code == 200
        headers = {
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": login.json()["csrf_token"],
            "X-ChineScan-Organization-ID": org,
        }
        listed = client.get(base, headers=headers)
        assert listed.status_code == 200
        body = listed.json()
        assert body["items"][0]["snapshot_id"] == evidence["snapshot_id"]
        assert "managed" not in json.dumps(body).casefold()
        assert str(_source) not in json.dumps(body)
        sources = client.get(f"{base}/sources", headers=headers)
        assert sources.status_code == 200
        assert sources.json()["items"] == [
            {"source_id": "synthetic", "display_name": "Synthetic logs"}
        ]
        assert str(_source) not in sources.text
        registered = client.post(
            base,
            json={"source_id": "synthetic", "label": "Synthetic second source"},
            headers=headers,
        )
        assert registered.status_code == 201
        assert str(_source) not in registered.text
        denied = client.get(
            f"/api/organizations/{uuid4()}/engagements/{engagement}/log-evidence",
            headers=headers,
        )
        assert denied.status_code == 404
    finally:
        client.close()
        app.state.repository.close()
