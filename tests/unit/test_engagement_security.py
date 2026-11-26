from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from chinescan.core.accounts import create_operator
from chinescan.core.engagement_security import (
    EngagementSecurityError,
    normalize_target,
)
from chinescan.core.storage.sqlite import (
    approval_requests,
    assessment_audit_events,
    execution_jobs,
    execution_result_provenance,
    records,
    users,
)
from chinescan.web.app import create_app


def _setup(tmp_path: Path):
    credential = tmp_path / "operator.json"
    create_operator(credential, "owner@example.test", "synthetic-secure-passphrase-77!")
    app = create_app(tmp_path / "phase1c.sqlite3", credential, serve_frontend=False)
    repo = app.state.repository
    orgs = app.state.organization_service
    with repo.engine.connect() as connection:
        owner_id = connection.execute(select(users.c.id)).scalar_one()
    client = orgs.create_client(
        owner_id, orgs.accessible_organizations(owner_id)[0]["id"], "Example Client", None
    )
    org_id = client["organization_id"]
    engagement = orgs.create_engagement(
        owner_id, org_id, client["id"], "Assessment", "Synthetic test", "active"
    )
    reviewer_id = str(uuid4())
    stamp = datetime.now(UTC).isoformat()
    with repo.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=reviewer_id,
                email_normalized="reviewer@example.test",
                display_name="Reviewer",
                status="active",
                auth_epoch="synthetic",
                created_at=stamp,
                updated_at=stamp,
            )
        )
    orgs.add_member(owner_id, org_id, reviewer_id, "member")
    orgs.change_assignment(owner_id, org_id, engagement["id"], reviewer_id, role="reviewer")
    service = app.state.engagement_security_service
    asset = service.create_asset(owner_id, org_id, engagement["id"], "domain", "Example.test")
    scope = service.create_scope_revision(
        owner_id,
        org_id,
        engagement["id"],
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "subdomains",
                "techniques": ["http_metadata", "service_fingerprint", "exploit_verification"],
            },
            {"asset_id": asset["id"], "effect": "exclude", "match_mode": "exact", "techniques": []},
        ],
        "Initial authorized scope",
    )
    published = service.publish_scope_revision(reviewer_id, org_id, engagement["id"], scope["id"])
    auth = service.create_authorization(
        owner_id,
        org_id,
        engagement["id"],
        published["id"],
        "AUTH-1",
        "Example Client",
        ["http_metadata", "service_fingerprint", "exploit_verification"],
        datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )
    return app, owner_id, reviewer_id, org_id, engagement["id"], asset, published, auth


def _result_adapter(
    repository,
    *,
    finding_id: str,
    scan_id: str,
    status: str = "complete",
    after_records=None,
):
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.models.common import EvidenceKind
    from chinescan.core.models.finding import Finding
    from chinescan.core.models.investigation import Scan, Target

    class ResultAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.result-provenance",
            techniques=("service_fingerprint",),
            target_types=("domain",),
            action_class="controlled_active",
            enabled=True,
            performs_external_operations=False,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, context, _parameters, control) -> AdapterResult:
            now = datetime.now(UTC)
            repository.save(
                "target",
                context.asset_id,
                Target(value=context.target, kind=context.asset_type).model_dump(mode="json"),
            )
            repository.save(
                "scan",
                scan_id,
                Scan(
                    scan_id=scan_id,
                    target_id=context.asset_id,
                    scanner=self.capabilities.adapter_id,
                    started_at=now,
                    finished_at=now,
                    status=status,
                    finding_ids=[finding_id],
                ).model_dump(mode="json"),
            )
            repository.save(
                "finding",
                finding_id,
                Finding(
                    finding_id=finding_id,
                    title="Synthetic governed finding",
                    fingerprint=f"synthetic-{finding_id}",
                    scanner=self.capabilities.adapter_id,
                    rule_id="synthetic.rule",
                    evidence=EvidenceKind.CONFIRMED_ARTIFACT,
                    code_excerpt="synthetic evidence excerpt",
                ).model_dump(mode="json"),
            )
            if after_records is not None:
                after_records()
            control.check_cancelled()
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="partial" if status == "partial" else "complete",
                result_id=scan_id,
                summary={"finding_count": 1},
            )

    return AdapterRegistry((ResultAdapter(),))


def test_target_normalization_and_strict_networks() -> None:
    ambiguous_numeric_hosts = (
        "127.1",
        "127.0.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
    )
    unicode_numeric_hosts = (
        "１２７。１",
        "０１７７。０。０。１",
        "１２７．１",
        "２１３０７０６４３３",
        "０ｘ７ｆ０００００１",
    )
    assert normalize_target("domain", "BÜCHER.example") == "xn--bcher-kva.example"
    assert normalize_target("domain", "example.com") == "example.com"
    assert normalize_target("ip", "2001:0db8::1") == "2001:db8::1"
    assert normalize_target("cidr", "192.0.2.0/24") == "192.0.2.0/24"
    assert normalize_target("url", "HTTPS://Example.test:443/a") == "https://example.test/a"
    assert normalize_target("url", "https://BÜCHER.example/a") == "https://xn--bcher-kva.example/a"
    for host in (*ambiguous_numeric_hosts, *unicode_numeric_hosts):
        with pytest.raises(EngagementSecurityError):
            normalize_target("domain", host)
        with pytest.raises(EngagementSecurityError):
            normalize_target("url", f"http://{host}/")
    with pytest.raises(EngagementSecurityError):
        normalize_target("cidr", "192.0.2.1/24")
    with pytest.raises(EngagementSecurityError):
        normalize_target("url", "https://user:pass@example.test/")


def test_ambiguous_numeric_targets_cannot_receive_policy_allow(tmp_path: Path) -> None:
    app, owner, _reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    hosts = (
        "127.1",
        "127.0.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "１２７。１",
        "０１７７。０。０。１",
        "１２７．１",
        "２１３０７０６４３３",
        "０ｘ７ｆ０００００１",
    )
    initial_assets = service.list_assets(owner, org, engagement)
    assert initial_assets is not None
    for host in hosts:
        for asset_type, target in (("domain", host), ("url", f"http://{host}/")):
            with pytest.raises(EngagementSecurityError):
                service.create_asset(owner, org, engagement, asset_type, target)
            with pytest.raises(EngagementSecurityError):
                service.evaluate_policy(owner, org, engagement, asset_type, target, "http_metadata")
    assert service.list_assets(owner, org, engagement) == initial_assets


def test_malformed_authorization_timestamps_return_422(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, _owner, _reviewer, org, engagement, _asset, scope, _auth = _setup(tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
    endpoint = f"/api/organizations/{org}/engagements/{engagement}/authorizations"
    valid_start = datetime.now(UTC).isoformat()
    valid_end = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    for field in ("effective_at", "expires_at"):
        payload = {
            "scope_revision_id": scope["id"],
            "authorization_reference": f"AUTH-BAD-{field}",
            "authorizing_party": "Example Client",
            "permitted_techniques": ["http_metadata"],
            "effective_at": valid_start,
            "expires_at": valid_end,
        }
        payload[field] = "not-a-valid-iso8601-timestamp"
        response = client.post(endpoint, json=payload, headers=headers)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "invalid_engagement_security_input"


def test_malformed_approval_timestamp_returns_422(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, _owner, _reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    response = client.post(
        f"/api/organizations/{org}/engagements/{engagement}/approvals",
        json={
            "asset_type": "domain",
            "target": "app.example.test",
            "technique": "exploit_verification",
            "expires_at": "not-a-valid-iso8601-timestamp",
        },
        headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_engagement_security_input"


def test_scope_authorization_policy_exclusion_and_approval_is_one_use(tmp_path: Path) -> None:
    _app, owner, reviewer, org, engagement, _asset, scope, auth = _setup(tmp_path)
    service = _app.state.engagement_security_service
    denied = service.evaluate_policy(
        owner, org, engagement, "domain", "example.test", "http_metadata"
    )
    assert denied["decision"] == "DENY" and denied["reason_code"] == "TARGET_EXCLUDED"
    assert (
        service.evaluate_policy(
            owner, org, engagement, "domain", "app.example.test", "http_metadata"
        )["decision"]
        == "ALLOW"
    )
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert (
        request
        and request["scope_revision_id"] == scope["id"]
        and request["authorization_id"] == auth["id"]
    )
    with pytest.raises(EngagementSecurityError):
        service.decide_approval(owner, org, engagement, request["id"], "approved", "self approval")
    assert (
        service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")[
            "decision"
        ]
        == "approved"
    )
    verified = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "app.example.test",
        "exploit_verification",
        request["id"],
    )
    assert verified["decision"] == "ALLOW"
    assert verified["reason_code"] == "APPROVAL_VALID"
    with _app.state.repository.engine.connect() as connection:
        assert (
            connection.execute(
                select(approval_requests.c.decision).where(approval_requests.c.id == request["id"])
            ).scalar_one()
            == "approved"
        )


def test_policy_api_cannot_consume_approval_without_execution(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request
    assert service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    response = client.post(
        f"/api/organizations/{org}/engagements/{engagement}/policy/evaluate",
        json={
            "asset_type": "domain",
            "target": "app.example.test",
            "technique": "exploit_verification",
            "approval_id": request["id"],
            "consume_approval": True,
        },
        headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "approval_consumption_requires_execution"
    with app.state.repository.engine.connect() as connection:
        assert connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one() == ("approved", None)


def test_atomic_approval_consumption_allows_only_one_concurrent_consumer(tmp_path: Path) -> None:
    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request
    assert service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")
    start = Barrier(2)

    def attempt_consume() -> str:
        start.wait(timeout=5)
        with app.state.repository.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                result = service._decision(
                    connection,
                    owner,
                    org,
                    engagement,
                    "domain",
                    "app.example.test",
                    "exploit_verification",
                    request["id"],
                    True,
                    datetime.now(UTC),
                )
                connection.commit()
                return result["decision"]
            except Exception:
                connection.rollback()
                raise

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: attempt_consume(), range(2)))
    assert outcomes.count("ALLOW") == 1
    assert outcomes.count("DENY") == 1
    with app.state.repository.engine.connect() as connection:
        assert (
            connection.execute(
                select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                    approval_requests.c.id == request["id"]
                )
            ).one()[0]
            == "consumed"
        )
        assert (
            len(
                connection.execute(
                    select(assessment_audit_events.c.id).where(
                        assessment_audit_events.c.action == "approval.consumed",
                        assessment_audit_events.c.resource_id == request["id"],
                    )
                ).all()
            )
            == 1
        )


def test_published_scope_is_immutable_and_snapshots_asset_type(tmp_path: Path) -> None:
    app, _owner, _reviewer, _org, _engagement, asset, scope, _auth = _setup(tmp_path)
    rules = scope["rules"]
    assert rules[0]["asset_type_snapshot"] == "domain"
    with app.state.repository.engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(
                update(
                    __import__(
                        "chinescan.core.storage.sqlite", fromlist=["scope_rules"]
                    ).scope_rules
                ).values(target_snapshot="changed.example")
            )


def test_api_requires_csrf_and_policy_route_does_not_run_scans(tmp_path: Path) -> None:
    app, _owner, _reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    from fastapi.testclient import TestClient

    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    path = f"/api/organizations/{org}/engagements/{engagement}/policy/evaluate"
    body = {"asset_type": "domain", "target": "app.example.test", "technique": "http_metadata"}
    assert client.post(path, json=body, headers={"Origin": "http://127.0.0.1"}).status_code == 403
    result = client.post(
        path,
        json=body,
        headers={"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]},
    )
    assert result.status_code == 200 and result.json()["decision"] == "ALLOW"


def test_organization_and_assignment_revocation_invalidate_approval(tmp_path: Path) -> None:
    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request is not None
    assert service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")
    app.state.organization_service.change_assignment(
        owner, org, engagement, reviewer, status="revoked"
    )
    decision = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "app.example.test",
        "exploit_verification",
        request["id"],
    )
    assert decision["decision"] == "DENY"
    assert decision["reason_code"] == "APPROVER_NO_LONGER_AUTHORIZED"


def test_authorization_revocation_and_cross_organization_references_fail_closed(
    tmp_path: Path,
) -> None:
    app, owner, _reviewer, org, engagement, asset, scope, auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    second_org = app.state.organization_service.create_organization(owner, "Second", "second-org")
    other_asset = service.create_asset(
        owner, second_org["id"], engagement, "domain", "outside.example"
    )
    assert other_asset is None
    with pytest.raises(EngagementSecurityError):
        service.create_scope_revision(
            owner,
            org,
            engagement,
            [
                {
                    "asset_id": other_asset["id"] if other_asset else "invalid",
                    "effect": "include",
                    "match_mode": "exact",
                    "techniques": ["http_metadata"],
                }
            ],
            "Cross-organization reference",
        )
    assert service.revoke_authorization(owner, org, engagement, auth["id"])
    denied = service.evaluate_policy(
        owner, org, engagement, "domain", "app.example.test", "http_metadata"
    )
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "AUTHORIZATION_MISSING_OR_INVALID"
    assert asset["organization_id"] == org


def test_authorization_document_is_private_bounded_and_digest_verified(tmp_path: Path) -> None:
    import hashlib

    app, owner, reviewer, org, engagement, _asset, _scope, auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    content = b"synthetic authorization record"
    stored = service.put_authorization_document(
        owner, org, engagement, auth["id"], "..\\authorization.pdf", "application/pdf", content
    )
    assert stored is not None
    assert "content" not in stored
    assert stored["sha256"] == hashlib.sha256(content).hexdigest()
    retrieved = service.get_authorization_document(reviewer, org, engagement, auth["id"])
    assert retrieved is not None and retrieved["content"] == content
    other_org = app.state.organization_service.create_organization(owner, "Private", "private-org")
    assert (
        service.get_authorization_document(owner, other_org["id"], engagement, auth["id"]) is None
    )
    with pytest.raises(EngagementSecurityError):
        service.put_authorization_document(
            owner,
            org,
            engagement,
            auth["id"],
            "too-large.pdf",
            "application/pdf",
            b"x" * (10 * 1024 * 1024 + 1),
        )


def test_expired_authorization_and_wrong_scope_authorization_deny(tmp_path: Path) -> None:
    from chinescan.core.storage.sqlite import authorization_records

    app, owner, reviewer, org, engagement, asset, scope, auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    with app.state.repository.engine.begin() as connection:
        connection.execute(
            update(authorization_records)
            .where(authorization_records.c.id == auth["id"])
            .values(
                effective_at=(datetime.now(UTC) - timedelta(minutes=2)).isoformat(),
                expires_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            )
        )
    expired = service.evaluate_policy(
        owner, org, engagement, "domain", "app.example.test", "http_metadata"
    )
    assert expired["decision"] == "DENY"
    assert expired["reason_code"] == "AUTHORIZATION_MISSING_OR_INVALID"

    revision = service.create_scope_revision(
        owner,
        org,
        engagement,
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "subdomains",
                "techniques": ["http_metadata"],
            }
        ],
        "Updated scope",
    )
    assert revision is not None
    assert service.publish_scope_revision(reviewer, org, engagement, revision["id"])
    with pytest.raises(EngagementSecurityError):
        service.create_authorization(
            owner,
            org,
            engagement,
            scope["id"],
            "AUTH-OLD",
            "Example Client",
            ["http_metadata"],
            datetime.now(UTC).isoformat(),
            (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        )


def test_approval_is_bound_to_target_and_expiry(tmp_path: Path) -> None:
    from chinescan.core.storage.sqlite import approval_requests

    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request
    service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")
    mismatch = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "other.example.test",
        "exploit_verification",
        request["id"],
    )
    assert mismatch["decision"] == "DENY"
    assert mismatch["reason_code"] == "APPROVAL_BINDING_MISMATCH"

    second = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert second
    service.decide_approval(reviewer, org, engagement, second["id"], "approved", "Reviewed")
    with app.state.repository.engine.begin() as connection:
        connection.execute(
            update(approval_requests)
            .where(approval_requests.c.id == second["id"])
            .values(expires_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat())
        )
    expired = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "app.example.test",
        "exploit_verification",
        second["id"],
    )
    assert expired["decision"] == "DENY"
    assert expired["reason_code"] == "APPROVAL_EXPIRED"


def test_approval_digest_and_requester_mismatch_are_denied(tmp_path: Path) -> None:
    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request
    assert service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")

    # An active assessor attempting the request as a different principal must not
    # inherit the requester's approval, even for the same operation.
    assessor_id = str(uuid4())
    stamp = datetime.now(UTC).isoformat()
    with app.state.repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=assessor_id,
                email_normalized="assessor@example.test",
                display_name="Assessor",
                status="active",
                auth_epoch="synthetic",
                created_at=stamp,
                updated_at=stamp,
            )
        )
    app.state.organization_service.add_member(owner, org, assessor_id, "member")
    app.state.organization_service.change_assignment(
        owner, org, engagement, assessor_id, role="assessor"
    )
    requester_mismatch = service.evaluate_policy(
        assessor_id,
        org,
        engagement,
        "domain",
        "app.example.test",
        "exploit_verification",
        request["id"],
    )
    assert requester_mismatch["decision"] == "DENY"
    assert requester_mismatch["reason_code"] == "APPROVAL_BINDING_MISMATCH"

    # A changed digest cannot be used to authorize the original operation.
    with app.state.repository.engine.begin() as connection:
        connection.execute(
            update(approval_requests)
            .where(approval_requests.c.id == request["id"])
            .values(request_digest="0" * 64)
        )
    digest_mismatch = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "app.example.test",
        "exploit_verification",
        request["id"],
    )
    assert digest_mismatch["decision"] == "DENY"
    assert digest_mismatch["reason_code"] == "APPROVAL_BINDING_MISMATCH"


def test_approval_is_invalidated_when_a_new_scope_is_published(tmp_path: Path) -> None:
    app, owner, reviewer, org, engagement, asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request
    assert service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")
    revision = service.create_scope_revision(
        owner,
        org,
        engagement,
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "subdomains",
                "techniques": ["http_metadata", "exploit_verification"],
            }
        ],
        "Revised scope",
    )
    assert revision
    assert service.publish_scope_revision(reviewer, org, engagement, revision["id"])
    current_auth = service.create_authorization(
        owner,
        org,
        engagement,
        revision["id"],
        "AUTH-2",
        "Example Client",
        ["http_metadata", "exploit_verification"],
        datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )
    assert current_auth
    result = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "app.example.test",
        "exploit_verification",
        request["id"],
    )
    assert result["decision"] == "DENY"
    assert result["reason_code"] in {"APPROVAL_BINDING_MISMATCH", "APPROVAL_SCOPE_STALE"}


def test_approval_cannot_be_reused_for_a_different_permitted_technique(tmp_path: Path) -> None:
    app, owner, reviewer, org, engagement, asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    revision = service.create_scope_revision(
        owner,
        org,
        engagement,
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "subdomains",
                "techniques": [
                    "http_metadata",
                    "exploit_verification",
                    "credential_testing",
                ],
            }
        ],
        "Scope permits two sensitive techniques",
    )
    assert revision
    assert service.publish_scope_revision(reviewer, org, engagement, revision["id"])
    assert service.create_authorization(
        owner,
        org,
        engagement,
        revision["id"],
        "AUTH-TECHNIQUE",
        "Example Client",
        ["http_metadata", "exploit_verification", "credential_testing"],
        datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )
    request = service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request
    assert service.decide_approval(reviewer, org, engagement, request["id"], "approved", "Reviewed")
    result = service.evaluate_policy(
        owner,
        org,
        engagement,
        "domain",
        "app.example.test",
        "credential_testing",
        request["id"],
    )
    assert result["decision"] == "DENY"
    assert result["reason_code"] == "APPROVAL_BINDING_MISMATCH"


def test_membership_revocation_denies_subsequent_policy_evaluation(tmp_path: Path) -> None:
    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    app.state.organization_service.update_membership(owner, org, reviewer, status="revoked")
    result = app.state.engagement_security_service.evaluate_policy(
        reviewer, org, engagement, "domain", "app.example.test", "http_metadata"
    )
    assert result["decision"] == "DENY"
    assert result["reason_code"] == "ENGAGEMENT_NOT_FOUND"


def test_invalid_engagement_ids_deny_without_invalid_audit_foreign_keys(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    organizations = app.state.organization_service
    other_org = organizations.create_organization(owner, "Other Org", "other-org")
    other_client = organizations.create_client(owner, other_org["id"], "Other Client", None)
    other_engagement = organizations.create_engagement(
        owner, other_org["id"], other_client["id"], "Other Engagement", "Synthetic", "active"
    )
    service = app.state.engagement_security_service

    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    csrf_headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
    body = {
        "asset_type": "domain",
        "target": "app.example.test",
        "technique": "http_metadata",
    }
    missing = client.post(
        f"/api/organizations/{org}/engagements/{uuid4()}/policy/evaluate",
        json=body,
        headers=csrf_headers,
    )
    cross_org = client.post(
        f"/api/organizations/{org}/engagements/{other_engagement['id']}/policy/evaluate",
        json=body,
        headers=csrf_headers,
    )
    assert missing.status_code == cross_org.status_code == 200
    missing, cross_org = missing.json(), cross_org.json()
    assert missing["decision"] == cross_org["decision"] == "DENY"
    assert missing["reason_code"] == cross_org["reason_code"] == "ENGAGEMENT_NOT_FOUND"
    assert missing["explanation"] == cross_org["explanation"]

    # A valid engagement with an excluded target remains engagement-linked in audit.
    valid_denial = service.evaluate_policy(
        owner, org, engagement, "domain", "example.test", "http_metadata"
    )
    assert valid_denial["decision"] == "DENY"
    assert valid_denial["reason_code"] == "TARGET_EXCLUDED"

    with app.state.repository.engine.connect() as connection:
        invalid_lookup_events = connection.execute(
            select(assessment_audit_events).where(
                assessment_audit_events.c.organization_id == org,
                assessment_audit_events.c.engagement_id.is_(None),
                assessment_audit_events.c.resource_type == "engagement_lookup",
            )
        ).all()
        assert len(invalid_lookup_events) == 2
        recorded_hashes = {
            dict(row._mapping)["details"]["attempted_engagement_sha256"]
            for row in invalid_lookup_events
        }
        assert len(recorded_hashes) == 2
        assert connection.execute(
            select(assessment_audit_events.c.id).where(
                assessment_audit_events.c.organization_id == org,
                assessment_audit_events.c.engagement_id == engagement,
                assessment_audit_events.c.reason_code == "TARGET_EXCLUDED",
            )
        ).first()
        assert (
            connection.execute(
                select(assessment_audit_events.c.id).where(
                    assessment_audit_events.c.organization_id == org,
                    assessment_audit_events.c.engagement_id == other_engagement["id"],
                )
            ).first()
            is None
        )


def test_cross_organization_api_ids_cannot_read_assets_authorizations_approvals_or_documents(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    organizations = app.state.organization_service
    service = app.state.engagement_security_service
    other_org = organizations.create_organization(owner, "Foreign Org", "foreign-org")
    other_client = organizations.create_client(owner, other_org["id"], "Foreign Client", None)
    other_engagement = organizations.create_engagement(
        owner, other_org["id"], other_client["id"], "Foreign Engagement", "Synthetic", "active"
    )
    organizations.add_member(owner, other_org["id"], reviewer, "member")
    organizations.change_assignment(
        owner, other_org["id"], other_engagement["id"], reviewer, role="reviewer"
    )
    foreign_asset = service.create_asset(
        owner, other_org["id"], other_engagement["id"], "domain", "foreign.example.test"
    )
    assert foreign_asset
    foreign_scope = service.create_scope_revision(
        owner,
        other_org["id"],
        other_engagement["id"],
        [
            {
                "asset_id": foreign_asset["id"],
                "effect": "include",
                "match_mode": "subdomains",
                "techniques": ["http_metadata", "exploit_verification"],
            }
        ],
        "Foreign scope",
    )
    assert foreign_scope
    assert service.publish_scope_revision(
        reviewer, other_org["id"], other_engagement["id"], foreign_scope["id"]
    )
    foreign_auth = service.create_authorization(
        owner,
        other_org["id"],
        other_engagement["id"],
        foreign_scope["id"],
        "FOREIGN-AUTH",
        "Foreign Client",
        ["http_metadata", "exploit_verification"],
        datetime.now(UTC).isoformat(),
        (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    )
    assert foreign_auth
    assert service.put_authorization_document(
        owner,
        other_org["id"],
        other_engagement["id"],
        foreign_auth["id"],
        "authorization.pdf",
        "application/pdf",
        b"synthetic foreign authorization",
    )
    foreign_approval = service.create_approval_request(
        owner,
        other_org["id"],
        other_engagement["id"],
        "domain",
        "app.foreign.example.test",
        "exploit_verification",
    )
    assert foreign_approval
    assert service.decide_approval(
        reviewer,
        other_org["id"],
        other_engagement["id"],
        foreign_approval["id"],
        "approved",
        "Reviewed",
    )

    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    prefix = f"/api/organizations/{org}/engagements/{engagement}"
    assert client.get(f"{prefix}/assets/{foreign_asset['id']}").status_code == 404
    assert client.get(f"{prefix}/approvals/{foreign_approval['id']}").status_code == 404
    assert client.get(f"{prefix}/authorizations/{foreign_auth['id']}/document").status_code == 404
    listed_auth = client.get(f"{prefix}/authorizations")
    assert listed_auth.status_code == 200
    assert foreign_auth["id"] not in {item["id"] for item in listed_auth.json()["items"]}


def test_governed_domain_job_uses_registered_asset_and_is_idempotent(tmp_path: Path) -> None:
    from chinescan.core.execution_governance import ExecutionGovernanceService

    app, owner, _reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    governance = ExecutionGovernanceService(service)
    first = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="domain-job-request-0001",
        requested_target="APP.EXAMPLE.TEST.",
    )
    assert first["status"] == "queued"
    assert first["target"] == "app.example.test"
    assert first["execution_context"]["request_digest"] == first["request_digest"]
    retry = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="domain-job-request-0001",
        requested_target="app.example.test",
    )
    assert retry["id"] == first["id"]
    with pytest.raises(ValueError, match="another target"):
        governance.create_domain_job(
            owner,
            org,
            engagement,
            asset["id"],
            approval_id=None,
            idempotency_key="domain-job-request-0001",
            requested_target="other.example.test",
        )


def test_governed_domain_job_revalidates_revoked_membership_before_claim(tmp_path: Path) -> None:
    from chinescan.core.execution_governance import ExecutionGovernanceService
    from chinescan.core.storage.sqlite import execution_jobs

    app, owner, reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    app.state.organization_service.change_assignment(
        owner, org, engagement, reviewer, role="assessor"
    )
    governance = ExecutionGovernanceService(service)
    job = governance.create_domain_job(
        reviewer,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="domain-job-revoke-0001",
    )
    assert job["status"] == "queued"
    app.state.organization_service.update_membership(owner, org, reviewer, status="suspended")
    assert governance.claim_job(job["id"]) is None
    with app.state.repository.engine.connect() as connection:
        blocked = (
            connection.execute(select(execution_jobs).where(execution_jobs.c.id == job["id"]))
            .mappings()
            .one()
        )
    assert blocked["status"] == "blocked"
    assert blocked["error_code"] == "ENGAGEMENT_NOT_FOUND"


def test_execution_api_rejects_client_target_substitution(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, _owner, _reviewer, org, engagement, asset, _scope, _auth = _setup(tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    response = client.post(
        f"/api/organizations/{org}/engagements/{engagement}/executions/domain",
        json={
            "asset_id": asset["id"],
            "idempotency_key": "api-execution-request-001",
            "target": "attacker.example",
        },
        headers={
            "Origin": "http://127.0.0.1",
            "X-CSRF-Token": login.json()["csrf_token"],
        },
    )
    assert response.status_code == 422


def test_governed_worker_dispatches_only_with_bound_context_and_can_cancel(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterFailure,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import (
        ExecutionGovernanceService,
        GovernedDomainWorker,
    )

    app, owner, _reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    governance = ExecutionGovernanceService(service)

    class FakeAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.governed-domain",
            techniques=("service_fingerprint",),
            target_types=("domain",),
            action_class="controlled_active",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            assert parameters == {}
            return {}

        def execute(self, context, _parameters, control) -> AdapterResult:
            assert context.organization_id == org
            assert app.state.repository._organization_context.get() == org
            assert app.state.repository._organization_principal_id.get() == owner
            assert app.state.repository._organization_write_access.get() is True
            assert context.engagement_id == engagement
            assert context.asset_id == asset["id"]
            assert context.target == "app.example.test"
            control.authorize_external_action(context.target, context.technique)
            control.report_progress(60, "synthetic_check")
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="complete",
                summary={"synthetic": True},
            )

    adapter_registry = AdapterRegistry((FakeAdapter(),))
    worker = GovernedDomainWorker(app.state.repository, governance, adapter_registry)
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="adapter-dispatch-request-001",
    )
    outcome = worker.run_one(job["id"])
    assert outcome == {
        "id": job["id"],
        "status": "completed",
        "scan_id": None,
        "adapter_id": "test.governed-domain",
        "result": {"synthetic": True},
    }
    stored = governance.get_job(owner, org, job["id"])
    assert stored and stored["status"] == "completed"
    assert stored["action_class"] == "controlled_active"
    assert stored["approval_id"] is None
    assert stored["approval_consumed_at"] is None
    assert stored["result_summary"] == {
        "adapter_id": "test.governed-domain",
        "status": "complete",
        "result_id": None,
        "summary": {"synthetic": True},
    }
    foreign_org = app.state.organization_service.create_organization(
        owner, "Separate Tenant", "separate-tenant"
    )
    assert governance.get_job(owner, foreign_org["id"], job["id"]) is None

    class CancellingAdapter(FakeAdapter):
        def execute(self, _context, _parameters, control) -> AdapterResult:
            cancel_worker.stop()
            control.check_cancelled()
            raise AssertionError("cancellation must stop adapter execution")

    cancel_worker = GovernedDomainWorker(
        app.state.repository, governance, AdapterRegistry((CancellingAdapter(),))
    )
    cancel_job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="adapter-cancel-request-001",
    )
    cancelled = cancel_worker.run_one(cancel_job["id"])
    assert cancelled == {"id": cancel_job["id"], "status": "cancelled"}
    stored_cancelled = governance.get_job(owner, org, cancel_job["id"])
    assert stored_cancelled and stored_cancelled["status"] == "cancelled"

    class FailingAdapter(FakeAdapter):
        def execute(self, _context, _parameters, _control) -> AdapterResult:
            raise AdapterFailure("SYNTHETIC_ADAPTER_FAILURE")

    failing_worker = GovernedDomainWorker(
        app.state.repository, governance, AdapterRegistry((FailingAdapter(),))
    )
    failed_job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="adapter-failure-request-001",
    )
    failed = failing_worker.run_one(failed_job["id"])
    assert failed == {
        "id": failed_job["id"],
        "status": "failed",
        "error_code": "SYNTHETIC_ADAPTER_FAILURE",
    }
    failed_record = governance.get_job(owner, org, failed_job["id"])
    assert failed_record and failed_record["error_code"] == "SYNTHETIC_ADAPTER_FAILURE"


def test_sensitive_approval_is_consumed_once_at_adapter_action_boundary(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import (
        ExecutionGovernanceService,
        GovernedDomainWorker,
    )

    app, owner, reviewer, org, engagement, asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class SensitiveTestAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.sensitive-boundary",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            assert parameters == {}
            return {}

        def execute(self, context, _parameters, control) -> AdapterResult:
            # These calls simulate two actions in the same operation. The first
            # atomically consumes approval; the second only revalidates it.
            control.authorize_external_action(context.target, context.technique)
            control.authorize_external_action(context.target, context.technique)
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="complete",
                summary={"synthetic": True},
            )

    registry = AdapterRegistry((SensitiveTestAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key="sensitive-boundary-request-01",
    )
    assert job["status"] == "queued"
    with app.state.repository.engine.connect() as connection:
        before_dispatch = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one()
    assert tuple(before_dispatch) == ("approved", None)

    duplicate_binding = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key="sensitive-boundary-request-02",
    )
    assert duplicate_binding["reason_code"] == "APPROVAL_ALREADY_BOUND"

    outcome = GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    assert outcome and outcome["status"] == "completed"
    with app.state.repository.engine.connect() as connection:
        approval = (
            connection.execute(
                select(approval_requests).where(approval_requests.c.id == request["id"])
            )
            .mappings()
            .one()
        )
        consumed_events = connection.execute(
            select(assessment_audit_events.c.id).where(
                assessment_audit_events.c.action == "approval.consumed",
                assessment_audit_events.c.resource_id == request["id"],
            )
        ).all()
        execution_events = connection.execute(
            select(assessment_audit_events.c.id).where(
                assessment_audit_events.c.action == "execution.approval_consumed",
                assessment_audit_events.c.resource_id == job["id"],
            )
        ).all()
        job_row = (
            connection.execute(select(execution_jobs).where(execution_jobs.c.id == job["id"]))
            .mappings()
            .one()
        )
    assert approval["decision"] == "consumed"
    assert approval["consumed_by"] == owner
    assert job_row["approval_consumed_at"] == approval["consumed_at"]
    assert len(consumed_events) == 1
    assert len(execution_events) == 1


def test_sensitive_job_without_action_boundary_does_not_consume_approval(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import (
        ExecutionGovernanceService,
        GovernedDomainWorker,
    )

    app, owner, reviewer, org, engagement, asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class NoActionAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.no-action",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, _context, _parameters, _control) -> AdapterResult:
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="complete",
                summary={"action_reached": False},
            )

    registry = AdapterRegistry((NoActionAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key="sensitive-no-action-request-01",
    )
    assert job["status"] == "queued"
    result = GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    assert result == {"id": job["id"], "status": "blocked"}
    with app.state.repository.engine.connect() as connection:
        approval = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one()
        blocked = connection.execute(
            select(execution_jobs.c.status, execution_jobs.c.approval_consumed_at).where(
                execution_jobs.c.id == job["id"]
            )
        ).one()
    assert tuple(approval) == ("approved", None)
    assert tuple(blocked) == ("blocked", None)


def test_sensitive_missing_approval_is_not_queued_or_consumed(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import AdapterCapabilities, AdapterRegistry
    from chinescan.core.execution_governance import ExecutionGovernanceService
    from chinescan.core.storage.sqlite import execution_jobs

    app, owner, _reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    asset = app.state.engagement_security_service.create_asset(
        owner, org, engagement, "domain", "app.example.test"
    )
    assert asset

    class SensitiveTestAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.missing-approval",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args):
            raise AssertionError("missing approval must not reach an adapter")

    governance = ExecutionGovernanceService(
        app.state.engagement_security_service, AdapterRegistry((SensitiveTestAdapter(),))
    )
    denied = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=None,
        idempotency_key="sensitive-missing-approval-01",
    )
    assert denied["decision"] == "REQUIRE_APPROVAL"
    with app.state.repository.engine.connect() as connection:
        assert connection.execute(select(execution_jobs.c.id)).first() is None


def test_sensitive_approval_remains_consumed_after_adapter_failure(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterFailure,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class FailingSensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.sensitive-failure",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, context, _parameters, control) -> AdapterResult:
            control.authorize_external_action(context.target, context.technique)
            raise AdapterFailure("SYNTHETIC_ACTION_FAILURE")

    registry = AdapterRegistry((FailingSensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key="sensitive-failure-request-01",
    )
    result = GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    # Phase 2D: once authorize_external_action() records the action as in_progress,
    # an AdapterFailure after dispatch leaves external outcome uncertain — the job
    # transitions to reconciliation_required rather than failed.
    assert result == {
        "id": job["id"],
        "status": "reconciliation_required",
        "error_code": "EXTERNAL_OUTCOME_UNCERTAIN",
    }
    with app.state.repository.engine.connect() as connection:
        approval = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one()
        persisted_job = connection.execute(
            select(execution_jobs.c.status, execution_jobs.c.approval_consumed_at).where(
                execution_jobs.c.id == job["id"]
            )
        ).one()
    assert approval.decision == "consumed" and approval.consumed_at is not None
    assert persisted_job.status == "reconciliation_required"
    assert persisted_job.approval_consumed_at == approval.consumed_at


def test_sensitive_approval_cannot_be_bound_to_two_concurrent_jobs(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import AdapterCapabilities, AdapterRegistry
    from chinescan.core.execution_governance import ExecutionGovernanceService

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.concurrent-sensitive",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args):
            raise AssertionError("admission tests must not execute adapters")

    governance = ExecutionGovernanceService(service, AdapterRegistry((SensitiveAdapter(),)))
    barrier = Barrier(2)

    def enqueue(suffix: str) -> dict:
        barrier.wait()
        return governance.create_governed_job(
            owner,
            org,
            engagement,
            asset["id"],
            technique="exploit_verification",
            approval_id=request["id"],
            idempotency_key=f"sensitive-concurrent-{suffix}",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(enqueue, ("a", "b")))
    assert sum(result.get("status") == "queued" for result in results) == 1
    assert sum(result.get("reason_code") == "APPROVAL_ALREADY_BOUND" for result in results) == 1


def test_concurrent_workers_claim_sensitive_job_and_consume_once(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.concurrent-worker",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, context, _parameters, control) -> AdapterResult:
            control.authorize_external_action(context.target, context.technique)
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="complete",
                summary={"executed": True},
            )

    registry = AdapterRegistry((SensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key="sensitive-concurrent-worker",
    )
    worker_barrier = Barrier(2)

    def run_worker() -> dict | None:
        worker = GovernedDomainWorker(app.state.repository, governance, registry)
        worker_barrier.wait()
        return worker.run_one(job["id"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: run_worker(), range(2)))
    assert sum(bool(result and result.get("status") == "completed") for result in results) == 1
    with app.state.repository.engine.connect() as connection:
        approval = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one()
        consumed_events = connection.execute(
            select(assessment_audit_events.c.id).where(
                assessment_audit_events.c.action == "approval.consumed",
                assessment_audit_events.c.resource_id == request["id"],
            )
        ).all()
    assert approval.decision == "consumed" and approval.consumed_at is not None
    assert len(consumed_events) == 1


def test_sensitive_execution_is_blocked_after_requester_membership_revocation(
    tmp_path: Path,
) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import (
        ExecutionGovernanceService,
        GovernedDomainWorker,
    )

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    repository = app.state.repository
    organizations = app.state.organization_service
    service = app.state.engagement_security_service
    requester = str(uuid4())
    stamp = datetime.now(UTC).isoformat()
    with repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=requester,
                email_normalized="assessor@example.test",
                display_name="Assessor",
                status="active",
                auth_epoch="synthetic",
                created_at=stamp,
                updated_at=stamp,
            )
        )
    organizations.add_member(owner, org, requester, "member")
    organizations.change_assignment(owner, org, engagement, requester, role="assessor")
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        requester, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.membership-revoked",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args) -> AdapterResult:
            raise AssertionError("revoked membership must stop before dispatch")

    registry = AdapterRegistry((SensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        requester,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key="sensitive-membership-revoked",
    )
    assert job["status"] == "queued"
    organizations.update_membership(owner, org, requester, status="revoked")
    result = GovernedDomainWorker(repository, governance, registry).run_one(job["id"])
    assert result == {"id": job["id"], "status": "blocked"}
    with repository.engine.connect() as connection:
        approval = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one()
    assert tuple(approval) == ("approved", None)


@pytest.mark.parametrize("change", ["authorization_revoked", "scope_revised"])
def test_sensitive_execution_is_blocked_after_authorization_context_changes(
    tmp_path: Path, change: str
) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import (
        ExecutionGovernanceService,
        GovernedDomainWorker,
    )

    app, owner, reviewer, org, engagement, root_asset, _scope, authorization = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.authorization-changed",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args) -> AdapterResult:
            raise AssertionError("changed authorization context must stop dispatch")

    registry = AdapterRegistry((SensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key=f"sensitive-context-changed-{change}",
    )
    assert job["status"] == "queued"
    if change == "authorization_revoked":
        assert service.revoke_authorization(owner, org, engagement, authorization["id"])
    else:
        revision = service.create_scope_revision(
            owner,
            org,
            engagement,
            [
                {
                    "asset_id": root_asset["id"],
                    "effect": "include",
                    "match_mode": "subdomains",
                    "techniques": ["exploit_verification"],
                }
            ],
            "Invalidate prior approval context",
        )
        assert revision
        assert service.publish_scope_revision(reviewer, org, engagement, revision["id"])
    result = GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    assert result == {"id": job["id"], "status": "blocked"}
    with app.state.repository.engine.connect() as connection:
        approval = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == request["id"]
            )
        ).one()
    assert tuple(approval) == ("approved", None)


def test_execution_cancellation_api_is_authenticated_scoped_and_idempotent(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    governance = app.state.execution_governance
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="cancel-api-job-request-01",
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    headers = {"Origin": "http://127.0.0.1", "X-CSRF-Token": login.json()["csrf_token"]}
    prefix = f"/api/organizations/{org}/engagements/{engagement}/executions/{job['id']}"
    cancelled = client.post(f"{prefix}/cancel", json={}, headers=headers)
    assert cancelled.status_code == 202
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["cancellation_outcome"] == "completed"
    assert cancelled.json()["cancellation_requested_by"] == owner
    assert cancelled.json()["cancellation_observed_at"] is None
    repeated = client.post(f"{prefix}/cancel", json={}, headers=headers)
    assert repeated.status_code == 409
    assert repeated.json()["detail"]["code"] == "execution_job_terminal"
    assert (
        client.post(
            f"/api/organizations/{org}/engagements/{uuid4()}/executions/{job['id']}/cancel",
            json={},
            headers=headers,
        ).status_code
        == 404
    )
    unauthenticated = TestClient(app, base_url="http://127.0.0.1")
    assert unauthenticated.post(f"{prefix}/cancel", json={}).status_code in {400, 401}

    denied = governance.request_cancellation(reviewer, org, engagement, job["id"])
    assert denied == {"outcome": "forbidden"}
    with app.state.repository.engine.connect() as connection:
        events = (
            connection.execute(
                select(assessment_audit_events.c.action).where(
                    assessment_audit_events.c.resource_id == job["id"],
                    assessment_audit_events.c.action.like("execution.cancellation_%"),
                )
            )
            .scalars()
            .all()
        )
    assert events.count("execution.cancellation_requested") == 1
    assert events.count("execution.cancellation_completed") == 1


def test_approval_decision_api_requires_reviewer_or_lead_assignment(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, owner, _existing_reviewer, org, engagement, _asset, _scope, _auth = _setup(tmp_path)
    credential = tmp_path / "operator.json"
    from chinescan.core.accounts import operator_auth_epoch

    epoch = operator_auth_epoch(credential)
    organizations = app.state.organization_service
    principals: dict[str, tuple[str, str]] = {}
    for principal_name, email, assignment, role in (
        ("assessor", "api-assessor@example.test", "assessor", "member"),
        ("observer", "api-observer@example.test", "observer", "member"),
        ("reviewer", "api-reviewer@example.test", "reviewer", "member"),
        ("viewer-reviewer", "api-viewer-reviewer@example.test", "reviewer", "viewer"),
    ):
        user_id = str(uuid4())
        user, _personal_org = organizations.ensure_operator(email, epoch, user_id)
        organizations.add_member(owner, org, user_id, role)
        organizations.change_assignment(owner, org, engagement, user_id, role=assignment)
        principals[principal_name] = (user_id, user["auth_epoch"])

    request = app.state.engagement_security_service.create_approval_request(
        owner, org, engagement, "domain", "app.example.test", "exploit_verification"
    )
    assert request is not None
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50111))
    url = f"/api/organizations/{org}/engagements/{engagement}/approvals/{request['id']}/decision"
    try:
        for principal_name in ("assessor", "observer", "viewer-reviewer"):
            user_id, auth_epoch = principals[principal_name]
            token, session = app.state.session_store.create(
                f"api-{principal_name}@example.test", auth_epoch, user_id=user_id
            )
            client.cookies.set("chinescan_session", token)
            response = client.post(
                url,
                json={"decision": "approved", "reason": "Not assigned to review."},
                headers={
                    "Origin": "http://127.0.0.1",
                    "X-CSRF-Token": session.csrf_token,
                },
            )
            assert response.status_code == 404
            with app.state.repository.engine.connect() as connection:
                state = connection.execute(
                    select(approval_requests.c.decision).where(
                        approval_requests.c.id == request["id"]
                    )
                ).scalar_one()
            assert state == "pending"

        reviewer_id, auth_epoch = principals["reviewer"]
        token, session = app.state.session_store.create(
            "api-reviewer@example.test", auth_epoch, user_id=reviewer_id
        )
        client.cookies.set("chinescan_session", token)
        allowed = client.post(
            url,
            json={"decision": "approved", "reason": "Reviewed by assigned reviewer."},
            headers={
                "Origin": "http://127.0.0.1",
                "X-CSRF-Token": session.csrf_token,
            },
        )
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["decision"] == "approved"
    finally:
        client.close()
        app.state.repository.close()


def test_viewer_with_assessor_assignment_cannot_submit_execution_job(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    app, owner, _reviewer, org, engagement, asset, _scope, _auth = _setup(tmp_path)
    user_id = str(uuid4())
    from chinescan.core.accounts import operator_auth_epoch

    epoch = operator_auth_epoch(tmp_path / "operator.json")
    stamp = datetime.now(UTC).isoformat()
    with app.state.repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=user_id,
                email_normalized="viewer-assessor@example.test",
                display_name="Viewer Assessor",
                status="active",
                auth_epoch=epoch,
                created_at=stamp,
                updated_at=stamp,
            )
        )
    app.state.organization_service.add_member(owner, org, user_id, "viewer")
    app.state.organization_service.change_assignment(
        owner, org, engagement, user_id, role="assessor"
    )
    token, session = app.state.session_store.create(
        "viewer-assessor@example.test", epoch, user_id=user_id
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50112))
    try:
        with app.state.repository.engine.connect() as connection:
            before = connection.execute(select(execution_jobs.c.id)).all()
        response = client.post(
            f"/api/organizations/{org}/engagements/{engagement}/executions/domain",
            json={"asset_id": asset["id"], "idempotency_key": "viewer-denied-job-0001"},
            cookies={"chinescan_session": token},
            headers={
                "Origin": "http://127.0.0.1",
                "X-CSRF-Token": session.csrf_token,
            },
        )
        assert response.status_code in {403, 404}
        with app.state.repository.engine.connect() as connection:
            after = connection.execute(select(execution_jobs.c.id)).all()
        assert after == before
    finally:
        client.close()
        app.state.repository.close()


@pytest.mark.parametrize("consume_before_cancel", [False, True])
def test_durable_cancellation_stops_sensitive_adapter_and_preserves_approval_state(
    tmp_path: Path, consume_before_cancel: bool
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent

    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    approval = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert approval
    assert service.decide_approval(
        reviewer, org, engagement, approval["id"], "approved", "Synthetic cancellation test"
    )
    entered = ThreadEvent()
    continue_adapter = ThreadEvent()
    external_actions: list[str] = []

    class WaitingSensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.durable-cancellation",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, context, _parameters, control) -> AdapterResult:
            if consume_before_cancel:
                control.authorize_external_action(context.target, context.technique)
                external_actions.append("first")
            entered.set()
            assert continue_adapter.wait(timeout=5)
            control.authorize_external_action(context.target, context.technique)
            external_actions.append("must-not-start")
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="complete",
                summary={"unexpected": True},
            )

    registry = AdapterRegistry((WaitingSensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    worker = GovernedDomainWorker(app.state.repository, governance, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=approval["id"],
        idempotency_key=f"durable-cancel-{consume_before_cancel}",
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker.run_one, job["id"])
        assert entered.wait(timeout=5)
        requested = worker.request_cancellation(owner, org, engagement, job["id"])
        assert requested and requested["outcome"] == "requested"
        continue_adapter.set()
        outcome = future.result(timeout=10)
    # Phase 2D: when approval was consumed and an action was recorded as in_progress
    # before the cancellation was observed, the outcome is uncertain — the job
    # transitions to reconciliation_required rather than cancelled.
    # When no action was started (consume_before_cancel=False), cancelled is returned.
    if consume_before_cancel:
        assert outcome == {"id": job["id"], "status": "reconciliation_required"}
    else:
        assert outcome == {"id": job["id"], "status": "cancelled"}
    assert external_actions == (["first"] if consume_before_cancel else [])
    with app.state.repository.engine.connect() as connection:
        persisted_job = (
            connection.execute(select(execution_jobs).where(execution_jobs.c.id == job["id"]))
            .mappings()
            .one()
        )
        persisted_approval = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == approval["id"]
            )
        ).one()
    if consume_before_cancel:
        assert persisted_job["status"] == "reconciliation_required"
    else:
        assert persisted_job["status"] == "cancelled"
    assert persisted_job["cancellation_requested_by"] == owner
    assert persisted_job["cancellation_requested_at"] is not None
    assert persisted_job["cancellation_observed_at"] is not None
    assert persisted_approval.decision == ("consumed" if consume_before_cancel else "approved")
    assert (persisted_approval.consumed_at is not None) is consume_before_cancel


def test_cancellation_rejects_non_owner_and_cross_organization_job_access(tmp_path: Path) -> None:
    from chinescan.core.execution_governance import ExecutionGovernanceService

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    organizations = app.state.organization_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    governance = ExecutionGovernanceService(service)
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="cancel-authz-job-request-01",
    )
    assert governance.request_cancellation(reviewer, org, engagement, job["id"]) == {
        "outcome": "forbidden"
    }
    foreign_org = organizations.create_organization(owner, "Foreign", "foreign-cancel")
    assert governance.request_cancellation(owner, foreign_org["id"], engagement, job["id"]) is None
    current = governance.get_job(owner, org, job["id"])
    assert current and current["status"] == "queued"


def test_queued_sensitive_cancellation_leaves_approval_unused(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import AdapterCapabilities, AdapterRegistry
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    approval = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert approval
    assert service.decide_approval(
        reviewer, org, engagement, approval["id"], "approved", "Synthetic cancellation test"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.queued-cancellation",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args):
            raise AssertionError("cancelled queued job must not reach adapter")

    registry = AdapterRegistry((SensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=approval["id"],
        idempotency_key="queued-sensitive-cancel-request-1",
    )
    cancellation = governance.request_cancellation(owner, org, engagement, job["id"])
    assert cancellation and cancellation["outcome"] == "completed"
    assert cancellation["job"]["status"] == "cancelled"
    result = GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    assert result == {"id": job["id"], "status": "cancelled"}
    with app.state.repository.engine.connect() as connection:
        approval_state = connection.execute(
            select(approval_requests.c.decision, approval_requests.c.consumed_at).where(
                approval_requests.c.id == approval["id"]
            )
        ).one()
    assert tuple(approval_state) == ("approved", None)


def test_cancellation_request_interrupted_by_adapter_failure_is_audited(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent

    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterFailure,
        AdapterRegistry,
    )
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, _reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    entered, resume = ThreadEvent(), ThreadEvent()

    class FailingAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.cancel-failure",
            techniques=("service_fingerprint",),
            target_types=("domain",),
            action_class="controlled_active",
            enabled=True,
            performs_external_operations=False,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args):
            entered.set()
            assert resume.wait(timeout=5)
            raise AdapterFailure("SYNTHETIC_FAILURE")

    registry = AdapterRegistry((FailingAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    worker = GovernedDomainWorker(app.state.repository, governance, registry)
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="cancel-failure-request-01",
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker.run_one, job["id"])
        assert entered.wait(timeout=5)
        requested = worker.request_cancellation(owner, org, engagement, job["id"])
        assert requested and requested["outcome"] == "requested"
        resume.set()
        outcome = future.result(timeout=10)
    assert outcome == {
        "id": job["id"],
        "status": "failed",
        "error_code": "SYNTHETIC_FAILURE",
    }
    with app.state.repository.engine.connect() as connection:
        event = connection.execute(
            select(assessment_audit_events.c.reason_code).where(
                assessment_audit_events.c.action == "execution.cancellation_interrupted_by_failure",
                assessment_audit_events.c.resource_id == job["id"],
            )
        ).scalar_one()
    assert event == "EXECUTION_FAILED_BEFORE_CANCELLATION_COMPLETED"


@pytest.mark.parametrize(
    ("result_status", "job_status"), [("complete", "completed"), ("partial", "failed")]
)
def test_governed_result_records_keep_immutable_job_provenance(
    tmp_path: Path, result_status: str, job_status: str
) -> None:
    from chinescan.core.cases import CaseWorkflow
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker
    from chinescan.core.organizations import OrganizationService
    from chinescan.core.storage.recovery import backup_database, restore_backup, verify_backup

    app, owner, _reviewer, org, engagement, _asset, scope, authorization = _setup(tmp_path)
    asset = app.state.engagement_security_service.create_asset(
        owner, org, engagement, "domain", "provenance.example.test"
    )
    assert asset
    repository = app.state.repository
    finding_id, scan_id = str(uuid4()), str(uuid4())
    registry = _result_adapter(
        repository, finding_id=finding_id, scan_id=scan_id, status=result_status
    )
    governance = ExecutionGovernanceService(app.state.engagement_security_service, registry)
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key=f"provenance-result-{result_status}-0001",
    )
    context_snapshot = dict(job["execution_context"])
    outcome = GovernedDomainWorker(repository, governance, registry).run_one(job["id"])
    assert outcome and outcome["status"] == job_status

    provenance = governance.get_job_provenance(owner, org, engagement, job["id"])
    assert provenance is not None
    assert provenance["execution_context"] == context_snapshot
    assert provenance["execution"]["scope_revision_id"] == scope["id"]
    assert provenance["execution"]["authorization_id"] == authorization["id"]
    assert provenance["execution"]["request_digest"] == job["request_digest"]
    assert provenance["execution"]["outcome"] == job_status
    assert provenance["execution"]["scan_id"] == scan_id
    assert {(item["record_type"], item["record_id"]) for item in provenance["results"]} == {
        ("scan", scan_id),
        ("finding", finding_id),
    }

    with repository.engine.connect() as connection:
        ownership = connection.execute(
            select(records.c.record_type, records.c.record_id)
            .join(
                execution_result_provenance,
                (execution_result_provenance.c.record_type == records.c.record_type)
                & (execution_result_provenance.c.record_id == records.c.record_id),
            )
            .where(execution_result_provenance.c.job_id == job["id"])
        ).all()
        assert {(row.record_type, row.record_id) for row in ownership} == {
            ("scan", scan_id),
            ("finding", finding_id),
        }

    with repository.member_context(org, owner, write=True):
        case, warnings = CaseWorkflow(repository).create_from_scan(
            scan_id, title="Governed finding review"
        )
        assert not warnings
        assert finding_id in case.finding_ids
        finding = repository.get("finding", finding_id)
        assert finding is not None
        finding["description"] = "Reviewed without changing origin."
        repository.save("finding", finding_id, finding)
    after_case_link = governance.get_job_provenance(owner, org, engagement, job["id"])
    assert after_case_link is not None
    assert after_case_link["results"] == provenance["results"]

    backup = tmp_path / f"backup-{result_status}"
    backup_result = backup_database(repository.path, backup)
    assert backup_result.verification.verified
    assert verify_backup(backup).migration_revision == "0015_durable_job_leases_actions"
    restored_path = tmp_path / f"restored-{result_status}.sqlite3"
    restore_backup(backup, restored_path, active_database_path=repository.path)
    restored = type(repository)(restored_path)
    try:
        restored_governance = ExecutionGovernanceService(
            app.state.engagement_security_service.__class__(
                restored, OrganizationService(restored)
            ),
            registry,
        )
        restored_provenance = restored_governance.get_job_provenance(
            owner, org, engagement, job["id"]
        )
        assert restored_provenance is not None
        assert restored_provenance["results"] == provenance["results"]
        assert restored_provenance["execution"]["outcome"] == job_status
    finally:
        restored.close()


def test_cancelled_job_retains_partial_result_provenance(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent

    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, _reviewer, org, engagement, _asset, _scope, _authorization = _setup(tmp_path)
    asset = app.state.engagement_security_service.create_asset(
        owner, org, engagement, "domain", "cancel-provenance.example.test"
    )
    assert asset
    repository = app.state.repository
    finding_id, scan_id = str(uuid4()), str(uuid4())
    entered, resume = ThreadEvent(), ThreadEvent()

    def pause_after_results() -> None:
        entered.set()
        assert resume.wait(timeout=5)

    registry = _result_adapter(
        repository,
        finding_id=finding_id,
        scan_id=scan_id,
        after_records=pause_after_results,
    )
    governance = ExecutionGovernanceService(app.state.engagement_security_service, registry)
    worker = GovernedDomainWorker(repository, governance, registry)
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="provenance-cancelled-job-01",
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker.run_one, job["id"])
        assert entered.wait(timeout=5)
        request = worker.request_cancellation(owner, org, engagement, job["id"])
        assert request and request["outcome"] == "requested"
        resume.set()
        assert future.result(timeout=10) == {"id": job["id"], "status": "cancelled"}
    provenance = governance.get_job_provenance(owner, org, engagement, job["id"])
    assert provenance is not None
    assert provenance["execution"]["outcome"] == "cancelled"
    assert {(item["record_type"], item["record_id"]) for item in provenance["results"]} == {
        ("scan", scan_id),
        ("finding", finding_id),
    }


def test_preexisting_finding_is_not_attributed_and_provenance_is_tenant_bound(
    tmp_path: Path,
) -> None:
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, _reviewer, org, engagement, _asset, _scope, _authorization = _setup(tmp_path)
    asset = app.state.engagement_security_service.create_asset(
        owner, org, engagement, "domain", "imported-provenance.example.test"
    )
    assert asset
    repository = app.state.repository
    finding_id, scan_id = str(uuid4()), str(uuid4())
    with repository.member_context(org, owner, write=True):
        repository.save(
            "finding",
            finding_id,
            {"title": "Imported before governed execution", "fingerprint": "legacy-import"},
        )
    registry = _result_adapter(repository, finding_id=finding_id, scan_id=scan_id)
    governance = ExecutionGovernanceService(app.state.engagement_security_service, registry)
    job = governance.create_domain_job(
        owner,
        org,
        engagement,
        asset["id"],
        approval_id=None,
        idempotency_key="provenance-imported-finding-01",
    )
    assert GovernedDomainWorker(repository, governance, registry).run_one(job["id"])
    provenance = governance.get_job_provenance(owner, org, engagement, job["id"])
    assert provenance is not None
    assert [(item["record_type"], item["record_id"]) for item in provenance["results"]] == [
        ("scan", scan_id)
    ]

    organizations = app.state.organization_service
    foreign_org = organizations.create_organization(owner, "Other tenant", "provenance-other")
    assert governance.get_job_provenance(owner, foreign_org["id"], engagement, job["id"]) is None
    from fastapi.testclient import TestClient

    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50123))
    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.test", "password": "synthetic-secure-passphrase-77!"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    provenance_path = (
        f"/api/organizations/{org}/engagements/{engagement}/executions/{job['id']}/provenance"
    )
    response = client.get(provenance_path)
    assert response.status_code == 200
    assert response.json()["execution"]["job_id"] == job["id"]
    assert (
        client.get(
            f"/api/organizations/{foreign_org['id']}/engagements/{engagement}/executions/"
            f"{job['id']}/provenance"
        ).status_code
        == 404
    )
    with repository.engine.begin() as connection:
        connection.execute(
            records.insert().values(
                record_type="scan", record_id="cross-tenant-result", payload={"status": "complete"}
            )
        )
    with pytest.raises(IntegrityError):
        with repository.engine.begin() as connection:
            connection.execute(
                execution_result_provenance.insert().values(
                    record_type="scan",
                    record_id="cross-tenant-result",
                    job_id=job["id"],
                    organization_id=foreign_org["id"],
                    engagement_id=engagement,
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
    with pytest.raises(IntegrityError):
        with repository.engine.begin() as connection:
            connection.execute(
                execution_result_provenance.update()
                .where(execution_result_provenance.c.job_id == job["id"])
                .values(record_id="forged-origin")
            )
    with pytest.raises(IntegrityError):
        with repository.engine.begin() as connection:
            connection.execute(
                execution_result_provenance.delete().where(
                    execution_result_provenance.c.job_id == job["id"]
                )
            )


def test_approval_consumption_outcome_is_exposed_as_job_provenance(tmp_path: Path) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, reviewer, org, engagement, _root_asset, _scope, _authorization = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "approval.example.test")
    assert asset
    approval = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert approval
    assert service.decide_approval(
        reviewer, org, engagement, approval["id"], "approved", "Synthetic provenance approval"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.provenance-approval",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, context, _parameters, control) -> AdapterResult:
            control.authorize_external_action(context.target, context.technique)
            return AdapterResult(
                adapter_id=self.capabilities.adapter_id,
                status="complete",
                summary={"verified": True},
            )

    registry = AdapterRegistry((SensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=approval["id"],
        idempotency_key="provenance-consumed-approval-01",
    )
    assert GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    provenance = governance.get_job_provenance(owner, org, engagement, job["id"])
    assert provenance is not None
    assert provenance["execution"]["approval_id"] == approval["id"]
    assert provenance["execution"]["approval_consumption_outcome"] == "consumed"
    assert provenance["execution"]["approval_consumed_at"] is not None


@pytest.mark.parametrize(
    "invalid_state", ["expired", "revoked", "digest_mismatch", "reviewer_role_downgrade"]
)
def test_sensitive_job_rejects_invalidated_approval_before_action(
    tmp_path: Path, invalid_state: str
) -> None:
    from chinescan.core.execution_adapters import (
        AdapterCapabilities,
        AdapterRegistry,
        AdapterResult,
    )
    from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker

    app, owner, reviewer, org, engagement, _root_asset, _scope, _auth = _setup(tmp_path)
    service = app.state.engagement_security_service
    asset = service.create_asset(owner, org, engagement, "domain", "app.example.test")
    assert asset
    request = service.create_approval_request(
        owner, org, engagement, "domain", asset["target"], "exploit_verification"
    )
    assert request
    assert service.decide_approval(
        reviewer, org, engagement, request["id"], "approved", "Synthetic test approval"
    )

    class SensitiveAdapter:
        capabilities = AdapterCapabilities(
            adapter_id="test.invalidated-sensitive",
            techniques=("exploit_verification",),
            target_types=("domain",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

        def validate_parameters(self, parameters: dict) -> dict:
            return parameters

        def execute(self, *_args) -> AdapterResult:
            raise AssertionError("invalidated approval must block dispatch")

    registry = AdapterRegistry((SensitiveAdapter(),))
    governance = ExecutionGovernanceService(service, registry)
    job = governance.create_governed_job(
        owner,
        org,
        engagement,
        asset["id"],
        technique="exploit_verification",
        approval_id=request["id"],
        idempotency_key=f"sensitive-invalid-{invalid_state}",
    )
    assert job["status"] == "queued"
    if invalid_state == "reviewer_role_downgrade":
        app.state.organization_service.update_membership(owner, org, reviewer, role="viewer")
    else:
        with app.state.repository.engine.begin() as connection:
            changes = {
                "expired": {"expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
                "revoked": {"decision": "denied"},
                "digest_mismatch": {"request_digest": "0" * 64},
            }[invalid_state]
            connection.execute(
                update(approval_requests)
                .where(approval_requests.c.id == request["id"])
                .values(**changes)
            )
    result = GovernedDomainWorker(app.state.repository, governance, registry).run_one(job["id"])
    assert result == {"id": job["id"], "status": "blocked"}
    with app.state.repository.engine.connect() as connection:
        persisted = connection.execute(
            select(execution_jobs.c.status, execution_jobs.c.approval_consumed_at).where(
                execution_jobs.c.id == job["id"]
            )
        ).one()
    assert persisted.status == "blocked"
    assert persisted.approval_consumed_at is None
