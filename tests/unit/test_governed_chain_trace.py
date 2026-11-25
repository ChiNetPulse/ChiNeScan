from __future__ import annotations

import json
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from chinescan.chain_trace.providers.offline import OfflineProvider
from chinescan.core.accounts import Session
from chinescan.core.chain_trace_execution import (
    CHAIN_IMPORT_TECHNIQUE,
    CHAIN_PROVIDER_TECHNIQUE,
    GovernedChainImportAdapter,
    GovernedChainProviderAdapter,
)
from chinescan.core.engagement_security import TECHNIQUE_CLASSES, normalize_target
from chinescan.core.execution_adapters import AdapterFailure, ExecutionContext
from chinescan.web.execution_api import create_chain_execution_router

SEED = "0x" + "a" * 40


def _provider_context() -> ExecutionContext:
    return ExecutionContext(
        version=1,
        job_id=str(uuid4()),
        organization_id=str(uuid4()),
        requester_user_id=str(uuid4()),
        engagement_id=str(uuid4()),
        assignment_roles=("assessor",),
        asset_id=str(uuid4()),
        target=f"chain:ethereum:etherscan-v2:{SEED}",
        asset_type="chain_address",
        technique=CHAIN_PROVIDER_TECHNIQUE,
        action_class="sensitive",
        scope_revision_id=str(uuid4()),
        authorization_id=str(uuid4()),
        approval_id=str(uuid4()),
        policy_decision_id=str(uuid4()),
        request_digest="a" * 64,
        policy_request_digest="b" * 64,
        chain_context={"chain": "ethereum", "address": SEED, "provider": "etherscan-v2"},
        adapter_id="builtin.governed-chain-provider",
        adapter_version="1",
        created_at="2026-11-24T00:00:00Z",
        expires_at="2026-11-24T00:10:00Z",
    )


class _Control:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.authorized: list[tuple[str, str]] = []
        self.progress: list[tuple[int, str]] = []

    def check_cancelled(self) -> None:
        return None

    def authorize_external_action(self, target: str, technique: str) -> None:
        if self.denied:
            raise AdapterFailure("POLICY_REVALIDATION_DENIED")
        self.authorized.append((target, technique))

    def report_progress(self, percent: int, phase: str) -> None:
        self.progress.append((percent, phase))


def test_governed_offline_import_requires_matching_chain_and_valid_identifiers() -> None:
    body = (
        '[{"chain":"ethereum","tx_hash":"0x' + "b" * 64 + '",'
        '"sender":"' + SEED + '","receiver":"0x' + "c" * 40 + '",'
        '"amount":"1","block_time":1}]'
    )
    provider = OfflineProvider(body, "ethereum", "json", require_chain_field=True)
    page = provider.transfers(SEED, limit=10)
    assert len(page.transfers) == 1
    assert page.transfers[0].receiver == "0x" + "c" * 40

    mismatch = body.replace('"ethereum"', '"polygon"')
    with pytest.raises(ValueError, match="chain does not match"):
        OfflineProvider(mismatch, "ethereum", "json", require_chain_field=True)

    malformed = body.replace("0x" + "b" * 64, "0x123")
    with pytest.raises(ValueError, match="invalid chain identifier"):
        OfflineProvider(malformed, "ethereum", "json", require_chain_field=True)


def test_chain_policy_targets_and_classifications_are_explicit() -> None:
    target = normalize_target("chain_address", f"chain:ethereum:etherscan-v2:0x{'A' * 40}")
    assert target == f"chain:ethereum:etherscan-v2:{SEED}"
    assert TECHNIQUE_CLASSES[CHAIN_IMPORT_TECHNIQUE] == "passive"
    assert TECHNIQUE_CLASSES[CHAIN_PROVIDER_TECHNIQUE] == "sensitive"
    with pytest.raises(ValueError):
        normalize_target("chain_address", f"chain:ethereum:arbitrary-rpc:{SEED}")


def test_governed_chain_api_binds_import_request_and_rejects_path_fields() -> None:
    calls: list[dict[str, object]] = []

    class Governance:
        def create_governed_job(self, *args: object, **kwargs: object) -> dict[str, str]:
            calls.append({"args": args, **kwargs})
            return {"decision": "ALLOW", "id": str(uuid4()), "status": "queued"}

    session = Session("operator@example.test", "csrf", 0, "epoch", user_id=str(uuid4()))
    app = FastAPI()
    app.include_router(
        create_chain_execution_router(Governance(), object(), lambda: session, lambda: None)
    )
    client = TestClient(app)
    response = client.post(
        f"/api/organizations/{uuid4()}/engagements/{uuid4()}/chain-traces/imports",
        json={
            "asset_id": str(uuid4()),
            "chain": "ethereum",
            "seed": SEED,
            "depth": 2,
            "idempotency_key": "chain-import-api-test-01",
            "path": "C:/outside/input.json",
        },
    )
    assert response.status_code == 422
    assert calls == []

    response = client.post(
        f"/api/organizations/{uuid4()}/engagements/{uuid4()}/chain-traces/imports",
        json={
            "asset_id": str(uuid4()),
            "chain": "ethereum",
            "seed": SEED,
            "depth": 2,
            "idempotency_key": "chain-import-api-test-02",
        },
    )
    assert response.status_code == 202
    assert calls[-1]["chain_request"] == {"chain": "ethereum", "seed": SEED, "depth": 2}


def test_governed_provider_uses_fixed_endpoint_and_authorizes_each_request(repository) -> None:
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

    adapter = GovernedChainProviderAdapter(
        repository, api_key="test-secret", http_get=transport, max_requests=10
    )
    context = _provider_context()
    control = _Control()
    result = adapter.execute(context, {}, control)

    assert result.status == "complete"
    assert result.summary["provider"] == "etherscan-v2"
    assert len(calls) == 3
    assert {url for url, _ in calls} == {"https://api.etherscan.io/v2/api"}
    assert len(control.authorized) == len(calls)
    assert all(
        target == context.target and technique == context.technique
        for target, technique in control.authorized
    )
    assert all(kwargs["allowed_hosts"] == ("api.etherscan.io",) for _, kwargs in calls)


def test_governed_provider_policy_denial_prevents_transport(repository) -> None:
    calls = 0

    def transport(_url: str, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("provider transport must not run after denial")

    adapter = GovernedChainProviderAdapter(repository, api_key="test-secret", http_get=transport)
    with pytest.raises(AdapterFailure, match="CHAIN_PROVIDER_LOOKUP_FAILED"):
        adapter.execute(_provider_context(), {}, _Control(denied=True))
    assert calls == 0


def test_governed_chain_import_reads_only_verified_snapshot(repository, tmp_path) -> None:
    asset_id = str(uuid4())
    snapshot_id = str(uuid4())
    payload = [
        {
            "chain": "ethereum",
            "tx_hash": "0x" + "d" * 64,
            "sender": SEED,
            "receiver": "0x" + "e" * 40,
            "amount": "2",
            "block_time": 10,
        }
    ]
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    class Evidence:
        @staticmethod
        def verify(_organization_id: str, _engagement_id: str, _asset: str, _snapshot: str):
            return (
                {
                    "sha256": "f" * 64,
                    "manifest_version": 1,
                    "source_format": "json",
                    "manifest": {
                        "entries": [{"path": path.name, "size_bytes": path.stat().st_size}]
                    },
                },
                tmp_path,
            )

    context = ExecutionContext(
        version=1,
        job_id=str(uuid4()),
        organization_id=str(uuid4()),
        requester_user_id=str(uuid4()),
        engagement_id=str(uuid4()),
        assignment_roles=("assessor",),
        asset_id=asset_id,
        target=f"log:{asset_id}",
        asset_type="log_evidence",
        technique=CHAIN_IMPORT_TECHNIQUE,
        action_class="passive",
        scope_revision_id=str(uuid4()),
        authorization_id=str(uuid4()),
        policy_decision_id=str(uuid4()),
        request_digest="a" * 64,
        policy_request_digest="b" * 64,
        adapter_id="builtin.governed-chain-import",
        adapter_version="1",
        log_evidence_snapshot_id=snapshot_id,
        log_evidence_sha256="f" * 64,
        log_evidence_manifest_version=1,
        chain_context={"chain": "ethereum", "seed": SEED, "depth": 1},
        created_at="2026-11-24T00:00:00Z",
        expires_at="2026-11-24T00:10:00Z",
    )
    control = _Control()
    adapter = GovernedChainImportAdapter(repository, Evidence())
    result = adapter.execute(context, context.chain_context or {}, control)
    assert result.status == "partial"
    assert result.summary["source_kind"] == "registered_import"
    assert control.authorized == []
