from __future__ import annotations

from threading import Event
from uuid import uuid4

import pytest

from chinescan.core.execution_adapters import (
    AdapterCapabilities,
    AdapterFailure,
    AdapterRegistry,
    AdapterResult,
    ExecutionContext,
    ExecutionControl,
    UnsupportedAdapterError,
)
from chinescan.domain_assessment.probe import ExecutionCancelled


class FakeAdapter:
    def __init__(self, *, enabled: bool = True) -> None:
        self._capabilities = AdapterCapabilities(
            adapter_id="test.fake-adapter",
            techniques=("metadata_check",),
            target_types=("domain",),
            action_class="passive",
            enabled=enabled,
            performs_external_operations=False,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict) -> dict:
        if set(parameters) - {"sample"}:
            raise ValueError("unsupported parameter")
        return parameters

    def execute(self, context, parameters, control) -> AdapterResult:
        control.report_progress(50, "fake_execution")
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="complete",
            summary={"target": context.target, "parameter_count": len(parameters)},
        )


def _job() -> dict:
    values = {
        "id": str(uuid4()),
        "organization_id": str(uuid4()),
        "requester_user_id": str(uuid4()),
        "engagement_id": str(uuid4()),
        "asset_id": str(uuid4()),
        "target": "example.com",
        "asset_type": "domain",
        "technique": "metadata_check",
        "action_class": "passive",
        "scope_revision_id": str(uuid4()),
        "authorization_id": str(uuid4()),
        "approval_id": None,
        "policy_decision_id": str(uuid4()),
        "request_digest": "a" * 64,
        "created_at": "2026-11-23T00:00:00+00:00",
        "expires_at": "2026-11-23T00:10:00+00:00",
    }
    values["execution_context"] = {
        "version": 1,
        "job_id": values["id"],
        **{key: value for key, value in values.items() if key != "id"},
        "assignment_roles": ["assessor"],
    }
    return values


def test_registry_requires_declared_target_and_technique() -> None:
    registry = AdapterRegistry((FakeAdapter(),))
    assert registry.resolve("domain", "metadata_check").capabilities.adapter_id == (
        "test.fake-adapter"
    )
    with pytest.raises(UnsupportedAdapterError):
        registry.resolve("url", "metadata_check")
    with pytest.raises(UnsupportedAdapterError):
        registry.resolve("domain", "port_scan")
    with pytest.raises(ValueError, match="Disabled"):
        AdapterRegistry((FakeAdapter(enabled=False),))


def test_context_is_frozen_and_must_match_durable_job() -> None:
    job = _job()
    context = ExecutionContext.from_job(job)
    assert context.target == "example.com"
    with pytest.raises(ValueError):
        context.target = "other.example"  # type: ignore[misc]

    tampered = job | {"target": "other.example"}
    with pytest.raises(ValueError, match="does not match"):
        ExecutionContext.from_job(tampered)

    context_tampered = job | {
        "execution_context": job["execution_context"] | {"target": "other.example"}
    }
    with pytest.raises(ValueError, match="does not match"):
        ExecutionContext.from_job(context_tampered)


def test_adapter_parameters_and_result_are_structured() -> None:
    registry = AdapterRegistry((FakeAdapter(),))
    adapter, parameters = registry.validate_parameters(
        "domain", "metadata_check", {"sample": "safe"}
    )
    assert parameters == {"sample": "safe"}
    with pytest.raises(ValueError, match="parameters are invalid"):
        registry.validate_parameters("domain", "metadata_check", {"target": "other"})

    context = ExecutionContext.from_job(_job())
    progress: list[tuple[int, str]] = []
    control = ExecutionControl(
        context=context,
        cancellation=Event(),
        external_operations_enabled=True,
        revalidate=lambda: True,
        progress=lambda percent, phase: progress.append((percent, phase)),
    )
    result = adapter.execute(context, parameters, control)
    assert result.status == "complete"
    assert result.summary["target"] == context.target
    assert progress == [(50, "fake_execution")]


def test_control_rejects_target_or_technique_substitution() -> None:
    context = ExecutionContext.from_job(_job())
    control = ExecutionControl(
        context=context,
        cancellation=Event(),
        external_operations_enabled=True,
        revalidate=lambda: True,
        progress=lambda *_args: None,
    )
    with pytest.raises(AdapterFailure, match="MISMATCH"):
        control.authorize_external_action("other.example", context.technique)
    with pytest.raises(AdapterFailure, match="MISMATCH"):
        control.authorize_external_action(context.target, "different_technique")


def test_control_revalidates_policy_and_honors_cancellation() -> None:
    context = ExecutionContext.from_job(_job())
    control = ExecutionControl(
        context=context,
        cancellation=Event(),
        external_operations_enabled=True,
        revalidate=lambda: False,
        progress=lambda *_args: None,
    )
    with pytest.raises(AdapterFailure, match="POLICY_REVALIDATION_DENIED"):
        control.authorize_external_action(context.target, context.technique)

    cancelled = Event()
    cancelled.set()
    control = ExecutionControl(
        context=context,
        cancellation=cancelled,
        external_operations_enabled=True,
        revalidate=lambda: pytest.fail("cancelled execution must not revalidate or act"),
        progress=lambda *_args: None,
    )
    with pytest.raises(ExecutionCancelled):
        control.authorize_external_action(context.target, context.technique)
    with pytest.raises(ExecutionCancelled):
        control.report_progress(5, "still_running")


def test_progress_phase_and_failure_codes_are_safe_identifiers() -> None:
    context = ExecutionContext.from_job(_job())
    control = ExecutionControl(
        context=context,
        cancellation=Event(),
        external_operations_enabled=True,
        revalidate=lambda: True,
        progress=lambda *_args: None,
    )
    with pytest.raises(ValueError):
        control.report_progress(101, "bad")
    with pytest.raises(ValueError):
        control.report_progress(10, "unsafe phase")
    with pytest.raises(ValueError):
        AdapterFailure("internal error with secret")


def test_adapter_without_external_capability_cannot_request_network_action() -> None:
    context = ExecutionContext.from_job(_job())
    control = ExecutionControl(
        context=context,
        cancellation=Event(),
        external_operations_enabled=False,
        revalidate=lambda: pytest.fail("disabled external capability must fail first"),
        progress=lambda *_args: None,
    )
    with pytest.raises(AdapterFailure, match="EXTERNAL_OPERATION_DISABLED"):
        control.authorize_external_action(context.target, context.technique)
