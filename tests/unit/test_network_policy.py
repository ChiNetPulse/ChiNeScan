from __future__ import annotations

import sys

import pytest

from chinescan.core.linux_isolation import (
    LinuxIsolationRequest,
    native_linux_available,
)
from chinescan.core.network_policy import (
    ApprovedDestination,
    NetworkPolicy,
    NetworkPolicyError,
    approved_policy_available,
)


def _approved_policy() -> NetworkPolicy:
    return NetworkPolicy(
        mode="approved_destinations",
        scope_revision_id="scope-1",
        authorization_id="authorization-1",
        destinations=(ApprovedDestination("example.com", ("93.184.216.34",), ports=(443,)),),
    )


def test_deny_all_is_default_and_cannot_contain_destinations() -> None:
    assert NetworkPolicy().validated().mode == "deny_all"
    with pytest.raises(NetworkPolicyError, match="deny_all_policy_has_allowlist"):
        NetworkPolicy(
            destinations=(ApprovedDestination("example.com", ("93.184.216.34",)),),
        ).validated()


def test_approved_policy_rejects_private_and_unbound_destinations() -> None:
    with pytest.raises(NetworkPolicyError, match="destination_address_not_allowed"):
        ApprovedDestination("internal.example", ("10.0.0.1",)).normalized()
    with pytest.raises(NetworkPolicyError, match="approved_policy_binding_required"):
        NetworkPolicy(mode="approved_destinations").validated()


def test_approved_policy_is_fail_closed_without_deployment_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CHINESCAN_NETWORK_POLICY_HELPER", raising=False)

    available, reason = approved_policy_available(_approved_policy())

    assert not available
    assert reason == "network_policy_helper_unavailable"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only policy test")
def test_approved_namespace_command_requires_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("chinescan.core.linux_isolation.shutil.which", lambda _: "/usr/bin/unshare")
    monkeypatch.delenv("CHINESCAN_NETWORK_POLICY_HELPER", raising=False)
    request = LinuxIsolationRequest(
        namespaces=True,
        network=True,
        network_mode="approved_destinations",
        network_policy_json=_approved_policy().json(),
    )

    available, reason = native_linux_available(request)
    assert not available
    assert reason == "network_policy_helper_unavailable"
