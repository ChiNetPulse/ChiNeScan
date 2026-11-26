from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert

from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.execution_adapters import GovernedNmapAdapter, build_default_adapter_registry
from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker
from chinescan.core.organizations import OrganizationService
from chinescan.core.storage.sqlite import SQLiteRepository, users
from chinescan.integrations.nmap.executor import NmapExecutionError, NmapExecutor
from chinescan.integrations.nmap.parser import NmapParseError, parse_nmap_xml
from chinescan.integrations.nmap.profiles import build_nmap_arguments
from chinescan.integrations.nmap.targets import NmapTargetError, validate_nmap_target
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator

VALID_XML = b"""
<nmaprun version="7.95">
  <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="https" product="test" version="1"/></port></ports>
  </host>
  <runstats><finished timestr="2026-11-26T00:00:00Z"/></runstats>
</nmaprun>
"""


def test_nmap_status_is_authenticated_and_disabled_by_default(tmp_path: Path) -> None:
    credential = tmp_path / "private" / "operator.json"
    create_operator(credential, "nmap-api@example.test", "safe local password")
    app = create_app(tmp_path / "status.sqlite3", credential, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    assert client.get("/api/integrations/nmap/status").status_code == 401
    login = client.post(
        "/api/auth/login",
        json={"email": "nmap-api@example.test", "password": "safe local password"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    status = client.get("/api/integrations/nmap/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    assert status.json()["hostname_targets_supported"] is False
    organization_id = "11111111-1111-4111-8111-111111111111"
    engagement_id = "22222222-2222-4222-8222-222222222222"
    profiles = client.get(
        f"/api/organizations/{organization_id}/engagements/{engagement_id}/nmap/profiles"
    )
    assert profiles.status_code == 200
    assert profiles.json()["enabled"] is False
    csrf_headers = {
        "Origin": "http://127.0.0.1",
        "X-CSRF-Token": login.json()["csrf_token"],
    }
    disabled = client.post(
        f"/api/organizations/{organization_id}/engagements/{engagement_id}/nmap/executions",
        json={
            "asset_id": "33333333-3333-4333-8333-333333333333",
            "profile": "host_discovery",
            "ports": [],
            "idempotency_key": "nmap-disabled-request",
        },
        headers=csrf_headers,
    )
    assert disabled.status_code == 404
    missing = client.get(
        f"/api/organizations/{organization_id}/engagements/{engagement_id}/nmap/executions/"
        "44444444-4444-4444-8444-444444444444/result"
    )
    assert missing.status_code == 404


def test_nmap_executor_rejects_bad_versions_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["nmap", "--version"], 0, b"not nmap", b""
        ),
    )
    with pytest.raises(NmapExecutionError) as invalid:
        NmapExecutor().check_available()
    assert invalid.value.code == "nmap_version_invalid"

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["nmap", "--version"], 0, b"Nmap version 7.95\n", b""
        ),
    )
    with pytest.raises(NmapExecutionError) as unsupported:
        NmapExecutor(expected_major=8).check_available()
    assert unsupported.value.code == "nmap_version_unsupported"

    class FailedProcess:
        returncode = 2

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.stdout = self
            self.read_once = False

        def read(self, _size: int) -> bytes:
            if self.read_once:
                return b""
            self.read_once = True
            return VALID_XML

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", FailedProcess)
    with pytest.raises(NmapExecutionError) as failed:
        NmapExecutor().run(target="192.0.2.10", profile="host_discovery", ports=[])
    assert failed.value.code == "nmap_failed"


def test_nmap_executor_maps_timeout_and_parse_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["nmap", "--version"], 0, b"Nmap version 7.95\n", b""
        ),
    )

    class TimeoutProcess:
        returncode = -9

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.stdout = self
            self.timed_out = False
            self.read_once = False

        def read(self, _size: int) -> bytes:
            if self.read_once:
                return b""
            self.read_once = True
            return b""

        def wait(self, timeout: float | None = None) -> int:
            if timeout is not None and not self.timed_out:
                self.timed_out = True
                raise subprocess.TimeoutExpired("nmap", timeout)
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", TimeoutProcess)
    with pytest.raises(NmapExecutionError) as timeout:
        NmapExecutor(timeout_seconds=0.01).run(
            target="192.0.2.10", profile="host_discovery", ports=[]
        )
    assert timeout.value.code == "nmap_timeout"

    class InvalidXmlProcess(TimeoutProcess):
        def read(self, _size: int) -> bytes:
            if self.read_once:
                return b""
            self.read_once = True
            return b"<nmaprun version='7.95'>"

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    monkeypatch.setattr(subprocess, "Popen", InvalidXmlProcess)
    with pytest.raises(NmapExecutionError) as parse_error:
        NmapExecutor().run(target="192.0.2.10", profile="host_discovery", ports=[])
    assert parse_error.value.code == "nmap_output_invalid"


def test_nmap_targets_are_canonical_and_bounded() -> None:
    assert validate_nmap_target("192.0.2.10", asset_type="ip") == "192.0.2.10"
    assert validate_nmap_target("2001:db8::1", asset_type="ip") == "2001:db8::1"
    assert validate_nmap_target("192.0.2.0/24", asset_type="cidr") == "192.0.2.0/24"
    for value, asset_type in (("example.com", "domain"), ("192.0.2.0/8", "cidr"), ("*", "ip")):
        with pytest.raises(NmapTargetError):
            validate_nmap_target(value, asset_type=asset_type)


def test_nmap_arguments_are_structured_and_profile_bound() -> None:
    args = build_nmap_arguments("basic_port_assessment", "192.0.2.10", ports=[443, 80])
    assert args[-2:] == ["--", "192.0.2.10"]
    assert "-p" in args and "80,443" in args
    with pytest.raises(ValueError):
        build_nmap_arguments("host_discovery", "192.0.2.10;id", ports=[])
    with pytest.raises(ValueError):
        build_nmap_arguments("host_discovery", "192.0.2.10", ports=[80])


def test_nmap_parser_bounds_and_rejects_hostile_xml() -> None:
    result = parse_nmap_xml(VALID_XML, profile="basic_port_assessment", target="192.0.2.10")
    assert result.host_count == 1
    assert result.port_count == 1
    assert result.hosts[0].address == "192.0.2.10"
    with pytest.raises(NmapParseError):
        parse_nmap_xml(
            b"<!DOCTYPE nmaprun [<!ENTITY x 'y'>]><nmaprun/>",
            profile="host_discovery",
            target="192.0.2.10",
        )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(
            VALID_XML.replace(b"192.0.2.10", b"not-an-ip"),
            profile="host_discovery",
            target="192.0.2.10",
        )


def test_nmap_executor_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append({"args": args, **kwargs})
        command = args[0]
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, b"Nmap version 7.95\n", b"")
        return subprocess.CompletedProcess(command, 0, VALID_XML, b"")

    class FakeProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            calls.append({"args": (command,), **kwargs})
            self.returncode = 0
            self.stdout = _FakePipe(
                VALID_XML if command[-1] != "--version" else b"Nmap version 7.95\n"
            )

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    class _FakePipe:
        def __init__(self, value: bytes) -> None:
            self.value = value

        def read(self, _size: int) -> bytes:
            value, self.value = self.value, b""
            return value

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", FakeProcess)
    result = NmapExecutor().run(target="192.0.2.10", profile="host_discovery", ports=[])
    assert result.host_count == 1
    assert all(call.get("shell") is False for call in calls)
    assert all(";" not in str(call["args"][0]) for call in calls)


def test_nmap_executor_bounds_stdout_before_accumulation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["nmap", "--version"], 0, b"Nmap version 7.95\n", b""
        ),
    )

    class OverflowProcess:
        returncode = 0

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.stdout = self

        def read(self, _size: int) -> bytes:
            return b"x" * 4096

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", OverflowProcess)
    with pytest.raises(NmapExecutionError) as exc_info:
        NmapExecutor(max_output_bytes=1024).run(
            target="192.0.2.10", profile="host_discovery", ports=[]
        )
    assert exc_info.value.code == "nmap_output_too_large"


def test_nmap_executor_reports_missing_binary_without_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(NmapExecutionError) as exc_info:
        NmapExecutor().check_available()
    assert exc_info.value.code == "nmap_unavailable"


class _FakeNmapExecutor:
    def run(self, *, target: str, profile: str, ports: list[int]):
        del ports
        return parse_nmap_xml(VALID_XML, profile=profile, target=target)


def _seed_nmap_job(tmp_path: Path):
    repo = SQLiteRepository(tmp_path / "nmap.sqlite3")
    orgs = OrganizationService(repo)
    security = EngagementSecurityService(repo, orgs)
    owner, org = orgs.ensure_operator(
        "nmap-owner@example.test", "epoch", "11111111-1111-4111-8111-111111111111"
    )
    client = orgs.create_client(owner["id"], org["id"], "Nmap Client", None)
    engagement = orgs.create_engagement(
        owner["id"], org["id"], client["id"], "Nmap Engagement", "Synthetic", "active"
    )
    reviewer_id = str(uuid4())
    now = datetime.now(UTC)
    with repo.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=reviewer_id,
                email_normalized="nmap-reviewer@example.test",
                display_name="Nmap Reviewer",
                status="active",
                auth_epoch="epoch-r",
                created_at=now.isoformat(),
                updated_at=now.isoformat(),
            )
        )
    orgs.add_member(owner["id"], org["id"], reviewer_id, "member")
    orgs.change_assignment(owner["id"], org["id"], engagement["id"], reviewer_id, role="reviewer")
    asset = security.create_asset(owner["id"], org["id"], engagement["id"], "ip", "192.0.2.10")
    scope = security.create_scope_revision(
        owner["id"],
        org["id"],
        engagement["id"],
        [
            {
                "asset_id": asset["id"],
                "effect": "include",
                "match_mode": "exact",
                "techniques": ["port_scan"],
            }
        ],
        "Nmap scope",
    )
    published = security.publish_scope_revision(
        reviewer_id, org["id"], engagement["id"], scope["id"]
    )
    security.create_authorization(
        owner["id"],
        org["id"],
        engagement["id"],
        published["id"],
        "NMAP-AUTH",
        "Synthetic",
        ["port_scan"],
        (now - timedelta(minutes=1)).isoformat(),
        (now + timedelta(hours=1)).isoformat(),
    )
    adapter = GovernedNmapAdapter(repo, _FakeNmapExecutor())  # type: ignore[arg-type]
    governance = ExecutionGovernanceService(security)
    governance.adapters = build_default_adapter_registry(repo, nmap_adapter=adapter)
    job = governance.create_governed_job(
        owner["id"],
        org["id"],
        engagement["id"],
        asset["id"],
        technique="port_scan",
        approval_id=None,
        idempotency_key="nmap-idempotency-1",
        chain_request={"profile": "host_discovery", "ports": []},
    )
    return repo, governance, owner["id"], org["id"], engagement["id"], job


def test_nmap_job_binds_parameters_and_persists_tenant_scoped_evidence(tmp_path: Path) -> None:
    repo, governance, user_id, organization_id, engagement_id, job = _seed_nmap_job(tmp_path)
    try:
        assert job["status"] == "queued"
        assert job["execution_context"]["operation_parameters"] == {
            "profile": "host_discovery",
            "ports": [],
        }
        duplicate = governance.create_governed_job(
            user_id,
            organization_id,
            engagement_id,
            job["asset_id"],
            technique="port_scan",
            approval_id=None,
            idempotency_key="nmap-idempotency-1",
            chain_request={"profile": "host_discovery", "ports": []},
        )
        assert duplicate["id"] == job["id"]
        worker = GovernedDomainWorker(repo, governance)
        result = worker.run_one(job["id"])
        assert result is not None and result["status"] == "completed"
        persisted = governance.get_job(user_id, organization_id, job["id"])
        assert persisted is not None
        assert persisted["engagement_id"] == engagement_id
        with repo.member_context(organization_id, user_id, write=False):
            evidence = repo.get("evidence", persisted["scan_id"])
        assert evidence is not None
        assert evidence["evidence_type"] == "nmap_result"
        assert evidence["organization_id"] == organization_id
    finally:
        repo.close()
