from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import threading
import time
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from chinescan.core import execution_isolation
from chinescan.core.config.settings import NucleiIntegrationSettings, Settings
from chinescan.core.evidence_ingestion import EvidenceIngestionError, EvidenceIngestionService
from chinescan.core.execution_isolation import (
    IsolationProfile,
    IsolationUnavailableError,
    detect_isolation_capabilities,
    isolation_status,
    make_preexec_fn,
    require_isolation,
)
from chinescan.core.subprocess_supervision import (
    ExecutionDeadlineExceeded,
    SubprocessExecutionError,
    SupervisedProcessResult,
    run_supervised_subprocess,
)
from chinescan.integrations.nmap import executor as nmap_executor_mod
from chinescan.integrations.nmap.executor import NmapExecutionError, NmapExecutor
from chinescan.integrations.nuclei import executor as nuclei_executor_mod
from chinescan.integrations.nuclei.executor import NucleiExecutionError, NucleiExecutor
from chinescan.integrations.nuclei.parser import NucleiParseError, parse_nuclei_jsonl
from chinescan.integrations.nuclei.profiles import validate_parameters
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


def _fake_resource_module(*, fail_getrlimit: bool = False) -> SimpleNamespace:
    calls: list[tuple[int, tuple[int, int]]] = []

    def getrlimit(_limit_id: int) -> tuple[int, int]:
        if fail_getrlimit:
            raise OSError("rlimit query failed")
        return (1024, 1024)

    def setrlimit(limit_id: int, limits: tuple[int, int]) -> None:
        calls.append((limit_id, limits))

    return SimpleNamespace(
        RLIMIT_CPU=1,
        RLIMIT_AS=2,
        RLIMIT_NPROC=3,
        RLIMIT_NOFILE=4,
        RLIMIT_FSIZE=5,
        getrlimit=getrlimit,
        setrlimit=setrlimit,
        calls=calls,
    )


def test_hardened_isolation_reports_platform_capability() -> None:
    status = isolation_status()
    assert status["platform"] == sys.platform
    assert isinstance(status["platform_supported"], bool)
    assert isinstance(status["runtime_available"], bool)
    assert status["hardened_supported"] is (
        status["platform_supported"] and status["runtime_available"]
    )
    assert status["network_isolation"] is False
    assert "network_isolation" in status["unavailable_controls"]  # type: ignore[operator]
    assert "network_namespace_not_application_managed" in status["reasons"]  # type: ignore[operator]
    # Hardened network-isolated profiles must always fail closed on local hosts.
    with pytest.raises(IsolationUnavailableError) as exc_info:
        require_isolation(
            IsolationProfile(
                cpu_seconds=1, memory_bytes=32_000_000, network_isolation_required=True
            )
        )
    expected_code = (
        "NETWORK_ISOLATION_UNAVAILABLE" if status["hardened_supported"] else "ISOLATION_UNAVAILABLE"
    )
    assert exc_info.value.code == expected_code


def test_isolation_reports_windows_and_linux_runtime_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulated Windows host: platform unsupported, fails closed even without network isolation.
    monkeypatch.setattr(execution_isolation.os, "name", "nt")
    monkeypatch.setattr(execution_isolation.sys, "platform", "win32")
    win_caps = detect_isolation_capabilities()
    assert win_caps.platform_supported is False
    assert win_caps.runtime_available is False
    assert win_caps.hardened_supported is False
    assert win_caps.cpu_memory_limits is False
    assert win_caps.process_tree_cleanup is True
    assert win_caps.network_isolation is False
    assert "hardened_linux_worker_required" in win_caps.reasons
    assert "posix_rlimits" in win_caps.unavailable_controls
    with pytest.raises(IsolationUnavailableError, match="unavailable"):
        require_isolation(IsolationProfile(network_isolation_required=False))
    with pytest.raises(IsolationUnavailableError):
        make_preexec_fn(IsolationProfile())

    # Simulated Linux host with working rlimits.
    fake_res = _fake_resource_module()
    monkeypatch.setattr(execution_isolation.os, "name", "posix")
    monkeypatch.setattr(execution_isolation.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "resource", fake_res)
    linux_caps = detect_isolation_capabilities()
    assert linux_caps.platform_supported is True
    assert linux_caps.runtime_available is True
    assert linux_caps.hardened_supported is True
    assert linux_caps.cpu_memory_limits is True
    assert linux_caps.network_isolation is False
    assert "posix_rlimits" in linux_caps.enforced_controls
    assert "network_isolation" in linux_caps.unavailable_controls

    # Local rlimit profile succeeds when network_isolation_required=False, fails when True.
    verified = require_isolation(IsolationProfile(network_isolation_required=False))
    assert verified.hardened_supported is True
    with pytest.raises(IsolationUnavailableError) as net_exc:
        require_isolation(IsolationProfile(network_isolation_required=True))
    assert net_exc.value.code == "NETWORK_ISOLATION_UNAVAILABLE"

    preexec = make_preexec_fn(IsolationProfile(cpu_seconds=5, memory_bytes=128_000_000))
    preexec()
    assert len(fake_res.calls) == 5

    # Simulated Linux host where runtime rlimit probe fails.
    broken_res = _fake_resource_module(fail_getrlimit=True)
    monkeypatch.setitem(sys.modules, "resource", broken_res)
    broken_caps = detect_isolation_capabilities()
    assert broken_caps.platform_supported is True
    assert broken_caps.runtime_available is False
    assert broken_caps.hardened_supported is False
    assert "posix_resource_limits_unavailable" in broken_caps.reasons
    with pytest.raises(IsolationUnavailableError) as broken_exc:
        require_isolation(IsolationProfile(network_isolation_required=False))
    assert broken_exc.value.code == "ISOLATION_UNAVAILABLE"


def test_nmap_hardened_mode_fails_closed_when_unavailable() -> None:
    with pytest.raises(NmapExecutionError, match="isolation_unavailable"):
        NmapExecutor(require_hardened_isolation=True).check_available()


def test_nmap_hardened_run_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = IsolationProfile(network_isolation_required=False)
    executor = NmapExecutor(isolation_profile=profile, require_hardened_isolation=True)
    monkeypatch.setattr(executor, "check_available", lambda: "7.95")

    valid_xml = (
        b'<nmaprun version="7.95"><host><status state="up"/>'
        b'<address addr="192.0.2.10" addrtype="ipv4"/></host>'
        b'<runstats><finished timestr="2026-11-26T00:00:00Z"/></runstats></nmaprun>'
    )
    monkeypatch.setattr(
        nmap_executor_mod,
        "run_supervised_subprocess",
        lambda *_a, **_kw: SupervisedProcessResult(
            returncode=0, stdout=valid_xml, stderr=b"", duration_seconds=0.25
        ),
    )
    res = executor.run(target="192.0.2.10", profile="host_discovery")
    assert res.nmap_version == "7.95"
    assert executor.last_telemetry is not None
    assert executor.last_telemetry.returncode == 0

    for err_code, expected in (
        ("SUBPROCESS_TIMEOUT", "nmap_timeout"),
        ("SUBPROCESS_OUTPUT_LIMIT_EXCEEDED", "nmap_output_too_large"),
        ("SUBPROCESS_CANCELLED", "nmap_cancelled"),
        ("SUBPROCESS_START_FAILED", "nmap_unavailable"),
    ):

        def _raise(*_a: object, code: str = err_code, **_kw: object) -> SupervisedProcessResult:
            raise SubprocessExecutionError(code, code)

        monkeypatch.setattr(nmap_executor_mod, "run_supervised_subprocess", _raise)
        with pytest.raises(NmapExecutionError, match=expected):
            executor.run(target="192.0.2.10", profile="host_discovery")

    monkeypatch.setattr(
        nmap_executor_mod,
        "run_supervised_subprocess",
        lambda *_a, **_kw: SupervisedProcessResult(
            returncode=2, stdout=b"", stderr=b"err", duration_seconds=0.1
        ),
    )
    with pytest.raises(NmapExecutionError, match="nmap_failed"):
        executor.run(target="192.0.2.10", profile="host_discovery")

    monkeypatch.setattr(
        nmap_executor_mod,
        "run_supervised_subprocess",
        lambda *_a, **_kw: SupervisedProcessResult(
            returncode=0, stdout=b"not-xml", stderr=b"", duration_seconds=0.1
        ),
    )
    with pytest.raises(NmapExecutionError):
        executor.run(target="192.0.2.10", profile="host_discovery")


def test_nuclei_profiles_reject_arbitrary_templates() -> None:
    approved = {"a.yaml": "0" * 64}
    assert validate_parameters(
        {"profile": "safe_web_checks", "templates": ["a.yaml"]}, approved
    ) == {
        "profile": "safe_web_checks",
        "templates": ["a.yaml"],
    }
    for bad in (
        {"profile": "safe_web_checks", "templates": ["a.yaml"], "extra": 1},
        {"profile": "aggressive", "templates": ["a.yaml"]},
        {"profile": "safe_web_checks", "templates": []},
        {"profile": "safe_web_checks", "templates": "a.yaml"},
        {"profile": "safe_web_checks", "templates": ["../escape.yaml"]},
    ):
        with pytest.raises(ValueError):
            validate_parameters(bad, approved)  # type: ignore[arg-type]

    many = {f"t{i}.yaml": "0" * 64 for i in range(33)}
    with pytest.raises(ValueError, match="limit"):
        validate_parameters({"profile": "safe_web_checks", "templates": list(many)}, many)


def test_nuclei_parser_is_bounded_and_normalized() -> None:
    raw = (
        b'\n{"template-id":"x-001","info":{"name":"Example","severity":"low"},'
        b'"matched-at":"192.0.2.10","matcher-name":"status"}\n'
    )
    result = parse_nuclei_jsonl(raw, target="192.0.2.10", tool_version="3.3.0", max_bytes=4096)
    assert result.finding_count == 1
    assert result.findings[0].template_id == "x-001"
    assert result.findings[0].matcher_name == "status"

    for bad_raw in (
        b"",
        b"\xff\xfe",
        b"{bad-json}\n",
        b"[1, 2]\n",
        b'{"template-id":"x-001","info":"not-a-dict"}\n',
        b'{"template-id":"x-001","info":{"name":"Example"}}\n',
    ):
        with pytest.raises(NucleiParseError):
            parse_nuclei_jsonl(bad_raw, target="192.0.2.10", tool_version="3.3.0")

    with pytest.raises(NucleiParseError):
        parse_nuclei_jsonl(raw, target="192.0.2.10", tool_version="3.3.0", max_bytes=8)
    with pytest.raises(NucleiParseError, match="limit"):
        parse_nuclei_jsonl(raw * 2, target="192.0.2.10", tool_version="3.3.0", max_findings=1)


def test_nuclei_executor_validation_and_run_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = tmp_path / "x.yaml"
    content = b"id: x-001\n"
    template.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    bad_exec = NucleiExecutor(
        template_directory=tmp_path,
        approved_templates={"x.yaml": "0" * 64},
    )
    with pytest.raises(NucleiExecutionError, match="integrity_failed"):
        bad_exec._template_path("x.yaml")
    with pytest.raises(NucleiExecutionError, match="template_invalid"):
        bad_exec._template_path("../x.yaml")
    with pytest.raises(NucleiExecutionError, match="template_unavailable"):
        bad_exec._template_path("missing.yaml")

    bad_hash_exec = NucleiExecutor(
        template_directory=tmp_path,
        approved_templates={"x.yaml": "not-a-sha256"},
    )
    with pytest.raises(NucleiExecutionError, match="hash_invalid"):
        bad_hash_exec._template_path("x.yaml")

    # check_available error paths
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("no")))
    executor = NucleiExecutor(
        template_directory=tmp_path,
        approved_templates={"x.yaml": digest},
        expected_major=3,
    )
    with pytest.raises(NucleiExecutionError, match="nuclei_unavailable"):
        executor.check_available()

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(returncode=1, stdout=b"err"),
    )
    with pytest.raises(NucleiExecutionError, match="nuclei_version_invalid"):
        executor.check_available()

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(returncode=0, stdout=b"Nuclei Engine Version: v2.9.0"),
    )
    with pytest.raises(NucleiExecutionError, match="nuclei_version_unsupported"):
        executor.check_available()

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(returncode=0, stdout=b"Nuclei Engine Version: v3.3.0"),
    )
    assert executor.check_available() == "v3.3.0"
    assert executor._template_path("x.yaml") == str(template.resolve())

    # run() paths
    with pytest.raises(NucleiExecutionError, match="nuclei_parameters_invalid"):
        executor.run(target="192.0.2.10", parameters={"profile": "bad", "templates": []})

    jsonl = (
        b'{"template-id":"x-001","info":{"name":"Example","severity":"low"},'
        b'"matched-at":"192.0.2.10"}\n'
    )
    monkeypatch.setattr(
        nuclei_executor_mod,
        "run_supervised_subprocess",
        lambda *_a, **_kw: SupervisedProcessResult(
            returncode=0, stdout=jsonl, stderr=b"", duration_seconds=0.2
        ),
    )
    scan_res = executor.run(
        target="192.0.2.10", parameters={"profile": "safe_web_checks", "templates": ["x.yaml"]}
    )
    assert scan_res.finding_count == 1

    for code, expected in (
        ("SUBPROCESS_TIMEOUT", "nuclei_timeout"),
        ("SUBPROCESS_OUTPUT_LIMIT_EXCEEDED", "nuclei_output_too_large"),
        ("SUBPROCESS_START_FAILED", "nuclei_unavailable"),
    ):

        def _raise(*_a: object, err: str = code, **_kw: object) -> SupervisedProcessResult:
            raise SubprocessExecutionError(err, err)

        monkeypatch.setattr(nuclei_executor_mod, "run_supervised_subprocess", _raise)
        with pytest.raises(NucleiExecutionError, match=expected):
            executor.run(
                target="192.0.2.10",
                parameters={"profile": "safe_web_checks", "templates": ["x.yaml"]},
            )


class _EvidenceRepository:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, object]] = {}

    def member_context(self, *_args: object, **_kwargs: object) -> Any:
        return nullcontext()

    def execution_provenance_context(self, *_args: object, **_kwargs: object) -> Any:
        return nullcontext()

    def get(self, _record_type: str, record_id: str) -> dict[str, object] | None:
        return self.records.get(record_id)

    def save(self, _record_type: str, record_id: str, payload: dict[str, object]) -> None:
        self.records[record_id] = payload


def test_evidence_ingestion_is_canonical_idempotent_and_tenant_bound() -> None:
    repository = _EvidenceRepository()
    with pytest.raises(ValueError, match="retention_days"):
        EvidenceIngestionService(repository, retention_days=0)  # type: ignore[arg-type]
    service = EvidenceIngestionService(repository)  # type: ignore[arg-type]
    context = SimpleNamespace(
        job_id="11111111-1111-4111-8111-111111111111",
        organization_id="22222222-2222-4222-8222-222222222222",
        requester_user_id="33333333-3333-4333-8333-333333333333",
        engagement_id="44444444-4444-4444-8444-444444444444",
        scope_revision_id="55555555-5555-4555-8555-555555555555",
        target="192.0.2.10",
        model_dump=lambda mode=None: {"job_id": "11111111-1111-4111-8111-111111111111"},
    )
    with pytest.raises(EvidenceIngestionError, match="evidence_payload_invalid"):
        service.ingest(
            context,  # type: ignore[arg-type]
            evidence_type="nmap_result",
            source_format="json",
            parser_version="test-v1",
            tool="nmap",
            tool_version="8.0",
            payload={"bad": object()},
        )
    record_id, envelope = service.ingest(
        context,  # type: ignore[arg-type]
        evidence_type="nmap_result",
        source_format="json",
        parser_version="test-v1",
        tool="nmap",
        tool_version="8.0",
        payload={"result": {"hosts": []}},
    )
    repeat_id, repeat = service.ingest(
        context,  # type: ignore[arg-type]
        evidence_type="nmap_result",
        source_format="json",
        parser_version="test-v1",
        tool="nmap",
        tool_version="8.0",
        payload={"result": {"hosts": []}},
    )
    assert repeat_id == record_id
    assert repeat.content_sha256 == envelope.content_sha256
    assert repository.records[record_id]["organization_id"] == context.organization_id
    repository.records[record_id]["content_sha256"] = "0" * 64
    with pytest.raises(EvidenceIngestionError, match="collision"):
        service.ingest(
            context,  # type: ignore[arg-type]
            evidence_type="nmap_result",
            source_format="json",
            parser_version="test-v1",
            tool="nmap",
            tool_version="8.0",
            payload={"result": {"hosts": []}},
        )


def test_supervised_subprocess_controls_and_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SubprocessExecutionError, match="non-empty"):
        run_supervised_subprocess([])
    with pytest.raises(ValueError, match="timeout_seconds"):
        run_supervised_subprocess([sys.executable], timeout_seconds=0)
    with pytest.raises(ValueError, match="max_output_bytes"):
        run_supervised_subprocess([sys.executable], max_output_bytes=0)
    with pytest.raises(ValueError, match="isolation_profile"):
        run_supervised_subprocess([sys.executable], require_hardened_isolation=True)
    with pytest.raises(ExecutionDeadlineExceeded):
        run_supervised_subprocess([sys.executable], deadline_at=time.monotonic() - 1.0)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(SubprocessExecutionError, match="cancelled before launch"):
        run_supervised_subprocess([sys.executable], cancellation=cancel)

    class _FakeProcess:
        def __init__(self, stdout_data: bytes = b"ok", returncode: int = 0) -> None:
            self.pid = 999999
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(stdout_data)
            self.stderr = io.BytesIO(b"")
            self._rc: int | None = None
            self._final_rc = returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self._rc = self._final_rc
            return self._final_rc

        def poll(self) -> int | None:
            return self._rc

        def kill(self) -> None:
            self._rc = -9

    monkeypatch.setattr("chinescan.core.subprocess_supervision.resolve_executable", lambda exe: exe)
    ok_res = run_supervised_subprocess(
        ["fake-bin"],
        input_bytes=b"hello",
        popen_factory=lambda *_a, **_kw: _FakeProcess(b"done", 0),
    )
    assert ok_res.stdout == b"done"

    with pytest.raises(SubprocessExecutionError, match="output limit"):
        run_supervised_subprocess(
            ["fake-bin"],
            max_output_bytes=4,
            popen_factory=lambda *_a, **_kw: _FakeProcess(b"12345678", 0),
        )

    def _fail_launch(*_a: object, **_kw: object) -> Any:
        raise OSError("boom")

    with pytest.raises(SubprocessExecutionError, match="could not be started"):
        run_supervised_subprocess(["fake-bin"], popen_factory=_fail_launch)


def test_nuclei_api_routes_enforce_disabled_and_auth_boundaries(tmp_path: Path) -> None:
    credential = tmp_path / "private" / "operator.json"
    create_operator(credential, "nuclei-routes@example.test", "safe local password")
    settings = Settings(
        database_path=tmp_path / "nuclei.sqlite3",
        reports_dir=tmp_path / "reports",
        integrations={"nuclei": NucleiIntegrationSettings(enabled=False)},
    )
    app = create_app(
        tmp_path / "nuclei.sqlite3", credential, settings=settings, serve_frontend=False
    )
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50002))
    login = client.post(
        "/api/auth/login",
        json={"email": "nuclei-routes@example.test", "password": "safe local password"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert login.status_code == 200
    csrf_headers = {
        "Origin": "http://127.0.0.1",
        "X-CSRF-Token": login.json()["csrf_token"],
    }
    org_id = "11111111-1111-4111-8111-111111111111"
    eng_id = "22222222-2222-4222-8222-222222222222"
    profiles = client.get(f"/api/organizations/{org_id}/engagements/{eng_id}/nuclei/profiles")
    assert profiles.status_code == 200
    assert profiles.json()["enabled"] is False

    disabled = client.post(
        f"/api/organizations/{org_id}/engagements/{eng_id}/nuclei/executions",
        json={
            "asset_id": "33333333-3333-4333-8333-333333333333",
            "profile": "safe_web_checks",
            "templates": ["x.yaml"],
            "idempotency_key": "nuclei-disabled-request",
        },
        headers=csrf_headers,
    )
    assert disabled.status_code == 404
    missing = client.get(
        f"/api/organizations/{org_id}/engagements/{eng_id}/nuclei/executions/"
        "44444444-4444-4444-8444-444444444444/result"
    )
    assert missing.status_code == 404
