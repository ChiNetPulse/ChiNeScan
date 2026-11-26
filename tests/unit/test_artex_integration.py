"""Milestone 1 ARTEX policy, client, and HTTP route smoke tests."""

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from chinescan.core.config.settings import ArtexIntegrationSettings, Settings
from chinescan.integrations.artex.client import ArtexHealthClient, ArtexIntegrationError
from chinescan.integrations.artex.models import ArtexAuditEvent, ArtexHealth
from chinescan.integrations.artex.routes import RouteDenied, validate_outbound_route
from chinescan.web.app import create_app
from chinescan.web.auth import create_operator


@contextmanager
def _local_artex_server(
    status_code: int,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Iterator[tuple[str, list[str]]]:
    seen_paths: list[str] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen_paths.append(self.path)
            self.send_response(status_code)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            if payload is not None:
                body = json.dumps(payload).encode("utf-8")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", seen_paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _enabled_settings(
    base_url: str, release_id: str = "build-placeholder"
) -> ArtexIntegrationSettings:
    return ArtexIntegrationSettings(
        enabled=True,
        mode="health_only",
        health_enabled=True,
        release_id=release_id,
        base_url=base_url,
        sensitive_data_acknowledged=True,
        retention_policy_acknowledged=True,
    )


def _artex_app(tmp_path: Path, artex_settings: ArtexIntegrationSettings | None = None) -> FastAPI:
    database = tmp_path / "data" / "records.sqlite3"
    credential = tmp_path / "private" / "operator.json"
    credential.parent.mkdir(parents=True, exist_ok=True)
    create_operator(credential, "analyst@example.test", "safe local password")
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        _env_file=None,
        database_path=database,
        reports_dir=reports,
        integrations={"artex": artex_settings or ArtexIntegrationSettings()},
    )
    return create_app(
        database,
        credential,
        projects_path=tmp_path / "projects.toml",
        log_sources_path=tmp_path / "logs.toml",
        malware_registry_path=tmp_path / "malware.toml",
        settings=settings,
        serve_frontend=False,
    )


def _login(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@example.test", "password": "safe local password"},
        headers={"Origin": str(client.base_url).rstrip("/")},
    )
    assert response.status_code == 200


def test_artex_is_disabled_by_default() -> None:
    assert Settings(_env_file=None).integrations.artex.enabled is False


def test_health_route_only() -> None:
    assert validate_outbound_route("GET", "/api/health") == "/api/health"
    for method, target in (("POST", "/api/tasks"), ("GET", "/api/tasks"),
                           ("GET", "/api/health?debug=true"), ("GET", "/api/evidence.zip")):
        with pytest.raises(RouteDenied):
            validate_outbound_route(method, target)


def test_authenticated_feature_configuration_is_rejected() -> None:
    with pytest.raises(ValidationError, match="authenticated ARTEX features are blocked"):
        ArtexIntegrationSettings(task_list_enabled=True)


def test_health_enablement_requires_all_operator_gates() -> None:
    with pytest.raises(ValidationError):
        ArtexIntegrationSettings(enabled=True, mode="health_only", health_enabled=True)
    configured = ArtexIntegrationSettings(
        enabled=True,
        mode="health_only",
        health_enabled=True,
        release_id="build-placeholder",
        base_url="https://artex.example.invalid",
        sensitive_data_acknowledged=True,
        retention_policy_acknowledged=True,
    )
    assert configured.enabled and configured.health_enabled


def test_non_loopback_cleartext_and_url_components_are_rejected() -> None:
    common = {
        "enabled": True, "mode": "health_only", "health_enabled": True,
        "release_id": "build-placeholder", "sensitive_data_acknowledged": True,
        "retention_policy_acknowledged": True,
    }
    for base_url in ("http://artex.example.invalid", "https://artex.example.invalid/api", "https://user:pass@artex.example.invalid"):
        with pytest.raises(ValidationError):
            ArtexIntegrationSettings(**common, base_url=base_url)


def test_health_schema_is_strict_and_bounded() -> None:
    with pytest.raises(ValidationError):
        ArtexHealth.model_validate(
            {"ok": True, "service": "artex", "version": "x", "token": "secret"}
        )
    with pytest.raises(ValidationError):
        ArtexHealth.model_validate({"ok": "true", "service": "artex", "version": "x"})


def test_audit_model_rejects_unexpected_sensitive_fields() -> None:
    with pytest.raises(ValidationError):
        ArtexAuditEvent.model_validate({
            "event_type": "health_succeeded", "outcome": "success",
            "correlation_id": "test", "authorization": "secret",
        })


@pytest.mark.parametrize("status_code", [301, 302, 307, 308])
def test_client_explicitly_rejects_http_redirects(status_code: int) -> None:
    with _local_artex_server(
        status_code,
        headers={"Location": "http://127.0.0.1/redirected"},
    ) as (base_url, seen_paths):
        client = ArtexHealthClient(_enabled_settings(base_url))
        with pytest.raises(ArtexIntegrationError) as exc_info:
            client.get_health(correlation_id="redirect-test")
    assert exc_info.value.code == "upstream_redirect_rejected"
    assert seen_paths == ["/api/health"]


def test_http_routes_require_auth_and_preserve_disabled_default(tmp_path: Path) -> None:
    application = _artex_app(tmp_path)
    try:
        with TestClient(
            application, base_url="http://127.0.0.1", client=("127.0.0.1", 49320)
        ) as client:
            assert client.get("/api/integrations/artex/status").status_code == 401
            assert client.get("/api/integrations/artex/health").status_code == 401

            _login(client)

            status_resp = client.get("/api/integrations/artex/status")
            assert status_resp.status_code == 200
            status_body = status_resp.json()
            assert status_body["integration"] == "ARTEX"
            assert status_body["enabled"] is False
            assert status_body["state"] == "disabled"
            assert status_body["active_operations"] is False

            health_resp = client.get("/api/integrations/artex/health")
            assert health_resp.status_code == 403
            assert health_resp.json()["detail"] == {"code": "integration_disabled"}
    finally:
        application.state.repository.close()


def test_http_health_route_handles_success_and_redirect(tmp_path: Path) -> None:
    with _local_artex_server(
        200,
        payload={"ok": True, "service": "artex", "version": "build-placeholder"},
    ) as (base_url, seen_paths):
        application = _artex_app(tmp_path / "ok", _enabled_settings(base_url))
        try:
            with TestClient(
                application, base_url="http://127.0.0.1", client=("127.0.0.1", 49320)
            ) as client:
                _login(client)
                health_resp = client.get("/api/integrations/artex/health")
                assert health_resp.status_code == 200
                assert health_resp.json() == {
                    "integration": "ARTEX",
                    "state": "available",
                    "health": {"ok": True, "service": "artex", "version": "build-placeholder"},
                    "read_only": True,
                }
                status_resp = client.get("/api/integrations/artex/status")
                assert status_resp.status_code == 200
                assert status_resp.json()["state"] == "available"
                assert status_resp.json()["version"] == "build-placeholder"
        finally:
            application.state.repository.close()
        assert seen_paths == ["/api/health"]

    with _local_artex_server(
        302,
        headers={"Location": "http://127.0.0.1/redirected"},
    ) as (redirect_url, redirect_paths):
        redirect_app = _artex_app(tmp_path / "redir", _enabled_settings(redirect_url))
        try:
            with TestClient(
                redirect_app, base_url="http://127.0.0.1", client=("127.0.0.1", 49320)
            ) as client:
                _login(client)
                resp = client.get("/api/integrations/artex/health")
                assert resp.status_code == 503
                assert resp.json()["detail"] == {
                    "code": "upstream_redirect_rejected",
                    "state": "invalid",
                }
        finally:
            redirect_app.state.repository.close()
        assert redirect_paths == ["/api/health"]
