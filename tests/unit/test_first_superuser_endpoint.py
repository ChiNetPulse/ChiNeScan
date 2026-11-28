"""Focused tests for unauthenticated POST /api/auth/first-superuser/setup."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert

from chinescan.core.accounts import create_operator
from chinescan.core.first_superuser import (
    FIRST_SUPERUSER_EMAIL,
    FirstSuperuserBootstrapError,
)
from chinescan.core.storage.sqlite import SQLiteRepository, users
from chinescan.web import app as web_app_module
from chinescan.web.app import create_app


def _seed_pending_superuser(repository: SQLiteRepository, user_id: str) -> None:
    now = "2026-11-28T00:00:00+00:00"
    with repository.engine.begin() as connection:
        connection.execute(
            insert(users).values(
                id=user_id,
                email_normalized=FIRST_SUPERUSER_EMAIL,
                display_name="Platform Superuser",
                platform_role="superuser",
                status="active",
                auth_epoch="pending-epoch",
                created_at=now,
                updated_at=now,
            )
        )


def test_first_superuser_setup_endpoint_allows_unauthenticated_one_time_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = tmp_path / "private" / "operator.json"
    create_operator(credential, "existing-local@example.test", "Local-Test-Password-2026!x")
    application = create_app(tmp_path / "setup.sqlite3", credential, serve_frontend=False)
    repository: SQLiteRepository = application.state.repository

    valid_token = "T" * 43
    expired_token = "E" * 43
    user_id = str(uuid4())
    _seed_pending_superuser(repository, user_id)
    consumed = {"done": False}

    def fake_complete(engine: object, token: str, password: str) -> str:
        assert engine is repository.engine
        if token == expired_token or token != valid_token or consumed["done"]:
            raise FirstSuperuserBootstrapError(
                "Bootstrap token is invalid, expired, already used, or unavailable."
            )
        assert len(password) >= 12
        consumed["done"] = True
        return user_id

    monkeypatch.setattr(
        web_app_module,
        "PostgresRepository",
        (web_app_module.PostgresRepository, SQLiteRepository),
    )
    monkeypatch.setattr(web_app_module, "complete_first_superuser_setup", fake_complete)

    client = TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50010))
    headers = {"Origin": "http://127.0.0.1"}

    # Protected endpoints still require authentication.
    assert client.get("/api/ready").status_code == 401
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/auth/me").status_code == 401
    # Only POST is exempted on /api/auth/first-superuser/setup.
    assert client.get("/api/auth/first-superuser/setup").status_code == 401

    # Invalid / expired token reaches handler (400), not auth middleware (401).
    bad_token_resp = client.post(
        "/api/auth/first-superuser/setup",
        json={
            "email": FIRST_SUPERUSER_EMAIL,
            "token": expired_token,
            "password": "Superuser-Strong-Password-2026!",
        },
        headers=headers,
    )
    assert bad_token_resp.status_code == 400

    # Wrong email is rejected by handler (400), not auth middleware (401).
    wrong_email_resp = client.post(
        "/api/auth/first-superuser/setup",
        json={
            "email": "attacker@example.test",
            "token": valid_token,
            "password": "Superuser-Strong-Password-2026!",
        },
        headers=headers,
    )
    assert wrong_email_resp.status_code == 400

    # Valid unauthenticated activation succeeds and establishes superuser + first-operator session.
    ok_resp = client.post(
        "/api/auth/first-superuser/setup",
        json={
            "email": FIRST_SUPERUSER_EMAIL,
            "token": valid_token,
            "password": "Superuser-Strong-Password-2026!",
        },
        headers=headers,
    )
    assert ok_resp.status_code == 201
    assert ok_resp.json()["email"] == FIRST_SUPERUSER_EMAIL
    assert ok_resp.json()["csrf_token"]
    assert application.state.local_operator_user_id == user_id

    # Authenticated session belongs to the activated superuser and first operator.
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["id"] == user_id
    assert me_resp.json()["email_normalized"] == FIRST_SUPERUSER_EMAIL
    assert me_resp.json()["status"] == "active"

    # Reusing the consumed token is rejected even without auth cookies.
    client.cookies.clear()
    replay_resp = client.post(
        "/api/auth/first-superuser/setup",
        json={
            "email": FIRST_SUPERUSER_EMAIL,
            "token": valid_token,
            "password": "Another-Strong-Password-2026!",
        },
        headers=headers,
    )
    assert replay_resp.status_code == 400
