"""Phase 2C regression tests: DB identity, persistent sessions, lockouts, and invitations."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from chinescan.core.accounts import (
    confirm_totp_enrollment,
    create_operator,
    generate_totp_code,
    start_totp_enrollment,
)
from chinescan.core.identity import IdentityError
from chinescan.core.storage.sqlite import (
    organization_invitations,
    user_recovery_codes,
    users,
)
from chinescan.web.app import COOKIE_NAME, create_app


def _setup_app(tmp_path: Path, *, totp: bool = False):
    cred = tmp_path / "operator.json"
    db = tmp_path / "phase2c.sqlite3"
    create_operator(cred, "operator@example.test", "Operator-Secure-Passphrase-99!")
    recovery_codes: list[str] = []
    totp_secret: str | None = None
    if totp:
        totp_secret = start_totp_enrollment(cred)
        code = generate_totp_code(totp_secret)
        recovery_codes = confirm_totp_enrollment(cred, code) or []
        assert len(recovery_codes) == 10
    app = create_app(db, cred, serve_frontend=False)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    return app, client, cred, db, totp_secret, recovery_codes


def _login_http(client: TestClient, email: str, password: str, totp_code: str | None = None):
    payload: dict[str, str] = {"email": email, "password": password}
    if totp_code is not None:
        payload["totp_code"] = totp_code
    return client.post(
        "/api/auth/login",
        json=payload,
        headers={"Origin": str(client.base_url).rstrip("/")},
    )


def test_operator_migration_preserves_password_totp_recovery_and_is_idempotent(
    tmp_path: Path,
) -> None:
    app, client, cred, db, secret, recovery_codes = _setup_app(tmp_path, totp=True)
    try:
        identity = app.state.identity_service
        op_id = app.state.local_operator_user_id
        assert op_id

        # Idempotent re-run does not duplicate recovery codes or break credentials
        assert identity.migrate_operator_credentials(cred, op_id) is False
        with app.state.repository.engine.connect() as conn:
            rc_count = len(
                conn.execute(
                    select(user_recovery_codes.c.id).where(user_recovery_codes.c.user_id == op_id)
                ).all()
            )
            assert rc_count == 10

        # TOTP replay across app restart is rejected (persistent totp_last_counter)
        assert secret is not None
        import time

        now = int(time.time()) + 60
        live_code = generate_totp_code(secret, now=now)
        auth_ok = identity.authenticate(
            "operator@example.test", "Operator-Secure-Passphrase-99!", live_code, now=now
        )
        assert auth_ok is not None
        app.state.repository.close()

        app2 = create_app(db, cred, serve_frontend=False)
        try:
            # Replaying the exact same TOTP code after restart must fail
            assert (
                app2.state.identity_service.authenticate(
                    "operator@example.test", "Operator-Secure-Passphrase-99!", live_code, now=now
                )
                is None
            )
            # Single-use recovery code works once and fails on replay across restarts
            rc = recovery_codes[0]
            assert (
                app2.state.identity_service.authenticate(
                    "operator@example.test", "Operator-Secure-Passphrase-99!", rc, now=now + 60
                )
                is not None
            )
            assert (
                app2.state.identity_service.authenticate(
                    "operator@example.test", "Operator-Secure-Passphrase-99!", rc, now=now + 90
                )
                is None
            )
        finally:
            app2.state.repository.close()
    finally:
        app.state.repository.close()


def test_persistent_sessions_rotation_expiration_and_disabled_rejection(tmp_path: Path) -> None:
    app, client, cred, db, _secret, _codes = _setup_app(tmp_path)
    try:
        r_login = _login_http(client, "operator@example.test", "Operator-Secure-Passphrase-99!")
        assert r_login.status_code == 200
        token1 = client.cookies.get(COOKIE_NAME)
        assert r_login.json()["csrf_token"]
        assert token1

        # Re-login rotates session token (anti-fixation)
        r_login2 = _login_http(client, "operator@example.test", "Operator-Secure-Passphrase-99!")
        assert r_login2.status_code == 200
        token2 = client.cookies.get(COOKIE_NAME)
        csrf2 = r_login2.json()["csrf_token"]
        assert token2 and token2 != token1
        assert app.state.session_store.get(token1) is None

        # Password change requires CSRF, rotates session, and invalidates old token
        assert (
            client.post(
                "/api/auth/password/change",
                json={
                    "current_password": "Operator-Secure-Passphrase-99!",
                    "new_password": "New-Operator-Passphrase-2026!",
                },
                headers={"Origin": str(client.base_url).rstrip("/")},
            ).status_code
            == 403
        )
        r_pw = client.post(
            "/api/auth/password/change",
            json={
                "current_password": "Operator-Secure-Passphrase-99!",
                "new_password": "New-Operator-Passphrase-2026!",
            },
            headers={"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": csrf2},
        )
        assert r_pw.status_code == 200
        token3 = client.cookies.get(COOKIE_NAME)
        assert token3 and token3 != token2
        assert app.state.session_store.get(token2) is None

        # Session survives restart
        app.state.repository.close()
        app2 = create_app(db, cred, serve_frontend=False)
        try:
            client2 = TestClient(app2, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
            client2.cookies.set(COOKIE_NAME, token3)
            assert client2.get("/api/auth/me").status_code == 200
        finally:
            app2.state.repository.close()
    finally:
        app.state.repository.close()


def test_session_expiration_and_concurrent_validation_revocation(tmp_path: Path) -> None:
    app, client, cred, _db, _secret, _codes = _setup_app(tmp_path)
    try:
        op_id = app.state.local_operator_user_id
        now = 1_764_000_000.0
        store = app.state.session_store
        store._clock = lambda: now
        tok, _sess = store.create("operator@example.test", "epoch-1", user_id=op_id)
        assert store.get(tok) is not None

        # Concurrent get + revoke must not fail or raise
        barrier = Barrier(4)

        def worker(i: int) -> None:
            barrier.wait()
            if i == 0:
                store.revoke(tok)
            else:
                store.get(tok)

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(worker, range(4)))
        assert store.get(tok) is None

        # Idle expiration
        tok2, _ = store.create("operator@example.test", "epoch-1", user_id=op_id)
        store._clock = lambda: now + store.idle_ttl_seconds + 1
        assert store.get(tok2) is None
    finally:
        app.state.repository.close()


def test_persistent_lockout_survives_restart(tmp_path: Path) -> None:
    app, client, cred, db, _secret, _codes = _setup_app(tmp_path)
    try:
        for _ in range(5):
            r = _login_http(client, "operator@example.test", "wrong-password-12345")
            assert r.status_code in {401, 429}
        r_locked = _login_http(client, "operator@example.test", "wrong-password-12345")
        assert r_locked.status_code == 429
        app.state.repository.close()

        app2 = create_app(db, cred, serve_frontend=False)
        try:
            c2 = TestClient(app2, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
            r_locked2 = _login_http(c2, "operator@example.test", "Operator-Secure-Passphrase-99!")
            assert r_locked2.status_code == 429
        finally:
            app2.state.repository.close()
    finally:
        app.state.repository.close()


def test_invitation_lifecycle_permissions_concurrency_and_account_disablement(
    tmp_path: Path,
) -> None:
    app, client, _cred, _db, _secret, _codes = _setup_app(tmp_path)
    try:
        r_login = _login_http(client, "operator@example.test", "Operator-Secure-Passphrase-99!")
        assert r_login.status_code == 200
        op_csrf = r_login.json()["csrf_token"]
        op_headers = {"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": op_csrf}
        orgs = app.state.organization_service
        op_id = app.state.local_operator_user_id
        org_id = orgs.personal_organization_id(op_id)
        second_org = orgs.create_organization(op_id, "Second Org", "second-org")

        # Cannot invite owner role
        assert (
            client.post(
                f"/api/organizations/{org_id}/invitations",
                json={"email": "bad@example.test", "role": "owner"},
                headers=op_headers,
            ).status_code
            == 422
        )

        # Operator creates invitation for new member
        r_inv = client.post(
            f"/api/organizations/{org_id}/invitations",
            json={"email": "invited@example.test", "role": "admin"},
            headers=op_headers,
        )
        assert r_inv.status_code == 201
        inv_token = r_inv.json()["token"]
        assert r_inv.json()["id"]

        # Concurrent acceptance: exactly 1 succeeds, 1 fails
        barrier = Barrier(2)

        def accept_once(_i: int) -> bool:
            barrier.wait()
            try:
                app.state.identity_service.accept_invitation(
                    inv_token,
                    password="Invited-User-Passphrase-77!",
                    display_name="Invited Admin",
                )
                return True
            except IdentityError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(accept_once, range(2)))
        assert outcomes.count(True) == 1
        assert outcomes.count(False) == 1

        # Replay fails
        with pytest.raises(IdentityError):
            app.state.identity_service.accept_invitation(
                inv_token, password="Invited-User-Passphrase-77!"
            )

        # Invited user logs in via HTTP
        c_invited = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        r_il = _login_http(c_invited, "invited@example.test", "Invited-User-Passphrase-77!")
        assert r_il.status_code == 200
        inv_csrf = r_il.json()["csrf_token"]
        inv_headers = {"Origin": str(c_invited.base_url).rstrip("/"), "X-CSRF-Token": inv_csrf}

        # Invited admin can invite into org_id, but NOT into second_org, nor manage user status
        r_admin_inv = c_invited.post(
            f"/api/organizations/{org_id}/invitations",
            json={"email": "viewer@example.test", "role": "viewer"},
            headers=inv_headers,
        )
        assert r_admin_inv.status_code == 201
        viewer_inv_id = r_admin_inv.json()["id"]
        viewer_token = r_admin_inv.json()["token"]

        assert (
            c_invited.post(
                f"/api/organizations/{second_org['id']}/invitations",
                json={"email": "x@example.test", "role": "viewer"},
                headers=inv_headers,
            ).status_code
            == 404
        )
        assert (
            c_invited.patch(
                f"/api/auth/users/{op_id}/status",
                json={"status": "disabled"},
                headers=inv_headers,
            ).status_code
            == 404
        )

        # Revoke invitation prevents acceptance
        assert (
            c_invited.post(
                f"/api/organizations/{org_id}/invitations/{viewer_inv_id}/revoke",
                headers=inv_headers,
            ).status_code
            == 200
        )
        assert (
            c_invited.post(
                "/api/auth/invitations/accept",
                json={"token": viewer_token, "password": "Viewer-Password-88!"},
                headers={"Origin": str(c_invited.base_url).rstrip("/")},
            ).status_code
            == 400
        )

        # Expired invitation is rejected
        r_exp = client.post(
            f"/api/organizations/{org_id}/invitations",
            json={"email": "exp@example.test", "role": "member"},
            headers=op_headers,
        )
        assert r_exp.status_code == 201
        with app.state.repository.engine.begin() as conn:
            conn.execute(
                update(organization_invitations)
                .where(organization_invitations.c.id == r_exp.json()["id"])
                .values(expires_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat())
            )
        assert (
            client.post(
                "/api/auth/invitations/accept",
                json={"token": r_exp.json()["token"], "password": "Expired-User-Pass-99!"},
                headers={"Origin": str(client.base_url).rstrip("/")},
            ).status_code
            == 400
        )

        # Existing user invited into second_org must authenticate (or have matching session)
        r_existing_inv = client.post(
            f"/api/organizations/{second_org['id']}/invitations",
            json={"email": "invited@example.test", "role": "viewer"},
            headers=op_headers,
        )
        assert r_existing_inv.status_code == 201
        assert (
            client.post(
                "/api/auth/invitations/accept",
                json={"token": r_existing_inv.json()["token"], "password": "wrong-password-123"},
                headers={"Origin": str(client.base_url).rstrip("/")},
            ).status_code
            == 400
        )
        r_existing_ok = c_invited.post(
            "/api/auth/invitations/accept",
            json={"token": r_existing_inv.json()["token"]},
            headers={"Origin": str(c_invited.base_url).rstrip("/")},
        )
        assert r_existing_ok.status_code == 200

        # Local operator disables invited user -> existing session immediately rejected with 401
        with app.state.repository.engine.connect() as conn:
            invited_uid = conn.execute(
                select(users.c.id).where(users.c.email_normalized == "invited@example.test")
            ).scalar_one()
        assert (
            client.patch(
                f"/api/auth/users/{invited_uid}/status",
                json={"status": "disabled"},
                headers=op_headers,
            ).status_code
            == 200
        )
        assert c_invited.get("/api/organizations").status_code == 401
        r_disabled = _login_http(c_invited, "invited@example.test", "Invited-User-Passphrase-77!")
        assert r_disabled.status_code == 401
    finally:
        app.state.repository.close()
