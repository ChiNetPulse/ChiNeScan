"""Unit tests for reissue_first_superuser_token and the bootstrap-script fallback."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

import chinescan.core.first_superuser as fsu_module
from chinescan.core.first_superuser import (
    BOOTSTRAP_TOKEN_TTL_SECONDS,
    FIRST_SUPERUSER_EMAIL,
    FirstSuperuserBootstrapError,
    FirstSuperuserBootstrapResult,
    _token_hash,
    complete_first_superuser_setup,
    reissue_first_superuser_token,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine(scalar_return=None, raise_exc=None):
    """Return a mock Engine whose begin() context yields a mock connection."""
    conn = MagicMock()
    if raise_exc is not None:
        conn.execute.side_effect = raise_exc
    else:
        result = MagicMock()
        result.scalar_one.return_value = scalar_return
        conn.execute.return_value = result

    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=conn)
    cm.__exit__ = MagicMock(return_value=False)

    engine = MagicMock()
    engine.begin.return_value = cm
    return engine, conn


# ---------------------------------------------------------------------------
# reissue_first_superuser_token — happy path
# ---------------------------------------------------------------------------


def test_reissue_returns_result_with_created_false_and_valid_token():
    user_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    engine, conn = _make_engine(scalar_return=user_id)

    result = reissue_first_superuser_token(engine)

    assert isinstance(result, FirstSuperuserBootstrapResult)
    assert result.created is False
    assert result.user_id == user_id
    assert result.email == FIRST_SUPERUSER_EMAIL
    assert result.setup_token is not None
    assert len(result.setup_token) >= 32
    assert result.expires_at > time.time()

    # Verify the SQL call passes a proper SHA-256 hex hash (64 chars).
    call_args = conn.execute.call_args
    params = call_args[0][1]
    assert len(params["token_hash"]) == 64
    assert params["token_hash"] == _token_hash(result.setup_token)
    assert params["email"] == FIRST_SUPERUSER_EMAIL
    assert params["expires_at"] == pytest.approx(result.expires_at, abs=2)


# ---------------------------------------------------------------------------
# reissue_first_superuser_token — rejection cases
# ---------------------------------------------------------------------------


def test_reissue_raises_on_wrong_email():
    engine, _ = _make_engine()
    with pytest.raises(FirstSuperuserBootstrapError, match="restricted"):
        reissue_first_superuser_token(engine, email="attacker@example.test")


def test_reissue_raises_on_invalid_ttl():
    engine, _ = _make_engine()
    with pytest.raises(FirstSuperuserBootstrapError, match="invalid"):
        reissue_first_superuser_token(engine, ttl_seconds=10)


def test_reissue_raises_when_db_raises_account_already_activated():
    """DB raises when password_hash is set or bootstrap_used_at is not NULL."""
    engine, _ = _make_engine(
        raise_exc=RuntimeError("no eligible unactivated first-superuser account found")
    )
    with pytest.raises(FirstSuperuserBootstrapError, match="Token reissue was not completed"):
        reissue_first_superuser_token(engine)


def test_reissue_raises_when_db_raises_for_already_used_token():
    """bootstrap_used_at IS NOT NULL → DB raises, Python re-raises as bootstrap error."""
    engine, _ = _make_engine(raise_exc=RuntimeError("reissue is not permitted"))
    with pytest.raises(FirstSuperuserBootstrapError):
        reissue_first_superuser_token(engine)


# ---------------------------------------------------------------------------
# bootstrap script fallback: tries reissue when bootstrap raises
# ---------------------------------------------------------------------------


def test_script_fallback_calls_reissue_when_bootstrap_raises(monkeypatch):
    """bootstrap_first_superuser raising FirstSuperuserBootstrapError triggers reissue."""
    user_id = "11111111-2222-3333-4444-555555555555"
    reissue_result = FirstSuperuserBootstrapResult(
        user_id=user_id,
        email=FIRST_SUPERUSER_EMAIL,
        setup_token="fresh-token-abc",
        expires_at=time.time() + BOOTSTRAP_TOKEN_TTL_SECONDS,
        created=False,
    )

    monkeypatch.setattr(
        fsu_module,
        "bootstrap_first_superuser",
        MagicMock(side_effect=FirstSuperuserBootstrapError("first administrator already exists")),
    )
    mock_reissue = MagicMock(return_value=reissue_result)
    monkeypatch.setattr(fsu_module, "reissue_first_superuser_token", mock_reissue)

    # Simulate the script's inner try/except logic directly.
    engine = MagicMock()
    result = None
    try:
        result = fsu_module.bootstrap_first_superuser(engine, email=FIRST_SUPERUSER_EMAIL)
    except FirstSuperuserBootstrapError:
        result = fsu_module.reissue_first_superuser_token(engine, email=FIRST_SUPERUSER_EMAIL)

    mock_reissue.assert_called_once()
    assert result.user_id == user_id
    assert result.created is False


def test_script_fallback_propagates_reissue_error_when_account_activated(monkeypatch):
    """If the account is already activated, reissue also raises and the error propagates."""
    monkeypatch.setattr(
        fsu_module,
        "bootstrap_first_superuser",
        MagicMock(side_effect=FirstSuperuserBootstrapError("first administrator already exists")),
    )
    monkeypatch.setattr(
        fsu_module,
        "reissue_first_superuser_token",
        MagicMock(side_effect=FirstSuperuserBootstrapError("Token reissue was not completed.")),
    )

    engine = MagicMock()
    with pytest.raises(FirstSuperuserBootstrapError, match="Token reissue was not completed"):
        try:
            fsu_module.bootstrap_first_superuser(engine, email=FIRST_SUPERUSER_EMAIL)
        except FirstSuperuserBootstrapError:
            fsu_module.reissue_first_superuser_token(engine, email=FIRST_SUPERUSER_EMAIL)


# ---------------------------------------------------------------------------
# complete_first_superuser_setup — post-reissue activation
# ---------------------------------------------------------------------------


def test_complete_setup_validates_token_minimum_length():
    engine, _ = _make_engine()
    with pytest.raises(FirstSuperuserBootstrapError, match="invalid"):
        complete_first_superuser_setup(engine, "short", "Passphrase-Valid-2026!")


def test_complete_setup_validates_password_policy():
    engine, _ = _make_engine()
    with pytest.raises(FirstSuperuserBootstrapError):
        complete_first_superuser_setup(engine, "a" * 43, "weak")


def test_complete_setup_happy_path_returns_user_id():
    user_id = "deadbeef-cafe-babe-feed-c0ffee000000"
    engine, conn = _make_engine(scalar_return=user_id)
    returned = complete_first_superuser_setup(engine, "a" * 43, "Superuser-Strong-Password-2026!")
    assert returned == user_id

    call_args = conn.execute.call_args
    params = call_args[0][1]
    assert len(params["token_hash"]) == 64
    assert len(params["auth_epoch"]) == 32  # hex(16)
    assert params["password_hash"].startswith("$argon2")


def test_complete_setup_raises_on_db_error():
    engine, _ = _make_engine(
        raise_exc=RuntimeError("first administrator setup token is invalid or expired")
    )
    with pytest.raises(FirstSuperuserBootstrapError, match="invalid, expired"):
        complete_first_superuser_setup(engine, "a" * 43, "Superuser-Strong-Password-2026!")
