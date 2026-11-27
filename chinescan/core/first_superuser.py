"""One-time first platform-superuser bootstrap for PostgreSQL deployments."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from uuid import uuid4

from argon2 import PasswordHasher
from sqlalchemy import text
from sqlalchemy.engine import Engine

from chinescan.core.accounts import CredentialError, _validate_password, normalize_email

FIRST_SUPERUSER_EMAIL = "cipherchi@proton.me"
BOOTSTRAP_TOKEN_TTL_SECONDS = 15 * 60
_PASSWORD_HASHER = PasswordHasher()


class FirstSuperuserBootstrapError(ValueError):
    """A safe, operator-facing bootstrap failure."""


@dataclass(frozen=True)
class FirstSuperuserBootstrapResult:
    """The one-time setup material returned only to the invoking operator."""

    user_id: str
    email: str
    setup_token: str | None
    expires_at: float | None
    created: bool


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bootstrap_first_superuser(
    engine: Engine,
    *,
    email: str = FIRST_SUPERUSER_EMAIL,
    ttl_seconds: int = BOOTSTRAP_TOKEN_TTL_SECONDS,
) -> FirstSuperuserBootstrapResult:
    """Create the fixed first superuser without creating a password.

    The database function performs the one-time, exact-email checks under its
    SECURITY DEFINER owner. The returned token is never persisted in cleartext
    and must be delivered to the administrator out-of-band.
    """

    try:
        normalized = normalize_email(email)
    except CredentialError as exc:
        raise FirstSuperuserBootstrapError(str(exc)) from exc
    if normalized != FIRST_SUPERUSER_EMAIL:
        raise FirstSuperuserBootstrapError(
            f"First bootstrap is restricted to {FIRST_SUPERUSER_EMAIL}."
        )
    if not 60 <= ttl_seconds <= 3600:
        raise FirstSuperuserBootstrapError("Bootstrap token lifetime is invalid.")

    setup_token = secrets.token_urlsafe(32)
    expires_at = time.time() + ttl_seconds
    user_id = str(uuid4())
    organization_id = str(uuid4())
    try:
        with engine.begin() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT user_id, created
                      FROM public.chinescan_bootstrap_first_superuser(
                        :email, :user_id, :organization_id,
                        :token_hash, :expires_at
                      )
                    """
                ),
                {
                    "email": normalized,
                    "user_id": user_id,
                    "organization_id": organization_id,
                    "token_hash": _token_hash(setup_token),
                    "expires_at": expires_at,
                },
            ).one()
    except Exception as exc:
        raise FirstSuperuserBootstrapError(
            "First superuser bootstrap was not completed. Existing accounts were not changed."
        ) from exc

    if not bool(row.created):
        raise FirstSuperuserBootstrapError(
            "First superuser bootstrap has already been completed; refusing to issue a new token."
        )
    return FirstSuperuserBootstrapResult(
        user_id=str(row.user_id),
        email=normalized,
        setup_token=setup_token,
        expires_at=expires_at,
        created=True,
    )


def complete_first_superuser_setup(
    engine: Engine,
    token: str,
    password: str,
) -> str:
    """Consume the one-time token and establish the administrator password."""

    if not token or len(token) < 32:
        raise FirstSuperuserBootstrapError("The bootstrap token is invalid or unavailable.")
    try:
        _validate_password(FIRST_SUPERUSER_EMAIL, password)
    except CredentialError as exc:
        raise FirstSuperuserBootstrapError(str(exc)) from exc
    try:
        with engine.begin() as connection:
            user_id: str | None = connection.execute(
                text(
                    """
                    SELECT public.chinescan_complete_first_superuser_setup(
                        :token_hash, :password_hash, :auth_epoch
                    )
                    """
                ),
                {
                    "token_hash": _token_hash(token),
                    "password_hash": _PASSWORD_HASHER.hash(password),
                    "auth_epoch": secrets.token_hex(16),
                },
            ).scalar_one()
    except Exception as exc:
        raise FirstSuperuserBootstrapError(
            "Bootstrap token is invalid, expired, already used, or unavailable."
        ) from exc
    return str(user_id)
