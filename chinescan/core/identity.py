"""Database-backed multi-user identity, TOTP/recovery codes, and invitation lifecycle."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select, update

from chinescan.core.accounts import (
    TOTP_ENROLLMENT_TTL_SECONDS,
    TOTP_RECOVERY_CODE_COUNT,
    CredentialError,
    _matching_totp_counter,
    _totp_rate_limited,
    _validate_password,
    generate_totp_secret,
    normalize_email,
    perform_dummy_verification,
)
from chinescan.core.accounts import (
    _read as _read_credential_file,
)
from chinescan.core.organizations import OrganizationService, now_iso
from chinescan.core.storage.sqlite import (
    begin_immediate,
    organization_invitations,
    organization_memberships,
    organizations,
    user_credentials,
    user_recovery_codes,
    user_sessions,
    users,
)

INVITABLE_ROLES = {"admin", "member", "auditor", "viewer"}
MANAGED_ACCOUNT_STATUSES = {"active", "disabled", "revoked", "suspended"}
_PASSWORD_HASHER = PasswordHasher()


class IdentityError(ValueError):
    """Safe identity or invitation error."""


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _user_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "email_normalized": row.email_normalized,
        "display_name": row.display_name,
        "status": row.status,
        "platform_role": getattr(row, "platform_role", "user"),
        "auth_epoch": row.auth_epoch,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


class IdentityService:
    """Persistent multi-user credentials, TOTP, account lifecycle, and invitations."""

    def __init__(self, organizations_service: OrganizationService) -> None:
        self.organizations = organizations_service
        self.repository = organizations_service.repository
        self.engine = organizations_service.engine

    def active_auth_epoch_for_operator(self, user_id: str, op_epoch: str) -> str:
        """Preserve DB-rotated auth_epoch if operator.json was already migrated and unchanged."""
        with self.engine.connect() as connection:
            row = connection.execute(
                select(users.c.auth_epoch, user_credentials.c.migrated_operator_epoch)
                .join(user_credentials, user_credentials.c.user_id == users.c.id)
                .where(users.c.id == user_id)
            ).first()
        if row is not None and row.migrated_operator_epoch == op_epoch:
            return str(row.auth_epoch)
        return op_epoch

    def migrate_operator_credentials(self, credential_path: Path, user_id: str) -> bool:
        """Idempotently mirror operator.json password/TOTP/recovery into SQLite."""
        try:
            data = _read_credential_file(credential_path)
        except CredentialError:
            return False
        password_hash = data.get("password_hash")
        if not isinstance(password_hash, str) or not password_hash:
            return False
        op_epoch = str(data.get("auth_epoch") or "legacy")[:64]
        totp_enabled = 1 if data.get("totp_enabled") is True else 0
        totp_secret = data.get("totp_secret") if isinstance(data.get("totp_secret"), str) else None
        totp_last_counter = int(data.get("totp_last_counter", -1) or -1)
        totp_pending = (
            data.get("totp_pending_secret")
            if isinstance(data.get("totp_pending_secret"), str)
            else None
        )
        totp_exp = (
            int(data["totp_enrollment_expires_at"])
            if isinstance(data.get("totp_enrollment_expires_at"), int)
            else None
        )
        totp_failed = (
            list(data.get("totp_verify_failed_at", []))
            if isinstance(data.get("totp_verify_failed_at"), list)
            else []
        )
        recovery_hashes = [
            digest
            for digest in data.get("totp_recovery_code_hashes", [])
            if isinstance(digest, str) and digest.startswith("$argon2id$")
        ]
        stamp = now_iso()

        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                user_row = connection.execute(select(users).where(users.c.id == user_id)).first()
                if user_row is None:
                    connection.rollback()
                    return False
                existing = connection.execute(
                    select(user_credentials).where(user_credentials.c.user_id == user_id)
                ).first()
                if existing is None:
                    connection.execute(
                        user_credentials.insert().values(
                            user_id=user_id,
                            password_hash=password_hash,
                            totp_enabled=totp_enabled,
                            totp_secret=totp_secret,
                            totp_last_counter=totp_last_counter,
                            totp_pending_secret=totp_pending,
                            totp_enrollment_expires_at=totp_exp,
                            totp_verify_failed_at=totp_failed,
                            migrated_operator_epoch=op_epoch,
                            password_updated_at=stamp,
                            created_at=stamp,
                            updated_at=stamp,
                        )
                    )
                    for digest in recovery_hashes:
                        connection.execute(
                            user_recovery_codes.insert().values(
                                id=str(uuid4()),
                                user_id=user_id,
                                code_hash=digest,
                                used_at=None,
                                created_at=stamp,
                            )
                        )
                    connection.commit()
                    return True

                # Only sync from operator.json when operator.json rotated offline
                # (e.g. CLI reset-password) and the DB epoch has not diverged.
                if (
                    existing.migrated_operator_epoch != op_epoch
                    and user_row.auth_epoch == existing.migrated_operator_epoch
                ):
                    connection.execute(
                        update(user_credentials)
                        .where(user_credentials.c.user_id == user_id)
                        .values(
                            password_hash=password_hash,
                            totp_enabled=totp_enabled,
                            totp_secret=totp_secret,
                            totp_last_counter=max(
                                int(existing.totp_last_counter), totp_last_counter
                            ),
                            totp_pending_secret=totp_pending,
                            totp_enrollment_expires_at=totp_exp,
                            totp_verify_failed_at=totp_failed,
                            migrated_operator_epoch=op_epoch,
                            updated_at=stamp,
                        )
                    )
                    connection.execute(
                        update(users)
                        .where(users.c.id == user_id)
                        .values(auth_epoch=op_epoch, updated_at=stamp)
                    )
                    if recovery_hashes:
                        connection.execute(
                            user_recovery_codes.delete().where(
                                user_recovery_codes.c.user_id == user_id
                            )
                        )
                        for digest in recovery_hashes:
                            connection.execute(
                                user_recovery_codes.insert().values(
                                    id=str(uuid4()),
                                    user_id=user_id,
                                    code_hash=digest,
                                    used_at=None,
                                    created_at=stamp,
                                )
                            )
                    connection.commit()
                    return True
                connection.commit()
                return False
            except Exception:
                connection.rollback()
                raise

    def authenticate(
        self,
        email: str,
        password: str,
        totp_code: str | None = None,
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        try:
            normalized = normalize_email(email)
        except CredentialError:
            perform_dummy_verification(password)
            return None

        with self.engine.connect() as connection:
            row = connection.execute(
                select(users, user_credentials)
                .join(user_credentials, user_credentials.c.user_id == users.c.id)
                .where(users.c.email_normalized == normalized)
            ).first()
        if row is None or row.status != "active" or not row.password_hash:
            perform_dummy_verification(password)
            return None

        try:
            valid_pw: bool = bool(_PASSWORD_HASHER.verify(row.password_hash, password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid_pw = False
        if not valid_pw:
            return None

        if row.totp_enabled:
            if not totp_code or not self.verify_totp(row.id, totp_code, now=now):
                return None

        return _user_dict(row)

    def _verify_totp_connection(
        self, connection: Any, user_id: str, code: str, timestamp: float
    ) -> bool:
        cred = connection.execute(
            select(user_credentials).where(user_credentials.c.user_id == user_id)
        ).first()
        if cred is None or not cred.totp_enabled or not cred.totp_secret:
            return False
        failures, limited = _totp_rate_limited(
            {"totp_verify_failed_at": cred.totp_verify_failed_at or []}, timestamp
        )
        if limited:
            return False
        matched = _matching_totp_counter(
            cred.totp_secret, code.strip(), timestamp, int(cred.totp_last_counter)
        )
        stamp = now_iso()
        if matched is not None:
            connection.execute(
                update(user_credentials)
                .where(user_credentials.c.user_id == user_id)
                .values(totp_last_counter=matched, totp_verify_failed_at=[], updated_at=stamp)
            )
            return True

        recovery_rows = connection.execute(
            select(user_recovery_codes.c.id, user_recovery_codes.c.code_hash).where(
                user_recovery_codes.c.user_id == user_id,
                user_recovery_codes.c.used_at.is_(None),
            )
        ).all()
        matched_code_id: str | None = None
        candidate = code.strip().upper()
        for rec in recovery_rows:
            if not isinstance(rec.code_hash, str) or not rec.code_hash.startswith("$argon2id$"):
                continue
            try:
                if _PASSWORD_HASHER.verify(rec.code_hash, candidate):
                    matched_code_id = rec.id
                    break
            except (InvalidHashError, VerificationError):
                continue
        if matched_code_id is not None:
            res = connection.execute(
                update(user_recovery_codes)
                .where(
                    user_recovery_codes.c.id == matched_code_id,
                    user_recovery_codes.c.used_at.is_(None),
                )
                .values(used_at=stamp)
            )
            if res.rowcount == 1:
                connection.execute(
                    update(user_credentials)
                    .where(user_credentials.c.user_id == user_id)
                    .values(totp_verify_failed_at=[], updated_at=stamp)
                )
                return True

        failures.append(int(timestamp))
        connection.execute(
            update(user_credentials)
            .where(user_credentials.c.user_id == user_id)
            .values(totp_verify_failed_at=failures, updated_at=stamp)
        )
        return False

    def verify_totp(self, user_id: str, code: str, *, now: float | None = None) -> bool:
        timestamp = time.time() if now is None else float(now)
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                ok = self._verify_totp_connection(connection, user_id, code, timestamp)
                connection.commit()
                return ok
            except Exception:
                connection.rollback()
                raise

    def totp_status(self, user_id: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            cred = connection.execute(
                select(user_credentials.c.totp_enabled).where(user_credentials.c.user_id == user_id)
            ).first()
            remaining = len(
                connection.execute(
                    select(user_recovery_codes.c.id).where(
                        user_recovery_codes.c.user_id == user_id,
                        user_recovery_codes.c.used_at.is_(None),
                    )
                ).all()
            )
        return {
            "totp_enabled": bool(cred and cred.totp_enabled),
            "recovery_codes_remaining": remaining,
        }

    def start_totp_enrollment(self, user_id: str, *, now: float | None = None) -> str:
        timestamp = time.time() if now is None else float(now)
        secret = generate_totp_secret()
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                cred = connection.execute(
                    select(user_credentials).where(user_credentials.c.user_id == user_id)
                ).first()
                if cred is None:
                    raise IdentityError("Account credentials are unavailable.")
                if cred.totp_enabled:
                    raise IdentityError("Authenticator verification is already enabled.")
                connection.execute(
                    update(user_credentials)
                    .where(user_credentials.c.user_id == user_id)
                    .values(
                        totp_pending_secret=secret,
                        totp_enrollment_expires_at=int(timestamp) + TOTP_ENROLLMENT_TTL_SECONDS,
                        totp_verify_failed_at=[],
                        updated_at=stamp,
                    )
                )
                connection.commit()
                return secret
            except Exception:
                connection.rollback()
                raise

    def confirm_totp_enrollment(
        self, user_id: str, code: str, *, now: float | None = None
    ) -> list[str] | None:
        timestamp = time.time() if now is None else float(now)
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                cred = connection.execute(
                    select(user_credentials).where(user_credentials.c.user_id == user_id)
                ).first()
                if (
                    cred is None
                    or cred.totp_enabled
                    or not cred.totp_pending_secret
                    or cred.totp_enrollment_expires_at is None
                ):
                    connection.rollback()
                    return None
                if int(timestamp) >= int(cred.totp_enrollment_expires_at):
                    connection.execute(
                        update(user_credentials)
                        .where(user_credentials.c.user_id == user_id)
                        .values(
                            totp_pending_secret=None,
                            totp_enrollment_expires_at=None,
                            updated_at=stamp,
                        )
                    )
                    connection.commit()
                    return None
                failures, limited = _totp_rate_limited(
                    {"totp_verify_failed_at": cred.totp_verify_failed_at or []}, timestamp
                )
                if limited:
                    connection.rollback()
                    return None
                matched = _matching_totp_counter(
                    cred.totp_pending_secret, code.strip(), timestamp, -1
                )
                if matched is None:
                    failures.append(int(timestamp))
                    connection.execute(
                        update(user_credentials)
                        .where(user_credentials.c.user_id == user_id)
                        .values(totp_verify_failed_at=failures, updated_at=stamp)
                    )
                    connection.commit()
                    return None
                recovery_codes = [
                    secrets.token_hex(5).upper() for _ in range(TOTP_RECOVERY_CODE_COUNT)
                ]
                connection.execute(
                    update(user_credentials)
                    .where(user_credentials.c.user_id == user_id)
                    .values(
                        totp_enabled=1,
                        totp_secret=cred.totp_pending_secret,
                        totp_last_counter=matched,
                        totp_pending_secret=None,
                        totp_enrollment_expires_at=None,
                        totp_verify_failed_at=[],
                        updated_at=stamp,
                    )
                )
                connection.execute(
                    user_recovery_codes.delete().where(user_recovery_codes.c.user_id == user_id)
                )
                for value in recovery_codes:
                    connection.execute(
                        user_recovery_codes.insert().values(
                            id=str(uuid4()),
                            user_id=user_id,
                            code_hash=_PASSWORD_HASHER.hash(value),
                            used_at=None,
                            created_at=stamp,
                        )
                    )
                connection.commit()
                return recovery_codes
            except Exception:
                connection.rollback()
                raise

    def disable_totp(self, user_id: str, code: str, *, now: float | None = None) -> bool:
        timestamp = time.time() if now is None else float(now)
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                if not self._verify_totp_connection(connection, user_id, code, timestamp):
                    connection.commit()
                    return False
                connection.execute(
                    update(user_credentials)
                    .where(user_credentials.c.user_id == user_id)
                    .values(
                        totp_enabled=0,
                        totp_secret=None,
                        totp_last_counter=-1,
                        totp_pending_secret=None,
                        totp_enrollment_expires_at=None,
                        totp_verify_failed_at=[],
                        updated_at=stamp,
                    )
                )
                connection.execute(
                    user_recovery_codes.delete().where(user_recovery_codes.c.user_id == user_id)
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def regenerate_recovery_codes(
        self, user_id: str, code: str, *, now: float | None = None
    ) -> list[str] | None:
        timestamp = time.time() if now is None else float(now)
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                if not self._verify_totp_connection(connection, user_id, code, timestamp):
                    connection.commit()
                    return None
                recovery_codes = [
                    secrets.token_hex(5).upper() for _ in range(TOTP_RECOVERY_CODE_COUNT)
                ]
                connection.execute(
                    user_recovery_codes.delete().where(user_recovery_codes.c.user_id == user_id)
                )
                for value in recovery_codes:
                    connection.execute(
                        user_recovery_codes.insert().values(
                            id=str(uuid4()),
                            user_id=user_id,
                            code_hash=_PASSWORD_HASHER.hash(value),
                            used_at=None,
                            created_at=stamp,
                        )
                    )
                connection.commit()
                return recovery_codes
            except Exception:
                connection.rollback()
                raise

    def change_password(self, user_id: str, current_password: str, new_password: str) -> str | None:
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                row = connection.execute(
                    select(users, user_credentials)
                    .join(user_credentials, user_credentials.c.user_id == users.c.id)
                    .where(users.c.id == user_id, users.c.status == "active")
                ).first()
                if row is None or not row.password_hash:
                    connection.rollback()
                    return None
                try:
                    if not _PASSWORD_HASHER.verify(row.password_hash, current_password):
                        connection.rollback()
                        return None
                except (VerifyMismatchError, VerificationError, InvalidHashError):
                    connection.rollback()
                    return None
                try:
                    _validate_password(row.email_normalized, new_password)
                except CredentialError as exc:
                    connection.rollback()
                    raise IdentityError(str(exc)) from exc
                new_epoch = secrets.token_hex(16)
                new_hash = _PASSWORD_HASHER.hash(new_password)
                connection.execute(
                    update(user_credentials)
                    .where(user_credentials.c.user_id == user_id)
                    .values(
                        password_hash=new_hash,
                        password_updated_at=stamp,
                        updated_at=stamp,
                    )
                )
                connection.execute(
                    update(users)
                    .where(users.c.id == user_id)
                    .values(auth_epoch=new_epoch, updated_at=stamp)
                )
                connection.commit()
                return new_epoch
            except Exception:
                connection.rollback()
                raise

    def set_account_status(
        self, actor_user_id: str, target_user_id: str, status: str
    ) -> dict[str, Any] | None:
        """Local-operator-only global account status management."""
        if (
            not self.organizations.operator_user_id
            or actor_user_id != self.organizations.operator_user_id
        ):
            return None
        if status not in MANAGED_ACCOUNT_STATUSES:
            raise IdentityError("Account status is invalid.")
        if target_user_id == actor_user_id and status != "active":
            raise IdentityError("Cannot disable or revoke the active local operator account.")
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                target = connection.execute(
                    select(users).where(users.c.id == target_user_id)
                ).first()
                if target is None:
                    connection.rollback()
                    return None
                new_epoch = secrets.token_hex(16) if status != "active" else target.auth_epoch
                connection.execute(
                    update(users)
                    .where(users.c.id == target_user_id)
                    .values(status=status, auth_epoch=new_epoch, updated_at=stamp)
                )
                if status != "active":
                    connection.execute(
                        update(user_sessions)
                        .where(
                            user_sessions.c.user_id == target_user_id,
                            user_sessions.c.revoked_at.is_(None),
                        )
                        .values(revoked_at=time.time())
                    )
                updated = connection.execute(
                    select(users).where(users.c.id == target_user_id)
                ).first()
                connection.commit()
                return _user_dict(updated)
            except Exception:
                connection.rollback()
                raise

    def create_invitation(
        self,
        actor_user_id: str,
        organization_id: str,
        email: str,
        role: str,
        *,
        ttl_hours: int = 168,
    ) -> dict[str, Any] | None:
        if not self.organizations.has_role(actor_user_id, organization_id, {"owner", "admin"}):
            return None
        if role not in INVITABLE_ROLES:
            raise IdentityError("Invitation role is invalid.")
        try:
            normalized_email = normalize_email(email)
        except CredentialError as exc:
            raise IdentityError(str(exc)) from exc
        if not 1 <= ttl_hours <= 720:
            raise IdentityError("Invitation expiration is invalid.")
        token = secrets.token_urlsafe(32)
        invitation_id = str(uuid4())
        stamp = now_iso()
        expires_at = (datetime.now(UTC) + timedelta(hours=ttl_hours)).isoformat(timespec="seconds")
        with self.engine.begin() as connection:
            connection.execute(
                organization_invitations.insert().values(
                    id=invitation_id,
                    organization_id=organization_id,
                    email_normalized=normalized_email,
                    role=role,
                    token_hash=_token_hash(token),
                    invited_by_user_id=actor_user_id,
                    status="pending",
                    expires_at=expires_at,
                    accepted_by_user_id=None,
                    accepted_at=None,
                    revoked_at=None,
                    created_at=stamp,
                )
            )
            self.organizations._audit(
                connection,
                organization_id,
                actor_user_id,
                "invitation.created",
                "invitation",
                invitation_id,
            )
        return {
            "id": invitation_id,
            "organization_id": organization_id,
            "email_normalized": normalized_email,
            "role": role,
            "status": "pending",
            "expires_at": expires_at,
            "created_at": stamp,
            "token": token,
        }

    def list_invitations(
        self, actor_user_id: str, organization_id: str
    ) -> list[dict[str, Any]] | None:
        if not self.organizations.has_role(actor_user_id, organization_id, {"owner", "admin"}):
            return None
        now = now_iso()
        with self.engine.begin() as connection:
            connection.execute(
                update(organization_invitations)
                .where(
                    organization_invitations.c.organization_id == organization_id,
                    organization_invitations.c.status == "pending",
                    organization_invitations.c.expires_at <= now,
                )
                .values(status="expired")
            )
            rows = connection.execute(
                select(
                    organization_invitations.c.id,
                    organization_invitations.c.organization_id,
                    organization_invitations.c.email_normalized,
                    organization_invitations.c.role,
                    organization_invitations.c.invited_by_user_id,
                    organization_invitations.c.status,
                    organization_invitations.c.expires_at,
                    organization_invitations.c.accepted_at,
                    organization_invitations.c.revoked_at,
                    organization_invitations.c.created_at,
                )
                .where(organization_invitations.c.organization_id == organization_id)
                .order_by(organization_invitations.c.created_at.desc())
            ).all()
            return [dict(row._mapping) for row in rows]

    def revoke_invitation(
        self, actor_user_id: str, organization_id: str, invitation_id: str
    ) -> bool:
        if not self.organizations.has_role(actor_user_id, organization_id, {"owner", "admin"}):
            return False
        stamp = now_iso()
        with self.engine.begin() as connection:
            res = connection.execute(
                update(organization_invitations)
                .where(
                    organization_invitations.c.id == invitation_id,
                    organization_invitations.c.organization_id == organization_id,
                    organization_invitations.c.status == "pending",
                )
                .values(status="revoked", revoked_at=stamp)
            )
            if res.rowcount != 1:
                return False
            self.organizations._audit(
                connection,
                organization_id,
                actor_user_id,
                "invitation.revoked",
                "invitation",
                invitation_id,
            )
            return True

    def accept_invitation(
        self,
        token: str,
        *,
        password: str | None = None,
        display_name: str | None = None,
        authenticated_user_id: str | None = None,
    ) -> dict[str, Any]:
        if not token or len(token) < 16:
            raise IdentityError("Invitation token is invalid or unavailable.")
        digest = _token_hash(token)
        stamp = now_iso()
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                inv = connection.execute(
                    select(organization_invitations).where(
                        organization_invitations.c.token_hash == digest
                    )
                ).first()
                if inv is None or inv.status != "pending":
                    connection.rollback()
                    raise IdentityError("Invitation token is invalid or unavailable.")
                if inv.expires_at <= stamp:
                    connection.execute(
                        update(organization_invitations)
                        .where(
                            organization_invitations.c.id == inv.id,
                            organization_invitations.c.status == "pending",
                        )
                        .values(status="expired")
                    )
                    self.organizations._audit(
                        connection,
                        inv.organization_id,
                        inv.invited_by_user_id,
                        "invitation.expired",
                        "invitation",
                        inv.id,
                    )
                    connection.commit()
                    raise IdentityError("Invitation token is invalid or unavailable.")

                org = connection.execute(
                    select(organizations.c.id).where(
                        organizations.c.id == inv.organization_id,
                        organizations.c.status == "active",
                    )
                ).first()
                if org is None:
                    connection.rollback()
                    raise IdentityError("Invitation token is invalid or unavailable.")

                existing_user = connection.execute(
                    select(users).where(users.c.email_normalized == inv.email_normalized)
                ).first()
                if existing_user is not None:
                    if existing_user.status != "active":
                        connection.rollback()
                        raise IdentityError("Account is unavailable.")
                    verified_existing = authenticated_user_id is not None and hmac.compare_digest(
                        existing_user.id, authenticated_user_id
                    )
                    if not verified_existing:
                        if not password:
                            connection.rollback()
                            raise IdentityError(
                                "Existing account requires current password or active session."
                            )
                        cred = connection.execute(
                            select(user_credentials.c.password_hash).where(
                                user_credentials.c.user_id == existing_user.id
                            )
                        ).first()
                        try:
                            if (
                                cred is None
                                or not cred.password_hash
                                or not _PASSWORD_HASHER.verify(cred.password_hash, password)
                            ):
                                connection.rollback()
                                raise IdentityError("Authentication failed for existing account.")
                        except (VerifyMismatchError, VerificationError, InvalidHashError):
                            connection.rollback()
                            raise IdentityError(
                                "Authentication failed for existing account."
                            ) from None
                    user_id = existing_user.id
                    user_payload = _user_dict(existing_user)
                else:
                    if not password:
                        connection.rollback()
                        raise IdentityError("A password is required to activate this account.")
                    try:
                        _validate_password(inv.email_normalized, password)
                    except CredentialError as exc:
                        connection.rollback()
                        raise IdentityError(str(exc)) from exc
                    user_id = str(uuid4())
                    auth_epoch = secrets.token_hex(16)
                    local_part = inv.email_normalized.split("@", 1)[0]
                    clean_name = (
                        " ".join((display_name or local_part).split())[:120] or local_part[:120]
                    )
                    user_payload = {
                        "id": user_id,
                        "email_normalized": inv.email_normalized,
                        "display_name": clean_name,
                        "status": "active",
                        "auth_epoch": auth_epoch,
                        "created_at": stamp,
                        "updated_at": stamp,
                    }
                    connection.execute(users.insert().values(**user_payload))
                    connection.execute(
                        user_credentials.insert().values(
                            user_id=user_id,
                            password_hash=_PASSWORD_HASHER.hash(password),
                            totp_enabled=0,
                            totp_secret=None,
                            totp_last_counter=-1,
                            totp_pending_secret=None,
                            totp_enrollment_expires_at=None,
                            totp_verify_failed_at=[],
                            migrated_operator_epoch=None,
                            password_updated_at=stamp,
                            created_at=stamp,
                            updated_at=stamp,
                        )
                    )

                existing_membership = connection.execute(
                    select(organization_memberships).where(
                        organization_memberships.c.organization_id == inv.organization_id,
                        organization_memberships.c.user_id == user_id,
                    )
                ).first()
                if existing_membership is not None:
                    if existing_membership.status == "active":
                        connection.rollback()
                        raise IdentityError("Membership already exists.")
                    connection.execute(
                        update(organization_memberships)
                        .where(organization_memberships.c.id == existing_membership.id)
                        .values(role=inv.role, status="active", updated_at=stamp)
                    )
                else:
                    connection.execute(
                        organization_memberships.insert().values(
                            id=str(uuid4()),
                            organization_id=inv.organization_id,
                            user_id=user_id,
                            role=inv.role,
                            status="active",
                            created_at=stamp,
                            updated_at=stamp,
                        )
                    )

                consumed = connection.execute(
                    update(organization_invitations)
                    .where(
                        organization_invitations.c.id == inv.id,
                        organization_invitations.c.status == "pending",
                    )
                    .values(
                        status="accepted",
                        accepted_by_user_id=user_id,
                        accepted_at=stamp,
                    )
                )
                if consumed.rowcount != 1:
                    connection.rollback()
                    raise IdentityError("Invitation token is invalid or unavailable.")

                self.organizations._audit(
                    connection,
                    inv.organization_id,
                    user_id,
                    "invitation.accepted",
                    "invitation",
                    inv.id,
                )
                connection.commit()
                return {
                    "user": user_payload,
                    "organization_id": inv.organization_id,
                    "role": inv.role,
                }
            except Exception:
                connection.rollback()
                raise
