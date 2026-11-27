"""Opt-in disposable PostgreSQL acceptance tests for first-admin bootstrap."""

import importlib.util
import os

import pytest
from sqlalchemy import text

from chinescan.core.first_superuser import (
    FirstSuperuserBootstrapError,
    bootstrap_first_superuser,
    complete_first_superuser_setup,
)
from chinescan.core.identity import IdentityService
from chinescan.core.organizations import OrganizationService
from chinescan.core.storage.postgres import PostgresRepository


def test_first_superuser_bootstrap_is_one_time_and_authorizes_admin(tmp_path):
    """Exercise the real backend role against a fresh disposable PostgreSQL schema."""

    url = os.environ.get("CHINESCAN_TEST_POSTGRES_BOOTSTRAP_URL")
    if os.environ.get("CHINESCAN_TEST_POSTGRES_BOOTSTRAP") != "1" or not url:
        pytest.skip("Set CHINESCAN_TEST_POSTGRES_BOOTSTRAP=1 and a disposable PostgreSQL URL.")
    if importlib.util.find_spec("psycopg") is None:
        pytest.skip("Install the optional postgres extra for PostgreSQL acceptance.")

    repository = PostgresRepository(url, storage_root=tmp_path)
    try:
        result = bootstrap_first_superuser(repository.engine)
        assert result.created is True
        assert result.setup_token
        assert result.email == "cipherchi@proton.me"

        with pytest.raises(FirstSuperuserBootstrapError):
            bootstrap_first_superuser(repository.engine)
        with pytest.raises(FirstSuperuserBootstrapError):
            bootstrap_first_superuser(repository.engine, email="attacker@example.test")

        user_id = complete_first_superuser_setup(
            repository.engine, result.setup_token, "Local-Test-Password-2026!x"
        )
        assert user_id == result.user_id
        with pytest.raises(FirstSuperuserBootstrapError):
            complete_first_superuser_setup(
                repository.engine, result.setup_token, "Another-Test-Password-2026!x"
            )

        organizations = OrganizationService(repository)
        identity = IdentityService(organizations)
        account = identity.authenticate("cipherchi@proton.me", "Local-Test-Password-2026!x")
        assert account is not None
        assert account["platform_role"] == "superuser"
        assert organizations.operator_user_id == result.user_id

        with repository.engine.connect() as connection:
            organization_id = connection.execute(
                text(
                    """
                    SELECT id FROM public.organizations
                     WHERE owner_user_id = :user_id
                    """
                ),
                {"user_id": result.user_id},
            ).scalar_one()
        with repository.member_context(str(organization_id), result.user_id):
            with repository.engine.connect() as connection:
                membership = connection.execute(
                    text(
                        """
                        SELECT role, status FROM public.organization_memberships
                         WHERE user_id = :user_id
                        """
                    ),
                    {"user_id": result.user_id},
                ).one()
                assert membership.role == "owner"
                assert membership.status == "active"
                actions = (
                    connection.execute(
                        text(
                            """
                        SELECT action FROM public.organization_audit_events
                         WHERE actor_user_id = :user_id ORDER BY created_at
                        """
                        ),
                        {"user_id": result.user_id},
                    )
                    .scalars()
                    .all()
                )
                assert actions == [
                    "platform.superuser_bootstrap_started",
                    "platform.superuser_password_initialized",
                ]
    finally:
        repository.close()
