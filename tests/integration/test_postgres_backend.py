import importlib.util
import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from chinescan.core.storage.postgres import PostgresRepository


def test_postgres_backend_connects_to_reviewed_baseline(tmp_path):
    """Run only when an operator supplies a real PostgreSQL acceptance URL."""

    url = os.environ.get("CHINESCAN_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("Set CHINESCAN_TEST_POSTGRES_URL for PostgreSQL acceptance.")
    if importlib.util.find_spec("psycopg") is None:
        pytest.skip("Install the optional postgres extra for PostgreSQL acceptance.")

    repository = PostgresRepository(url, storage_root=tmp_path)
    try:
        with repository.engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            assert revision == "0016_phase6_governance"
    finally:
        repository.close()


def _acceptance_inputs() -> tuple[str, dict[str, str]] | None:
    url = os.environ.get("CHINESCAN_TEST_POSTGRES_URL")
    required = {
        "organization_id": os.environ.get("CHINESCAN_TEST_ORGANIZATION_ID", ""),
        "user_id": os.environ.get("CHINESCAN_TEST_USER_ID", ""),
        "engagement_id": os.environ.get("CHINESCAN_TEST_ENGAGEMENT_ID", ""),
        "asset_id": os.environ.get("CHINESCAN_TEST_ASSET_ID", ""),
    }
    if not url or not all(required.values()):
        return None
    if importlib.util.find_spec("psycopg") is None:
        return None
    return url, required


def test_postgres_scope_guards_cover_draft_and_published_operations(tmp_path):
    """Exercise all trigger operation paths in one rollback-only transaction."""

    inputs = _acceptance_inputs()
    if inputs is None:
        pytest.skip("Set PostgreSQL acceptance URL, psycopg, and scoped fixture IDs.")
    url, values = inputs
    repository = PostgresRepository(url, storage_root=tmp_path)
    try:
        with repository.engine.connect() as connection:
            transaction = connection.begin()
            try:
                for setting, value in (
                    ("chinescan.user_id", values["user_id"]),
                    ("chinescan.organization_id", values["organization_id"]),
                ):
                    connection.execute(
                        text("SELECT set_config(:setting, :value, true)"),
                        {"setting": setting, "value": value},
                    )
                revision = int(
                    connection.execute(
                        text(
                            """
                            SELECT COALESCE(MAX(revision), 0) + 1
                              FROM public.scope_revisions
                             WHERE organization_id = :organization_id
                               AND engagement_id = :engagement_id
                            """
                        ),
                        values,
                    ).scalar_one()
                )
                draft_id = "00000000-0000-4000-8000-000000000001"
                published_id = "00000000-0000-4000-8000-000000000002"
                rule_id = "00000000-0000-4000-8000-000000000003"
                connection.execute(
                    text(
                        """
                        INSERT INTO public.scope_revisions
                            (id, organization_id, engagement_id, revision, status,
                             created_by, created_at, change_summary)
                        VALUES (:id, :organization_id, :engagement_id, :revision,
                                'draft', :user_id, '2030-01-01T00:00:00+00:00', 'test')
                        """
                    ),
                    {**values, "id": draft_id, "revision": revision},
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO public.scope_rules
                            (id, organization_id, scope_revision_id, asset_id,
                             asset_type_snapshot, target_snapshot, effect, match_mode,
                             techniques, created_at)
                        VALUES (:id, :organization_id, :scope_revision_id, :asset_id,
                                'domain', 'draft.example', 'include', 'exact',
                                '["domain"]'::jsonb, '2030-01-01T00:00:00+00:00')
                        """
                    ),
                    {**values, "id": rule_id, "scope_revision_id": draft_id},
                )
                connection.execute(
                    text(
                        "UPDATE public.scope_rules SET target_snapshot = "
                        "'changed.example' WHERE id = :id"
                    ),
                    {"id": rule_id},
                )
                connection.execute(
                    text("DELETE FROM public.scope_rules WHERE id = :id"), {"id": rule_id}
                )
                connection.execute(
                    text("DELETE FROM public.scope_revisions WHERE id = :id"), {"id": draft_id}
                )

                published_rule_id = "00000000-0000-4000-8000-000000000004"
                connection.execute(
                    text(
                        """
                        INSERT INTO public.scope_revisions
                            (id, organization_id, engagement_id, revision, status,
                             created_by, created_at, change_summary)
                        VALUES (:id, :organization_id, :engagement_id, :revision,
                                'draft', :user_id, '2030-01-01T00:00:00+00:00', 'test')
                        """
                    ),
                    {**values, "id": published_id, "revision": revision + 1},
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO public.scope_rules
                            (id, organization_id, scope_revision_id, asset_id,
                             asset_type_snapshot, target_snapshot, effect, match_mode,
                             techniques, created_at)
                        VALUES (:id, :organization_id, :scope_revision_id, :asset_id,
                                'domain', 'published.example', 'include', 'exact',
                                '["domain"]'::jsonb, '2030-01-01T00:00:00+00:00')
                        """
                    ),
                    {**values, "id": published_rule_id, "scope_revision_id": published_id},
                )
                connection.execute(
                    text("UPDATE public.scope_revisions SET status = 'published' WHERE id = :id"),
                    {"id": published_id},
                )

                def assert_rejected(statement, parameters):
                    savepoint = connection.begin_nested()
                    try:
                        connection.execute(statement, parameters)
                    except DBAPIError:
                        savepoint.rollback()
                    else:
                        savepoint.rollback()
                        pytest.fail("expected PostgreSQL trigger rejection")

                assert_rejected(
                    text(
                        """
                        INSERT INTO public.scope_rules
                            (id, organization_id, scope_revision_id, asset_id,
                             asset_type_snapshot, target_snapshot, effect, match_mode,
                             techniques, created_at)
                        VALUES (:id, :organization_id, :scope_revision_id, :asset_id,
                                'domain', 'blocked.example', 'include', 'exact',
                                '["domain"]'::jsonb, '2030-01-01T00:00:00+00:00')
                        """
                    ),
                    {**values, "id": rule_id, "scope_revision_id": published_id},
                )
                assert_rejected(
                    text(
                        "UPDATE public.scope_rules SET target_snapshot = "
                        "'blocked.example' WHERE id = :id"
                    ),
                    {"id": published_rule_id},
                )
                assert_rejected(
                    text("DELETE FROM public.scope_rules WHERE id = :id"),
                    {"id": published_rule_id},
                )
                assert_rejected(
                    text("UPDATE public.scope_revisions SET status = 'draft' WHERE id = :id"),
                    {"id": published_id},
                )
                assert_rejected(
                    text("DELETE FROM public.scope_revisions WHERE id = :id"),
                    {"id": published_id},
                )
            finally:
                transaction.rollback()
    finally:
        repository.close()


def test_postgres_backend_identity_binding_blocks_cross_organization_reads(tmp_path):
    """Fail acceptance if the actual backend role bypasses the RLS policy."""

    url = os.environ.get("CHINESCAN_TEST_POSTGRES_URL")
    organization_a = os.environ.get("CHINESCAN_TEST_ORGANIZATION_A")
    organization_b = os.environ.get("CHINESCAN_TEST_ORGANIZATION_B")
    user_a = os.environ.get("CHINESCAN_TEST_USER_A")
    if not url or not organization_a or not organization_b or not user_a:
        pytest.skip("Set PostgreSQL URL and two organization identity fixtures.")
    if importlib.util.find_spec("psycopg") is None:
        pytest.skip("Install the optional postgres extra for PostgreSQL acceptance.")

    repository = PostgresRepository(url, storage_root=tmp_path)
    try:
        assert not repository.database_role_bypasses_rls, (
            "backend database role is a superuser or has BYPASSRLS; "
            "database tenant isolation is not effective"
        )
        assert not repository.database_role_owns_application_tables, (
            "backend database role owns application tables; database tenant "
            "isolation is not effective without FORCE ROW LEVEL SECURITY"
        )
        with repository.member_context(organization_a, user_a):
            with repository.engine.connect() as connection:
                visible = connection.execute(
                    text("SELECT id FROM public.clients WHERE id = :organization_id"),
                    {"organization_id": organization_b},
                ).all()
                assert visible == []
    finally:
        repository.close()
