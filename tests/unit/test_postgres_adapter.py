from pathlib import Path

from chinescan.core.storage.postgres import postgresql_driver_url


def test_postgresql_driver_url_selects_psycopg_without_logging_credentials() -> None:
    value = "postgresql://app:secret@example.test:5432/chinescan"

    assert (
        postgresql_driver_url(value)
        == "postgresql+psycopg://app:secret@example.test:5432/chinescan"
    )


def test_supabase_baseline_contains_schema_rls_and_guards() -> None:
    migration = Path("supabase/migrations/20261127000000_chinescan_baseline.sql")
    sql = migration.read_text(encoding="utf-8")

    assert "CREATE TABLE execution_jobs" in sql
    assert 'ALTER TABLE public."execution_jobs" ENABLE ROW LEVEL SECURITY;' in sql
    assert "TO service_role USING (true) WITH CHECK (true)" in sql
    assert "chinescan_execution_job_guard" in sql
    assert "chinescan_action_attempt_guard" in sql


def test_supabase_baseline_translates_sqlite_integrity_boundaries() -> None:
    sql = Path("supabase/migrations/20261127000000_chinescan_baseline.sql").read_text(
        encoding="utf-8"
    )

    for marker in (
        "chinescan_is_org_member",
        "chinescan_current_user_id",
        "execution_job_state_guard",
        "execution_result_provenance_guard",
        "scope_revision_published_guard",
        "scope_rule_published_guard",
        "repository_asset_bindings_append_only",
        "repository_attestations_append_only",
        "repository_snapshot_metadata_guard",
        "log_evidence_snapshot_guard",
        "malware_evidence_snapshot_guard",
        "organization_audit_events_append_only",
        "assessment_audit_events_append_only",
        "retention_audit_events_append_only",
    ):
        assert marker in sql

    assert "CREATE POLICY" in sql
    assert "WITH CHECK (public.chinescan_is_org_member(organization_id))" in sql
