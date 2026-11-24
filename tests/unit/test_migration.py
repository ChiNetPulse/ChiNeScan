import hashlib
import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError

from chinescan.core.storage.sqlite import SQLiteRepository, metadata


def test_initial_migration_creates_records_table(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        assert "records" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_repository_asset_migration_upgrades_and_empty_downgrade_is_safe(tmp_path: Path) -> None:
    database = tmp_path / "repository-migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0009_execution_result_provenance")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        assert "repository_snapshots" in inspect(engine).get_table_names()
        assert {"repository_binding_id", "repository_attestation_id"} <= {
            item["name"] for item in inspect(engine).get_columns("execution_jobs")
        }
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            assert revision == "0013_governed_chain_trace"
            checks = inspect(connection).get_check_constraints("engagement_assets")
            assert any("chain_address" in str(item.get("sqltext")) for item in checks)
        command.downgrade(config, "0009_execution_result_provenance")
        with engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            assert revision == "0009_execution_result_provenance"
            assert "repository_snapshots" not in inspect(connection).get_table_names()
        command.upgrade(config, "head")
        with engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            assert revision == "0013_governed_chain_trace"
    finally:
        engine.dispose()


def test_repository_migration_preserves_records_and_enforces_tenant_binding(
    tmp_path: Path,
) -> None:
    database = tmp_path / "repository-tenant-migration.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0009_execution_result_provenance")
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    now = "2026-11-23T00:00:00+00:00"
    try:
        with engine.begin() as connection:
            for suffix in ("a", "b"):
                connection.execute(
                    text(
                        "INSERT INTO users "
                        "(id,email_normalized,display_name,status,auth_epoch,"
                        "created_at,updated_at) "
                        "VALUES (:id,:email,:name,'active','epoch',:now,:now)"
                    ),
                    {
                        "id": f"user-{suffix}",
                        "email": f"{suffix}@example.test",
                        "name": suffix,
                        "now": now,
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO organizations "
                        "(id,name,slug,status,owner_user_id,created_at,updated_at) "
                        "VALUES (:id,:name,:slug,'active',:user,:now,:now)"
                    ),
                    {
                        "id": f"org-{suffix}",
                        "name": suffix,
                        "slug": f"org-{suffix}",
                        "user": f"user-{suffix}",
                        "now": now,
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO organization_memberships "
                        "(id,organization_id,user_id,role,status,created_at,updated_at) "
                        "VALUES (:id,:org,:user,'owner','active',:now,:now)"
                    ),
                    {
                        "id": f"membership-{suffix}",
                        "org": f"org-{suffix}",
                        "user": f"user-{suffix}",
                        "now": now,
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO engagements "
                        "(id,organization_id,client_id,name,description,status,"
                        "created_at,updated_at) "
                        "VALUES (:id,:org,NULL,'Legacy engagement','Preserve me',"
                        "'active',:now,:now)"
                    ),
                    {"id": f"engagement-{suffix}", "org": f"org-{suffix}", "now": now},
                )
                connection.execute(
                    text(
                        "INSERT INTO engagement_assets "
                        "(id,organization_id,client_id,engagement_id,asset_type,target,"
                        "description,"
                        "status,created_by,created_at,updated_at) "
                        "VALUES (:id,:org,NULL,:engagement,'domain',:target,NULL,"
                        "'active',:user,:now,:now)"
                    ),
                    {
                        "id": f"asset-{suffix}", "org": f"org-{suffix}",
                        "engagement": f"engagement-{suffix}", "target": f"{suffix}.example.test",
                        "user": f"user-{suffix}", "now": now,
                    },
                )
            connection.execute(
                text(
                    "INSERT INTO records (record_type,record_id,payload) "
                    "VALUES ('case','legacy','{\"title\":\"Preserve\"}')"
                )
            )
        command.upgrade(config, "head")
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
            assert connection.execute(
                text("SELECT payload FROM records WHERE record_type='case' AND record_id='legacy'")
            ).scalar_one() == '{"title":"Preserve"}'
            assert connection.execute(
                text("SELECT target FROM engagement_assets WHERE id='asset-a'")
            ).scalar_one() == "a.example.test"
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
                ).scalar_one() == "0013_governed_chain_trace"

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO repository_snapshots "
                    "(id,organization_id,sha256,size_bytes,manifest,manifest_version,scanner_version,"
                    "created_at,status,legal_hold) "
                    "VALUES ('snapshot-b','org-b',:digest,0,'{}',1,'scanner-v1',:now,'available',0)"
                ),
                {"digest": "b" * 64, "now": now},
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO repository_asset_bindings "
                        "(id,organization_id,engagement_id,asset_id,project_registry_id,source_kind,"
                        "snapshot_id,snapshot_sha256,created_by,created_at,display_label) "
                        "VALUES ('cross-binding','org-b','engagement-b','asset-a','project-b',"
                        "'local_project_registry','snapshot-b',:digest,'user-b',:now,'Project B')"
                    ),
                    {"digest": "b" * 64, "now": now},
                )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO repository_asset_bindings "
                    "(id,organization_id,engagement_id,asset_id,project_registry_id,source_kind,"
                    "snapshot_id,snapshot_sha256,created_by,created_at,display_label) "
                    "VALUES ('valid-binding','org-b','engagement-b','asset-b','project-b',"
                    "'local_project_registry','snapshot-b',:digest,'user-b',:now,'Project B')"
                ),
                {"digest": "b" * 64, "now": now},
            )
    finally:
        engine.dispose()


def test_malware_backend_revision_upgrades_existing_records_without_rewrite(tmp_path: Path) -> None:
    database = tmp_path / "upgrade.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0001_initial")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO records VALUES ('case', 'legacy', '{\"title\":\"Keep\"}')")
        )
    engine.dispose()

    repository = SQLiteRepository(database)
    try:
        assert repository.get("case", "legacy") == {"title": "Keep"}
        with repository.engine.connect() as connection:
            from alembic.runtime.migration import MigrationContext

            assert (
                MigrationContext.configure(connection).get_current_revision()
                == "0013_governed_chain_trace"
            )
    finally:
        repository.close()


def test_malware_evidence_migration_enforces_tenant_constraints_and_downgrades_empty(
    tmp_path: Path,
) -> None:
    database = tmp_path / "malware-tenant.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0011_governed_log_evidence")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    now = "2026-11-24T00:00:00+00:00"
    try:
        with engine.begin() as connection:
            for suffix in ("a", "b"):
                connection.execute(text(
                    "INSERT INTO users (id,email_normalized,display_name,status,auth_epoch,created_at,updated_at) "
                    "VALUES (:id,:email,:name,'active','epoch',:now,:now)"
                ), {"id": f"user-{suffix}", "email": f"{suffix}@example.test", "name": suffix, "now": now})
                connection.execute(text(
                    "INSERT INTO organizations (id,name,slug,status,owner_user_id,created_at,updated_at) "
                    "VALUES (:id,:name,:slug,'active',:user,:now,:now)"
                ), {"id": f"org-{suffix}", "name": suffix, "slug": f"org-{suffix}", "user": f"user-{suffix}", "now": now})
                connection.execute(text(
                    "INSERT INTO organization_memberships "
                    "(id,organization_id,user_id,role,status,created_at,updated_at) "
                    "VALUES (:id,:org,:user,'owner','active',:now,:now)"
                ), {"id": f"membership-{suffix}", "org": f"org-{suffix}", "user": f"user-{suffix}", "now": now})
                connection.execute(text(
                    "INSERT INTO engagements (id,organization_id,client_id,name,description,status,created_at,updated_at) "
                    "VALUES (:id,:org,NULL,'engagement','synthetic','active',:now,:now)"
                ), {"id": f"engagement-{suffix}", "org": f"org-{suffix}", "now": now})
                connection.execute(text(
                    "INSERT INTO engagement_assets "
                    "(id,organization_id,client_id,engagement_id,asset_type,target,status,created_by,created_at,updated_at) "
                    "VALUES (:id,:org,NULL,:engagement,'malware_evidence',:target,'active',:user,:now,:now)"
                ), {"id": f"asset-{suffix}", "org": f"org-{suffix}", "engagement": f"engagement-{suffix}",
                    "target": f"malware:asset-{suffix}", "user": f"user-{suffix}", "now": now})
        manifest = json.dumps({"manifest_version": 1, "files": [{"path": "sample", "size_bytes": 4, "sha256": "a" * 64}]})
        values = {
            "id": "snapshot-valid", "organization_id": "org-a", "engagement_id": "engagement-a",
            "asset_id": "asset-a", "registered_by": "user-a", "source_registry_id": "synthetic",
            "original_filename": "sample.bin", "classification": "unknown", "object_key": "b" * 64,
            "sha256": "a" * 64, "manifest": manifest, "manifest_sha256": hashlib.sha256(
                json.dumps(json.loads(manifest), sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(), "now": now,
        }
        insert_sql = text(
            "INSERT INTO malware_evidence_snapshots "
            "(id,organization_id,engagement_id,asset_id,registered_by,source_registry_id,original_filename,"
            "classification,object_key,sha256,size_bytes,file_type,manifest,manifest_sha256,manifest_version,"
            "created_at,status,legal_hold) VALUES (:id,:organization_id,:engagement_id,:asset_id,:registered_by,"
            ":source_registry_id,:original_filename,:classification,:object_key,:sha256,4,'unknown',:manifest,"
            ":manifest_sha256,1,:now,'available',0)"
        )
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(insert_sql, values | {"id": "cross-org", "organization_id": "org-a",
                    "engagement_id": "engagement-a", "asset_id": "asset-a", "registered_by": "user-b",
                    "object_key": "c" * 64})
        with engine.begin() as connection:
            connection.execute(insert_sql, values)
        with engine.connect() as connection:
            assert connection.execute(text(
                "SELECT COUNT(*) FROM malware_evidence_snapshots WHERE id='snapshot-valid'"
            )).scalar_one() == 1
            assert connection.execute(text(
                "SELECT version_num FROM alembic_version"
            )).scalar_one() == "0013_governed_chain_trace"
        with pytest.raises(RuntimeError, match="history exists"):
            command.downgrade(config, "0011_governed_log_evidence")
        with engine.connect() as connection:
            assert connection.execute(text(
                "SELECT version_num FROM alembic_version"
            )).scalar_one() == "0013_governed_chain_trace"
    finally:
        engine.dispose()


def test_engagement_security_migration_upgrades_and_empty_downgrade_is_safe(
    tmp_path: Path,
) -> None:
    database = tmp_path / "phase1c-upgrade.sqlite3"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "0005_identity_organizations")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        names = set(inspect(engine).get_table_names())
        assert {
            "engagement_assets",
            "scope_rules",
            "authorization_records",
            "approval_requests",
            "assessment_audit_events",
            "execution_jobs",
            "execution_result_provenance",
            "repository_snapshots",
            "repository_asset_bindings",
            "repository_attestations",
            "repository_quota_reservations",
        } <= names
        assert "result_summary" in {
            column["name"] for column in inspect(engine).get_columns("execution_jobs")
        }
        assert {
            "cancellation_requested_at",
            "cancellation_requested_by",
            "cancellation_observed_at",
        } <= {
            column["name"] for column in inspect(engine).get_columns("execution_jobs")
        }
        assert "authorization_document_sha256" in {
            column["name"] for column in inspect(engine).get_columns("execution_jobs")
        }
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO engagement_assets "
                        "(id, organization_id, asset_type, target, status, created_by, "
                        "created_at, updated_at) "
                        "VALUES ('orphan', 'missing-org', 'domain', 'example.test', "
                        "'active', 'missing-user', 'now', 'now')"
                    )
                )
    finally:
        engine.dispose()
    command.downgrade(config, "0005_identity_organizations")
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        assert {
            "assessment_audit_events", "execution_jobs", "execution_result_provenance"
        } <= set(
            inspect(engine).get_table_names()
        )
    finally:
        engine.dispose()


def test_engagement_audit_metadata_matches_migrated_foreign_keys(tmp_path: Path) -> None:
    metadata_database = tmp_path / "metadata-schema.sqlite3"
    migrated_database = tmp_path / "migrated-schema.sqlite3"
    metadata_engine = create_engine(f"sqlite:///{metadata_database.as_posix()}")
    migrated_engine = create_engine(f"sqlite:///{migrated_database.as_posix()}")
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{migrated_database.as_posix()}")

    def engine_with_foreign_keys(database: Path):
        engine = create_engine(f"sqlite:///{database.as_posix()}")

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    metadata_engine.dispose()
    metadata_engine = engine_with_foreign_keys(metadata_database)
    try:
        metadata.create_all(metadata_engine)
        command.upgrade(config, "head")
        migrated_engine.dispose()
        migrated_engine = engine_with_foreign_keys(migrated_database)

        def audit_foreign_keys(engine):
            return sorted(
                (
                    tuple(item["constrained_columns"]),
                    item["referred_table"],
                    tuple(item["referred_columns"]),
                    (item.get("options") or {}).get("ondelete"),
                )
                for item in inspect(engine).get_foreign_keys("assessment_audit_events")
            )

        metadata_keys = audit_foreign_keys(metadata_engine)
        migrated_keys = audit_foreign_keys(migrated_engine)
        assert metadata_keys == migrated_keys
        assert (
            ("organization_id", "actor_user_id"),
            "organization_memberships",
            ("organization_id", "user_id"),
            "RESTRICT",
        ) in metadata_keys

        def provenance_foreign_keys(engine):
            return sorted(
                (
                    tuple(item["constrained_columns"]),
                    item["referred_table"],
                    tuple(item["referred_columns"]),
                    (item.get("options") or {}).get("ondelete"),
                )
                for item in inspect(engine).get_foreign_keys("execution_result_provenance")
            )

        assert provenance_foreign_keys(metadata_engine) == provenance_foreign_keys(
            migrated_engine
        )
        for engine in (metadata_engine, migrated_engine):
            with engine.connect() as connection:
                trigger_names = set(
                    connection.execute(
                        text(
                            "SELECT name FROM sqlite_master WHERE type='trigger' "
                            "AND name LIKE 'execution_result_provenance_%'"
                        )
                    ).scalars()
                )
            assert {
                "execution_result_provenance_scope_guard",
                "execution_result_provenance_no_update",
                "execution_result_provenance_no_delete",
            } <= trigger_names

        def seed_tenants(connection) -> tuple[str, str, str]:
            timestamp = "2026-01-01T00:00:00Z"
            connection.execute(
                text(
                    "INSERT INTO users "
                    "(id,email_normalized,display_name,status,auth_epoch,created_at,updated_at) "
                    "VALUES (:id,:email,:name,'active','test',:created,:updated)"
                ),
                [
                    {
                        "id": "actor-a",
                        "email": "actor-a@example.test",
                        "name": "Actor A",
                        "created": timestamp,
                        "updated": timestamp,
                    },
                    {
                        "id": "actor-b",
                        "email": "actor-b@example.test",
                        "name": "Actor B",
                        "created": timestamp,
                        "updated": timestamp,
                    },
                ],
            )
            connection.execute(
                text(
                    "INSERT INTO organizations "
                    "(id,name,slug,status,owner_user_id,created_at,updated_at) "
                    "VALUES (:id,:name,:slug,'active',:owner,:created,:updated)"
                ),
                [
                    {
                        "id": "org-a",
                        "name": "Organization A",
                        "slug": "organization-a",
                        "owner": "actor-a",
                        "created": timestamp,
                        "updated": timestamp,
                    },
                    {
                        "id": "org-b",
                        "name": "Organization B",
                        "slug": "organization-b",
                        "owner": "actor-b",
                        "created": timestamp,
                        "updated": timestamp,
                    },
                ],
            )
            connection.execute(
                text(
                    "INSERT INTO organization_memberships "
                    "(id,organization_id,user_id,role,status,created_at,updated_at) "
                    "VALUES (:id,:org,:user,'owner','active',:created,:updated)"
                ),
                [
                    {
                        "id": "membership-a",
                        "org": "org-a",
                        "user": "actor-a",
                        "created": timestamp,
                        "updated": timestamp,
                    },
                    {
                        "id": "membership-b",
                        "org": "org-b",
                        "user": "actor-b",
                        "created": timestamp,
                        "updated": timestamp,
                    },
                ],
            )
            assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
            return "org-a", "actor-a", "actor-b"

        def verify_actor_membership(engine) -> None:
            with engine.begin() as connection:
                organization_id, valid_actor, foreign_actor = seed_tenants(connection)
                bad_values = {
                    "id": "audit-invalid",
                    "org": organization_id,
                    "actor": foreign_actor,
                    "action": "test",
                    "resource_type": "test",
                    "details": "{}",
                    "occurred_at": "2026-01-01T00:00:00Z",
                }
                with pytest.raises(IntegrityError):
                    connection.execute(
                        text(
                            "INSERT INTO assessment_audit_events "
                            "(id,organization_id,actor_user_id,action,resource_type,details,"
                            "occurred_at) "
                            "VALUES (:id,:org,:actor,:action,:resource_type,:details,:occurred_at)"
                        ),
                        bad_values,
                    )
                valid_values = bad_values | {"id": "audit-valid", "actor": valid_actor}
                connection.execute(
                    text(
                        "INSERT INTO assessment_audit_events "
                        "(id,organization_id,actor_user_id,action,resource_type,details,"
                        "occurred_at) "
                        "VALUES (:id,:org,:actor,:action,:resource_type,:details,:occurred_at)"
                    ),
                    valid_values,
                )
                assert (
                    connection.execute(
                        text("SELECT COUNT(*) FROM assessment_audit_events WHERE id='audit-valid'")
                    ).scalar_one()
                    == 1
                )

        verify_actor_membership(metadata_engine)
        verify_actor_membership(migrated_engine)

        metadata_org_audit = inspect(metadata_engine).get_foreign_keys("organization_audit_events")
        migrated_org_audit = inspect(migrated_engine).get_foreign_keys("organization_audit_events")
        for foreign_keys in (metadata_org_audit, migrated_org_audit):
            assert any(
                item["constrained_columns"] == ["actor_user_id"]
                and item["referred_table"] == "users"
                and item["referred_columns"] == ["id"]
                for item in foreign_keys
            )
    finally:
        metadata_engine.dispose()
        migrated_engine.dispose()
