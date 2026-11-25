"""Phase 2D Alembic roundtrip and downgrade guard verification script."""
from __future__ import annotations

import os
import sys
import tempfile
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command


def run_roundtrip() -> None:
    db = os.path.join(tempfile.mkdtemp(), "roundtrip.sqlite3")
    url = f"sqlite:///{db}"
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)

    # Step 1: upgrade to head
    command.upgrade(cfg, "head")
    with create_engine(url).connect() as conn:
        rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        tbl_rows = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        ).fetchall()
        tables = [r[0] for r in tbl_rows if not r[0].startswith("sqlite")]
        fk = conn.execute(text("PRAGMA foreign_key_check")).fetchall()
    print(f"upgrade head OK — revision: {rev}")
    print(f"  tables: {tables}")
    print(f"  foreign_key_check violations: {len(fk)}")
    assert rev == "0015_durable_job_leases_actions", f"unexpected head: {rev}"
    assert "execution_action_attempts" in tables
    assert "worker_leases" in tables
    assert len(fk) == 0, f"FK violations: {fk}"

    # Step 2: downgrade to 0014
    command.downgrade(cfg, "0014_multi_user_identity_sessions")
    with create_engine(url).connect() as conn:
        rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    print(f"downgrade to 0014 OK — revision: {rev}")
    assert rev == "0014_multi_user_identity_sessions", f"unexpected rev: {rev}"

    # Step 3: re-upgrade to head
    command.upgrade(cfg, "head")
    with create_engine(url).connect() as conn:
        rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        fk = conn.execute(text("PRAGMA foreign_key_check")).fetchall()
    print(f"re-upgrade head OK — revision: {rev}")
    assert rev == "0015_durable_job_leases_actions"
    assert len(fk) == 0
    print("roundtrip PASSED")


def run_guard() -> None:
    db = os.path.join(tempfile.mkdtemp(), "guard.sqlite3")
    url = f"sqlite:///{db}"
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")

    engine = create_engine(url)
    with engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO execution_action_attempts "
            "(id, job_id, organization_id, engagement_id, action_sequence, "
            "lease_generation, worker_id, adapter_id, operation, "
            "authorization_id, approval_id, request_digest, state, "
            "created_at, updated_at) "
            "VALUES ('g1','j1','o1','e1',1,1,'w1','a1','op1','auth1',"
            "NULL,'digest1','authorized','2026-01-01','2026-01-01')"
        ))
        conn.commit()

    try:
        command.downgrade(cfg, "0014_multi_user_identity_sessions")
        print("FAIL: downgrade guard did not fire")
        sys.exit(1)
    except RuntimeError as exc:
        print(f"downgrade guard fired correctly: {str(exc)[:160]}")
        print("guard PASSED")
    except Exception as exc:  # noqa: BLE001
        print(f"unexpected exception type {type(exc).__name__}: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    run_roundtrip()
    run_guard()
    print("\nAll Alembic checks PASSED")
