"""PostgreSQL repository adapter for explicitly configured deployments.

SQLite remains the default backend. This adapter deliberately reuses the
application repository contract so services keep the same authorization and
transaction code while the schema is migrated through Alembic.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Connection, Engine

from chinescan.core.errors import StorageError
from chinescan.core.storage.sqlite import SQLiteRepository, metadata

POSTGRES_BACKEND_ROLE = "chinescan_backend"


def postgresql_driver_url(database_url: str) -> str:
    """Use psycopg 3 explicitly for both common PostgreSQL URL spellings."""

    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
    return database_url


class PostgresRepository(SQLiteRepository):
    """Repository backed by PostgreSQL using the existing service contract."""

    def __init__(self, database_url: str, *, storage_root: Path | str) -> None:
        if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise StorageError("PostgreSQL deployments require a PostgreSQL database URL.")
        self.path = Path(storage_root).expanduser().resolve(strict=False) / "postgres-backend"
        self.path.mkdir(parents=True, exist_ok=True)
        driver_url = postgresql_driver_url(database_url)
        (
            self.database_role,
            self.database_role_bypasses_rls,
            self.database_role_owns_application_tables,
        ) = self._verify_schema(driver_url)
        self.engine: Engine = create_engine(
            driver_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=2,
            connect_args={"application_name": "chinescan"},
        )
        self._initialize_context()
        event.listen(self.engine, "begin", self._apply_transaction_context)

    def _apply_transaction_context(self, connection: Connection) -> None:
        """Bind the already-validated application session to PostgreSQL RLS."""

        values = {
            "chinescan.user_id": self._organization_principal_id.get() or "",
            "chinescan.organization_id": self._current_organization_id() or "",
            "chinescan.write_access": "true" if self._organization_write_access.get() else "false",
        }
        for setting, value in values.items():
            connection.execute(
                text("SELECT set_config(:setting, :value, true)"),
                {"setting": setting, "value": value},
            )

    @contextmanager
    def member_context(
        self, organization_id: str, user_id: str, *, write: bool = False
    ) -> Iterator[None]:
        """Bind identity before the RLS-protected membership lookup.

        SQLite validates membership before entering its context. PostgreSQL
        must bind the authenticated principal first because the membership
        table itself is protected by the organization-member policy.
        """

        if not organization_id or not user_id:
            raise StorageError("An authenticated organization membership is required.")
        with self.organization_context(organization_id):
            principal_token = self._organization_principal_id.set(user_id)
            write_token = self._organization_write_access.set(write)
            try:
                with self.engine.connect() as connection:
                    membership = connection.execute(
                        text(
                            """
                            SELECT role
                              FROM public.organization_memberships
                             WHERE organization_id = :organization_id
                               AND user_id = :user_id
                               AND status = 'active'
                            """
                        ),
                        {"organization_id": organization_id, "user_id": user_id},
                    ).scalar_one_or_none()
                if membership is None:
                    raise StorageError("The organization membership is unavailable.")
                if write and membership not in {"owner", "admin", "member"}:
                    raise StorageError("The organization role does not allow this action.")
                yield
            finally:
                self._organization_write_access.reset(write_token)
                self._organization_principal_id.reset(principal_token)

    @contextmanager
    def local_operator_context(self) -> Iterator[None]:
        """Resolve the platform superuser and their admin org for background workers.

        On PostgreSQL/Supabase, the _local_operator_organization_id attribute is
        populated by OrganizationService.load_platform_superuser() at startup, but
        the RLS setup requires the principal to be set in the context var *before*
        any query.  This override looks up the superuser and their org dynamically
        and delegates to member_context, which correctly sets up Supabase RLS session
        variables (chinescan.user_id, chinescan.organization_id, chinescan.write_access).
        """
        from sqlalchemy import select

        from chinescan.core.storage.sqlite import organization_memberships, organizations, users

        organization_id = self._local_operator_organization_id
        user_id: str | None = None

        if not organization_id:
            # Fall back: query the DB for an active superuser and their admin org.
            with self.engine.connect() as connection:
                row = connection.execute(
                    select(
                        users.c.id,
                        organization_memberships.c.organization_id,
                    )
                    .join(
                        organization_memberships,
                        organization_memberships.c.user_id == users.c.id,
                    )
                    .join(
                        organizations,
                        organizations.c.id == organization_memberships.c.organization_id,
                    )
                    .where(
                        users.c.platform_role == "superuser",
                        users.c.status == "active",
                        organizations.c.status == "active",
                        organization_memberships.c.role == "owner",
                        organization_memberships.c.status == "active",
                    )
                    .limit(1)
                ).one_or_none()
            if row is not None:
                user_id = str(row[0])
                organization_id = str(row[1])
                # Cache for future calls.
                self._local_operator_organization_id = organization_id

        if not organization_id or not user_id:
            # Try to get user_id from the already-cached org.
            if organization_id and not user_id:
                with self.engine.connect() as connection:
                    uid = connection.execute(
                        select(users.c.id)
                        .join(
                            organization_memberships,
                            organization_memberships.c.user_id == users.c.id,
                        )
                        .where(
                            organization_memberships.c.organization_id == organization_id,
                            organization_memberships.c.role == "owner",
                            organization_memberships.c.status == "active",
                            users.c.platform_role == "superuser",
                            users.c.status == "active",
                        )
                        .limit(1)
                    ).scalar_one_or_none()
                    user_id = str(uid) if uid else None

        if not organization_id or not user_id:
            raise StorageError("Local operator authorization is unavailable.")

        with self.member_context(organization_id, user_id, write=True):
            yield

    @staticmethod
    def _verify_schema(database_url: str) -> tuple[str, bool, bool]:
        """Require the reviewed Supabase baseline before opening the app backend."""

        engine = create_engine(database_url, pool_pre_ping=True)
        try:
            inspector = inspect(engine)
            tables = set(inspector.get_table_names())
            required = set(metadata.tables)
            missing = required - tables
            with engine.connect() as connection:
                revision = MigrationContext.configure(connection).get_current_revision()
                role = connection.execute(
                    text(
                        """
                        SELECT current_user, COALESCE(rolsuper, false),
                               COALESCE(rolbypassrls, false)
                          FROM pg_roles
                         WHERE rolname = current_user
                        """
                    )
                ).one_or_none()
                backend_policy_count = int(
                    connection.execute(
                        text(
                            """
                            SELECT count(*)
                              FROM pg_policies
                             WHERE schemaname = 'public'
                               AND policyname LIKE '%\\_backend' ESCAPE '\\'
                               AND roles @> ARRAY[current_user::name]
                            """
                        )
                    ).scalar_one()
                )
                missing_privileges = int(
                    connection.execute(
                        text(
                            """
                            SELECT count(*)
                              FROM information_schema.tables table_info
                             WHERE table_info.table_schema = 'public'
                               AND table_info.table_type = 'BASE TABLE'
                               AND table_info.table_name <> 'alembic_version'
                               AND NOT (
                                 has_table_privilege(
                                   current_user,
                                   'public.' || quote_ident(table_info.table_name),
                                   'SELECT'
                                 )
                                 AND has_table_privilege(
                                   current_user,
                                   'public.' || quote_ident(table_info.table_name),
                                   'INSERT'
                                 )
                                 AND has_table_privilege(
                                   current_user,
                                   'public.' || quote_ident(table_info.table_name),
                                   'UPDATE'
                                 )
                                 AND has_table_privilege(
                                   current_user,
                                   'public.' || quote_ident(table_info.table_name),
                                   'DELETE'
                                 )
                               )
                            """
                        )
                    ).scalar_one()
                )
                owns_tables: bool = bool(
                    connection.execute(
                        text(
                            """
                        SELECT EXISTS (
                            SELECT 1
                              FROM pg_class relation
                              JOIN pg_namespace namespace
                                ON namespace.oid = relation.relnamespace
                             WHERE namespace.nspname = 'public'
                               AND relation.relkind = 'r'
                               AND relation.relname <> 'alembic_version'
                               AND relation.relowner = (
                                   SELECT oid FROM pg_roles WHERE rolname = current_user
                               )
                        )
                        """
                        )
                    ).scalar_one()
                )
            if missing or revision != "0016_phase6_governance":
                raise StorageError(
                    "PostgreSQL schema is not the reviewed ChineScan baseline; "
                    "apply the local Supabase migration before starting the backend."
                )
            if role is None:
                raise StorageError("PostgreSQL connection role could not be verified.")
            role_name, is_superuser, bypasses_rls = role
            if str(role_name) != POSTGRES_BACKEND_ROLE:
                raise StorageError(
                    "PostgreSQL backend must connect as the dedicated "
                    f"{POSTGRES_BACKEND_ROLE} role."
                )
            if backend_policy_count != len(required):
                raise StorageError(
                    "PostgreSQL baseline is missing explicit policies for the "
                    f"{POSTGRES_BACKEND_ROLE} role."
                )
            if missing_privileges != 0:
                raise StorageError(
                    f"PostgreSQL role {POSTGRES_BACKEND_ROLE} lacks required table privileges."
                )
            if is_superuser or bypasses_rls or owns_tables:
                raise StorageError(
                    f"PostgreSQL role {POSTGRES_BACKEND_ROLE} must not be a superuser, "
                    "BYPASSRLS role, or owner of application tables."
                )
            return str(role_name), bool(is_superuser or bypasses_rls), bool(owns_tables)
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                "PostgreSQL schema verification failed; database contents were not changed."
            ) from exc
        finally:
            engine.dispose()
