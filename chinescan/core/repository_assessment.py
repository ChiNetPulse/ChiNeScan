"""Tenant-scoped local repository bindings and immutable source snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import func, select, update

from chinescan.core.engagement_security import (
    EngagementSecurityError,
    EngagementSecurityService,
    _utc,
)
from chinescan.core.organizations import now_iso
from chinescan.core.projects import ProjectError, ProjectService, safe_project_tree
from chinescan.core.storage.security import StorageSecurityError, secure_snapshot_directory
from chinescan.core.storage.sqlite import (
    assessment_audit_events,
    authorization_records,
    engagement_assets,
    engagement_assignments,
    engagements,
    execution_jobs,
    organization_memberships,
    organizations,
    repository_asset_bindings,
    repository_attestations,
    repository_quota_reservations,
    repository_snapshots,
    scope_revisions,
    scope_rules,
    users,
)

MANIFEST_VERSION = 1
SCANNER_VERSION = "builtin-code-rules-v1"
EXCLUSION_POLICY_VERSION = "repository-exclusions-v1"
ATTESTATION_VERSION = "repository-code-authorization-v1"
ATTESTATION_TEXT = (
    "I confirm that I have confirmed the source is authorized for assessment, that the selected "
    "authorization record covers repository code assessment, and that this repository and "
    "published scope revision are the intended assessment targets. This is an accountability "
    "record, not independent proof of ownership or legal permission."
)
RETENTION_DAYS_AFTER_CLOSURE = 90
REPOSITORY_TECHNIQUE = "repository_code_assessment"
EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "out",
    "coverage",
    ".turbo",
    ".vercel",
}


class RepositorySnapshotError(ValueError):
    """Safe repository snapshot failure with stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _is_reparse_or_link(path: Path) -> bool:
    try:
        info = path.lstat()
        return path.is_symlink() or bool(
            os.name == "nt"
            and getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except OSError:
        return True


class RepositorySnapshotStore:
    """Managed content-addressed snapshots; database metadata stores no public path."""

    def __init__(
        self,
        repository: Any,
        root: Path,
        *,
        max_snapshot_bytes: int,
        organization_quota_bytes: int,
        max_files: int = 50_000,
        max_depth: int = 32,
    ) -> None:
        self.repository = repository
        self.engine = repository.engine
        self.root = root.expanduser().absolute()
        self.max_snapshot_bytes = max_snapshot_bytes
        self.organization_quota_bytes = organization_quota_bytes
        self.max_files = max_files
        self.max_depth = max_depth
        try:
            self.root = secure_snapshot_directory(self.root)
        except StorageSecurityError as exc:
            raise RepositorySnapshotError(
                "snapshot_store_unsafe", "Managed snapshot storage is unavailable."
            ) from exc

    def _snapshot_path(self, organization_id: str, digest: str) -> Path:
        if (
            len(organization_id) != 36
            or any(char not in "0123456789abcdef-" for char in organization_id)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise RepositorySnapshotError(
                "snapshot_identity_invalid", "Managed snapshot identity is invalid."
            )
        root = self.root.resolve(strict=True)
        if _is_reparse_or_link(self.root) or not root.is_dir():
            raise RepositorySnapshotError(
                "snapshot_store_unsafe", "Managed snapshot storage is unavailable."
            )
        organization_path = root / organization_id
        if organization_path.exists():
            if _is_reparse_or_link(organization_path):
                raise RepositorySnapshotError(
                    "snapshot_store_unsafe", "Managed snapshot storage is unavailable."
                )
            if organization_path.resolve(strict=True).parent != root:
                raise RepositorySnapshotError(
                    "snapshot_store_unsafe", "Managed snapshot storage is unavailable."
                )
        candidate = organization_path / digest
        if (candidate.exists() or candidate.is_symlink()) and _is_reparse_or_link(candidate):
            raise RepositorySnapshotError(
                "snapshot_store_unsafe", "Managed snapshot storage is unavailable."
            )
        return candidate

    def _inventory(self, root: Path) -> tuple[list[dict[str, Any]], int]:
        try:
            canonical = root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositorySnapshotError(
                "project_unavailable", "Registered project is unavailable."
            ) from exc
        if (
            not canonical.is_dir()
            or _is_reparse_or_link(canonical)
            or not safe_project_tree(canonical)
        ):
            raise RepositorySnapshotError(
                "project_unsafe", "Registered project contains an unsafe path."
            )
        entries: list[dict[str, Any]] = []
        total = 0
        file_count = 0
        for directory, dirs, files in os.walk(canonical, topdown=True, followlinks=False):
            current = Path(directory)
            rel_dir = current.relative_to(canonical)
            for name in dirs:
                if _is_reparse_or_link(current / name):
                    raise RepositorySnapshotError(
                        "project_unsafe", "Registered project contains an unsafe linked directory."
                    )
            dirs[:] = sorted(
                name
                for name in dirs
                if name not in EXCLUDED_DIRECTORIES
                and not (current / name / ".git").exists()
                and len((rel_dir / name).parts) <= self.max_depth
            )
            for name in sorted(files):
                path = current / name
                if _is_reparse_or_link(path):
                    raise RepositorySnapshotError(
                        "project_unsafe", "Registered project contains an unsafe path."
                    )
                try:
                    info = path.stat(follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    file_count += 1
                    if file_count > self.max_files:
                        raise RepositorySnapshotError(
                            "snapshot_file_limit",
                            "Repository exceeds the configured file-count limit.",
                        )
                    if (
                        len(PurePosixPath(path.relative_to(canonical).as_posix()).parts)
                        > self.max_depth
                    ):
                        raise RepositorySnapshotError(
                            "snapshot_depth_limit",
                            "Repository exceeds the configured traversal-depth limit.",
                        )
                    relative = PurePosixPath(path.relative_to(canonical).as_posix()).as_posix()
                    if relative.startswith("../") or relative.startswith("/"):
                        raise ValueError
                    digest = hashlib.sha256()
                    size = 0
                    with path.open("rb") as stream:
                        while chunk := stream.read(1024 * 1024):
                            size += len(chunk)
                            total += len(chunk)
                            if total > self.max_snapshot_bytes:
                                raise RepositorySnapshotError(
                                    "snapshot_too_large",
                                    "Repository exceeds the configured snapshot limit.",
                                )
                            digest.update(chunk)
                    entries.append(
                        {"path": relative, "size_bytes": size, "sha256": digest.hexdigest()}
                    )
                except RepositorySnapshotError:
                    raise
                except (OSError, ValueError) as exc:
                    raise RepositorySnapshotError(
                        "project_read_failed", "Registered project could not be read safely."
                    ) from exc
        entries.sort(key=lambda item: item["path"].encode("utf-8"))
        return entries, total

    def create(
        self,
        organization_id: str,
        project_root: Path,
        *,
        actor_user_id: str | None = None,
        engagement_id: str | None = None,
    ) -> dict[str, Any]:
        entries, total = self._inventory(project_root)
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "exclusion_policy": EXCLUSION_POLICY_VERSION,
            "scanner_version": SCANNER_VERSION,
            "entries": entries,
        }
        digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
        now = now_iso()
        reservation_id = str(uuid.uuid4())
        reservation_expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        staging: Path | None = None
        expired_reservations: list[dict[str, Any]] = []
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                expired_reservations = [
                    dict(row._mapping)
                    for row in connection.execute(
                        select(
                            repository_quota_reservations.c.id,
                            repository_quota_reservations.c.content_digest,
                        ).where(
                            repository_quota_reservations.c.organization_id == organization_id,
                            repository_quota_reservations.c.expires_at <= now,
                        )
                    ).all()
                ]
                if expired_reservations:
                    connection.execute(
                        repository_quota_reservations.delete().where(
                            repository_quota_reservations.c.id.in_(
                                [item["id"] for item in expired_reservations]
                            )
                        )
                    )
                existing = connection.execute(
                    select(repository_snapshots).where(
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.sha256 == digest,
                        repository_snapshots.c.status == "available",
                    )
                ).first()
                if existing and self._verify_path(
                    self._snapshot_path(organization_id, digest), manifest
                ):
                    if actor_user_id and engagement_id:
                        self._audit(
                            connection,
                            organization_id,
                            engagement_id,
                            actor_user_id,
                            "repository.snapshot_reused",
                            existing.id,
                            {"sha256": digest, "size_bytes": existing.size_bytes},
                        )
                    connection.commit()
                    return dict(existing._mapping)
                if existing:
                    connection.execute(
                        update(repository_snapshots)
                        .where(
                            repository_snapshots.c.id == existing.id,
                        )
                        .values(status="corrupt")
                    )
                    connection.commit()
                    raise RepositorySnapshotError(
                        "snapshot_corrupt",
                        "An existing content-addressed snapshot failed integrity verification.",
                    )
                used_rows = connection.execute(
                    select(
                        repository_snapshots.c.sha256,
                        repository_snapshots.c.size_bytes,
                    ).where(
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.status != "deleted",
                    )
                ).all()
                # Count content-addressed bytes once, even if historical metadata rows
                # refer to the same digest.
                used = sum({row.sha256: int(row.size_bytes) for row in used_rows}.values())
                reserved = connection.execute(
                    select(
                        func.coalesce(func.sum(repository_quota_reservations.c.reserved_bytes), 0)
                    ).where(
                        repository_quota_reservations.c.organization_id == organization_id,
                    )
                ).scalar_one()
                if int(used) + int(reserved) + total > self.organization_quota_bytes:
                    if actor_user_id and engagement_id:
                        self._audit(
                            connection,
                            organization_id,
                            engagement_id,
                            actor_user_id,
                            "repository.snapshot_quota_denied",
                            reservation_id,
                            {
                                "requested_bytes": total,
                                "used_bytes": int(used),
                                "reserved_bytes": int(reserved),
                                "limit_bytes": self.organization_quota_bytes,
                            },
                            decision="DENY",
                        )
                    connection.commit()
                    raise RepositorySnapshotError(
                        "organization_quota_exceeded",
                        "Organization repository snapshot quota is exhausted.",
                    )
                connection.execute(
                    repository_quota_reservations.insert().values(
                        id=reservation_id,
                        organization_id=organization_id,
                        reserved_bytes=total,
                        content_digest=digest,
                        created_at=now,
                        expires_at=reservation_expires,
                    )
                )
                if actor_user_id and engagement_id:
                    self._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        actor_user_id,
                        "repository.snapshot_quota_reserved",
                        reservation_id,
                        {"reserved_bytes": total, "content_sha256": digest},
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        for expired in expired_reservations:
            expired_id = expired["id"]
            for stale in (self.root / organization_id).glob(f".snapshot-{expired_id}-*"):
                if stale.exists() and not _is_reparse_or_link(stale):
                    shutil.rmtree(stale, ignore_errors=True)
            with self.engine.connect() as connection:
                committed = connection.execute(
                    select(repository_snapshots.c.id).where(
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.sha256 == expired["content_digest"],
                        repository_snapshots.c.status != "deleted",
                    )
                ).first()
            orphan = self._snapshot_path(organization_id, expired["content_digest"])
            if not committed and orphan.exists() and not _is_reparse_or_link(orphan):
                shutil.rmtree(orphan, ignore_errors=True)
        try:
            base = self._snapshot_path(organization_id, digest).parent
            base.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f".snapshot-{reservation_id}-", dir=base))
            source_root = project_root.resolve(strict=True)
            copied = 0
            by_path = {item["path"]: item for item in entries}
            for item in entries:
                relative = PurePosixPath(item["path"])
                source = source_root.joinpath(*relative.parts)
                destination = staging.joinpath(*relative.parts)
                if _is_reparse_or_link(source) or not source.resolve(strict=True).is_relative_to(
                    source_root
                ):
                    raise RepositorySnapshotError(
                        "project_changed", "Project changed while the snapshot was being created."
                    )
                destination.parent.mkdir(parents=True, exist_ok=True)
                hasher = hashlib.sha256()
                with source.open("rb") as src, destination.open("xb") as dst:
                    while chunk := src.read(1024 * 1024):
                        copied += len(chunk)
                        if copied > self.max_snapshot_bytes:
                            raise RepositorySnapshotError(
                                "snapshot_too_large",
                                "Repository exceeds the configured snapshot limit.",
                            )
                        hasher.update(chunk)
                        dst.write(chunk)
                if copied < 0 or hasher.hexdigest() != by_path[item["path"]]["sha256"]:
                    raise RepositorySnapshotError(
                        "project_changed", "Project changed while the snapshot was being created."
                    )
            if copied != total:
                raise RepositorySnapshotError(
                    "project_changed", "Project changed while the snapshot was being created."
                )
            destination_root = self._snapshot_path(organization_id, digest)
            destination_root.parent.mkdir(parents=True, exist_ok=True)
            if destination_root.exists():
                shutil.rmtree(staging)
                staging = None
            else:
                os.rename(staging, destination_root)
                staging = None
            with self.engine.connect() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    existing = connection.execute(
                        select(repository_snapshots).where(
                            repository_snapshots.c.organization_id == organization_id,
                            repository_snapshots.c.sha256 == digest,
                            repository_snapshots.c.status == "available",
                        )
                    ).first()
                    if existing:
                        row = dict(existing._mapping)
                    else:
                        snapshot_id = str(uuid.uuid4())
                        connection.execute(
                            repository_snapshots.insert().values(
                                id=snapshot_id,
                                organization_id=organization_id,
                                sha256=digest,
                                size_bytes=total,
                                manifest=manifest,
                                manifest_version=MANIFEST_VERSION,
                                scanner_version=SCANNER_VERSION,
                                created_at=now,
                                status="available",
                                closed_at=None,
                                delete_after=None,
                                legal_hold=0,
                                hold_reason=None,
                                deleted_at=None,
                            )
                        )
                        row = {
                            "id": snapshot_id,
                            "organization_id": organization_id,
                            "sha256": digest,
                            "size_bytes": total,
                            "manifest": manifest,
                            "manifest_version": MANIFEST_VERSION,
                            "scanner_version": SCANNER_VERSION,
                            "created_at": now,
                            "status": "available",
                            "closed_at": None,
                            "delete_after": None,
                            "legal_hold": 0,
                            "hold_reason": None,
                            "deleted_at": None,
                        }
                    connection.execute(
                        repository_quota_reservations.delete().where(
                            repository_quota_reservations.c.id == reservation_id
                        )
                    )
                    if actor_user_id and engagement_id:
                        self._audit(
                            connection,
                            organization_id,
                            engagement_id,
                            actor_user_id,
                            "repository.snapshot_quota_accounted",
                            row["id"],
                            {"size_bytes": total, "sha256": digest},
                        )
                    connection.commit()
                    return row
                except Exception:
                    connection.rollback()
                    raise
        except Exception:
            with self.engine.begin() as connection:
                connection.execute(
                    repository_quota_reservations.delete().where(
                        repository_quota_reservations.c.id == reservation_id
                    )
                )
                if actor_user_id and engagement_id:
                    self._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        actor_user_id,
                        "repository.snapshot_quota_released",
                        reservation_id,
                        {"reserved_bytes": total},
                    )
            if staging and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            destination_root = self._snapshot_path(organization_id, digest)
            with self.engine.connect() as connection:
                referenced = connection.execute(
                    select(repository_snapshots.c.id).where(
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.sha256 == digest,
                        repository_snapshots.c.status != "deleted",
                    )
                ).first()
            if (
                not referenced
                and destination_root.exists()
                and not _is_reparse_or_link(destination_root)
            ):
                shutil.rmtree(destination_root, ignore_errors=True)
            raise

    def _verify_path(self, path: Path, manifest: dict[str, Any]) -> bool:
        try:
            if not path.is_dir() or _is_reparse_or_link(path):
                return False
            if set(manifest) != {
                "manifest_version",
                "exclusion_policy",
                "scanner_version",
                "entries",
            }:
                return False
            if (
                manifest["manifest_version"] != MANIFEST_VERSION
                or manifest["exclusion_policy"] != EXCLUSION_POLICY_VERSION
                or manifest["scanner_version"] != SCANNER_VERSION
            ):
                return False
            entries = manifest["entries"]
            if not isinstance(entries, list):
                return False
            expected_paths: list[str] = []
            previous_key: bytes | None = None
            total_bytes = 0
            if len(entries) > self.max_files:
                return False
            for item in entries:
                if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}:
                    return False
                raw_path = item["path"]
                if not isinstance(raw_path, str) or "\\" in raw_path or "\x00" in raw_path:
                    return False
                relative = PurePosixPath(raw_path)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or ".." in relative.parts
                    or "." in relative.parts
                ):
                    return False
                if len(relative.parts) > self.max_depth or any(
                    part in EXCLUDED_DIRECTORIES for part in relative.parts
                ):
                    return False
                encoded = raw_path.encode("utf-8")
                if previous_key is not None and encoded <= previous_key:
                    return False
                previous_key = encoded
                if (
                    isinstance(item["size_bytes"], bool)
                    or not isinstance(item["size_bytes"], int)
                    or item["size_bytes"] < 0
                ):
                    return False
                total_bytes += item["size_bytes"]
                if total_bytes > self.max_snapshot_bytes:
                    return False
                if not isinstance(item["sha256"], str) or len(item["sha256"]) != 64:
                    return False
                int(item["sha256"], 16)
                expected_paths.append(raw_path)
            root = path.resolve(strict=True)
            actual_paths: list[str] = []
            for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
                current = Path(directory)
                for name in dirs:
                    candidate = current / name
                    if _is_reparse_or_link(candidate):
                        return False
                for name in files:
                    candidate = current / name
                    if _is_reparse_or_link(candidate) or not stat.S_ISREG(
                        candidate.stat(follow_symlinks=False).st_mode
                    ):
                        return False
                    actual_paths.append(
                        PurePosixPath(candidate.relative_to(root).as_posix()).as_posix()
                    )
            actual_paths.sort(key=lambda value: value.encode("utf-8"))
            if actual_paths != expected_paths:
                return False
            for item in manifest["entries"]:
                relative = PurePosixPath(item["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    return False
                file_path = root.joinpath(*relative.parts)
                if _is_reparse_or_link(file_path) or not file_path.resolve(
                    strict=True
                ).is_relative_to(root):
                    return False
                digest = hashlib.sha256()
                size = 0
                with file_path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                if size != item["size_bytes"] or digest.hexdigest() != item["sha256"]:
                    return False
            return True
        except (OSError, KeyError, TypeError, ValueError):
            return False

    def verify(
        self, organization_id: str, snapshot_id: str
    ) -> tuple[dict[str, Any] | None, Path | None]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(repository_snapshots).where(
                    repository_snapshots.c.organization_id == organization_id,
                    repository_snapshots.c.id == snapshot_id,
                    repository_snapshots.c.status == "available",
                )
            ).first()
            if not row:
                return None, None
            item = dict(row._mapping)
        path = self._snapshot_path(organization_id, item["sha256"])
        valid = hashlib.sha256(_canonical_json(item["manifest"])).hexdigest() == item[
            "sha256"
        ] and self._verify_path(path, item["manifest"])
        if not valid:
            status = "missing" if not path.exists() else "corrupt"
            with self.engine.begin() as connection:
                connection.execute(
                    update(repository_snapshots)
                    .where(
                        repository_snapshots.c.id == snapshot_id,
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.status == "available",
                    )
                    .values(status=status)
                )
        return (item, path) if valid else (None, None)

    def remove_unreferenced(self, organization_id: str, snapshot_id: str) -> None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(repository_snapshots).where(
                    repository_snapshots.c.organization_id == organization_id,
                    repository_snapshots.c.id == snapshot_id,
                )
            ).first()
            if not row:
                return
            digest = row.sha256
            binding = connection.execute(
                select(repository_asset_bindings.c.id).where(
                    repository_asset_bindings.c.snapshot_id == snapshot_id,
                )
            ).first()
            if binding:
                return
            duplicate = connection.execute(
                select(repository_snapshots.c.id).where(
                    repository_snapshots.c.organization_id == organization_id,
                    repository_snapshots.c.sha256 == digest,
                    repository_snapshots.c.id != snapshot_id,
                    repository_snapshots.c.status != "deleted",
                )
            ).first()
        if not duplicate:
            shutil.rmtree(self._snapshot_path(organization_id, digest), ignore_errors=True)
        with self.engine.begin() as connection:
            connection.execute(
                update(repository_snapshots)
                .where(
                    repository_snapshots.c.id == snapshot_id,
                    repository_snapshots.c.organization_id == organization_id,
                )
                .values(status="deleted", deleted_at=now_iso())
            )

    @staticmethod
    def _audit(
        connection: Any,
        organization_id: str,
        engagement_id: str,
        actor_id: str,
        action: str,
        resource_id: str,
        details: dict[str, Any],
        *,
        decision: str = "ALLOW",
    ) -> None:
        connection.execute(
            assessment_audit_events.insert().values(
                id=str(uuid.uuid4()),
                organization_id=organization_id,
                engagement_id=engagement_id,
                actor_user_id=actor_id,
                action=action,
                resource_type="repository_snapshot",
                resource_id=resource_id,
                decision=decision,
                reason_code=action.upper().replace(".", "_"),
                occurred_at=now_iso(),
                details=details,
            )
        )

    def hold(
        self, user_id: str, organization_id: str, engagement_id: str, snapshot_id: str, reason: str
    ) -> bool:
        if not reason.strip() or len(reason) > 500:
            raise RepositorySnapshotError(
                "hold_reason_required", "A short hold reason is required."
            )
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                if not RepositoryAssessmentService._is_lead_connection(
                    connection,
                    user_id,
                    organization_id,
                    engagement_id,
                    require_active_engagement=False,
                ):
                    connection.rollback()
                    return False
                snapshot = connection.execute(
                    select(repository_snapshots)
                    .join(
                        repository_asset_bindings,
                        (repository_asset_bindings.c.snapshot_id == repository_snapshots.c.id)
                        & (
                            repository_asset_bindings.c.organization_id
                            == repository_snapshots.c.organization_id
                        ),
                    )
                    .where(
                        repository_snapshots.c.id == snapshot_id,
                        repository_snapshots.c.organization_id == organization_id,
                        repository_asset_bindings.c.engagement_id == engagement_id,
                    )
                ).first()
                if not snapshot:
                    connection.rollback()
                    return False
                connection.execute(
                    update(repository_snapshots)
                    .where(
                        repository_snapshots.c.id == snapshot_id,
                        repository_snapshots.c.organization_id == organization_id,
                    )
                    .values(legal_hold=1, hold_reason=reason.strip())
                )
                self._audit_repository(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "repository.snapshot_hold_placed",
                    snapshot_id,
                    {"reason": reason.strip()},
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def release_hold(
        self, user_id: str, organization_id: str, engagement_id: str, snapshot_id: str, reason: str
    ) -> bool:
        if not reason.strip() or len(reason) > 500:
            raise RepositorySnapshotError(
                "hold_reason_required", "A short hold-release reason is required."
            )
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                if not RepositoryAssessmentService._is_lead_connection(
                    connection,
                    user_id,
                    organization_id,
                    engagement_id,
                    require_active_engagement=False,
                ):
                    connection.rollback()
                    return False
                snapshot = connection.execute(
                    select(repository_snapshots)
                    .join(
                        repository_asset_bindings,
                        (repository_asset_bindings.c.snapshot_id == repository_snapshots.c.id)
                        & (
                            repository_asset_bindings.c.organization_id
                            == repository_snapshots.c.organization_id
                        ),
                    )
                    .where(
                        repository_snapshots.c.id == snapshot_id,
                        repository_snapshots.c.organization_id == organization_id,
                        repository_asset_bindings.c.engagement_id == engagement_id,
                    )
                ).first()
                if not snapshot:
                    connection.rollback()
                    return False
                connection.execute(
                    update(repository_snapshots)
                    .where(
                        repository_snapshots.c.id == snapshot_id,
                        repository_snapshots.c.organization_id == organization_id,
                    )
                    .values(legal_hold=0, hold_reason=None)
                )
                self._audit_repository(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "repository.snapshot_hold_released",
                    snapshot_id,
                    {"reason": reason.strip()},
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def delete_eligible(
        self, user_id: str, organization_id: str, engagement_id: str, snapshot_id: str
    ) -> bool:
        """Explicit auditable deletion; never a side effect of a normal read/write request."""
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                if not RepositoryAssessmentService._is_lead_connection(
                    connection,
                    user_id,
                    organization_id,
                    engagement_id,
                    require_active_engagement=False,
                ):
                    connection.rollback()
                    return False
                snapshot = connection.execute(
                    select(repository_snapshots).where(
                        repository_snapshots.c.id == snapshot_id,
                        repository_snapshots.c.organization_id == organization_id,
                    )
                ).first()
                if not snapshot or snapshot.status not in {
                    "available",
                    "missing",
                    "corrupt",
                    "deleting",
                }:
                    connection.rollback()
                    return False
                digest_rows = connection.execute(
                    select(
                        repository_snapshots.c.id,
                        repository_snapshots.c.legal_hold,
                    ).where(
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.sha256 == snapshot.sha256,
                        repository_snapshots.c.status != "deleted",
                    )
                ).all()
                snapshot_ids = [row.id for row in digest_rows]
                if not snapshot_ids:
                    connection.rollback()
                    return False
                if any(row.legal_hold for row in digest_rows):
                    raise RepositorySnapshotError(
                        "snapshot_on_hold",
                        "Snapshot content is protected by a legal or investigation hold.",
                    )
                if any(row.id != snapshot_id and row.status == "available" for row in digest_rows):
                    # A content-addressed object shared with another live metadata row
                    # cannot be deleted from one binding's retention workflow.
                    raise RepositorySnapshotError(
                        "snapshot_shared",
                        "Snapshot content is still referenced by another repository binding.",
                    )
                bindings = connection.execute(
                    select(
                        repository_asset_bindings.c.engagement_id,
                    ).where(
                        repository_asset_bindings.c.organization_id == organization_id,
                        repository_asset_bindings.c.snapshot_id.in_(snapshot_ids),
                    )
                ).all()
                if not bindings:
                    raise RepositorySnapshotError(
                        "snapshot_retained",
                        "Snapshot metadata has no verifiable engagement ownership.",
                    )
                now = datetime.now(UTC)
                for binding in bindings:
                    engagement = connection.execute(
                        select(engagements.c.status, engagements.c.closed_at).where(
                            engagements.c.id == binding.engagement_id,
                            engagements.c.organization_id == organization_id,
                        )
                    ).first()
                    if (
                        not engagement
                        or engagement.status not in {"completed", "archived"}
                        or not engagement.closed_at
                    ):
                        raise RepositorySnapshotError(
                            "snapshot_retained",
                            "Snapshot is retained while any associated engagement remains open.",
                        )
                    if now < _utc(engagement.closed_at) + timedelta(
                        days=RETENTION_DAYS_AFTER_CLOSURE
                    ):
                        raise RepositorySnapshotError(
                            "snapshot_retained", "Snapshot has not reached its retention date."
                        )
                active = connection.execute(
                    select(execution_jobs.c.id).where(
                        execution_jobs.c.organization_id == organization_id,
                        execution_jobs.c.repository_snapshot_id.in_(snapshot_ids),
                        execution_jobs.c.status.in_(["queued", "claimed", "running"]),
                    )
                ).first()
                if active:
                    raise RepositorySnapshotError(
                        "snapshot_job_active",
                        "Snapshot is referenced by a nonterminal execution job.",
                    )
                connection.execute(
                    update(repository_snapshots)
                    .where(
                        repository_snapshots.c.organization_id == organization_id,
                        repository_snapshots.c.id.in_(snapshot_ids),
                    )
                    .values(status="deleting")
                )
                self._audit_repository(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "repository.snapshot_deletion_started",
                    snapshot_id,
                    {},
                )
                digest = snapshot.sha256
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        path = self._snapshot_path(organization_id, digest)
        try:
            if path.exists() or path.is_symlink():
                if _is_reparse_or_link(path):
                    raise OSError("managed snapshot root is a reparse point")
                shutil.rmtree(path)
        except OSError as exc:
            with self.engine.begin() as connection:
                self._audit_repository(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "repository.snapshot_deletion_failed",
                    snapshot_id,
                    {},
                )
            raise RepositorySnapshotError(
                "snapshot_delete_failed", "Managed snapshot content could not be safely removed."
            ) from exc
        with self.engine.begin() as connection:
            connection.execute(
                update(repository_snapshots)
                .where(
                    repository_snapshots.c.organization_id == organization_id,
                    repository_snapshots.c.sha256 == digest,
                    repository_snapshots.c.status == "deleting",
                )
                .values(status="deleted", deleted_at=now_iso())
            )
            self._audit_repository(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "repository.snapshot_deleted",
                snapshot_id,
                {"sha256": digest},
            )
        return True

    @staticmethod
    def _audit_repository(
        connection: Any,
        organization_id: str,
        engagement_id: str,
        actor_id: str,
        event: str,
        object_id: str,
        details: dict[str, Any],
    ) -> None:
        from chinescan.core.storage.sqlite import assessment_audit_events

        connection.execute(
            assessment_audit_events.insert().values(
                id=str(uuid.uuid4()),
                organization_id=organization_id,
                engagement_id=engagement_id,
                actor_user_id=actor_id,
                action=event,
                resource_type="repository_snapshot",
                resource_id=object_id,
                decision="ALLOW",
                reason_code=event.upper().replace(".", "_"),
                occurred_at=now_iso(),
                details=details,
            )
        )


class RepositoryAssessmentService:
    """Lead-attested binding and tenant-scoped repository asset operations."""

    def __init__(
        self,
        repository: Any,
        security: EngagementSecurityService,
        projects: ProjectService,
        snapshots: RepositorySnapshotStore,
    ) -> None:
        self.repository = repository
        self.engine = repository.engine
        self.security = security
        self.projects = projects
        self.snapshots = snapshots

    def projects_for(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, str]] | None:
        if not self._is_lead(user_id, organization_id, engagement_id):
            return None
        values = []
        # Listing the local registry is authorized by the engagement lead check
        # above and must remain scoped to the requested organization.
        with self.repository.organization_context(organization_id):
            for item in self.projects.list():
                if item.get("kind") == "github":
                    continue
                values.append(
                    {
                        "project_registry_id": str(item["project_id"]),
                        "display_label": str(
                            item.get("display_name", item.get("name", "Local project"))
                        ),
                    }
                )
        return values

    def create_asset(
        self, user_id: str, organization_id: str, engagement_id: str, description: str | None = None
    ) -> dict[str, Any] | None:
        if description is not None and len(description) > 2000:
            raise EngagementSecurityError("Repository description is too long.")
        with self.engine.begin() as connection:
            engagement = self.security._engagement(connection, organization_id, engagement_id)
            if not engagement or not self._is_lead_connection(
                connection, user_id, organization_id, engagement_id
            ):
                return None
            if engagement["status"] != "active":
                raise RepositorySnapshotError(
                    "engagement_inactive", "Repository assets require an active engagement."
                )
            asset_id = str(uuid.uuid4())
            timestamp = now_iso()
            item = {
                "id": asset_id,
                "organization_id": organization_id,
                "client_id": engagement.get("client_id"),
                "engagement_id": engagement_id,
                "asset_type": "repository",
                "target": f"repo:{asset_id}",
                "description": description,
                "status": "active",
                "created_by": user_id,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            connection.execute(engagement_assets.insert().values(**item))
            self.security._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "repository.asset_created",
                "asset",
                asset_id,
                details={"asset_type": "repository", "source_kind": "local_project_registry"},
            )
            return item

    def bind(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        project_registry_id: str,
        authorization_id: str,
        scope_revision_id: str,
        attestation_text: str,
    ) -> dict[str, Any] | None:
        if attestation_text != ATTESTATION_TEXT:
            raise RepositorySnapshotError(
                "attestation_required",
                "The exact repository authorization attestation is required.",
            )
        if not project_registry_id or len(project_registry_id) > 80:
            raise RepositorySnapshotError(
                "project_unavailable", "Registered project is unavailable."
            )
        self._validate_binding(
            user_id,
            organization_id,
            engagement_id,
            asset_id,
            authorization_id,
            scope_revision_id,
        )
        # `_validate_binding` verifies the active engagement and lead assignment.
        # Read the operator-managed project registry only inside that org scope.
        with self.repository.organization_context(organization_id):
            stored = self.projects._stored(project_registry_id)
            if stored and stored.get("kind") == "github":
                raise RepositorySnapshotError(
                    "project_source_unsupported",
                    "Only operator-registered local projects are supported.",
                )
            try:
                label, root = self.projects.resolve(project_registry_id)
            except ProjectError as exc:
                raise RepositorySnapshotError(
                    "project_unavailable", "Registered project is unavailable."
                ) from exc
        with self.engine.connect() as connection:
            existing_binding = connection.execute(
                select(repository_asset_bindings).where(
                    repository_asset_bindings.c.organization_id == organization_id,
                    repository_asset_bindings.c.engagement_id == engagement_id,
                    repository_asset_bindings.c.asset_id == asset_id,
                )
            ).first()
        if existing_binding:
            existing_binding = dict(existing_binding._mapping)
            if existing_binding["project_registry_id"] != project_registry_id:
                raise RepositorySnapshotError(
                    "repository_binding_conflict",
                    "Repository asset is already bound to another registered project.",
                )
            snapshot, _snapshot_path = self.snapshots.verify(
                organization_id, existing_binding["snapshot_id"]
            )
            if not snapshot:
                raise RepositorySnapshotError(
                    "snapshot_unavailable",
                    "The previously bound repository snapshot is unavailable.",
                )
            created_snapshot = False
        else:
            snapshot = self.snapshots.create(
                organization_id, root, actor_user_id=user_id, engagement_id=engagement_id
            )
            created_snapshot = True
        now = now_iso()
        attestation_id, binding_id = str(uuid.uuid4()), str(uuid.uuid4())
        try:
            with self.engine.connect() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    self._validate_binding_connection(
                        connection,
                        user_id,
                        organization_id,
                        engagement_id,
                        asset_id,
                        authorization_id,
                        scope_revision_id,
                    )
                    if not existing_binding:
                        connection.execute(
                            repository_asset_bindings.insert().values(
                                id=binding_id,
                                organization_id=organization_id,
                                engagement_id=engagement_id,
                                asset_id=asset_id,
                                project_registry_id=project_registry_id,
                                source_kind="local_project_registry",
                                snapshot_id=snapshot["id"],
                                snapshot_sha256=snapshot["sha256"],
                                created_by=user_id,
                                created_at=now,
                                display_label=label[:120],
                            )
                        )
                    else:
                        binding_id = existing_binding["id"]
                    connection.execute(
                        repository_attestations.insert().values(
                            id=attestation_id,
                            organization_id=organization_id,
                            engagement_id=engagement_id,
                            asset_id=asset_id,
                            authorization_id=authorization_id,
                            scope_revision_id=scope_revision_id,
                            actor_user_id=user_id,
                            attestation_version=ATTESTATION_VERSION,
                            attestation_text=ATTESTATION_TEXT,
                            created_at=now,
                        )
                    )
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "repository.asset_bound",
                        "asset",
                        asset_id,
                        details={
                            "binding_id": binding_id,
                            "snapshot_id": snapshot["id"],
                            "snapshot_sha256": snapshot["sha256"],
                            "authorization_id": authorization_id,
                            "scope_revision_id": scope_revision_id,
                            "attestation_id": attestation_id,
                        },
                    )
                    self.security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "repository.attested",
                        "repository_attestation",
                        attestation_id,
                        details={
                            "asset_id": asset_id,
                            "authorization_id": authorization_id,
                            "scope_revision_id": scope_revision_id,
                            "attestation_version": ATTESTATION_VERSION,
                        },
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    if created_snapshot:
                        self.snapshots.remove_unreferenced(organization_id, snapshot["id"])
                    raise
        except Exception:
            raise
        return self.get_asset(user_id, organization_id, engagement_id, asset_id)

    def _validate_binding(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        authorization_id: str,
        scope_revision_id: str,
    ) -> None:
        with self.engine.connect() as connection:
            self._validate_binding_connection(
                connection,
                user_id,
                organization_id,
                engagement_id,
                asset_id,
                authorization_id,
                scope_revision_id,
            )

    def _validate_binding_connection(
        self,
        connection: Any,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        authorization_id: str,
        scope_revision_id: str,
    ) -> None:
        if not self._is_lead_connection(connection, user_id, organization_id, engagement_id):
            raise RepositorySnapshotError(
                "engagement_lead_required", "An active engagement lead assignment is required."
            )
        engagement = connection.execute(
            select(engagements).where(
                engagements.c.id == engagement_id,
                engagements.c.organization_id == organization_id,
                engagements.c.status == "active",
            )
        ).first()
        org = connection.execute(
            select(organizations.c.id).where(
                organizations.c.id == organization_id, organizations.c.status == "active"
            )
        ).first()
        user = connection.execute(
            select(users.c.id).where(users.c.id == user_id, users.c.status == "active")
        ).first()
        asset = connection.execute(
            select(engagement_assets).where(
                engagement_assets.c.id == asset_id,
                engagement_assets.c.organization_id == organization_id,
                engagement_assets.c.engagement_id == engagement_id,
                engagement_assets.c.asset_type == "repository",
                engagement_assets.c.status == "active",
            )
        ).first()
        scope = connection.execute(
            select(scope_revisions).where(
                scope_revisions.c.id == scope_revision_id,
                scope_revisions.c.organization_id == organization_id,
                scope_revisions.c.engagement_id == engagement_id,
                scope_revisions.c.status == "published",
            )
        ).first()
        latest = self.security._latest_published_scope(connection, organization_id, engagement_id)
        auth = connection.execute(
            select(authorization_records).where(
                authorization_records.c.id == authorization_id,
                authorization_records.c.organization_id == organization_id,
                authorization_records.c.engagement_id == engagement_id,
                authorization_records.c.scope_revision_id == scope_revision_id,
                authorization_records.c.status == "active",
            )
        ).first()
        if (
            not all((engagement, org, user, asset, scope, latest, auth))
            or latest is None
            or latest["id"] != scope_revision_id
        ):
            raise RepositorySnapshotError(
                "repository_binding_invalid",
                "Repository, engagement, scope, or authorization is unavailable.",
            )
        authorization = dict(auth._mapping)
        if (
            REPOSITORY_TECHNIQUE not in authorization["permitted_techniques"]
            or _utc(authorization["effective_at"]) > datetime.now(UTC)
            or _utc(authorization["expires_at"]) <= datetime.now(UTC)
        ):
            raise RepositorySnapshotError(
                "repository_authorization_invalid",
                "Authorization must be active, current, and cover code assessment.",
            )
        rules = connection.execute(
            select(scope_rules).where(
                scope_rules.c.organization_id == organization_id,
                scope_rules.c.scope_revision_id == scope_revision_id,
                scope_rules.c.asset_id == asset_id,
            )
        ).all()
        allowed = any(
            row.effect == "include"
            and row.match_mode == "exact"
            and REPOSITORY_TECHNIQUE in row.techniques
            for row in rules
        )
        excluded = any(
            row.effect == "exclude"
            and row.match_mode == "exact"
            and (not row.techniques or REPOSITORY_TECHNIQUE in row.techniques)
            for row in rules
        )
        if not allowed or excluded:
            raise RepositorySnapshotError(
                "repository_out_of_scope",
                "The current published scope does not include this repository for code assessment.",
            )

    def _is_lead(self, user_id: str, organization_id: str, engagement_id: str) -> bool:
        with self.engine.connect() as connection:
            return self._is_lead_connection(connection, user_id, organization_id, engagement_id)

    @staticmethod
    def _is_lead_connection(
        connection: Any,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        *,
        require_active_engagement: bool = True,
    ) -> bool:
        return bool(
            connection.execute(
                select(engagement_assignments.c.id)
                .join(
                    organization_memberships,
                    (
                        organization_memberships.c.organization_id
                        == engagement_assignments.c.organization_id
                    )
                    & (organization_memberships.c.user_id == engagement_assignments.c.user_id),
                )
                .join(organizations, organizations.c.id == engagement_assignments.c.organization_id)
                .join(
                    engagements,
                    (engagements.c.id == engagement_assignments.c.engagement_id)
                    & (engagements.c.organization_id == engagement_assignments.c.organization_id),
                )
                .join(users, users.c.id == engagement_assignments.c.user_id)
                .where(
                    engagement_assignments.c.user_id == user_id,
                    engagement_assignments.c.organization_id == organization_id,
                    engagement_assignments.c.engagement_id == engagement_id,
                    engagement_assignments.c.role == "lead",
                    engagement_assignments.c.status == "active",
                    organization_memberships.c.status == "active",
                    organization_memberships.c.role.in_(("owner", "admin", "member")),
                    organizations.c.status == "active",
                    users.c.status == "active",
                    *([engagements.c.status == "active"] if require_active_engagement else []),
                )
            ).first()
        )

    def list_assets(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self.security._can_read(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(
                    engagement_assets.c.id,
                    engagement_assets.c.organization_id,
                    engagement_assets.c.engagement_id,
                    engagement_assets.c.description,
                    engagement_assets.c.status,
                    engagement_assets.c.created_at,
                    engagement_assets.c.updated_at,
                    repository_asset_bindings.c.id.label("binding_id"),
                    repository_asset_bindings.c.snapshot_id,
                    repository_asset_bindings.c.snapshot_sha256,
                    repository_snapshots.c.size_bytes,
                    repository_snapshots.c.manifest_version,
                    repository_snapshots.c.scanner_version,
                    repository_snapshots.c.created_at.label("snapshot_created_at"),
                    repository_snapshots.c.status.label("snapshot_status"),
                    repository_snapshots.c.delete_after,
                    repository_snapshots.c.legal_hold,
                    repository_attestations.c.id.label("attestation_id"),
                    repository_attestations.c.authorization_id,
                    repository_attestations.c.scope_revision_id,
                    repository_attestations.c.attestation_version,
                    repository_attestations.c.created_at.label("attested_at"),
                )
                .outerjoin(
                    repository_asset_bindings,
                    (repository_asset_bindings.c.asset_id == engagement_assets.c.id)
                    & (repository_asset_bindings.c.organization_id == organization_id),
                )
                .outerjoin(
                    repository_snapshots,
                    repository_snapshots.c.id == repository_asset_bindings.c.snapshot_id,
                )
                .outerjoin(
                    repository_attestations,
                    (repository_attestations.c.asset_id == engagement_assets.c.id)
                    & (repository_attestations.c.organization_id == organization_id),
                )
                .where(
                    engagement_assets.c.organization_id == organization_id,
                    engagement_assets.c.engagement_id == engagement_id,
                    engagement_assets.c.asset_type == "repository",
                )
            ).all()
            result = []
            for row in rows:
                item = dict(row._mapping)
                # Paths, manifests, and source project identifiers are private server data.
                result.append(
                    {
                        k: item.get(k)
                        for k in (
                            "id",
                            "organization_id",
                            "engagement_id",
                            "description",
                            "status",
                            "created_at",
                            "updated_at",
                            "binding_id",
                            "snapshot_id",
                            "snapshot_sha256",
                            "size_bytes",
                            "manifest_version",
                            "scanner_version",
                            "snapshot_created_at",
                            "snapshot_status",
                            "delete_after",
                            "legal_hold",
                            "attestation_id",
                            "authorization_id",
                            "scope_revision_id",
                            "attestation_version",
                            "attested_at",
                        )
                    }
                )
            return result

    def retention_candidates(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self.security._can_read(connection, user_id, organization_id, engagement_id):
                return None
        now = now_iso()
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(repository_snapshots)
                .join(
                    repository_asset_bindings,
                    (repository_asset_bindings.c.snapshot_id == repository_snapshots.c.id)
                    & (
                        repository_asset_bindings.c.organization_id
                        == repository_snapshots.c.organization_id
                    ),
                )
                .where(
                    repository_asset_bindings.c.organization_id == organization_id,
                    repository_asset_bindings.c.engagement_id == engagement_id,
                )
                .distinct()
            ).all()
            results = []
            for row in rows:
                if row.legal_hold:
                    state = "held"
                elif not row.delete_after:
                    state = "engagement_active"
                elif row.delete_after > now:
                    state = "retained"
                else:
                    digest_ids = (
                        connection.execute(
                            select(repository_snapshots.c.id).where(
                                repository_snapshots.c.organization_id == organization_id,
                                repository_snapshots.c.sha256 == row.sha256,
                                repository_snapshots.c.status != "deleted",
                            )
                        )
                        .scalars()
                        .all()
                    )
                    active_job = (
                        connection.execute(
                            select(execution_jobs.c.id).where(
                                execution_jobs.c.organization_id == organization_id,
                                execution_jobs.c.repository_snapshot_id.in_(digest_ids),
                                execution_jobs.c.status.in_(("queued", "claimed", "running")),
                            )
                        ).first()
                        if digest_ids
                        else None
                    )
                    open_binding = (
                        connection.execute(
                            select(repository_asset_bindings.c.id)
                            .join(
                                engagements,
                                (engagements.c.id == repository_asset_bindings.c.engagement_id)
                                & (
                                    engagements.c.organization_id
                                    == repository_asset_bindings.c.organization_id
                                ),
                            )
                            .where(
                                repository_asset_bindings.c.organization_id == organization_id,
                                repository_asset_bindings.c.snapshot_id.in_(digest_ids),
                                engagements.c.status.notin_(("completed", "archived")),
                            )
                        ).first()
                        if digest_ids
                        else None
                    )
                    state = (
                        "job_active"
                        if active_job
                        else ("engagement_active" if open_binding else "eligible")
                    )
                results.append(
                    {
                        "snapshot_id": row.id,
                        "status": row.status,
                        "size_bytes": row.size_bytes,
                        "created_at": row.created_at,
                        "delete_after": row.delete_after,
                        "legal_hold": bool(row.legal_hold),
                        "retention_state": state,
                    }
                )
            return results

    def get_asset(
        self, user_id: str, organization_id: str, engagement_id: str, asset_id: str
    ) -> dict[str, Any] | None:
        items = self.list_assets(user_id, organization_id, engagement_id)
        return next((item for item in items or [] if item["id"] == asset_id), None)

    def quota(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> dict[str, int] | None:
        if not self._is_lead(user_id, organization_id, engagement_id):
            return None
        with self.engine.connect() as connection:
            used_rows = connection.execute(
                select(
                    repository_snapshots.c.sha256,
                    repository_snapshots.c.size_bytes,
                ).where(
                    repository_snapshots.c.organization_id == organization_id,
                    repository_snapshots.c.status != "deleted",
                )
            ).all()
            used = sum({row.sha256: int(row.size_bytes) for row in used_rows}.values())
            reserved = connection.execute(
                select(
                    func.coalesce(func.sum(repository_quota_reservations.c.reserved_bytes), 0)
                ).where(repository_quota_reservations.c.organization_id == organization_id)
            ).scalar_one()
        return {
            "used_bytes": int(used),
            "reserved_bytes": int(reserved),
            "organization_limit_bytes": self.snapshots.organization_quota_bytes,
            "snapshot_limit_bytes": self.snapshots.max_snapshot_bytes,
            "available_bytes": max(
                0, self.snapshots.organization_quota_bytes - int(used) - int(reserved)
            ),
        }

    def _is_lead_connection_allowed_closed(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> bool:
        with self.engine.connect() as connection:
            return self._is_lead_connection(
                connection,
                user_id,
                organization_id,
                engagement_id,
                require_active_engagement=False,
            )
