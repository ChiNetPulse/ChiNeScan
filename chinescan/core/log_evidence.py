"""Tenant-scoped immutable snapshots for governed local log analysis."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select, update

from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.logging.redaction import redact
from chinescan.core.organizations import now_iso
from chinescan.core.storage.security import is_reparse_or_link, secure_snapshot_directory
from chinescan.core.storage.sqlite import (
    assessment_audit_events,
    engagement_assets,
    engagements,
    execution_jobs,
    log_evidence_quota_reservations,
    log_evidence_snapshots,
    organizations,
)
from chinescan.log_analysis.ingest import (
    MAX_FILE_BYTES,
    MAX_LOG_FILES,
    MAX_TOTAL_BYTES,
    _supported,
)

MANIFEST_VERSION = 1
MAX_ORGANIZATION_EVIDENCE_BYTES = 2_000_000_000
MAX_EVIDENCE_DEPTH = 32
_IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}


class LogEvidenceError(ValueError):
    """Safe governed-evidence error with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical(value: Any) -> bytes:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return serialized.encode("utf-8")


class LogEvidenceStore:
    """Snapshots approved local log inputs without persisting their source path."""

    def __init__(
        self,
        repository: Any,
        root: Path,
        *,
        allowed_roots: list[Path],
        max_snapshot_bytes: int = MAX_TOTAL_BYTES,
        organization_quota_bytes: int = MAX_ORGANIZATION_EVIDENCE_BYTES,
    ) -> None:
        self.repository = repository
        self.engine = repository.engine
        self.root = secure_snapshot_directory(root.expanduser().absolute())
        self.allowed_roots = tuple(
            path.expanduser().resolve(strict=False) for path in allowed_roots
        )
        if not 0 < max_snapshot_bytes <= MAX_TOTAL_BYTES:
            raise ValueError("log evidence snapshot limit is invalid")
        if max_snapshot_bytes > organization_quota_bytes:
            raise ValueError("log evidence quota is smaller than the snapshot limit")
        self.max_snapshot_bytes = max_snapshot_bytes
        self.organization_quota_bytes = organization_quota_bytes

    def _org_root(self, organization_id: str) -> Path:
        if len(organization_id) != 36 or any(c not in "0123456789abcdef-" for c in organization_id):
            raise LogEvidenceError("evidence_identity_invalid")
        root = self.root.resolve(strict=True)
        if is_reparse_or_link(self.root) or not root.is_dir():
            raise LogEvidenceError("evidence_storage_unavailable")
        candidate = root / organization_id
        if candidate.exists():
            if is_reparse_or_link(candidate) or candidate.resolve(strict=True).parent != root:
                raise LogEvidenceError("evidence_storage_unsafe")
        else:
            candidate.mkdir(mode=0o700)
            candidate = secure_snapshot_directory(candidate)
        return candidate

    def _path(self, organization_id: str, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise LogEvidenceError("evidence_identity_invalid")
        base = self._org_root(organization_id)
        path = base / digest
        if (path.exists() or path.is_symlink()) and is_reparse_or_link(path):
            raise LogEvidenceError("evidence_storage_unsafe")
        return path

    def _inventory(self, source: Path) -> tuple[Path, list[dict[str, Any]], int, str]:
        try:
            expanded = source.expanduser().absolute()
            if any(
                (candidate.exists() or candidate.is_symlink()) and is_reparse_or_link(candidate)
                for candidate in (expanded, *expanded.parents)
            ):
                raise LogEvidenceError("evidence_source_unsafe")
            root = expanded.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LogEvidenceError("evidence_source_unavailable") from exc
        if not any(root == allowed or allowed in root.parents for allowed in self.allowed_roots):
            raise LogEvidenceError("evidence_source_outside_allowed_roots")
        if not root.is_file() and not root.is_dir():
            raise LogEvidenceError("evidence_source_invalid")
        candidates: list[Path] = []
        if root.is_file():
            candidates = [root]
        else:
            for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
                current = Path(directory)
                current_depth = len(current.relative_to(root).parts)
                if current_depth >= MAX_EVIDENCE_DEPTH and dirs:
                    raise LogEvidenceError("evidence_path_depth_limit")
                for name in dirs:
                    child = current / name
                    if is_reparse_or_link(child):
                        raise LogEvidenceError("evidence_source_unsafe")
                dirs[:] = sorted(name for name in dirs if name not in _IGNORED_DIRS)
                for name in sorted(files):
                    child = current / name
                    if is_reparse_or_link(child):
                        raise LogEvidenceError("evidence_source_unsafe")
                    if _supported(name):
                        candidates.append(child)
                        if len(candidates) > min(MAX_LOG_FILES, 10_000):
                            raise LogEvidenceError("evidence_file_count_limit")
        if not candidates or len(candidates) > min(MAX_LOG_FILES, 10_000):
            raise LogEvidenceError("evidence_file_count_limit")
        entries: list[dict[str, Any]] = []
        total = 0
        for path in candidates:
            try:
                relative = path.name if root.is_file() else path.relative_to(root).as_posix()
                relative_path = PurePosixPath(relative)
                if (
                    relative_path.is_absolute()
                    or any(part in {"", ".", ".."} for part in relative_path.parts)
                    or len(relative_path.parts) > MAX_EVIDENCE_DEPTH
                    or "\\" in relative
                ):
                    raise LogEvidenceError("evidence_path_invalid")
                info = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                    raise LogEvidenceError("evidence_file_size_limit")
                file_digest = hashlib.sha256()
                size = 0
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_FILE_BYTES or total > min(
                            self.max_snapshot_bytes, MAX_TOTAL_BYTES
                        ):
                            raise LogEvidenceError("evidence_total_size_limit")
                        file_digest.update(chunk)
                entries.append(
                    {
                        "path": relative_path.as_posix(),
                        "size_bytes": size,
                        "sha256": file_digest.hexdigest(),
                    }
                )
            except LogEvidenceError:
                raise
            except (OSError, ValueError) as exc:
                raise LogEvidenceError("evidence_source_read_failed") from exc
        entries.sort(key=lambda item: item["path"].encode("utf-8"))
        manifest = {"manifest_version": MANIFEST_VERSION, "entries": entries}
        return root, entries, total, hashlib.sha256(_canonical(manifest)).hexdigest()

    def register(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        source: Path,
        label: str,
        security: EngagementSecurityService,
    ) -> dict[str, Any] | None:
        if not label.strip() or len(label) > 120:
            raise LogEvidenceError("evidence_label_invalid")
        with self.engine.connect() as connection:
            if not security._can_operate(connection, user_id, organization_id, engagement_id):
                return None
            engagement = security._engagement(connection, organization_id, engagement_id)
            if not engagement or engagement["status"] != "active":
                return None
        root, entries, size_bytes, digest = self._inventory(source)
        reservation_id = str(uuid4())
        reserved_at = now_iso()
        reservation_expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                expired = connection.execute(
                    select(
                        log_evidence_quota_reservations.c.id,
                        log_evidence_quota_reservations.c.reserved_bytes,
                    ).where(
                        log_evidence_quota_reservations.c.organization_id == organization_id,
                        log_evidence_quota_reservations.c.expires_at <= reserved_at,
                    )
                ).all()
                connection.execute(
                    log_evidence_quota_reservations.delete().where(
                        log_evidence_quota_reservations.c.organization_id == organization_id,
                        log_evidence_quota_reservations.c.expires_at <= reserved_at,
                    )
                )
                for expired_row in expired:
                    security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "log_evidence.quota_reservation_expired",
                        "log_evidence_quota_reservation",
                        str(expired_row.id),
                        details={"reserved_bytes": int(expired_row.reserved_bytes)},
                    )
                active = connection.execute(
                    select(
                        log_evidence_snapshots.c.sha256,
                        func.max(log_evidence_snapshots.c.size_bytes),
                    )
                    .where(
                        log_evidence_snapshots.c.organization_id == organization_id,
                        log_evidence_snapshots.c.status != "deleted",
                    )
                    .group_by(log_evidence_snapshots.c.sha256)
                ).all()
                used = sum(int(row[1]) for row in active)
                reserved = int(
                    connection.execute(
                        select(
                            func.coalesce(
                                func.sum(log_evidence_quota_reservations.c.reserved_bytes), 0
                            )
                        ).where(
                            log_evidence_quota_reservations.c.organization_id == organization_id,
                            log_evidence_quota_reservations.c.expires_at > reserved_at,
                        )
                    ).scalar_one()
                )
                duplicate = any(row[0] == digest for row in active)
                reserve_bytes = 0 if duplicate else size_bytes
                if used + reserved + reserve_bytes > self.organization_quota_bytes:
                    raise LogEvidenceError("evidence_organization_quota_exceeded")
                connection.execute(
                    log_evidence_quota_reservations.insert().values(
                        id=reservation_id,
                        organization_id=organization_id,
                        reserved_bytes=reserve_bytes,
                        created_at=reserved_at,
                        expires_at=reservation_expires,
                    )
                )
                security._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "log_evidence.quota_reserved",
                    "log_evidence_quota_reservation",
                    reservation_id,
                    details={"reserved_bytes": reserve_bytes, "sha256": digest},
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        stage: Path | None = None
        destination = self._path(organization_id, digest)
        content_created = False
        try:
            if destination.exists():
                if not self._verify_content(
                    destination,
                    {"manifest_version": MANIFEST_VERSION, "entries": entries},
                    digest,
                    size_bytes,
                ):
                    raise LogEvidenceError("evidence_existing_snapshot_corrupt")
            else:
                org_root = self._org_root(organization_id)
                stage = Path(tempfile.mkdtemp(prefix=".log-stage-", dir=org_root))
                secure_snapshot_directory(stage)
                copied_so_far = 0
                for entry in entries:
                    source_path = root if root.is_file() else root / PurePosixPath(entry["path"])
                    target_path = stage / PurePosixPath(entry["path"])
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    if is_reparse_or_link(source_path):
                        raise LogEvidenceError("evidence_source_unsafe")
                    file_digest = hashlib.sha256()
                    copied_size = 0
                    with (
                        source_path.open("rb") as source_stream,
                        target_path.open("xb") as target_stream,
                    ):
                        while chunk := source_stream.read(1024 * 1024):
                            copied_size += len(chunk)
                            if (
                                copied_size > MAX_FILE_BYTES
                                or copied_size > entry["size_bytes"]
                                or copied_size + copied_so_far
                                > min(self.max_snapshot_bytes, MAX_TOTAL_BYTES)
                            ):
                                raise LogEvidenceError("evidence_source_changed")
                            target_stream.write(chunk)
                            file_digest.update(chunk)
                        target_stream.flush()
                        os.fsync(target_stream.fileno())
                    copied_so_far += copied_size
                    if (
                        copied_size != entry["size_bytes"]
                        or file_digest.hexdigest() != entry["sha256"]
                    ):
                        raise LogEvidenceError("evidence_source_changed")
                if copied_so_far != size_bytes:
                    raise LogEvidenceError("evidence_source_changed")
                copied_manifest = {"manifest_version": MANIFEST_VERSION, "entries": entries}
                if hashlib.sha256(_canonical(copied_manifest)).hexdigest() != digest:
                    raise LogEvidenceError("evidence_manifest_mismatch")
                try:
                    os.replace(stage, destination)
                    content_created = True
                except OSError:
                    # Another registration may have published the same content digest.
                    if not self._verify_content(
                        destination,
                        {"manifest_version": MANIFEST_VERSION, "entries": entries},
                        digest,
                        size_bytes,
                    ):
                        raise LogEvidenceError("evidence_snapshot_publish_failed") from None
                finally:
                    if stage and stage.exists():
                        shutil.rmtree(stage, ignore_errors=True)
                    stage = None
            snapshot_id, asset_id, now = str(uuid4()), str(uuid4()), now_iso()
            target = f"log:{asset_id}"
            source_format = _source_format(root, entries)
            manifest = {"manifest_version": MANIFEST_VERSION, "entries": entries}
            with self.engine.connect() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    if not security._can_operate(
                        connection, user_id, organization_id, engagement_id
                    ):
                        connection.rollback()
                        raise LogEvidenceError("evidence_registration_forbidden")
                    org = connection.execute(
                        select(organizations.c.id).where(
                            organizations.c.id == organization_id,
                            organizations.c.status == "active",
                        )
                    ).first()
                    engagement = connection.execute(
                        select(engagements.c.id).where(
                            engagements.c.id == engagement_id,
                            engagements.c.organization_id == organization_id,
                            engagements.c.status == "active",
                        )
                    ).first()
                    if not org or not engagement:
                        connection.rollback()
                        raise LogEvidenceError("evidence_registration_forbidden")
                    connection.execute(
                        engagement_assets.insert().values(
                            id=asset_id,
                            organization_id=organization_id,
                            client_id=None,
                            engagement_id=engagement_id,
                            asset_type="log_evidence",
                            target=target,
                            description=redact(label.strip())[:120],
                            status="active",
                            created_by=user_id,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                    connection.execute(
                        log_evidence_snapshots.insert().values(
                            id=snapshot_id,
                            organization_id=organization_id,
                            engagement_id=engagement_id,
                            asset_id=asset_id,
                            registered_by=user_id,
                            source_format=source_format,
                            label=redact(label.strip())[:120],
                            sha256=digest,
                            size_bytes=size_bytes,
                            file_count=len(entries),
                            manifest=manifest,
                            manifest_version=MANIFEST_VERSION,
                            created_at=now,
                            status="available",
                            legal_hold=0,
                            hold_reason=None,
                            deleted_at=None,
                        )
                    )
                    connection.execute(
                        log_evidence_quota_reservations.delete().where(
                            log_evidence_quota_reservations.c.id == reservation_id
                        )
                    )
                    security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "log_evidence.quota_reservation_released",
                        "log_evidence_quota_reservation",
                        reservation_id,
                        details={"reserved_bytes": reserve_bytes, "outcome": "committed"},
                    )
                    security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "log_evidence.registered",
                        "log_evidence",
                        snapshot_id,
                        details={
                            "asset_id": asset_id,
                            "sha256": digest,
                            "size_bytes": size_bytes,
                            "file_count": len(entries),
                            "source_format": source_format,
                        },
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            return {
                "asset_id": asset_id,
                "snapshot_id": snapshot_id,
                "target": target,
                "label": redact(label.strip())[:120],
                "source_format": source_format,
                "sha256": digest,
                "size_bytes": size_bytes,
                "file_count": len(entries),
                "status": "available",
                "retention": "retained_until_explicit_authorized_deletion",
            }
        except Exception:
            with self.engine.begin() as connection:
                reservation = connection.execute(
                    select(log_evidence_quota_reservations.c.reserved_bytes).where(
                        log_evidence_quota_reservations.c.id == reservation_id
                    )
                ).scalar_one_or_none()
                if reservation is not None:
                    connection.execute(
                        log_evidence_quota_reservations.delete().where(
                            log_evidence_quota_reservations.c.id == reservation_id
                        )
                    )
                    security._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        user_id,
                        "log_evidence.quota_reservation_released",
                        "log_evidence_quota_reservation",
                        reservation_id,
                        details={"reserved_bytes": int(reservation), "outcome": "failed"},
                    )
            if stage and stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            if content_created:
                self._remove_if_unreferenced(organization_id, digest)
            raise

    def verify(
        self, organization_id: str, engagement_id: str, asset_id: str, snapshot_id: str
    ) -> tuple[dict[str, Any] | None, Path | None]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(log_evidence_snapshots).where(
                    log_evidence_snapshots.c.id == snapshot_id,
                    log_evidence_snapshots.c.organization_id == organization_id,
                    log_evidence_snapshots.c.engagement_id == engagement_id,
                    log_evidence_snapshots.c.asset_id == asset_id,
                    log_evidence_snapshots.c.status == "available",
                )
            ).first()
            if row is None:
                return None, None
            item = dict(row._mapping)
        path = self._path(organization_id, item["sha256"])
        try:
            valid = self._verify_content(path, item["manifest"], item["sha256"], item["size_bytes"])
        except (OSError, LogEvidenceError):
            valid = False
        if not valid:
            with self.engine.begin() as connection:
                connection.execute(
                    update(log_evidence_snapshots)
                    .where(
                        log_evidence_snapshots.c.id == snapshot_id,
                        log_evidence_snapshots.c.organization_id == organization_id,
                        log_evidence_snapshots.c.status == "available",
                    )
                    .values(status="corrupt" if path.exists() else "missing")
                )
                connection.execute(
                    assessment_audit_events.insert().values(
                        id=str(uuid4()),
                        organization_id=organization_id,
                        engagement_id=engagement_id,
                        actor_user_id=item["registered_by"],
                        action="log_evidence.integrity_failed",
                        resource_type="log_evidence",
                        resource_id=snapshot_id,
                        decision="DENY",
                        reason_code="LOG_EVIDENCE_INTEGRITY_FAILED",
                        occurred_at=now_iso(),
                        details={"asset_id": asset_id, "sha256": item["sha256"]},
                    )
                )
            return None, None
        return item, path

    def list_for(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        security: EngagementSecurityService,
    ) -> list[dict[str, Any]] | None:
        """Return path-free evidence metadata only to an active assigned operator."""
        with self.engine.connect() as connection:
            if not security._can_operate(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(
                    log_evidence_snapshots.c.id,
                    log_evidence_snapshots.c.asset_id,
                    log_evidence_snapshots.c.source_format,
                    log_evidence_snapshots.c.label,
                    log_evidence_snapshots.c.sha256,
                    log_evidence_snapshots.c.size_bytes,
                    log_evidence_snapshots.c.file_count,
                    log_evidence_snapshots.c.manifest_version,
                    log_evidence_snapshots.c.created_at,
                    log_evidence_snapshots.c.status,
                    log_evidence_snapshots.c.legal_hold,
                    engagements.c.status.label("engagement_status"),
                )
                .join(
                    engagements,
                    (engagements.c.id == log_evidence_snapshots.c.engagement_id)
                    & (engagements.c.organization_id == log_evidence_snapshots.c.organization_id),
                )
                .where(
                    log_evidence_snapshots.c.organization_id == organization_id,
                    log_evidence_snapshots.c.engagement_id == engagement_id,
                )
                .order_by(log_evidence_snapshots.c.created_at.desc())
            ).all()
        items = []
        for row in rows:
            item = dict(row._mapping)
            item["snapshot_id"] = item.pop("id")
            item["legal_hold"] = bool(item["legal_hold"])
            item["retention"] = "retained_until_explicit_authorized_deletion"
            item["deletion_eligible"] = (
                item["status"] == "available"
                and item["engagement_status"] in {"completed", "archived"}
                and not item["legal_hold"]
                and not self._has_active_job(item["snapshot_id"])
            )
            item.pop("engagement_status", None)
            items.append(item)
        return items

    def _has_active_job(self, snapshot_id: str) -> bool:
        with self.engine.connect() as connection:
            return (
                connection.execute(
                    select(execution_jobs.c.id).where(
                        execution_jobs.c.log_evidence_snapshot_id == snapshot_id,
                        execution_jobs.c.status.in_(("queued", "claimed", "running")),
                    )
                ).first()
                is not None
            )

    def _snapshot_id_for_asset(
        self, organization_id: str, engagement_id: str, asset_id: str
    ) -> str | None:
        with self.engine.connect() as connection:
            result = connection.execute(
                select(log_evidence_snapshots.c.id).where(
                    log_evidence_snapshots.c.organization_id == organization_id,
                    log_evidence_snapshots.c.engagement_id == engagement_id,
                    log_evidence_snapshots.c.asset_id == asset_id,
                )
            ).scalar_one_or_none()
            return str(result) if result is not None else None

    def place_hold_for_asset(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        reason: str,
        security: EngagementSecurityService,
    ) -> bool:
        snapshot_id = self._snapshot_id_for_asset(organization_id, engagement_id, asset_id)
        if snapshot_id is None:
            return False
        return self.place_hold(
            user_id, organization_id, engagement_id, snapshot_id, reason, security
        )

    def delete_asset(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        security: EngagementSecurityService,
    ) -> bool:
        snapshot_id = self._snapshot_id_for_asset(organization_id, engagement_id, asset_id)
        if snapshot_id is None:
            return False
        return self.delete_explicitly(
            user_id, organization_id, engagement_id, snapshot_id, security
        )

    def place_hold(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        snapshot_id: str,
        reason: str,
        security: EngagementSecurityService,
    ) -> bool:
        if not reason.strip() or len(reason) > 500:
            raise LogEvidenceError("evidence_hold_reason_invalid")
        with self.engine.begin() as connection:
            if not security._can_manage(connection, user_id, organization_id, engagement_id):
                return False
            row = connection.execute(
                select(log_evidence_snapshots).where(
                    log_evidence_snapshots.c.id == snapshot_id,
                    log_evidence_snapshots.c.organization_id == organization_id,
                    log_evidence_snapshots.c.engagement_id == engagement_id,
                )
            ).first()
            if not row or row.status == "deleted":
                return False
            connection.execute(
                update(log_evidence_snapshots)
                .where(
                    log_evidence_snapshots.c.id == snapshot_id,
                    log_evidence_snapshots.c.organization_id == organization_id,
                )
                .values(legal_hold=1, hold_reason=redact(reason.strip())[:500])
            )
            security._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "log_evidence.hold_placed",
                "log_evidence",
                snapshot_id,
                details={"reason": redact(reason.strip())[:200]},
            )
            return True

    def delete_explicitly(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        snapshot_id: str,
        security: EngagementSecurityService,
    ) -> bool:
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                if not security._can_manage(connection, user_id, organization_id, engagement_id):
                    connection.rollback()
                    return False
                row = connection.execute(
                    select(log_evidence_snapshots).where(
                        log_evidence_snapshots.c.id == snapshot_id,
                        log_evidence_snapshots.c.organization_id == organization_id,
                        log_evidence_snapshots.c.engagement_id == engagement_id,
                    )
                ).first()
                if not row or row.status != "available" or row.legal_hold:
                    connection.rollback()
                    return False
                engagement = connection.execute(
                    select(engagements.c.status).where(
                        engagements.c.id == engagement_id,
                        engagements.c.organization_id == organization_id,
                    )
                ).scalar_one_or_none()
                if engagement not in {"completed", "archived"}:
                    connection.rollback()
                    return False
                active = connection.execute(
                    select(execution_jobs.c.id).where(
                        execution_jobs.c.log_evidence_snapshot_id == snapshot_id,
                        execution_jobs.c.status.in_(("queued", "claimed", "running")),
                    )
                ).first()
                if active:
                    connection.rollback()
                    return False
                connection.execute(
                    update(log_evidence_snapshots)
                    .where(
                        log_evidence_snapshots.c.id == snapshot_id,
                        log_evidence_snapshots.c.organization_id == organization_id,
                        log_evidence_snapshots.c.status == "available",
                        log_evidence_snapshots.c.legal_hold == 0,
                    )
                    .values(status="deleted", deleted_at=now_iso())
                )
                security._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "log_evidence.deletion_recorded",
                    "log_evidence",
                    snapshot_id,
                    details={"sha256": row.sha256, "size_bytes": row.size_bytes},
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        try:
            self._remove_if_unreferenced(organization_id, str(row.sha256))
        except (OSError, LogEvidenceError):
            with self.engine.begin() as connection:
                security._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "log_evidence.deletion_failed",
                    "log_evidence",
                    snapshot_id,
                    details={"sha256": row.sha256, "reason_code": "STORAGE_DELETE_FAILED"},
                )
            raise LogEvidenceError("evidence_storage_delete_failed") from None
        return True

    def _remove_if_unreferenced(self, organization_id: str, digest: str) -> None:
        with self.engine.connect() as connection:
            refs = connection.execute(
                select(log_evidence_snapshots.c.id).where(
                    log_evidence_snapshots.c.organization_id == organization_id,
                    log_evidence_snapshots.c.sha256 == digest,
                    log_evidence_snapshots.c.status == "available",
                )
            ).first()
        if refs:
            return
        path = self._path(organization_id, digest)
        if path.exists():
            org_root = self._org_root(organization_id).resolve(strict=True)
            if is_reparse_or_link(path) or path.resolve(strict=True).parent != org_root:
                raise LogEvidenceError("evidence_storage_unsafe")
            shutil.rmtree(path)

    @staticmethod
    def _verify_content(
        path: Path, manifest: dict[str, Any], digest: str, expected_size: int
    ) -> bool:
        if (
            not path.is_dir()
            or is_reparse_or_link(path)
            or not 0 <= expected_size <= MAX_TOTAL_BYTES
        ):
            return False
        if not isinstance(manifest, dict):
            return False
        entries = manifest.get("entries")
        if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_LOG_FILES:
            return False
        if hashlib.sha256(_canonical(manifest)).hexdigest() != digest:
            return False
        actual: dict[str, Path] = {}
        for directory, dirs, files in os.walk(path, topdown=True, followlinks=False):
            current = Path(directory)
            for name in dirs:
                child = current / name
                if is_reparse_or_link(child):
                    return False
            for name in files:
                child = current / name
                if is_reparse_or_link(child) or not child.is_file():
                    return False
                actual[child.relative_to(path).as_posix()] = child
                if len(actual) > MAX_LOG_FILES:
                    return False
        total = 0
        manifest_paths: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                return False
            relative = PurePosixPath(str(entry.get("path", "")))
            if (
                relative.is_absolute()
                or "\\" in str(entry.get("path", ""))
                or len(relative.parts) > MAX_EVIDENCE_DEPTH
                or any(part in {"", ".", ".."} for part in relative.parts)
                or isinstance(entry.get("size_bytes"), bool)
                or not isinstance(entry.get("size_bytes"), int)
                or not 0 <= entry["size_bytes"] <= MAX_FILE_BYTES
                or not isinstance(entry.get("sha256"), str)
                or len(entry["sha256"]) != 64
            ):
                return False
            normalized = relative.as_posix()
            if normalized in manifest_paths:
                return False
            manifest_paths.add(normalized)
            candidate = actual.get(normalized)
            if candidate is None:
                return False
            actual_size = candidate.stat(follow_symlinks=False).st_size
            if actual_size > MAX_FILE_BYTES or total + actual_size > expected_size:
                return False
            digest_reader = hashlib.sha256()
            with candidate.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest_reader.update(chunk)
            actual_digest = digest_reader.hexdigest()
            if actual_size != entry.get("size_bytes") or actual_digest != entry.get("sha256"):
                return False
            total += actual_size
        return total == expected_size and set(actual) == {str(entry["path"]) for entry in entries}


def _source_format(root: Path, entries: list[dict[str, Any]]) -> str:
    if root.is_file():
        name = root.name.casefold()
        return "tar.gz" if name.endswith(".tar.gz") else root.suffix.lower().lstrip(".")[:24]
    formats = sorted({Path(str(item["path"])).suffix.lower().lstrip(".") for item in entries})
    return formats[0] if len(formats) == 1 else "mixed"
