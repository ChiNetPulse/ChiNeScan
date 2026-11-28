"""Engagement asset, scope, authorization, approval, and policy services.

These services describe authorization decisions. They do not launch scanners or
grant permission to local CLI operations, which remain separately authorized.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import uuid4

from sqlalchemy import and_, func, select, update

from chinescan.core.organizations import OrganizationService, now_iso
from chinescan.core.storage.sqlite import (
    approval_requests,
    assessment_audit_events,
    authorization_documents,
    authorization_records,
    begin_immediate,
    clients,
    engagement_assets,
    engagement_assignments,
    engagements,
    log_evidence_snapshots,
    malware_evidence_snapshots,
    organization_memberships,
    organizations,
    repository_asset_bindings,
    repository_attestations,
    repository_snapshots,
    scope_revisions,
    scope_rules,
    users,
)
from chinescan.domain_assessment.authorization import AuthorizationError, normalize_hostname

MAX_SCOPE_RULES = 200
MAX_AUTHORIZATION_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_APPROVAL_TTL = timedelta(hours=24)
TECHNIQUE_CLASSES = {
    "dns_metadata": "passive",
    "http_metadata": "passive",
    "service_fingerprint": "controlled_active",
    "port_scan": "controlled_active",
    "vulnerability_probe": "controlled_active",
    "exploit_verification": "sensitive",
    "credential_testing": "sensitive",
    "destructive_test": "sensitive",
    "repository_code_assessment": "passive",
    "log_analysis": "passive",
    "malware_static_triage": "passive",
    "chain_trace_import": "passive",
    "chain_provider_lookup": "sensitive",
}
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


class EngagementSecurityError(ValueError):
    """Expected invalid or inaccessible engagement-security operation."""


def _utc(value: str | datetime) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise EngagementSecurityError("Timestamp must be a valid ISO 8601 value.") from exc
    if parsed.tzinfo is None:
        raise EngagementSecurityError("Timestamps must include a timezone.")
    return parsed.astimezone(UTC)


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize_target(asset_type: str, value: str) -> str:
    """Canonicalize a domain, IP, strict CIDR, or HTTP(S) URL without resolving it."""
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 2048:
        raise EngagementSecurityError("Target is empty, padded, or too long.")
    try:
        if asset_type == "domain":
            return normalize_hostname(value)
        if asset_type == "ip":
            if "%" in value or "/" in value:
                raise ValueError("IP address has a zone or network suffix")
            return ipaddress.ip_address(value).compressed.lower()
        if asset_type == "cidr":
            if "%" in value:
                raise ValueError("CIDR cannot contain a zone identifier")
            return str(ipaddress.ip_network(value, strict=True))
        if asset_type == "url":
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL must use HTTP or HTTPS and include a host")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("URL user information is not allowed")
            if parsed.query or parsed.fragment or "\\" in parsed.path:
                raise ValueError("URL query, fragment, and backslash paths are not accepted")
            if any(segment in {".", ".."} for segment in unquote(parsed.path).split("/")):
                raise ValueError("URL path traversal segments are not accepted")
            host = parsed.hostname
            try:
                if "%" in host:
                    raise ValueError("URL host zone identifiers are not accepted")
                normalized_host = ipaddress.ip_address(host).compressed.lower()
                if ":" in normalized_host:
                    normalized_host = f"[{normalized_host}]"
            except ValueError:
                normalized_host = normalize_hostname(host)
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("URL port is invalid")
            default_port = (parsed.scheme.lower() == "http" and port == 80) or (
                parsed.scheme.lower() == "https" and port == 443
            )
            authority = (
                normalized_host if port is None or default_port else f"{normalized_host}:{port}"
            )
            path = parsed.path or "/"
            return urlunsplit((parsed.scheme.lower(), authority, path, "", ""))
        if asset_type == "repository":
            match = re.fullmatch(
                r"repo:([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})",
                value,
                re.I,
            )
            if not match:
                raise ValueError("Repository targets must be opaque server-generated identifiers")
            return f"repo:{match.group(1).lower()}"
        if asset_type == "log_evidence":
            match = re.fullmatch(
                r"log:([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})",
                value,
                re.I,
            )
            if not match:
                raise ValueError("Log evidence targets must be opaque server-generated identifiers")
            return f"log:{match.group(1).lower()}"
        if asset_type == "malware_evidence":
            match = re.fullmatch(
                r"malware:([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})",
                value,
                re.I,
            )
            if not match:
                raise ValueError(
                    "Malware evidence targets must be opaque server-generated identifiers"
                )
            return f"malware:{match.group(1).lower()}"
        if asset_type == "chain_address":
            from chinescan.chain_trace.registry import CHAINS, normalize_address

            parts = value.split(":")
            if len(parts) != 4 or parts[0] != "chain" or parts[2] != "etherscan-v2":
                raise ValueError("Chain targets must use the configured Etherscan V2 provider")
            chain = CHAINS.get(parts[1])
            if not chain or chain.family != "evm" or not chain.chain_id:
                raise ValueError("Chain target is not supported by the configured provider")
            address = normalize_address(chain, parts[3])
            return f"chain:{chain.name}:etherscan-v2:{address}"
    except (ValueError, UnicodeError, AuthorizationError) as exc:
        raise EngagementSecurityError("Target is invalid for its declared asset type.") from exc
    raise EngagementSecurityError("Asset type is unsupported.")


def operation_digest(
    *,
    organization_id: str,
    engagement_id: str,
    requester_user_id: str,
    asset_type: str,
    target: str,
    technique: str,
    action_class: str,
    scope_revision_id: str,
    authorization_id: str,
) -> str:
    payload = {
        "organization_id": organization_id,
        "engagement_id": engagement_id,
        "requester_user_id": requester_user_id,
        "asset_type": asset_type,
        "target": target,
        "technique": technique,
        "action_class": action_class,
        "scope_revision_id": scope_revision_id,
        "authorization_id": authorization_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class EngagementSecurityService:
    def __init__(self, repository: Any, organizations_service: OrganizationService) -> None:
        self.repository = repository
        self.engine = repository.engine
        self.organizations = organizations_service

    def _membership(self, connection: Any, user_id: str, organization_id: str) -> str | None:
        result = connection.execute(
            select(organization_memberships.c.role)
            .join(organizations, organizations.c.id == organization_memberships.c.organization_id)
            .join(users, users.c.id == organization_memberships.c.user_id)
            .where(
                organization_memberships.c.organization_id == organization_id,
                organization_memberships.c.user_id == user_id,
                organization_memberships.c.status == "active",
                organizations.c.status == "active",
                users.c.status == "active",
            )
        ).scalar_one_or_none()
        return cast(str | None, result)

    def _assignment_roles(
        self, connection: Any, user_id: str, organization_id: str, engagement_id: str
    ) -> set[str]:
        return set(
            connection.execute(
                select(engagement_assignments.c.role)
                .join(
                    organization_memberships,
                    and_(
                        organization_memberships.c.organization_id
                        == engagement_assignments.c.organization_id,
                        organization_memberships.c.user_id == engagement_assignments.c.user_id,
                    ),
                )
                .join(engagements, engagements.c.id == engagement_assignments.c.engagement_id)
                .join(organizations, organizations.c.id == engagement_assignments.c.organization_id)
                .join(users, users.c.id == engagement_assignments.c.user_id)
                .where(
                    engagement_assignments.c.organization_id == organization_id,
                    engagement_assignments.c.engagement_id == engagement_id,
                    engagement_assignments.c.user_id == user_id,
                    engagement_assignments.c.status == "active",
                    organization_memberships.c.status == "active",
                    organizations.c.status == "active",
                    users.c.status == "active",
                )
            ).scalars()
        )

    def _engagement(
        self, connection: Any, organization_id: str, engagement_id: str
    ) -> dict[str, Any] | None:
        row = connection.execute(
            select(engagements).where(
                engagements.c.id == engagement_id,
                engagements.c.organization_id == organization_id,
            )
        ).first()
        return dict(row._mapping) if row else None

    def _can_manage(
        self, connection: Any, user_id: str, organization_id: str, engagement_id: str
    ) -> bool:
        role = self._membership(connection, user_id, organization_id)
        if role in {"owner", "admin"}:
            return True
        return role == "member" and "lead" in self._assignment_roles(
            connection, user_id, organization_id, engagement_id
        )

    def _can_read(
        self, connection: Any, user_id: str, organization_id: str, engagement_id: str
    ) -> bool:
        role = self._membership(connection, user_id, organization_id)
        if role is None:
            return False
        if role in {"owner", "admin", "auditor", "viewer"}:
            return True
        return bool(self._assignment_roles(connection, user_id, organization_id, engagement_id))

    def _can_operate(
        self, connection: Any, user_id: str, organization_id: str, engagement_id: str
    ) -> bool:
        role = self._membership(connection, user_id, organization_id)
        if role not in {"owner", "admin", "member"}:
            return False
        return bool(
            self._assignment_roles(connection, user_id, organization_id, engagement_id)
            & {"lead", "assessor"}
        )

    def _can_review(
        self, connection: Any, user_id: str, organization_id: str, engagement_id: str
    ) -> bool:
        role = self._membership(connection, user_id, organization_id)
        return role in {"owner", "admin"} or (
            role == "member"
            and bool(
                self._assignment_roles(connection, user_id, organization_id, engagement_id)
                & {"lead", "reviewer"}
            )
        )

    def _audit(
        self,
        connection: Any,
        organization_id: str,
        engagement_id: str | None,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        decision: str | None = None,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            assessment_audit_events.insert().values(
                id=str(uuid4()),
                organization_id=organization_id,
                engagement_id=engagement_id,
                actor_user_id=actor_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                decision=decision,
                reason_code=reason_code,
                details=details or {},
                occurred_at=now_iso(),
            )
        )

    def list_assets(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self._can_read(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(engagement_assets)
                .where(
                    engagement_assets.c.organization_id == organization_id,
                    engagement_assets.c.engagement_id == engagement_id,
                )
                .order_by(engagement_assets.c.created_at, engagement_assets.c.id)
            ).all()
            return [dict(row._mapping) for row in rows]

    def create_asset(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_type: str,
        target: str,
        client_id: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any] | None:
        if asset_type == "repository":
            raise EngagementSecurityError(
                "Repository assets must use the governed repository binding workflow."
            )
        normalized = normalize_target(asset_type, target)
        if description is not None and len(description) > 2000:
            raise EngagementSecurityError("Asset description is too long.")
        with self.engine.begin() as connection:
            engagement = self._engagement(connection, organization_id, engagement_id)
            if not engagement or not self._can_manage(
                connection, user_id, organization_id, engagement_id
            ):
                return None
            selected_client = client_id or engagement.get("client_id")
            if (
                selected_client
                and not connection.execute(
                    select(clients.c.id).where(
                        clients.c.id == selected_client,
                        clients.c.organization_id == organization_id,
                        clients.c.status == "active",
                    )
                ).first()
            ):
                raise EngagementSecurityError(
                    "Client must be active and belong to this organization."
                )
            timestamp, asset_id = now_iso(), str(uuid4())
            row = {
                "id": asset_id,
                "organization_id": organization_id,
                "client_id": selected_client,
                "engagement_id": engagement_id,
                "asset_type": asset_type,
                "target": normalized,
                "description": description,
                "status": "active",
                "created_by": user_id,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            connection.execute(engagement_assets.insert().values(**row))
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "asset.created",
                "asset",
                asset_id,
                details={"asset_type": asset_type, "target": normalized},
            )
            return row

    def update_asset(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        *,
        target: str | None = None,
        asset_type: str | None = None,
        description: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        with self.engine.begin() as connection:
            if not self._can_manage(connection, user_id, organization_id, engagement_id):
                return None
            old = connection.execute(
                select(engagement_assets).where(
                    engagement_assets.c.id == asset_id,
                    engagement_assets.c.organization_id == organization_id,
                    engagement_assets.c.engagement_id == engagement_id,
                )
            ).first()
            if not old:
                return None
            item = dict(old._mapping)
            chosen_type = asset_type or item["asset_type"]
            chosen_target = normalize_target(
                chosen_type, target if target is not None else item["target"]
            )
            if description is not None and len(description) > 2000:
                raise EngagementSecurityError("Asset description is too long.")
            if status is not None and status not in {"active", "inactive"}:
                raise EngagementSecurityError("Asset status is invalid.")
            changes: dict[str, Any] = {
                "asset_type": chosen_type,
                "target": chosen_target,
                "updated_at": now_iso(),
            }
            if description is not None:
                changes["description"] = description
            if status is not None:
                changes["status"] = status
            connection.execute(
                update(engagement_assets)
                .where(engagement_assets.c.id == asset_id)
                .values(**changes)
            )
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "asset.updated",
                "asset",
                asset_id,
                details={"changed_fields": sorted(changes)},
            )
            return {**item, **changes}

    def scope_revisions(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self._can_read(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(scope_revisions)
                .where(
                    scope_revisions.c.organization_id == organization_id,
                    scope_revisions.c.engagement_id == engagement_id,
                )
                .order_by(scope_revisions.c.revision.desc())
            ).all()
            return [self._scope_detail(connection, dict(row._mapping)) for row in rows]

    def _scope_detail(self, connection: Any, revision: dict[str, Any]) -> dict[str, Any]:
        rows = connection.execute(
            select(
                scope_rules,
                engagement_assets.c.asset_type,
                engagement_assets.c.target.label("asset_target"),
            )
            .join(
                engagement_assets,
                and_(
                    engagement_assets.c.id == scope_rules.c.asset_id,
                    engagement_assets.c.organization_id == scope_rules.c.organization_id,
                ),
            )
            .where(
                scope_rules.c.scope_revision_id == revision["id"],
                scope_rules.c.organization_id == revision["organization_id"],
            )
            .order_by(scope_rules.c.created_at, scope_rules.c.id)
        ).all()
        return {**revision, "rules": [dict(row._mapping) for row in rows]}

    def get_scope_revision(
        self, user_id: str, organization_id: str, engagement_id: str, revision_id: str
    ) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            if not self._can_read(connection, user_id, organization_id, engagement_id):
                return None
            row = connection.execute(
                select(scope_revisions).where(
                    scope_revisions.c.id == revision_id,
                    scope_revisions.c.organization_id == organization_id,
                    scope_revisions.c.engagement_id == engagement_id,
                )
            ).first()
            return self._scope_detail(connection, dict(row._mapping)) if row else None

    def create_scope_revision(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        rules: list[dict[str, Any]],
        change_summary: str,
    ) -> dict[str, Any] | None:
        if not 1 <= len(rules) <= MAX_SCOPE_RULES:
            raise EngagementSecurityError(f"A scope revision requires 1–{MAX_SCOPE_RULES} rules.")
        if not change_summary.strip() or len(change_summary) > 2000:
            raise EngagementSecurityError("A concise scope change summary is required.")
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                if not self._can_manage(connection, user_id, organization_id, engagement_id):
                    connection.rollback()
                    return None
                engagement = self._engagement(connection, organization_id, engagement_id)
                if not engagement or engagement["status"] not in {"draft", "active", "paused"}:
                    raise EngagementSecurityError("Engagement cannot accept a scope revision.")
                number = (
                    int(
                        connection.execute(
                            select(func.coalesce(func.max(scope_revisions.c.revision), 0)).where(
                                scope_revisions.c.organization_id == organization_id,
                                scope_revisions.c.engagement_id == engagement_id,
                            )
                        ).scalar_one()
                    )
                    + 1
                )
                timestamp, revision_id = now_iso(), str(uuid4())
                revision = {
                    "id": revision_id,
                    "organization_id": organization_id,
                    "engagement_id": engagement_id,
                    "revision": number,
                    "status": "draft",
                    "created_by": user_id,
                    "approved_by": None,
                    "created_at": timestamp,
                    "published_at": None,
                    "change_summary": change_summary.strip(),
                }
                connection.execute(scope_revisions.insert().values(**revision))
                seen: set[tuple[str, str, str, str]] = set()
                for rule in rules:
                    asset = connection.execute(
                        select(engagement_assets).where(
                            engagement_assets.c.id == rule.get("asset_id"),
                            engagement_assets.c.organization_id == organization_id,
                            engagement_assets.c.status == "active",
                            (engagement_assets.c.engagement_id == engagement_id)
                            | (engagement_assets.c.engagement_id.is_(None)),
                        )
                    ).first()
                    if not asset:
                        raise EngagementSecurityError(
                            "Every scope rule must reference an active in-organization asset."
                        )
                    asset_data = dict(asset._mapping)
                    effect = rule.get("effect")
                    mode = rule.get("match_mode")
                    allowed_modes = {
                        "domain": {"exact", "subdomains"},
                        "ip": {"exact"},
                        "cidr": {"network"},
                        "url": {"exact", "url_prefix"},
                        "repository": {"exact"},
                        "log_evidence": {"exact"},
                        "malware_evidence": {"exact"},
                        "chain_address": {"exact"},
                    }
                    if (
                        effect not in {"include", "exclude"}
                        or mode not in allowed_modes[asset_data["asset_type"]]
                    ):
                        raise EngagementSecurityError(
                            "Scope rule effect or match mode is invalid for the asset."
                        )
                    techniques = rule.get("techniques", [])
                    if not isinstance(techniques, list) or any(
                        item not in TECHNIQUE_CLASSES for item in techniques
                    ):
                        raise EngagementSecurityError(
                            "Scope rule contains an unsupported technique."
                        )
                    normalized_techniques = sorted(set(techniques))
                    if effect == "include" and not normalized_techniques:
                        raise EngagementSecurityError(
                            "Include rules must name at least one permitted technique."
                        )
                    key = (asset_data["id"], effect, mode, json.dumps(normalized_techniques))
                    if key in seen:
                        raise EngagementSecurityError("Duplicate scope rule.")
                    seen.add(key)
                    connection.execute(
                        scope_rules.insert().values(
                            id=str(uuid4()),
                            organization_id=organization_id,
                            scope_revision_id=revision_id,
                            asset_id=asset_data["id"],
                            asset_type_snapshot=asset_data["asset_type"],
                            target_snapshot=asset_data["target"],
                            effect=effect,
                            match_mode=mode,
                            techniques=normalized_techniques,
                            created_at=timestamp,
                        )
                    )
                self._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "scope_revision.created",
                    "scope_revision",
                    revision_id,
                    details={"revision": number, "rule_count": len(rules)},
                )
                result = self._scope_detail(connection, revision)
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise

    def publish_scope_revision(
        self, user_id: str, organization_id: str, engagement_id: str, revision_id: str
    ) -> dict[str, Any] | None:
        with self.engine.begin() as connection:
            row = connection.execute(
                select(scope_revisions).where(
                    scope_revisions.c.id == revision_id,
                    scope_revisions.c.organization_id == organization_id,
                    scope_revisions.c.engagement_id == engagement_id,
                    scope_revisions.c.status == "draft",
                )
            ).first()
            if not row or not self._can_review(connection, user_id, organization_id, engagement_id):
                return None
            revision = dict(row._mapping)
            if revision["created_by"] == user_id:
                raise EngagementSecurityError("The scope author cannot publish their own revision.")
            rules = (
                connection.execute(
                    select(scope_rules.c.effect).where(
                        scope_rules.c.scope_revision_id == revision_id,
                        scope_rules.c.organization_id == organization_id,
                    )
                )
                .scalars()
                .all()
            )
            if not rules or "include" not in rules:
                raise EngagementSecurityError("A published scope must contain an inclusion rule.")
            timestamp = now_iso()
            connection.execute(
                update(scope_revisions)
                .where(scope_revisions.c.id == revision_id)
                .values(
                    status="published",
                    approved_by=user_id,
                    published_at=timestamp,
                )
            )
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "scope_revision.published",
                "scope_revision",
                revision_id,
                details={"revision": revision["revision"], "created_by": revision["created_by"]},
            )
            return self._scope_detail(
                connection,
                {
                    **revision,
                    "status": "published",
                    "approved_by": user_id,
                    "published_at": timestamp,
                },
            )

    def _latest_published_scope(
        self, connection: Any, organization_id: str, engagement_id: str
    ) -> dict[str, Any] | None:
        row = connection.execute(
            select(scope_revisions)
            .where(
                scope_revisions.c.organization_id == organization_id,
                scope_revisions.c.engagement_id == engagement_id,
                scope_revisions.c.status == "published",
            )
            .order_by(scope_revisions.c.revision.desc())
            .limit(1)
        ).first()
        return dict(row._mapping) if row else None

    def list_authorizations(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self._can_read(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(authorization_records)
                .where(
                    authorization_records.c.organization_id == organization_id,
                    authorization_records.c.engagement_id == engagement_id,
                )
                .order_by(authorization_records.c.created_at.desc())
            ).all()
            result = []
            for row in rows:
                item = dict(row._mapping)
                doc = connection.execute(
                    select(
                        authorization_documents.c.id,
                        authorization_documents.c.filename,
                        authorization_documents.c.content_type,
                        authorization_documents.c.size_bytes,
                        authorization_documents.c.sha256,
                        authorization_documents.c.created_at,
                    ).where(authorization_documents.c.authorization_id == item["id"])
                ).first()
                item["document"] = dict(doc._mapping) if doc else None
                result.append(item)
            return result

    def create_authorization(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        scope_revision_id: str,
        authorization_reference: str,
        authorizing_party: str,
        permitted_techniques: list[str],
        effective_at: str,
        expires_at: str,
    ) -> dict[str, Any] | None:
        start, end = _utc(effective_at), _utc(expires_at)
        if end <= start or end <= datetime.now(UTC):
            raise EngagementSecurityError(
                "Authorization expiry must follow its effective date and be in the future."
            )
        if not authorization_reference.strip() or len(authorization_reference) > 160:
            raise EngagementSecurityError(
                "Authorization reference is required and must be at most 160 characters."
            )
        if not authorizing_party.strip() or len(authorizing_party) > 200:
            raise EngagementSecurityError(
                "Authorizing party is required and must be at most 200 characters."
            )
        techniques = sorted(set(permitted_techniques))
        if not techniques or any(item not in TECHNIQUE_CLASSES for item in techniques):
            raise EngagementSecurityError("Authorization must list supported permitted techniques.")
        with self.engine.begin() as connection:
            engagement = self._engagement(connection, organization_id, engagement_id)
            revision = connection.execute(
                select(scope_revisions).where(
                    scope_revisions.c.id == scope_revision_id,
                    scope_revisions.c.organization_id == organization_id,
                    scope_revisions.c.engagement_id == engagement_id,
                    scope_revisions.c.status == "published",
                )
            ).first()
            latest = self._latest_published_scope(connection, organization_id, engagement_id)
            if not engagement or not self._can_manage(
                connection, user_id, organization_id, engagement_id
            ):
                return None
            if not revision or not latest or latest["id"] != scope_revision_id:
                raise EngagementSecurityError(
                    "Authorization must reference the current published scope revision."
                )
            if engagement.get("client_id") is None:
                raise EngagementSecurityError(
                    "An engagement authorization requires a linked client."
                )
            timestamp, auth_id = now_iso(), str(uuid4())
            item = {
                "id": auth_id,
                "organization_id": organization_id,
                "engagement_id": engagement_id,
                "client_id": engagement["client_id"],
                "scope_revision_id": scope_revision_id,
                "authorization_reference": authorization_reference.strip(),
                "authorizing_party": authorizing_party.strip(),
                "permitted_techniques": techniques,
                "effective_at": _stamp(start),
                "expires_at": _stamp(end),
                "status": "active",
                "recorded_by": user_id,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            connection.execute(authorization_records.insert().values(**item))
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "authorization.created",
                "authorization",
                auth_id,
                details={"scope_revision_id": scope_revision_id, "expires_at": item["expires_at"]},
            )
            return item

    def revoke_authorization(
        self, user_id: str, organization_id: str, engagement_id: str, authorization_id: str
    ) -> dict[str, Any] | None:
        with self.engine.begin() as connection:
            if not self._can_manage(connection, user_id, organization_id, engagement_id):
                return None
            result = connection.execute(
                update(authorization_records)
                .where(
                    authorization_records.c.id == authorization_id,
                    authorization_records.c.organization_id == organization_id,
                    authorization_records.c.engagement_id == engagement_id,
                    authorization_records.c.status == "active",
                )
                .values(status="revoked", updated_at=now_iso())
            )
            if result.rowcount != 1:
                return None
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "authorization.revoked",
                "authorization",
                authorization_id,
            )
            row = connection.execute(
                select(authorization_records).where(authorization_records.c.id == authorization_id)
            ).first()
            return dict(row._mapping) if row else None

    def put_authorization_document(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        authorization_id: str,
        filename: str,
        content_type: str,
        content: bytes,
    ) -> dict[str, Any] | None:
        if not content or len(content) > MAX_AUTHORIZATION_DOCUMENT_BYTES:
            raise EngagementSecurityError(
                "Authorization document must be between 1 byte and 10 MiB."
            )
        safe_name = _SAFE_FILENAME.sub("_", filename.replace("\\", "/").split("/")[-1])[:180].strip(
            "._"
        )
        if not safe_name:
            raise EngagementSecurityError("Authorization document filename is invalid.")
        allowed_types = {"application/pdf", "image/png", "image/jpeg", "application/octet-stream"}
        normalized_type = content_type.split(";", 1)[0].strip().lower()
        if normalized_type not in allowed_types:
            raise EngagementSecurityError("Authorization document content type is not supported.")
        sha = hashlib.sha256(content).hexdigest()
        with self.engine.begin() as connection:
            if not self._can_manage(connection, user_id, organization_id, engagement_id):
                return None
            auth = connection.execute(
                select(authorization_records).where(
                    authorization_records.c.id == authorization_id,
                    authorization_records.c.organization_id == organization_id,
                    authorization_records.c.engagement_id == engagement_id,
                )
            ).first()
            if not auth:
                return None
            existing = connection.execute(
                select(authorization_documents.c.id).where(
                    authorization_documents.c.authorization_id == authorization_id
                )
            ).scalar_one_or_none()
            document_id = str(existing or uuid4())
            doc = {
                "id": document_id,
                "organization_id": organization_id,
                "authorization_id": authorization_id,
                "filename": safe_name,
                "content_type": normalized_type,
                "size_bytes": len(content),
                "sha256": sha,
                "content": content,
                "created_by": user_id,
                "created_at": now_iso(),
            }
            if existing:
                connection.execute(
                    authorization_documents.update()
                    .where(authorization_documents.c.id == existing)
                    .values(
                        **{
                            key: value
                            for key, value in doc.items()
                            if key not in {"id", "created_at"}
                        }
                    )
                )
            else:
                connection.execute(authorization_documents.insert().values(**doc))
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "authorization_document.stored",
                "authorization_document",
                document_id,
                details={"size_bytes": len(content), "sha256": sha},
            )
            return {key: value for key, value in doc.items() if key != "content"}

    def get_authorization_document(
        self, user_id: str, organization_id: str, engagement_id: str, authorization_id: str
    ) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            if not self._can_read(connection, user_id, organization_id, engagement_id):
                return None
            row = connection.execute(
                select(authorization_documents)
                .join(
                    authorization_records,
                    and_(
                        authorization_records.c.id == authorization_documents.c.authorization_id,
                        authorization_records.c.organization_id
                        == authorization_documents.c.organization_id,
                    ),
                )
                .where(
                    authorization_documents.c.organization_id == organization_id,
                    authorization_records.c.engagement_id == engagement_id,
                    authorization_documents.c.authorization_id == authorization_id,
                )
            ).first()
            return dict(row._mapping) if row else None

    def list_approvals(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            if not self._can_read(connection, user_id, organization_id, engagement_id):
                return None
            rows = connection.execute(
                select(approval_requests)
                .where(
                    approval_requests.c.organization_id == organization_id,
                    approval_requests.c.engagement_id == engagement_id,
                )
                .order_by(approval_requests.c.created_at.desc())
            ).all()
            return [dict(row._mapping) for row in rows]

    @staticmethod
    def _asset_matches(
        asset_type: str, asset_target: str, target_type: str, target: str, mode: str
    ) -> bool:
        if mode == "exact":
            return asset_type == target_type and asset_target == target
        if mode == "subdomains":
            return (
                asset_type == "domain"
                and target_type == "domain"
                and (target == asset_target or target.endswith("." + asset_target))
            )
        if mode == "network":
            return (
                asset_type == "cidr"
                and target_type == "ip"
                and ipaddress.ip_address(target) in ipaddress.ip_network(asset_target, strict=True)
            )
        if mode == "url_prefix":
            if asset_type != "url" or target_type != "url":
                return False
            base, candidate = urlsplit(asset_target), urlsplit(target)
            return (
                base.scheme == candidate.scheme
                and base.netloc == candidate.netloc
                and (
                    candidate.path == base.path.rstrip("/")
                    or candidate.path.startswith(base.path.rstrip("/") + "/")
                )
            )
        return False

    @staticmethod
    def _specificity(asset_type: str, asset_target: str, mode: str) -> int:
        if mode == "exact":
            return 1_000_000 + len(asset_target)
        if mode == "subdomains":
            return 100_000 + len(asset_target.split("."))
        if mode == "network":
            return 100_000 + ipaddress.ip_network(asset_target, strict=True).prefixlen
        if mode == "url_prefix":
            return 100_000 + len(urlsplit(asset_target).path)
        return 0

    def _decision(
        self,
        connection: Any,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_type: str,
        target_value: str,
        technique: str,
        approval_id: str | None,
        consume_approval: bool,
        current: datetime,
    ) -> dict[str, Any]:
        normalized = normalize_target(asset_type, target_value)
        action_class = TECHNIQUE_CLASSES.get(technique)
        base = {
            "organization_id": organization_id,
            "engagement_id": engagement_id,
            "asset_type": asset_type,
            "target": normalized,
            "technique": technique,
            "action_class": action_class,
        }
        engagement = self._engagement(connection, organization_id, engagement_id)
        if not engagement or self._membership(connection, user_id, organization_id) is None:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "ENGAGEMENT_NOT_FOUND",
                "explanation": "The engagement is unavailable to this user.",
            }
        if engagement["status"] != "active":
            return {
                **base,
                "decision": "DENY",
                "reason_code": "ENGAGEMENT_INACTIVE",
                "explanation": "Assessment policy requires an active engagement.",
            }
        if not self._can_operate(connection, user_id, organization_id, engagement_id):
            return {
                **base,
                "decision": "DENY",
                "reason_code": "ENGAGEMENT_ROLE_REQUIRED",
                "explanation": (
                    "An active lead or assessor assignment is required for assessment operations."
                ),
            }
        if action_class is None:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "TECHNIQUE_UNSUPPORTED",
                "explanation": "The requested technique is not in the supported policy catalog.",
            }
        scope = self._latest_published_scope(connection, organization_id, engagement_id)
        if not scope:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "SCOPE_MISSING",
                "explanation": "No published scope revision exists.",
            }
        base["scope_revision_id"] = scope["id"]
        rules = connection.execute(
            select(
                scope_rules,
                scope_rules.c.asset_type_snapshot.label("rule_asset_type"),
                scope_rules.c.target_snapshot.label("rule_target"),
            )
            .join(
                engagement_assets,
                and_(
                    engagement_assets.c.id == scope_rules.c.asset_id,
                    engagement_assets.c.organization_id == scope_rules.c.organization_id,
                ),
            )
            .where(
                scope_rules.c.organization_id == organization_id,
                scope_rules.c.scope_revision_id == scope["id"],
            )
        ).all()
        matching: list[tuple[dict[str, Any], int]] = []
        excluded = False
        for result in rules:
            rule = dict(result._mapping)
            if self._asset_matches(
                rule["rule_asset_type"],
                rule["rule_target"],
                asset_type,
                normalized,
                rule["match_mode"],
            ):
                if rule["effect"] == "exclude" and (
                    not rule["techniques"] or technique in rule["techniques"]
                ):
                    excluded = True
                elif rule["effect"] == "include":
                    matching.append(
                        (
                            rule,
                            self._specificity(
                                rule["rule_asset_type"], rule["rule_target"], rule["match_mode"]
                            ),
                        )
                    )
        if excluded:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "TARGET_EXCLUDED",
                "explanation": "An exclusion rule overrides all matching inclusions.",
            }
        if not matching:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "TARGET_OUT_OF_SCOPE",
                "explanation": "The target does not match an inclusion rule in the current scope.",
            }
        top = max(score for _rule, score in matching)
        allowed = set().union(
            *(set(rule["techniques"]) for rule, score in matching if score == top)
        )
        if technique not in allowed:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "TECHNIQUE_OUT_OF_SCOPE",
                "explanation": "The current scope does not permit this technique for the target.",
            }
        auth_rows = connection.execute(
            select(authorization_records)
            .where(
                authorization_records.c.organization_id == organization_id,
                authorization_records.c.engagement_id == engagement_id,
                authorization_records.c.scope_revision_id == scope["id"],
                authorization_records.c.status == "active",
            )
            .order_by(authorization_records.c.created_at.desc())
        ).all()
        auth = next(
            (
                dict(row._mapping)
                for row in auth_rows
                if (
                    _utc(row.effective_at) <= current < _utc(row.expires_at)
                    and technique in row.permitted_techniques
                )
            ),
            None,
        )
        if auth is None:
            stale = connection.execute(
                select(authorization_records.c.id).where(
                    authorization_records.c.organization_id == organization_id,
                    authorization_records.c.engagement_id == engagement_id,
                    authorization_records.c.status == "active",
                    authorization_records.c.scope_revision_id != scope["id"],
                )
            ).first()
            reason = "AUTHORIZATION_SCOPE_STALE" if stale else "AUTHORIZATION_MISSING_OR_INVALID"
            explanation = (
                "Authorization must be active, within its validity window, cover this technique, "
                "and reference the current scope revision."
            )
            return {**base, "decision": "DENY", "reason_code": reason, "explanation": explanation}
        base["authorization_id"] = auth["id"]
        if asset_type == "repository":
            binding = connection.execute(
                select(repository_asset_bindings).where(
                    repository_asset_bindings.c.organization_id == organization_id,
                    repository_asset_bindings.c.engagement_id == engagement_id,
                    repository_asset_bindings.c.asset_id
                    == self._asset_id_for_target(
                        connection, organization_id, engagement_id, normalized
                    ),
                    repository_asset_bindings.c.snapshot_sha256.is_not(None),
                )
            ).first()
            if not binding:
                return {
                    **base,
                    "decision": "DENY",
                    "reason_code": "REPOSITORY_BINDING_UNAVAILABLE",
                    "explanation": "The authorized repository source is unavailable.",
                }
            binding_data = dict(binding._mapping)
            attestation = connection.execute(
                select(repository_attestations).where(
                    repository_attestations.c.organization_id == organization_id,
                    repository_attestations.c.engagement_id == engagement_id,
                    repository_attestations.c.asset_id == binding_data["asset_id"],
                    repository_attestations.c.authorization_id == auth["id"],
                    repository_attestations.c.scope_revision_id == scope["id"],
                )
            ).first()
            snapshot = connection.execute(
                select(repository_snapshots).where(
                    repository_snapshots.c.id == binding_data["snapshot_id"],
                    repository_snapshots.c.organization_id == organization_id,
                    repository_snapshots.c.status == "available",
                )
            ).first()
            if not attestation or not snapshot:
                return {
                    **base,
                    "decision": "DENY",
                    "reason_code": "REPOSITORY_AUTHORIZATION_UNAVAILABLE",
                    "explanation": "Repository authorization or snapshot is unavailable.",
                }
        elif asset_type == "log_evidence":
            evidence_asset_id = connection.execute(
                select(engagement_assets.c.id).where(
                    engagement_assets.c.organization_id == organization_id,
                    engagement_assets.c.engagement_id == engagement_id,
                    engagement_assets.c.asset_type == "log_evidence",
                    engagement_assets.c.target == normalized,
                )
            ).scalar_one_or_none()
            snapshot = (
                connection.execute(
                    select(log_evidence_snapshots.c.id).where(
                        log_evidence_snapshots.c.asset_id == evidence_asset_id,
                        log_evidence_snapshots.c.organization_id == organization_id,
                        log_evidence_snapshots.c.engagement_id == engagement_id,
                        log_evidence_snapshots.c.status == "available",
                    )
                ).first()
                if evidence_asset_id
                else None
            )
            if not snapshot:
                return {
                    **base,
                    "decision": "DENY",
                    "reason_code": "LOG_EVIDENCE_UNAVAILABLE",
                    "explanation": (
                        "Registered log evidence is unavailable or failed integrity validation."
                    ),
                }
        elif asset_type == "malware_evidence":
            evidence_asset_id = self._asset_id_for_target(
                connection, organization_id, engagement_id, normalized
            )
            snapshot = (
                connection.execute(
                    select(malware_evidence_snapshots.c.id).where(
                        malware_evidence_snapshots.c.asset_id == evidence_asset_id,
                        malware_evidence_snapshots.c.organization_id == organization_id,
                        malware_evidence_snapshots.c.engagement_id == engagement_id,
                        malware_evidence_snapshots.c.status == "available",
                    )
                ).first()
                if evidence_asset_id
                else None
            )
            if not snapshot:
                return {
                    **base,
                    "decision": "DENY",
                    "reason_code": "MALWARE_EVIDENCE_UNAVAILABLE",
                    "explanation": (
                        "Registered malware evidence is unavailable or failed integrity validation."
                    ),
                }
        digest = operation_digest(
            organization_id=organization_id,
            engagement_id=engagement_id,
            requester_user_id=user_id,
            asset_type=asset_type,
            target=normalized,
            technique=technique,
            action_class=action_class,
            scope_revision_id=scope["id"],
            authorization_id=auth["id"],
        )
        base["request_digest"] = digest
        if action_class != "sensitive":
            if approval_id:
                return {
                    **base,
                    "decision": "DENY",
                    "reason_code": "APPROVAL_NOT_APPLICABLE",
                    "explanation": "Approval IDs are valid only for sensitive operations.",
                }
            return {
                **base,
                "decision": "ALLOW",
                "reason_code": "AUTHORIZED_WITHIN_SCOPE",
                "explanation": (
                    "Active membership, assignment, scope, and authorization checks passed."
                ),
            }
        if not approval_id:
            return {
                **base,
                "decision": "REQUIRE_APPROVAL",
                "reason_code": "HUMAN_APPROVAL_REQUIRED",
                "explanation": "This sensitive operation requires a distinct authorized approver.",
            }
        approval = connection.execute(
            select(approval_requests).where(
                approval_requests.c.id == approval_id,
                approval_requests.c.organization_id == organization_id,
                approval_requests.c.engagement_id == engagement_id,
            )
        ).first()
        if not approval:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVAL_NOT_FOUND",
                "explanation": "The approval request is unavailable.",
            }
        request = dict(approval._mapping)
        base["approval_id"] = approval_id
        if request["requester_user_id"] != user_id or request["request_digest"] != digest:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVAL_BINDING_MISMATCH",
                "explanation": "The approval is bound to another user or operation.",
            }
        if request["scope_revision_id"] != scope["id"] or request["authorization_id"] != auth["id"]:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVAL_SCOPE_STALE",
                "explanation": "Scope or authorization changed after the approval request.",
            }
        if _utc(request["expires_at"]) <= current:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVAL_EXPIRED",
                "explanation": "The approval has expired.",
            }
        if request["decision"] == "consumed" or request["consumed_at"]:
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVAL_ALREADY_CONSUMED",
                "explanation": "The approval is one-use and has already been consumed.",
            }
        if request["decision"] != "approved" or not request["approver_user_id"]:
            return {
                **base,
                "decision": "REQUIRE_APPROVAL",
                "reason_code": "APPROVAL_PENDING",
                "explanation": "A distinct authorized reviewer has not approved this request.",
            }
        if (
            request["approver_user_id"] == user_id
            or request["approver_user_id"] == request["requester_user_id"]
        ):
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVER_NOT_DISTINCT",
                "explanation": "The approver must be distinct from the requester.",
            }
        approver_role = self._membership(connection, request["approver_user_id"], organization_id)
        approver_assignments = self._assignment_roles(
            connection, request["approver_user_id"], organization_id, engagement_id
        )
        if approver_role not in {"owner", "admin"} and not (
            approver_role == "member" and approver_assignments.intersection({"lead", "reviewer"})
        ):
            return {
                **base,
                "decision": "DENY",
                "reason_code": "APPROVER_NO_LONGER_AUTHORIZED",
                "explanation": "The approving user no longer has an active review role.",
            }
        if consume_approval:
            updated = connection.execute(
                update(approval_requests)
                .where(
                    approval_requests.c.id == approval_id,
                    approval_requests.c.organization_id == organization_id,
                    approval_requests.c.decision == "approved",
                    approval_requests.c.consumed_at.is_(None),
                    approval_requests.c.expires_at > _stamp(current),
                    approval_requests.c.request_digest == digest,
                )
                .values(decision="consumed", consumed_at=_stamp(current), consumed_by=user_id)
            )
            if updated.rowcount != 1:
                return {
                    **base,
                    "decision": "DENY",
                    "reason_code": "APPROVAL_REPLAYED",
                    "explanation": "The approval was consumed concurrently or is no longer valid.",
                }
            self._audit(
                connection,
                organization_id,
                engagement_id,
                user_id,
                "approval.consumed",
                "approval",
                approval_id,
                decision="ALLOW",
                reason_code="APPROVAL_CONSUMED",
                details={
                    "request_digest": digest,
                    "scope_revision_id": scope["id"],
                    "authorization_id": auth["id"],
                },
            )
        return {
            **base,
            "decision": "ALLOW",
            "reason_code": "APPROVAL_VALID" if not consume_approval else "APPROVAL_CONSUMED",
            "explanation": "A distinct approver approved this exact operation."
            if not consume_approval
            else "The one-use approval was atomically consumed for this exact operation.",
        }

    @staticmethod
    def _asset_id_for_target(
        connection: Any, organization_id: str, engagement_id: str, target: str
    ) -> str | None:
        result = connection.execute(
            select(engagement_assets.c.id).where(
                engagement_assets.c.organization_id == organization_id,
                engagement_assets.c.engagement_id == engagement_id,
                engagement_assets.c.target == target,
            )
        ).scalar_one_or_none()
        return cast(str | None, result)

    def evaluate_policy(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_type: str,
        target: str,
        technique: str,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        with self.engine.begin() as connection:
            result = self._decision(
                connection,
                user_id,
                organization_id,
                engagement_id,
                asset_type,
                target,
                technique,
                approval_id,
                False,
                datetime.now(UTC),
            )
            audit_engagement_id: str | None = engagement_id
            audit_resource_type = "policy"
            audit_resource_id = result.get("approval_id")
            audit_details = {
                "asset_type": asset_type,
                "target": result.get("target"),
                "technique": technique,
                "scope_revision_id": result.get("scope_revision_id"),
                "authorization_id": result.get("authorization_id"),
                "request_digest": result.get("request_digest"),
            }
            if result["reason_code"] == "ENGAGEMENT_NOT_FOUND":
                # A missing or foreign engagement is intentionally indistinguishable.
                # Keep an organization-scoped audit event, but never bind it to the
                # untrusted engagement ID or persist that ID in clear text.
                audit_scope_exists = connection.execute(
                    select(organization_memberships.c.id).where(
                        organization_memberships.c.organization_id == organization_id,
                        organization_memberships.c.user_id == user_id,
                    )
                ).first()
                if audit_scope_exists is None:
                    # There is no valid tenant relationship in which to record this
                    # event. The API middleware rejects this case before routing.
                    return result
                audit_engagement_id = None
                audit_resource_type = "engagement_lookup"
                audit_resource_id = None
                audit_details["attempted_engagement_sha256"] = hashlib.sha256(
                    engagement_id.encode("utf-8")
                ).hexdigest()
            self._audit(
                connection,
                organization_id,
                audit_engagement_id,
                user_id,
                "policy.evaluated",
                audit_resource_type,
                audit_resource_id,
                decision=result["decision"],
                reason_code=result["reason_code"],
                details=audit_details,
            )
            return result

    def create_approval_request(
        self,
        user_id: str,
        organization_id: str,
        engagement_id: str,
        asset_type: str,
        target: str,
        technique: str,
        expires_at: str | None = None,
    ) -> dict[str, Any] | None:
        current = datetime.now(UTC)
        expiry = _utc(expires_at) if expires_at else current + MAX_APPROVAL_TTL
        if expiry <= current or expiry > current + MAX_APPROVAL_TTL:
            raise EngagementSecurityError("Approval expiry must be within the next 24 hours.")
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                decision = self._decision(
                    connection,
                    user_id,
                    organization_id,
                    engagement_id,
                    asset_type,
                    target,
                    technique,
                    None,
                    False,
                    current,
                )
                if decision["decision"] == "DENY":
                    raise EngagementSecurityError(decision["explanation"])
                if (
                    decision["decision"] != "REQUIRE_APPROVAL"
                    or decision["action_class"] != "sensitive"
                ):
                    raise EngagementSecurityError(
                        "This operation does not require a sensitive-action approval."
                    )
                auth_expiry = _utc(
                    connection.execute(
                        select(authorization_records.c.expires_at).where(
                            authorization_records.c.id == decision["authorization_id"],
                            authorization_records.c.organization_id == organization_id,
                            authorization_records.c.status == "active",
                        )
                    ).scalar_one()
                )
                expiry = min(expiry, auth_expiry)
                if expiry <= current:
                    raise EngagementSecurityError(
                        "Authorization expires before an approval can be used."
                    )
                item = {
                    "id": str(uuid4()),
                    "organization_id": organization_id,
                    "engagement_id": engagement_id,
                    "requester_user_id": user_id,
                    "approver_user_id": None,
                    "asset_type": asset_type,
                    "target": decision["target"],
                    "technique": technique,
                    "action_class": decision["action_class"],
                    "scope_revision_id": decision["scope_revision_id"],
                    "authorization_id": decision["authorization_id"],
                    "request_digest": decision["request_digest"],
                    "expires_at": _stamp(expiry),
                    "decision": "pending",
                    "decision_reason": None,
                    "consumed_at": None,
                    "consumed_by": None,
                    "created_at": _stamp(current),
                    "decided_at": None,
                }
                connection.execute(approval_requests.insert().values(**item))
                self._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "policy.evaluated",
                    "policy",
                    None,
                    decision=decision["decision"],
                    reason_code=decision["reason_code"],
                    details={
                        "asset_type": asset_type,
                        "target": decision["target"],
                        "technique": technique,
                        "scope_revision_id": decision["scope_revision_id"],
                        "authorization_id": decision["authorization_id"],
                        "request_digest": decision["request_digest"],
                    },
                )
                self._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    user_id,
                    "approval.requested",
                    "approval",
                    item["id"],
                    decision="REQUIRE_APPROVAL",
                    reason_code="HUMAN_APPROVAL_REQUIRED",
                    details={
                        "request_digest": item["request_digest"],
                        "scope_revision_id": item["scope_revision_id"],
                        "authorization_id": item["authorization_id"],
                        "expires_at": item["expires_at"],
                    },
                )
                connection.commit()
                return item
            except Exception:
                connection.rollback()
                raise

    def decide_approval(
        self,
        approver_id: str,
        organization_id: str,
        engagement_id: str,
        approval_id: str,
        decision: str,
        reason: str,
    ) -> dict[str, Any] | None:
        if decision not in {"approved", "denied"} or len(reason.strip()) > 500:
            raise EngagementSecurityError("Approval decision or reason is invalid.")
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                row = connection.execute(
                    select(approval_requests).where(
                        approval_requests.c.id == approval_id,
                        approval_requests.c.organization_id == organization_id,
                        approval_requests.c.engagement_id == engagement_id,
                        approval_requests.c.decision == "pending",
                    )
                ).first()
                if not row:
                    connection.rollback()
                    return None
                item = dict(row._mapping)
                if item["requester_user_id"] == approver_id:
                    raise EngagementSecurityError("Requesters cannot approve their own operation.")
                role = self._membership(connection, approver_id, organization_id)
                assignment_roles = self._assignment_roles(
                    connection, approver_id, organization_id, engagement_id
                )
                if role not in {"owner", "admin"} and not (
                    role == "member" and assignment_roles.intersection({"lead", "reviewer"})
                ):
                    connection.rollback()
                    return None
                current = datetime.now(UTC)
                if _utc(item["expires_at"]) <= current:
                    reason_text = "Approval request expired before review."
                    connection.execute(
                        update(approval_requests)
                        .where(approval_requests.c.id == approval_id)
                        .values(
                            decision="expired",
                            decided_at=_stamp(current),
                            decision_reason=reason_text,
                        )
                    )
                    self._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        approver_id,
                        "approval.expired",
                        "approval",
                        approval_id,
                        decision="DENY",
                        reason_code="APPROVAL_EXPIRED",
                    )
                    connection.commit()
                    return {
                        **item,
                        "decision": "expired",
                        "decided_at": _stamp(current),
                        "decision_reason": reason_text,
                    }
                # Re-evaluate all operation bindings before an approver can decide.
                checked = self._decision(
                    connection,
                    item["requester_user_id"],
                    organization_id,
                    engagement_id,
                    item["asset_type"],
                    item["target"],
                    item["technique"],
                    None,
                    False,
                    current,
                )
                if (
                    checked["decision"] != "REQUIRE_APPROVAL"
                    or checked.get("request_digest") != item["request_digest"]
                ):
                    reason_text = "Scope or authorization changed after the request."
                    connection.execute(
                        update(approval_requests)
                        .where(approval_requests.c.id == approval_id)
                        .values(
                            decision="expired",
                            decided_at=_stamp(current),
                            decision_reason=reason_text,
                        )
                    )
                    self._audit(
                        connection,
                        organization_id,
                        engagement_id,
                        approver_id,
                        "approval.invalidated",
                        "approval",
                        approval_id,
                        decision="DENY",
                        reason_code="APPROVAL_BINDING_STALE",
                    )
                    connection.commit()
                    return {
                        **item,
                        "decision": "expired",
                        "decided_at": _stamp(current),
                        "decision_reason": reason_text,
                    }
                connection.execute(
                    update(approval_requests)
                    .where(approval_requests.c.id == approval_id)
                    .values(
                        decision=decision,
                        approver_user_id=approver_id,
                        decision_reason=reason.strip() or None,
                        decided_at=_stamp(current),
                    )
                )
                self._audit(
                    connection,
                    organization_id,
                    engagement_id,
                    approver_id,
                    "approval." + decision,
                    "approval",
                    approval_id,
                    decision=decision.upper(),
                    reason_code="HUMAN_DECISION",
                    details={
                        "request_digest": item["request_digest"],
                        "requester_user_id": item["requester_user_id"],
                    },
                )
                connection.commit()
                return {
                    **item,
                    "decision": decision,
                    "approver_user_id": approver_id,
                    "decision_reason": reason.strip() or None,
                    "decided_at": _stamp(current),
                }
            except Exception:
                connection.rollback()
                raise

    def audit_history(
        self, user_id: str, organization_id: str, engagement_id: str, limit: int = 100
    ) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            role = self._membership(connection, user_id, organization_id)
            if role not in {"owner", "admin", "auditor"} or not self._can_read(
                connection, user_id, organization_id, engagement_id
            ):
                return None
            rows = connection.execute(
                select(assessment_audit_events)
                .where(
                    assessment_audit_events.c.organization_id == organization_id,
                    assessment_audit_events.c.engagement_id == engagement_id,
                )
                .order_by(assessment_audit_events.c.occurred_at.desc())
                .limit(limit)
            ).all()
            return [dict(row._mapping) for row in rows]
