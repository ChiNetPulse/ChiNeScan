-- Generated from ChineScan SQLAlchemy metadata. Review before remote application.
BEGIN;
-- Supabase SQL Editor runs this file in a transaction. Pin unqualified table
-- and index creation to the intended application schema before any DDL.
SET LOCAL search_path = public;
CREATE TABLE IF NOT EXISTS public.alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY);

CREATE TABLE auth_lockouts (
	key_hash VARCHAR(64) NOT NULL,
	failure_count INTEGER DEFAULT '0' NOT NULL,
	locked_until FLOAT,
	updated_at FLOAT NOT NULL,
	PRIMARY KEY (key_hash)
)

;

CREATE TABLE organization_bootstrap_reports (
	report_id VARCHAR(80) NOT NULL,
	payload JSON NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (report_id)
)

;

CREATE TABLE records (
	record_type VARCHAR(80) NOT NULL,
	record_id VARCHAR(255) NOT NULL,
	payload JSON NOT NULL,
	PRIMARY KEY (record_type, record_id)
)

;

CREATE TABLE users (
	id VARCHAR(36) NOT NULL,
	email_normalized VARCHAR(254) NOT NULL,
	display_name VARCHAR(120) NOT NULL,
	status VARCHAR(20) NOT NULL,
	platform_role VARCHAR(20) DEFAULT 'user' NOT NULL,
	auth_epoch VARCHAR(64) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id)
	,CONSTRAINT ck_users_platform_role CHECK (platform_role IN ('user','superuser'))
)

;

CREATE TABLE worker_leases (
	worker_id VARCHAR(64) NOT NULL,
	status VARCHAR(20) NOT NULL,
	started_at VARCHAR(40) NOT NULL,
	last_heartbeat_at FLOAT NOT NULL,
	stopped_at VARCHAR(40),
	PRIMARY KEY (worker_id),
	CONSTRAINT ck_worker_lease_status CHECK (status IN ('active','stopping','stopped'))
)

;

CREATE TABLE organizations (
	id VARCHAR(36) NOT NULL,
	name VARCHAR(160) NOT NULL,
	slug VARCHAR(100) NOT NULL,
	status VARCHAR(20) NOT NULL,
	owner_user_id VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE RESTRICT
)

;

CREATE TABLE user_credentials (
	user_id VARCHAR(36) NOT NULL,
	password_hash VARCHAR(255),
	totp_enabled INTEGER DEFAULT '0' NOT NULL,
	totp_secret VARCHAR(64),
	totp_last_counter INTEGER DEFAULT '-1' NOT NULL,
	totp_pending_secret VARCHAR(64),
	totp_enrollment_expires_at INTEGER,
	totp_verify_failed_at JSON DEFAULT '[]' NOT NULL,
	migrated_operator_epoch VARCHAR(64),
	password_updated_at VARCHAR(40),
	bootstrap_token_hash VARCHAR(64),
	bootstrap_expires_at FLOAT,
	bootstrap_used_at FLOAT,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (user_id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
	CONSTRAINT ck_user_credentials_totp_enabled CHECK (totp_enabled IN (0, 1))
)

;

CREATE TABLE user_recovery_codes (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	code_hash VARCHAR(255) NOT NULL,
	used_at VARCHAR(40),
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)

;

CREATE TABLE user_sessions (
	id VARCHAR(36) NOT NULL,
	token_hash VARCHAR(64) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	email_normalized VARCHAR(254) NOT NULL,
	csrf_token VARCHAR(128) NOT NULL,
	auth_epoch VARCHAR(64) NOT NULL,
	created_at FLOAT NOT NULL,
	last_seen_at FLOAT NOT NULL,
	expires_at FLOAT NOT NULL,
	revoked_at FLOAT,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)

;

CREATE TABLE clients (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	name VARCHAR(160) NOT NULL,
	description VARCHAR(2000),
	status VARCHAR(20) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	CONSTRAINT uq_client_id_org UNIQUE (id, organization_id)
)

;

CREATE TABLE legal_holds (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36),
	reason VARCHAR(500) NOT NULL,
	status VARCHAR(16) NOT NULL,
	created_by VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	released_by VARCHAR(36),
	released_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(created_by) REFERENCES users (id) ON DELETE RESTRICT,
	FOREIGN KEY(released_by) REFERENCES users (id) ON DELETE RESTRICT,
	CONSTRAINT ck_legal_hold_status CHECK (status IN ('active','released'))
)

;

CREATE TABLE log_evidence_quota_reservations (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	reserved_bytes INTEGER NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	CONSTRAINT ck_log_reservation_bytes CHECK (reserved_bytes BETWEEN 0 AND 250000000)
)

;

CREATE TABLE malware_evidence_quota_reservations (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	reserved_bytes INTEGER NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	CONSTRAINT ck_malware_reservation_bytes CHECK (reserved_bytes BETWEEN 1 AND 67108864)
)

;

CREATE TABLE organization_audit_events (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	actor_user_id VARCHAR(36) NOT NULL,
	action VARCHAR(80) NOT NULL,
	resource_type VARCHAR(40) NOT NULL,
	resource_id VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(actor_user_id) REFERENCES users (id) ON DELETE RESTRICT
)

;

CREATE TABLE organization_invitations (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	email_normalized VARCHAR(254) NOT NULL,
	role VARCHAR(20) NOT NULL,
	token_hash VARCHAR(64) NOT NULL,
	invited_by_user_id VARCHAR(36) NOT NULL,
	status VARCHAR(20) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	accepted_by_user_id VARCHAR(36),
	accepted_at VARCHAR(40),
	revoked_at VARCHAR(40),
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(invited_by_user_id) REFERENCES users (id) ON DELETE RESTRICT,
	FOREIGN KEY(accepted_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
	CONSTRAINT ck_org_invitation_role CHECK (role IN ('admin','member','auditor','viewer')),
	CONSTRAINT ck_org_invitation_status CHECK (status IN ('pending','accepted','revoked','expired'))
)

;

CREATE TABLE organization_memberships (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	role VARCHAR(20) NOT NULL,
	status VARCHAR(20) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE RESTRICT,
	CONSTRAINT uq_membership_org_user UNIQUE (organization_id, user_id)
)

;

CREATE TABLE repository_quota_reservations (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	reserved_bytes INTEGER NOT NULL,
	content_digest VARCHAR(64) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	CONSTRAINT ck_repository_reservation_bytes CHECK (reserved_bytes >= 0)
)

;

CREATE TABLE repository_snapshots (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	size_bytes INTEGER NOT NULL,
	manifest JSON NOT NULL,
	manifest_version INTEGER NOT NULL,
	scanner_version VARCHAR(80) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	status VARCHAR(20) NOT NULL,
	closed_at VARCHAR(40),
	delete_after VARCHAR(40),
	legal_hold INTEGER DEFAULT '0' NOT NULL,
	hold_reason VARCHAR(500),
	deleted_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE RESTRICT,
	CONSTRAINT uq_repository_snapshot_id_org UNIQUE (id, organization_id),
	CONSTRAINT ck_repository_snapshot_size CHECK (size_bytes BETWEEN 0 AND 10737418240),
	CONSTRAINT ck_repository_manifest_version CHECK (manifest_version > 0),
	CONSTRAINT ck_repository_snapshot_status CHECK (status IN ('available','missing','corrupt','deleting','deleted')),
	CONSTRAINT ck_repository_snapshot_hold CHECK (legal_hold IN (0,1))
)

;

CREATE TABLE retention_audit_events (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	actor_user_id VARCHAR(36) NOT NULL,
	action VARCHAR(80) NOT NULL,
	resource_type VARCHAR(80) NOT NULL,
	resource_id VARCHAR(255),
	details JSON NOT NULL,
	occurred_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(actor_user_id) REFERENCES users (id) ON DELETE RESTRICT
)

;

CREATE TABLE retention_jobs (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	record_type VARCHAR(80) NOT NULL,
	record_id VARCHAR(255) NOT NULL,
	status VARCHAR(20) NOT NULL,
	decision_reason VARCHAR(120) NOT NULL,
	attempt_count INTEGER DEFAULT '0' NOT NULL,
	last_error VARCHAR(500),
	created_at VARCHAR(40) NOT NULL,
	completed_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	CONSTRAINT ck_retention_job_status CHECK (status IN ('eligible','blocked','deleted','failed')),
	CONSTRAINT uq_retention_job_record UNIQUE (organization_id, record_type, record_id)
)

;

CREATE TABLE engagements (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	client_id VARCHAR(36),
	name VARCHAR(160) NOT NULL,
	description VARCHAR(4000) NOT NULL,
	status VARCHAR(20) NOT NULL,
	closed_at VARCHAR(40),
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(client_id, organization_id) REFERENCES clients (id, organization_id) ON DELETE RESTRICT,
	CONSTRAINT uq_engagement_id_org UNIQUE (id, organization_id)
)

;

CREATE TABLE legal_hold_records (
	hold_id VARCHAR(36) NOT NULL,
	record_type VARCHAR(80) NOT NULL,
	record_id VARCHAR(255) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (hold_id, record_type, record_id),
	FOREIGN KEY(hold_id) REFERENCES legal_holds (id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE
)

;

CREATE TABLE assessment_audit_events (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36),
	actor_user_id VARCHAR(36) NOT NULL,
	action VARCHAR(80) NOT NULL,
	resource_type VARCHAR(40) NOT NULL,
	resource_id VARCHAR(36),
	decision VARCHAR(24),
	reason_code VARCHAR(80),
	details JSON NOT NULL,
	occurred_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id, actor_user_id) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT
)

;

CREATE TABLE engagement_assets (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	client_id VARCHAR(36),
	engagement_id VARCHAR(36),
	asset_type VARCHAR(20) NOT NULL,
	target VARCHAR(2048) NOT NULL,
	description VARCHAR(2000),
	status VARCHAR(20) NOT NULL,
	created_by VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(client_id, organization_id) REFERENCES clients (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, created_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_engagement_asset_id_org UNIQUE (id, organization_id),
	CONSTRAINT uq_engagement_asset_id_org_engagement UNIQUE (id, organization_id, engagement_id),
	CONSTRAINT uq_engagement_asset_target UNIQUE (organization_id, engagement_id, asset_type, target),
	CONSTRAINT ck_asset_type CHECK (asset_type IN ('domain','ip','cidr','url','repository','log_evidence','malware_evidence','chain_address')),
	CONSTRAINT ck_asset_status CHECK (status IN ('active','inactive'))
)

;

CREATE TABLE engagement_assignments (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	role VARCHAR(20) NOT NULL,
	status VARCHAR(20) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id, user_id) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_assignment_engagement_user UNIQUE (engagement_id, user_id)
)

;

CREATE TABLE record_ownership (
	record_type VARCHAR(80) NOT NULL,
	record_id VARCHAR(255) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36),
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (record_type, record_id),
	FOREIGN KEY(record_type, record_id) REFERENCES records (record_type, record_id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE RESTRICT
)

;

CREATE TABLE retention_policies (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36),
	evidence_category VARCHAR(80),
	retention_days INTEGER NOT NULL,
	version INTEGER DEFAULT '1' NOT NULL,
	status VARCHAR(16) NOT NULL,
	effective_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40),
	created_by VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(created_by) REFERENCES users (id) ON DELETE RESTRICT,
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	CONSTRAINT ck_retention_policy_days CHECK (retention_days >= 1),
	CONSTRAINT ck_retention_policy_status CHECK (status IN ('active','expired','superseded'))
)

;

CREATE TABLE scope_revisions (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	revision INTEGER NOT NULL,
	status VARCHAR(20) NOT NULL,
	created_by VARCHAR(36) NOT NULL,
	approved_by VARCHAR(36),
	created_at VARCHAR(40) NOT NULL,
	published_at VARCHAR(40),
	change_summary VARCHAR(2000) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id, created_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, approved_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_scope_revision_number UNIQUE (engagement_id, revision),
	CONSTRAINT uq_scope_revision_id_org UNIQUE (id, organization_id),
	CONSTRAINT ck_scope_revision_positive CHECK (revision > 0),
	CONSTRAINT ck_scope_revision_status CHECK (status IN ('draft','published'))
)

;

CREATE TABLE authorization_records (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	client_id VARCHAR(36),
	scope_revision_id VARCHAR(36) NOT NULL,
	authorization_reference VARCHAR(160) NOT NULL,
	authorizing_party VARCHAR(200) NOT NULL,
	permitted_techniques JSON NOT NULL,
	effective_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	status VARCHAR(20) NOT NULL,
	recorded_by VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(client_id, organization_id) REFERENCES clients (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(scope_revision_id, organization_id) REFERENCES scope_revisions (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, recorded_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_authorization_id_org UNIQUE (id, organization_id),
	CONSTRAINT uq_authorization_reference UNIQUE (engagement_id, authorization_reference),
	CONSTRAINT ck_authorization_status CHECK (status IN ('active','revoked'))
)

;

CREATE TABLE log_evidence_snapshots (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	asset_id VARCHAR(36) NOT NULL,
	registered_by VARCHAR(36) NOT NULL,
	source_format VARCHAR(24) NOT NULL,
	label VARCHAR(120) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	size_bytes INTEGER NOT NULL,
	file_count INTEGER NOT NULL,
	manifest JSON NOT NULL,
	manifest_version INTEGER NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	status VARCHAR(20) NOT NULL,
	legal_hold INTEGER DEFAULT '0' NOT NULL,
	hold_reason VARCHAR(500),
	deleted_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(asset_id, organization_id, engagement_id) REFERENCES engagement_assets (id, organization_id, engagement_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, registered_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_log_snapshot_scope UNIQUE (id, organization_id, engagement_id, asset_id),
	CONSTRAINT uq_log_snapshot_asset UNIQUE (asset_id),
	CONSTRAINT ck_log_snapshot_size CHECK (size_bytes BETWEEN 0 AND 250000000),
	CONSTRAINT ck_log_snapshot_file_count CHECK (file_count BETWEEN 1 AND 10000),
	CONSTRAINT ck_log_manifest_version CHECK (manifest_version = 1),
	CONSTRAINT ck_log_snapshot_status CHECK (status IN ('available','missing','corrupt','deleted')),
	CONSTRAINT ck_log_snapshot_hold CHECK (legal_hold IN (0,1))
)

;

CREATE TABLE malware_evidence_snapshots (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	asset_id VARCHAR(36) NOT NULL,
	registered_by VARCHAR(36) NOT NULL,
	source_registry_id VARCHAR(80) NOT NULL,
	original_filename VARCHAR(255) NOT NULL,
	classification VARCHAR(40) NOT NULL,
	object_key VARCHAR(64) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	size_bytes INTEGER NOT NULL,
	file_type VARCHAR(120) DEFAULT 'unknown' NOT NULL,
	manifest JSON NOT NULL,
	manifest_sha256 VARCHAR(64) NOT NULL,
	manifest_version INTEGER NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	status VARCHAR(20) NOT NULL,
	legal_hold INTEGER DEFAULT '0' NOT NULL,
	hold_reason VARCHAR(500),
	deleted_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(asset_id, organization_id, engagement_id) REFERENCES engagement_assets (id, organization_id, engagement_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, registered_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_malware_snapshot_scope UNIQUE (id, organization_id, engagement_id, asset_id),
	CONSTRAINT uq_malware_snapshot_asset UNIQUE (asset_id),
	CONSTRAINT uq_malware_snapshot_object UNIQUE (object_key),
	CONSTRAINT ck_malware_snapshot_size CHECK (size_bytes BETWEEN 1 AND 67108864),
	CONSTRAINT ck_malware_manifest_version CHECK (manifest_version = 1),
	CONSTRAINT ck_malware_snapshot_status CHECK (status IN ('available','missing','corrupt','deleted')),
	CONSTRAINT ck_malware_snapshot_hold CHECK (legal_hold IN (0,1))
)

;

CREATE TABLE repository_asset_bindings (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	asset_id VARCHAR(36) NOT NULL,
	project_registry_id VARCHAR(80) NOT NULL,
	source_kind VARCHAR(40) NOT NULL,
	snapshot_id VARCHAR(36) NOT NULL,
	snapshot_sha256 VARCHAR(64) NOT NULL,
	created_by VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	display_label VARCHAR(120) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(asset_id, organization_id, engagement_id) REFERENCES engagement_assets (id, organization_id, engagement_id) ON DELETE RESTRICT,
	FOREIGN KEY(snapshot_id, organization_id) REFERENCES repository_snapshots (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, created_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_repository_binding_asset UNIQUE (asset_id),
	CONSTRAINT uq_repository_binding_scope UNIQUE (id, organization_id, engagement_id, asset_id),
	CONSTRAINT ck_repository_source_kind CHECK (source_kind = 'local_project_registry')
)

;

CREATE TABLE scope_rules (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	scope_revision_id VARCHAR(36) NOT NULL,
	asset_id VARCHAR(36) NOT NULL,
	asset_type_snapshot VARCHAR(20) NOT NULL,
	target_snapshot VARCHAR(2048) NOT NULL,
	effect VARCHAR(10) NOT NULL,
	match_mode VARCHAR(20) NOT NULL,
	techniques JSON NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(scope_revision_id, organization_id) REFERENCES scope_revisions (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(asset_id, organization_id) REFERENCES engagement_assets (id, organization_id) ON DELETE RESTRICT,
	CONSTRAINT ck_scope_rule_effect CHECK (effect IN ('include','exclude')),
	CONSTRAINT ck_scope_rule_match_mode CHECK (match_mode IN ('exact','subdomains','network','url_prefix'))
)

;

CREATE TABLE approval_requests (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	requester_user_id VARCHAR(36) NOT NULL,
	approver_user_id VARCHAR(36),
	asset_type VARCHAR(20) NOT NULL,
	target VARCHAR(2048) NOT NULL,
	technique VARCHAR(80) NOT NULL,
	action_class VARCHAR(24) NOT NULL,
	scope_revision_id VARCHAR(36) NOT NULL,
	authorization_id VARCHAR(36) NOT NULL,
	request_digest VARCHAR(64) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	decision VARCHAR(20) NOT NULL,
	decision_reason VARCHAR(500),
	consumed_at VARCHAR(40),
	consumed_by VARCHAR(36),
	created_at VARCHAR(40) NOT NULL,
	decided_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	CONSTRAINT uq_approval_id_org UNIQUE (id, organization_id),
	FOREIGN KEY(organization_id, requester_user_id) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, approver_user_id) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, consumed_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	FOREIGN KEY(scope_revision_id, organization_id) REFERENCES scope_revisions (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(authorization_id, organization_id) REFERENCES authorization_records (id, organization_id) ON DELETE RESTRICT,
	CONSTRAINT ck_approval_distinct_approver CHECK (approver_user_id IS NULL OR approver_user_id != requester_user_id),
	CONSTRAINT ck_approval_decision CHECK (decision IN ('pending','approved','denied','consumed','expired')),
	CONSTRAINT ck_approval_action_class CHECK (action_class IN ('passive','controlled_active','sensitive'))
)

;

CREATE TABLE authorization_documents (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	authorization_id VARCHAR(36) NOT NULL,
	filename VARCHAR(180) NOT NULL,
	content_type VARCHAR(120) NOT NULL,
	size_bytes INTEGER NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	content BYTEA NOT NULL,
	created_by VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(authorization_id, organization_id) REFERENCES authorization_records (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id, created_by) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_authorization_document_record UNIQUE (authorization_id),
	CONSTRAINT ck_authorization_document_size CHECK (size_bytes BETWEEN 1 AND 10485760)
)

;

CREATE TABLE repository_attestations (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	asset_id VARCHAR(36) NOT NULL,
	authorization_id VARCHAR(36) NOT NULL,
	scope_revision_id VARCHAR(36) NOT NULL,
	actor_user_id VARCHAR(36) NOT NULL,
	attestation_version VARCHAR(40) NOT NULL,
	attestation_text VARCHAR(1000) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(asset_id, organization_id, engagement_id) REFERENCES engagement_assets (id, organization_id, engagement_id) ON DELETE RESTRICT,
	FOREIGN KEY(authorization_id, organization_id) REFERENCES authorization_records (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(scope_revision_id, organization_id) REFERENCES scope_revisions (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id, actor_user_id) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	CONSTRAINT uq_repository_attestation_binding UNIQUE (id, organization_id, engagement_id, asset_id, authorization_id, scope_revision_id),
	CONSTRAINT uq_repository_attestation_id_org UNIQUE (id, organization_id)
)

;

CREATE TABLE execution_jobs (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	requester_user_id VARCHAR(36) NOT NULL,
	asset_id VARCHAR(36) NOT NULL,
	target VARCHAR(2048) NOT NULL,
	asset_type VARCHAR(20) NOT NULL,
	technique VARCHAR(80) NOT NULL,
	action_class VARCHAR(24) NOT NULL,
	scope_revision_id VARCHAR(36) NOT NULL,
	authorization_id VARCHAR(36) NOT NULL,
	authorization_document_sha256 VARCHAR(64),
	policy_request_digest VARCHAR(64),
	repository_binding_id VARCHAR(36),
	repository_snapshot_id VARCHAR(36),
	repository_snapshot_sha256 VARCHAR(64),
	repository_manifest_version INTEGER,
	repository_attestation_id VARCHAR(36),
	repository_scanner_version VARCHAR(80),
	repository_scan_bounds JSON,
	repository_attestation_version VARCHAR(40),
	log_evidence_snapshot_id VARCHAR(36),
	log_evidence_sha256 VARCHAR(64),
	log_evidence_manifest_version INTEGER,
	log_evidence_source_format VARCHAR(24),
	log_analysis_version VARCHAR(80),
	log_ruleset_version VARCHAR(80),
	malware_evidence_snapshot_id VARCHAR(36),
	malware_evidence_sha256 VARCHAR(64),
	malware_evidence_manifest_sha256 VARCHAR(64),
	malware_evidence_manifest_version INTEGER,
	malware_analysis_version VARCHAR(80),
	adapter_id VARCHAR(80),
	adapter_version VARCHAR(80),
	exclusion_policy_version VARCHAR(80),
	approval_id VARCHAR(36),
	policy_decision_id VARCHAR(36) NOT NULL,
	request_digest VARCHAR(64) NOT NULL,
	execution_context JSON NOT NULL,
	idempotency_key VARCHAR(80) NOT NULL,
	status VARCHAR(24) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	started_at VARCHAR(40),
	finished_at VARCHAR(40),
	scan_id VARCHAR(36),
	result_summary JSON,
	approval_consumed_at VARCHAR(40),
	cancellation_requested_at VARCHAR(40),
	cancellation_requested_by VARCHAR(36),
	cancellation_observed_at VARCHAR(40),
	error_code VARCHAR(80),
	worker_id VARCHAR(64),
	lease_generation INTEGER DEFAULT '0' NOT NULL,
	lease_expires_at FLOAT,
	heartbeat_at FLOAT,
	claimed_at VARCHAR(40),
	attempt_number INTEGER DEFAULT '0' NOT NULL,
	last_recovery_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id, requester_user_id) REFERENCES organization_memberships (organization_id, user_id) ON DELETE RESTRICT,
	FOREIGN KEY(asset_id, organization_id, engagement_id) REFERENCES engagement_assets (id, organization_id, engagement_id) ON DELETE RESTRICT,
	FOREIGN KEY(scope_revision_id, organization_id) REFERENCES scope_revisions (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(authorization_id, organization_id) REFERENCES authorization_records (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(approval_id, organization_id) REFERENCES approval_requests (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(repository_binding_id, organization_id, engagement_id, asset_id) REFERENCES repository_asset_bindings (id, organization_id, engagement_id, asset_id) ON DELETE RESTRICT,
	FOREIGN KEY(repository_snapshot_id, organization_id) REFERENCES repository_snapshots (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(repository_attestation_id, organization_id) REFERENCES repository_attestations (id, organization_id) ON DELETE RESTRICT,
	FOREIGN KEY(log_evidence_snapshot_id, organization_id, engagement_id, asset_id) REFERENCES log_evidence_snapshots (id, organization_id, engagement_id, asset_id) ON DELETE RESTRICT,
	FOREIGN KEY(malware_evidence_snapshot_id, organization_id, engagement_id, asset_id) REFERENCES malware_evidence_snapshots (id, organization_id, engagement_id, asset_id) ON DELETE RESTRICT,
	CONSTRAINT uq_execution_job_idempotency UNIQUE (organization_id, engagement_id, requester_user_id, idempotency_key),
	CONSTRAINT ck_execution_job_status CHECK (status IN ('queued','claimed','running','completed','blocked','cancelled','failed','reconciliation_required')),
	CONSTRAINT ck_execution_job_action_class CHECK (action_class IN ('passive','controlled_active','sensitive'))
)

;

CREATE TABLE execution_action_attempts (
	id VARCHAR(36) NOT NULL,
	job_id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	action_sequence INTEGER NOT NULL,
	lease_generation INTEGER NOT NULL,
	worker_id VARCHAR(64) NOT NULL,
	adapter_id VARCHAR(80) NOT NULL,
	operation VARCHAR(80) NOT NULL,
	authorization_id VARCHAR(36) NOT NULL,
	approval_id VARCHAR(36),
	request_digest VARCHAR(64) NOT NULL,
	state VARCHAR(32) NOT NULL,
	started_at VARCHAR(40),
	completed_at VARCHAR(40),
	outcome_classification VARCHAR(40),
	result_reference VARCHAR(120),
	created_at VARCHAR(40) NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES execution_jobs (id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE RESTRICT,
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE RESTRICT,
	CONSTRAINT uq_exec_action_job_seq UNIQUE (job_id, action_sequence),
	CONSTRAINT ck_exec_action_state CHECK (state IN ('not_started','authorized','in_progress','completed','failed_before_dispatch','outcome_uncertain','reconciliation_required'))
)

;

CREATE TABLE execution_capability_snapshots (
	id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	job_id VARCHAR(36),
	profile VARCHAR(24) NOT NULL,
	platform VARCHAR(32) NOT NULL,
	policy_version VARCHAR(40) NOT NULL,
	required_controls JSON NOT NULL,
	available_controls JSON NOT NULL,
	enforced_controls JSON NOT NULL,
	unavailable_controls JSON NOT NULL,
	initialization_status VARCHAR(24) NOT NULL,
	failure_reason VARCHAR(160),
	execution_identity VARCHAR(128),
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	FOREIGN KEY(job_id) REFERENCES execution_jobs (id) ON DELETE SET NULL,
	CONSTRAINT ck_capability_snapshot_status CHECK (initialization_status IN ('initialized','failed','unavailable'))
)

;

CREATE TABLE execution_result_provenance (
	record_type VARCHAR(80) NOT NULL,
	record_id VARCHAR(255) NOT NULL,
	job_id VARCHAR(36) NOT NULL,
	organization_id VARCHAR(36) NOT NULL,
	engagement_id VARCHAR(36) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (record_type, record_id),
	CONSTRAINT ck_execution_result_provenance_type CHECK (record_type IN ('scan','finding','evidence','artifact','report','malware_analysis')),
	FOREIGN KEY(record_type, record_id) REFERENCES records (record_type, record_id) ON DELETE RESTRICT,
	FOREIGN KEY(job_id) REFERENCES execution_jobs (id) ON DELETE RESTRICT,
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE RESTRICT,
	FOREIGN KEY(engagement_id, organization_id) REFERENCES engagements (id, organization_id) ON DELETE RESTRICT
)

;
CREATE UNIQUE INDEX ix_users_email_normalized ON users (email_normalized);
CREATE UNIQUE INDEX ix_organizations_slug ON organizations (slug);
CREATE INDEX ix_user_recovery_codes_user_id ON user_recovery_codes (user_id);
CREATE INDEX ix_user_sessions_expires_at ON user_sessions (expires_at);
CREATE UNIQUE INDEX ix_user_sessions_token_hash ON user_sessions (token_hash);
CREATE INDEX ix_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX ix_clients_organization_id ON clients (organization_id);
CREATE INDEX ix_legal_holds_org_status ON legal_holds (organization_id, status);
CREATE INDEX ix_log_reservation_org ON log_evidence_quota_reservations (organization_id);
CREATE INDEX ix_malware_reservation_org ON malware_evidence_quota_reservations (organization_id);
CREATE INDEX ix_organization_audit_events_organization_id ON organization_audit_events (organization_id);
CREATE INDEX ix_org_invitations_org_email ON organization_invitations (organization_id, email_normalized);
CREATE INDEX ix_organization_invitations_expires_at ON organization_invitations (expires_at);
CREATE UNIQUE INDEX ix_organization_invitations_token_hash ON organization_invitations (token_hash);
CREATE INDEX ix_organization_memberships_organization_id ON organization_memberships (organization_id);
CREATE INDEX ix_organization_memberships_user_id ON organization_memberships (user_id);
CREATE INDEX ix_repository_reservation_org ON repository_quota_reservations (organization_id);
CREATE INDEX ix_repository_snapshot_org_status ON repository_snapshots (organization_id, status);
CREATE INDEX ix_retention_audit_org_time ON retention_audit_events (organization_id, occurred_at);
CREATE INDEX ix_retention_jobs_due ON retention_jobs (organization_id, status);
CREATE INDEX ix_engagements_organization_id ON engagements (organization_id);
CREATE INDEX ix_legal_hold_records_record ON legal_hold_records (organization_id, record_type, record_id);
CREATE INDEX ix_assessment_audit_org_time ON assessment_audit_events (organization_id, occurred_at);
CREATE INDEX ix_assets_engagement ON engagement_assets (organization_id, engagement_id);
CREATE INDEX ix_engagement_assets_organization_id ON engagement_assets (organization_id);
CREATE INDEX ix_engagement_assignments_engagement_id ON engagement_assignments (engagement_id);
CREATE INDEX ix_engagement_assignments_organization_id ON engagement_assignments (organization_id);
CREATE INDEX ix_engagement_assignments_user_id ON engagement_assignments (user_id);
CREATE INDEX ix_record_ownership_organization_id ON record_ownership (organization_id);
CREATE INDEX ix_retention_policy_lookup ON retention_policies (organization_id, status);
CREATE INDEX ix_scope_revisions_engagement ON scope_revisions (organization_id, engagement_id, revision);
CREATE INDEX ix_authorizations_engagement ON authorization_records (organization_id, engagement_id);
CREATE INDEX ix_log_snapshot_tenant ON log_evidence_snapshots (organization_id, engagement_id);
CREATE INDEX ix_malware_snapshot_tenant ON malware_evidence_snapshots (organization_id, engagement_id);
CREATE INDEX ix_repository_binding_tenant ON repository_asset_bindings (organization_id, engagement_id);
CREATE INDEX ix_scope_rules_revision ON scope_rules (organization_id, scope_revision_id);
CREATE INDEX ix_approval_requests_engagement ON approval_requests (organization_id, engagement_id, created_at);
CREATE INDEX ix_approval_requests_pending ON approval_requests (decision, expires_at);
CREATE INDEX ix_repository_attestation_asset ON repository_attestations (organization_id, engagement_id, asset_id);
CREATE INDEX ix_execution_jobs_lease_expiry ON execution_jobs (status, lease_expires_at);
CREATE INDEX ix_execution_jobs_org_status_created ON execution_jobs (organization_id, status, created_at);
CREATE INDEX ix_execution_jobs_queue ON execution_jobs (status, created_at);
CREATE UNIQUE INDEX uq_execution_job_approval_binding ON execution_jobs (approval_id);
CREATE INDEX ix_exec_action_job_state ON execution_action_attempts (job_id, state);
CREATE INDEX ix_capability_snapshots_org_job ON execution_capability_snapshots (organization_id, job_id);
CREATE INDEX ix_execution_result_provenance_job ON execution_result_provenance (job_id, organization_id, engagement_id);
INSERT INTO public.alembic_version(version_num) VALUES ('0016_phase6_governance') ON CONFLICT (version_num) DO NOTHING;

-- The Oracle backend must connect as this dedicated login role.  The role is
-- intentionally provisioned outside this migration because Supabase-managed
-- PostgreSQL may restrict CREATE ROLE in the SQL Editor and the password must
-- never be stored in repository SQL.
DO $$
DECLARE backend_role pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO backend_role FROM pg_roles WHERE rolname = 'chinescan_backend';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'missing prerequisite role chinescan_backend; create it as a non-superuser, non-BYPASSRLS login before applying this migration';
  END IF;
  IF backend_role.rolsuper OR backend_role.rolbypassrls OR NOT backend_role.rolcanlogin THEN
    RAISE EXCEPTION 'role chinescan_backend must be LOGIN, NOSUPERUSER, and NOBYPASSRLS';
  END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO chinescan_backend;
REVOKE ALL ON TABLE public.alembic_version FROM PUBLIC, anon, authenticated;
GRANT SELECT ON TABLE public.alembic_version TO chinescan_backend;
ALTER TABLE public.alembic_version ENABLE ROW LEVEL SECURITY;
CREATE POLICY "alembic_version_read" ON public.alembic_version
  AS PERMISSIVE FOR SELECT TO chinescan_backend USING (true);

REVOKE ALL ON TABLE public."auth_lockouts" FROM anon, authenticated;
ALTER TABLE public."auth_lockouts" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "auth_lockouts_service_role" ON public."auth_lockouts" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."organization_bootstrap_reports" FROM anon, authenticated;
ALTER TABLE public."organization_bootstrap_reports" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "organization_bootstrap_reports_service_role" ON public."organization_bootstrap_reports" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."records" FROM anon, authenticated;
ALTER TABLE public."records" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "records_service_role" ON public."records" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."users" FROM anon, authenticated;
ALTER TABLE public."users" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_service_role" ON public."users" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."worker_leases" FROM anon, authenticated;
ALTER TABLE public."worker_leases" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "worker_leases_service_role" ON public."worker_leases" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."organizations" FROM anon, authenticated;
ALTER TABLE public."organizations" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "organizations_service_role" ON public."organizations" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."user_credentials" FROM anon, authenticated;
ALTER TABLE public."user_credentials" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "user_credentials_service_role" ON public."user_credentials" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."user_recovery_codes" FROM anon, authenticated;
ALTER TABLE public."user_recovery_codes" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "user_recovery_codes_service_role" ON public."user_recovery_codes" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."user_sessions" FROM anon, authenticated;
ALTER TABLE public."user_sessions" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "user_sessions_service_role" ON public."user_sessions" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."clients" FROM anon, authenticated;
ALTER TABLE public."clients" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "clients_service_role" ON public."clients" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."legal_holds" FROM anon, authenticated;
ALTER TABLE public."legal_holds" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "legal_holds_service_role" ON public."legal_holds" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."log_evidence_quota_reservations" FROM anon, authenticated;
ALTER TABLE public."log_evidence_quota_reservations" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "log_evidence_quota_reservations_service_role" ON public."log_evidence_quota_reservations" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."malware_evidence_quota_reservations" FROM anon, authenticated;
ALTER TABLE public."malware_evidence_quota_reservations" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "malware_evidence_quota_reservations_service_role" ON public."malware_evidence_quota_reservations" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."organization_audit_events" FROM anon, authenticated;
ALTER TABLE public."organization_audit_events" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "organization_audit_events_service_role" ON public."organization_audit_events" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."organization_invitations" FROM anon, authenticated;
ALTER TABLE public."organization_invitations" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "organization_invitations_service_role" ON public."organization_invitations" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."organization_memberships" FROM anon, authenticated;
ALTER TABLE public."organization_memberships" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "organization_memberships_service_role" ON public."organization_memberships" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."repository_quota_reservations" FROM anon, authenticated;
ALTER TABLE public."repository_quota_reservations" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "repository_quota_reservations_service_role" ON public."repository_quota_reservations" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."repository_snapshots" FROM anon, authenticated;
ALTER TABLE public."repository_snapshots" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "repository_snapshots_service_role" ON public."repository_snapshots" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."retention_audit_events" FROM anon, authenticated;
ALTER TABLE public."retention_audit_events" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "retention_audit_events_service_role" ON public."retention_audit_events" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."retention_jobs" FROM anon, authenticated;
ALTER TABLE public."retention_jobs" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "retention_jobs_service_role" ON public."retention_jobs" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."engagements" FROM anon, authenticated;
ALTER TABLE public."engagements" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "engagements_service_role" ON public."engagements" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."legal_hold_records" FROM anon, authenticated;
ALTER TABLE public."legal_hold_records" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "legal_hold_records_service_role" ON public."legal_hold_records" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."assessment_audit_events" FROM anon, authenticated;
ALTER TABLE public."assessment_audit_events" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "assessment_audit_events_service_role" ON public."assessment_audit_events" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."engagement_assets" FROM anon, authenticated;
ALTER TABLE public."engagement_assets" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "engagement_assets_service_role" ON public."engagement_assets" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."engagement_assignments" FROM anon, authenticated;
ALTER TABLE public."engagement_assignments" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "engagement_assignments_service_role" ON public."engagement_assignments" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."record_ownership" FROM anon, authenticated;
ALTER TABLE public."record_ownership" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "record_ownership_service_role" ON public."record_ownership" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."retention_policies" FROM anon, authenticated;
ALTER TABLE public."retention_policies" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "retention_policies_service_role" ON public."retention_policies" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."scope_revisions" FROM anon, authenticated;
ALTER TABLE public."scope_revisions" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "scope_revisions_service_role" ON public."scope_revisions" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."authorization_records" FROM anon, authenticated;
ALTER TABLE public."authorization_records" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "authorization_records_service_role" ON public."authorization_records" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."log_evidence_snapshots" FROM anon, authenticated;
ALTER TABLE public."log_evidence_snapshots" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "log_evidence_snapshots_service_role" ON public."log_evidence_snapshots" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."malware_evidence_snapshots" FROM anon, authenticated;
ALTER TABLE public."malware_evidence_snapshots" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "malware_evidence_snapshots_service_role" ON public."malware_evidence_snapshots" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."repository_asset_bindings" FROM anon, authenticated;
ALTER TABLE public."repository_asset_bindings" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "repository_asset_bindings_service_role" ON public."repository_asset_bindings" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."scope_rules" FROM anon, authenticated;
ALTER TABLE public."scope_rules" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "scope_rules_service_role" ON public."scope_rules" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."approval_requests" FROM anon, authenticated;
ALTER TABLE public."approval_requests" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "approval_requests_service_role" ON public."approval_requests" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."authorization_documents" FROM anon, authenticated;
ALTER TABLE public."authorization_documents" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "authorization_documents_service_role" ON public."authorization_documents" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."repository_attestations" FROM anon, authenticated;
ALTER TABLE public."repository_attestations" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "repository_attestations_service_role" ON public."repository_attestations" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."execution_jobs" FROM anon, authenticated;
ALTER TABLE public."execution_jobs" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "execution_jobs_service_role" ON public."execution_jobs" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."execution_action_attempts" FROM anon, authenticated;
ALTER TABLE public."execution_action_attempts" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "execution_action_attempts_service_role" ON public."execution_action_attempts" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."execution_capability_snapshots" FROM anon, authenticated;
ALTER TABLE public."execution_capability_snapshots" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "execution_capability_snapshots_service_role" ON public."execution_capability_snapshots" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public."execution_result_provenance" FROM anon, authenticated;
ALTER TABLE public."execution_result_provenance" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "execution_result_provenance_service_role" ON public."execution_result_provenance" AS PERMISSIVE FOR ALL TO service_role USING (true) WITH CHECK (true);
-- Browser roles receive no application-table access. The backend must use a protected role.
CREATE OR REPLACE FUNCTION public.chinescan_action_attempt_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'execution action attempt history is retained'; END IF; IF TG_OP = 'UPDATE' AND (NEW.job_id, NEW.organization_id, NEW.engagement_id, NEW.action_sequence, NEW.lease_generation, NEW.worker_id, NEW.adapter_id, NEW.operation, NEW.authorization_id, NEW.approval_id, NEW.request_digest) IS DISTINCT FROM (OLD.job_id, OLD.organization_id, OLD.engagement_id, OLD.action_sequence, OLD.lease_generation, OLD.worker_id, OLD.adapter_id, OLD.operation, OLD.authorization_id, OLD.approval_id, OLD.request_digest) THEN RAISE EXCEPTION 'execution action attempt context is immutable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER execution_action_attempt_guard BEFORE UPDATE OR DELETE ON public.execution_action_attempts FOR EACH ROW EXECUTE FUNCTION public.chinescan_action_attempt_guard();

-- The application uses an organization-scoped session rather than Supabase
-- Auth identities.  These helpers are intentionally deny-by-default: a
-- backend connection must set LOCAL chinescan.user_id and
-- chinescan.organization_id after authenticating the existing session.
CREATE OR REPLACE FUNCTION public.chinescan_current_user_id() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT NULLIF(current_setting('chinescan.user_id', true), '')
$$;
CREATE OR REPLACE FUNCTION public.chinescan_current_organization_id() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT NULLIF(current_setting('chinescan.organization_id', true), '')
$$;
CREATE OR REPLACE FUNCTION public.chinescan_is_org_member(candidate_org_id text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.organization_memberships membership
     WHERE membership.organization_id = candidate_org_id
       AND membership.user_id = public.chinescan_current_user_id()
       AND membership.status = 'active'
  )
$$;
CREATE OR REPLACE FUNCTION public.chinescan_is_org_admin(candidate_org_id text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.organization_memberships membership
     WHERE membership.organization_id = candidate_org_id
       AND membership.user_id = public.chinescan_current_user_id()
       AND membership.status = 'active'
       AND membership.role IN ('owner', 'admin')
  )
$$;

-- First administrator bootstrap.  The backend role may call these functions,
-- but cannot insert the initial membership directly because membership tables
-- remain RLS-protected.  The functions are one-time, exact-email, and
-- SECURITY DEFINER; no password or cleartext setup token is stored in SQL.
CREATE OR REPLACE FUNCTION public.chinescan_bootstrap_first_superuser(
  p_email text,
  p_user_id text,
  p_organization_id text,
  p_token_hash text,
  p_expires_at double precision
) RETURNS TABLE(user_id text, created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  stamp text := clock_timestamp()::text;
BEGIN
  IF lower(trim(p_email)) <> 'cipherchi@proton.me' THEN
    RAISE EXCEPTION 'first administrator email is fixed';
  END IF;
  IF p_token_hash IS NULL OR length(p_token_hash) <> 64 OR p_expires_at <= extract(epoch FROM clock_timestamp()) THEN
    RAISE EXCEPTION 'first administrator bootstrap material is invalid';
  END IF;
  IF EXISTS (SELECT 1 FROM public.users WHERE platform_role = 'superuser') THEN
    RAISE EXCEPTION 'first administrator already exists';
  END IF;
  IF EXISTS (SELECT 1 FROM public.users WHERE email_normalized = 'cipherchi@proton.me') THEN
    RAISE EXCEPTION 'first administrator email is already registered';
  END IF;

  INSERT INTO public.users (
    id, email_normalized, display_name, status, platform_role,
    auth_epoch, created_at, updated_at
  ) VALUES (
    p_user_id, 'cipherchi@proton.me', 'cipherchi@proton.me', 'active', 'superuser',
    md5(random()::text || clock_timestamp()::text), stamp, stamp
  );
  INSERT INTO public.organizations (
    id, name, slug, status, owner_user_id, created_at, updated_at
  ) VALUES (
    p_organization_id, 'ChineScan Administration',
    'chinescan-administration', 'active', p_user_id, stamp, stamp
  );
  INSERT INTO public.organization_memberships (
    id, organization_id, user_id, role, status, created_at, updated_at
  ) VALUES (
    md5(random()::text || clock_timestamp()::text), p_organization_id, p_user_id,
    'owner', 'active', stamp, stamp
  );
  INSERT INTO public.user_credentials (
    user_id, password_hash, totp_enabled, totp_last_counter,
    totp_verify_failed_at, bootstrap_token_hash, bootstrap_expires_at,
    created_at, updated_at
  ) VALUES (
    p_user_id, NULL, 0, -1, '[]'::json, p_token_hash, p_expires_at, stamp, stamp
  );
  INSERT INTO public.organization_audit_events (
    id, organization_id, actor_user_id, action, resource_type, resource_id, created_at
  ) VALUES (
    md5(random()::text || clock_timestamp()::text), p_organization_id, p_user_id,
    'platform.superuser_bootstrap_started', 'user', p_user_id, stamp
  );
  RETURN QUERY SELECT p_user_id, true;
END
$$;

CREATE OR REPLACE FUNCTION public.chinescan_complete_first_superuser_setup(
  p_token_hash text,
  p_password_hash text,
  p_auth_epoch text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  selected_user_id text;
  selected_org_id text;
  stamp text := clock_timestamp()::text;
BEGIN
  IF p_token_hash IS NULL OR length(p_token_hash) <> 64
     OR p_password_hash IS NULL OR length(p_password_hash) = 0
     OR p_auth_epoch IS NULL OR length(p_auth_epoch) = 0 THEN
    RAISE EXCEPTION 'first administrator setup material is invalid';
  END IF;
  SELECT credential.user_id, membership.organization_id
    INTO selected_user_id, selected_org_id
    FROM public.user_credentials credential
    JOIN public.users account ON account.id = credential.user_id
    JOIN public.organization_memberships membership
      ON membership.user_id = account.id AND membership.role = 'owner'
   WHERE account.email_normalized = 'cipherchi@proton.me'
     AND account.platform_role = 'superuser'
     AND account.status = 'active'
     AND credential.password_hash IS NULL
     AND credential.bootstrap_token_hash = p_token_hash
     AND credential.bootstrap_used_at IS NULL
     AND credential.bootstrap_expires_at > extract(epoch FROM clock_timestamp())
   FOR UPDATE;
  IF selected_user_id IS NULL THEN
    RAISE EXCEPTION 'first administrator setup token is invalid or expired';
  END IF;
  UPDATE public.user_credentials
     SET password_hash = p_password_hash,
         password_updated_at = stamp,
         bootstrap_used_at = extract(epoch FROM clock_timestamp()),
         updated_at = stamp
   WHERE user_id = selected_user_id;
  UPDATE public.users
     SET auth_epoch = p_auth_epoch, updated_at = stamp
   WHERE id = selected_user_id;
  INSERT INTO public.organization_audit_events (
    id, organization_id, actor_user_id, action, resource_type, resource_id, created_at
  ) VALUES (
    md5(random()::text || clock_timestamp()::text), selected_org_id, selected_user_id,
    'platform.superuser_password_initialized', 'user', selected_user_id, stamp
  );
  RETURN selected_user_id;
END
$$;

CREATE OR REPLACE FUNCTION public.chinescan_execution_job_state_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT (
      (OLD.status = 'queued' AND NEW.status IN ('claimed', 'blocked', 'cancelled')) OR
      (OLD.status = 'claimed' AND NEW.status IN ('queued', 'running', 'blocked', 'cancelled', 'failed', 'reconciliation_required')) OR
      (OLD.status = 'running' AND NEW.status IN ('queued', 'completed', 'blocked', 'cancelled', 'failed', 'reconciliation_required')) OR
      (OLD.status = 'reconciliation_required' AND NEW.status IN ('completed', 'failed', 'blocked', 'cancelled'))
    ) THEN
      RAISE EXCEPTION 'invalid execution job state transition';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER execution_job_state_guard BEFORE UPDATE OF status ON public.execution_jobs
FOR EACH ROW EXECUTE FUNCTION public.chinescan_execution_job_state_guard();

CREATE OR REPLACE FUNCTION public.chinescan_execution_job_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'execution jobs are retained'; END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.organization_id, NEW.engagement_id, NEW.requester_user_id, NEW.asset_id,
    NEW.target, NEW.asset_type, NEW.technique, NEW.action_class,
    NEW.scope_revision_id, NEW.authorization_id,
    NEW.repository_binding_id, NEW.repository_snapshot_id, NEW.repository_snapshot_sha256,
    NEW.repository_manifest_version, NEW.repository_attestation_id,
    NEW.repository_scanner_version, NEW.repository_scan_bounds,
    NEW.repository_attestation_version, NEW.log_evidence_snapshot_id,
    NEW.log_evidence_sha256, NEW.log_evidence_manifest_version,
    NEW.log_evidence_source_format, NEW.malware_evidence_snapshot_id,
    NEW.malware_evidence_sha256, NEW.malware_evidence_manifest_sha256,
    NEW.malware_evidence_manifest_version, NEW.adapter_id, NEW.adapter_version,
    NEW.exclusion_policy_version, NEW.approval_id, NEW.policy_decision_id,
    NEW.request_digest, NEW.execution_context
  ) IS DISTINCT FROM (
    OLD.organization_id, OLD.engagement_id, OLD.requester_user_id, OLD.asset_id,
    OLD.target, OLD.asset_type, OLD.technique, OLD.action_class,
    OLD.scope_revision_id, OLD.authorization_id,
    OLD.repository_binding_id, OLD.repository_snapshot_id, OLD.repository_snapshot_sha256,
    OLD.repository_manifest_version, OLD.repository_attestation_id,
    OLD.repository_scanner_version, OLD.repository_scan_bounds,
    OLD.repository_attestation_version, OLD.log_evidence_snapshot_id,
    OLD.log_evidence_sha256, OLD.log_evidence_manifest_version,
    OLD.log_evidence_source_format, OLD.malware_evidence_snapshot_id,
    OLD.malware_evidence_sha256, OLD.malware_evidence_manifest_sha256,
    OLD.malware_evidence_manifest_version, OLD.adapter_id, OLD.adapter_version,
    OLD.exclusion_policy_version, OLD.approval_id, OLD.policy_decision_id,
    OLD.request_digest, OLD.execution_context
  ) THEN RAISE EXCEPTION 'execution context is immutable'; END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS execution_job_guard ON public.execution_jobs;
CREATE TRIGGER execution_job_guard BEFORE UPDATE OR DELETE ON public.execution_jobs
FOR EACH ROW EXECUTE FUNCTION public.chinescan_execution_job_guard();

CREATE OR REPLACE FUNCTION public.chinescan_execution_job_auth_document_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND NEW.authorization_document_sha256 IS DISTINCT FROM OLD.authorization_document_sha256 THEN
    RAISE EXCEPTION 'execution authorization digest is immutable';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER execution_job_auth_document_guard BEFORE UPDATE ON public.execution_jobs
FOR EACH ROW EXECUTE FUNCTION public.chinescan_execution_job_auth_document_guard();

CREATE OR REPLACE FUNCTION public.chinescan_append_only_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END
$$;
CREATE TRIGGER organization_audit_events_append_only BEFORE UPDATE OR DELETE ON public.organization_audit_events
FOR EACH ROW EXECUTE FUNCTION public.chinescan_append_only_guard();
CREATE TRIGGER assessment_audit_events_append_only BEFORE UPDATE OR DELETE ON public.assessment_audit_events
FOR EACH ROW EXECUTE FUNCTION public.chinescan_append_only_guard();
CREATE TRIGGER retention_audit_events_append_only BEFORE UPDATE OR DELETE ON public.retention_audit_events
FOR EACH ROW EXECUTE FUNCTION public.chinescan_append_only_guard();

CREATE OR REPLACE FUNCTION public.chinescan_result_provenance_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'result provenance is immutable'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.execution_jobs job
     WHERE job.id = NEW.job_id
       AND job.organization_id = NEW.organization_id
       AND job.engagement_id = NEW.engagement_id
  ) THEN RAISE EXCEPTION 'result provenance scope mismatch'; END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER execution_result_provenance_guard BEFORE INSERT OR UPDATE OR DELETE ON public.execution_result_provenance
FOR EACH ROW EXECUTE FUNCTION public.chinescan_result_provenance_guard();

CREATE OR REPLACE FUNCTION public.chinescan_log_snapshot_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'evidence snapshot history is retained'; END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.organization_id, NEW.engagement_id, NEW.asset_id, NEW.registered_by,
    NEW.sha256, NEW.size_bytes, NEW.file_count, NEW.manifest, NEW.manifest_version, NEW.created_at
  ) IS DISTINCT FROM (
    OLD.organization_id, OLD.engagement_id, OLD.asset_id, OLD.registered_by,
    OLD.sha256, OLD.size_bytes, OLD.file_count, OLD.manifest, OLD.manifest_version, OLD.created_at
  ) THEN RAISE EXCEPTION 'evidence snapshot metadata is immutable'; END IF;
  RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION public.chinescan_malware_snapshot_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'evidence snapshot history is retained'; END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.organization_id, NEW.engagement_id, NEW.asset_id, NEW.registered_by,
    NEW.sha256, NEW.size_bytes, NEW.manifest, NEW.manifest_sha256,
    NEW.manifest_version, NEW.object_key, NEW.created_at
  ) IS DISTINCT FROM (
    OLD.organization_id, OLD.engagement_id, OLD.asset_id, OLD.registered_by,
    OLD.sha256, OLD.size_bytes, OLD.manifest, OLD.manifest_sha256,
    OLD.manifest_version, OLD.object_key, OLD.created_at
  ) THEN RAISE EXCEPTION 'evidence snapshot metadata is immutable'; END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER log_evidence_snapshot_guard BEFORE UPDATE OR DELETE ON public.log_evidence_snapshots
FOR EACH ROW EXECUTE FUNCTION public.chinescan_log_snapshot_guard();
CREATE TRIGGER malware_evidence_snapshot_guard BEFORE UPDATE OR DELETE ON public.malware_evidence_snapshots
FOR EACH ROW EXECUTE FUNCTION public.chinescan_malware_snapshot_guard();

CREATE OR REPLACE FUNCTION public.chinescan_repository_append_only_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'repository provenance records are append-only';
END
$$;
CREATE TRIGGER repository_asset_bindings_append_only BEFORE UPDATE OR DELETE ON public.repository_asset_bindings
FOR EACH ROW EXECUTE FUNCTION public.chinescan_repository_append_only_guard();
CREATE TRIGGER repository_attestations_append_only BEFORE UPDATE OR DELETE ON public.repository_attestations
FOR EACH ROW EXECUTE FUNCTION public.chinescan_repository_append_only_guard();

CREATE OR REPLACE FUNCTION public.chinescan_repository_snapshot_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND (
    NEW.sha256, NEW.size_bytes, NEW.manifest, NEW.manifest_version,
    NEW.scanner_version, NEW.created_at
  ) IS DISTINCT FROM (
    OLD.sha256, OLD.size_bytes, OLD.manifest, OLD.manifest_version,
    OLD.scanner_version, OLD.created_at
  ) THEN RAISE EXCEPTION 'repository snapshot metadata is immutable'; END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER repository_snapshot_metadata_guard BEFORE UPDATE ON public.repository_snapshots
FOR EACH ROW EXECUTE FUNCTION public.chinescan_repository_snapshot_guard();

CREATE OR REPLACE FUNCTION public.chinescan_published_scope_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.status = 'published' THEN
    RAISE EXCEPTION 'published scope revisions are immutable';
  ELSIF TG_OP = 'UPDATE' THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' AND OLD.status = 'published' THEN
    RAISE EXCEPTION 'published scope revisions are immutable';
  ELSIF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER scope_revision_published_guard BEFORE UPDATE OR DELETE ON public.scope_revisions
FOR EACH ROW EXECUTE FUNCTION public.chinescan_published_scope_guard();

CREATE OR REPLACE FUNCTION public.chinescan_published_scope_rule_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE old_published boolean;
DECLARE new_published boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT status = 'published' INTO new_published FROM public.scope_revisions WHERE id = NEW.scope_revision_id;
    IF COALESCE(new_published, false) THEN
      RAISE EXCEPTION 'published scope rules are immutable';
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    SELECT status = 'published' INTO old_published FROM public.scope_revisions WHERE id = OLD.scope_revision_id;
    SELECT status = 'published' INTO new_published FROM public.scope_revisions WHERE id = NEW.scope_revision_id;
    IF COALESCE(old_published, false) OR COALESCE(new_published, false) THEN
      RAISE EXCEPTION 'published scope rules are immutable';
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    SELECT status = 'published' INTO old_published FROM public.scope_revisions WHERE id = OLD.scope_revision_id;
    IF COALESCE(old_published, false) THEN
      RAISE EXCEPTION 'published scope rules are immutable';
    END IF;
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'unsupported scope rule trigger operation';
END
$$;
CREATE TRIGGER scope_rule_published_guard BEFORE INSERT OR UPDATE OR DELETE ON public.scope_rules
FOR EACH ROW EXECUTE FUNCTION public.chinescan_published_scope_rule_guard();

-- Explicit least-privilege access for the actual Oracle backend role.  Every
-- application table receives table privileges and exactly one backend policy.
-- Organization-scoped tables require the transaction-local membership
-- identity.  Non-organization tables have an explicit backend-only policy;
-- browser roles still have no table privileges.
DO $$
DECLARE
  table_name text;
BEGIN
  FOR table_name IN
    SELECT c.table_name
      FROM information_schema.columns c
     WHERE c.table_schema = 'public' AND c.column_name = 'organization_id'
  LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO chinescan_backend', table_name);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO service_role', table_name);
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon, authenticated', table_name);
    EXECUTE format(
      'CREATE POLICY %I ON public.%I AS PERMISSIVE FOR ALL TO chinescan_backend USING (public.chinescan_is_org_member(organization_id)) WITH CHECK (public.chinescan_is_org_member(organization_id))',
      table_name || '_organization_member_backend', table_name);
  END LOOP;

  FOR table_name IN
    SELECT t.table_name
      FROM information_schema.tables t
     WHERE t.table_schema = 'public'
       AND t.table_type = 'BASE TABLE'
       AND t.table_name <> 'alembic_version'
       AND NOT EXISTS (
         SELECT 1 FROM information_schema.columns c
          WHERE c.table_schema = 'public'
            AND c.table_name = t.table_name
            AND c.column_name = 'organization_id'
       )
  LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO chinescan_backend', table_name);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO service_role', table_name);
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon, authenticated', table_name);
    EXECUTE format(
      'CREATE POLICY %I ON public.%I AS PERMISSIVE FOR ALL TO chinescan_backend USING (true) WITH CHECK (true)',
      table_name || '_backend', table_name);
  END LOOP;
END
$$;

REVOKE EXECUTE ON FUNCTION public.chinescan_current_user_id() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.chinescan_current_organization_id() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.chinescan_is_org_member(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.chinescan_is_org_admin(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.chinescan_bootstrap_first_superuser(text, text, text, text, double precision) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.chinescan_complete_first_superuser_setup(text, text, text) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.chinescan_current_user_id() TO chinescan_backend;
GRANT EXECUTE ON FUNCTION public.chinescan_current_organization_id() TO chinescan_backend;
GRANT EXECUTE ON FUNCTION public.chinescan_is_org_member(text) TO chinescan_backend;
GRANT EXECUTE ON FUNCTION public.chinescan_is_org_admin(text) TO chinescan_backend;
GRANT EXECUTE ON FUNCTION public.chinescan_bootstrap_first_superuser(text, text, text, text, double precision) TO chinescan_backend;
GRANT EXECUTE ON FUNCTION public.chinescan_complete_first_superuser_setup(text, text, text) TO chinescan_backend;

-- Recovery: reissue a fresh token for an existing unactivated first-superuser account.
-- Safe to call only when the account exists, its password is still NULL, and
-- the previous bootstrap token was never consumed.  The user ID, organization,
-- and membership are preserved unchanged.
CREATE OR REPLACE FUNCTION public.chinescan_reissue_first_superuser_token(
  p_email      text,
  p_token_hash text,
  p_expires_at double precision
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  selected_user_id text;
  stamp            text := clock_timestamp()::text;
BEGIN
  IF lower(trim(p_email)) <> 'cipherchi@proton.me' THEN
    RAISE EXCEPTION 'token reissue is restricted to the fixed first-superuser email';
  END IF;
  IF p_token_hash IS NULL OR length(p_token_hash) <> 64
     OR p_expires_at <= extract(epoch FROM clock_timestamp()) THEN
    RAISE EXCEPTION 'reissue bootstrap material is invalid';
  END IF;
  -- The account must exist with no password set and no prior token consumption.
  -- FOR UPDATE prevents concurrent reissue races.
  SELECT account.id INTO selected_user_id
    FROM public.users account
    JOIN public.user_credentials credential ON credential.user_id = account.id
   WHERE account.email_normalized = 'cipherchi@proton.me'
     AND account.platform_role   = 'superuser'
     AND account.status          = 'active'
     AND credential.password_hash       IS NULL
     AND credential.bootstrap_used_at   IS NULL
   FOR UPDATE;
  IF selected_user_id IS NULL THEN
    RAISE EXCEPTION 'no eligible unactivated first-superuser account found; reissue is not permitted';
  END IF;
  -- Atomically replace only the expired token hash and expiry.
  UPDATE public.user_credentials
     SET bootstrap_token_hash  = p_token_hash,
         bootstrap_expires_at  = p_expires_at,
         updated_at            = stamp
   WHERE user_id = selected_user_id;
  RETURN selected_user_id;
END
$$;

REVOKE ALL ON FUNCTION public.chinescan_reissue_first_superuser_token(text, text, double precision) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.chinescan_reissue_first_superuser_token(text, text, double precision) TO chinescan_backend;

COMMIT;
