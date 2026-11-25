# Phase 2C — Final Security Acceptance Review

**Date:** 2026-11-25
**Reviewer Mode:** Strictly read-only security acceptance review (no source or test modifications)
**Branch:** `main`
**HEAD:** `c09d3f150003421136790c42ffa96d570606da79`
**Alembic Head:** `0014_multi_user_identity_sessions`
**Reviewed Report:** [phase-2c-identity-sessions-report.md](file:///C:/GitHub/Chinescan/docs/reports/phase-2c-identity-sessions-report.md)

---

## Review 1 — Legacy Operator Migration

- **[VERIFIED] Existing password verification after migration:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L56-L107) (`test_operator_migration_preserves_password_totp_recovery_and_is_idempotent`) creates an `operator.json`, initializes the app, and verifies authentication succeeds with the migrated password via `identity.authenticate(...)`.
- **[VERIFIED] TOTP secret and replay-counter preservation:** The same test generates a live TOTP code, authenticates, closes and recreates the app (`app2 = create_app(...)`), and asserts replaying the same TOTP code returns `None` (`totp_last_counter` preserved in `user_credentials`).
- **[VERIFIED] Recovery-code preservation and one-use behavior:** The same test asserts `10` recovery codes exist in `user_recovery_codes`, authenticates once with `recovery_codes[0]` across app restart, and asserts replay fails (`None`).
- **[VERIFIED] Migration idempotency and no credential duplication:** The same test invokes `identity.migrate_operator_credentials(cred, op_id)` a second time, asserts it returns `False`, and asserts `user_recovery_codes` count remains `10`.
- **[INSPECTED] Interrupted migration and safe retry:** `IdentityService.migrate_operator_credentials` ([identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py#L123-L215)) executes inside `BEGIN IMMEDIATE` with explicit `rollback()` on exception, and `signup` ([app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py#L1753-L1767)) leaves `operator.json` intact on DB failure (returning HTTP 503) so startup/login retries idempotently. No fault-injection test simulates a mid-transaction crash.
- **[INSPECTED] No deletion or destructive replacement of legacy credential source:** `migrate_operator_credentials` ([identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py#L88-L93)) only reads `operator.json` via `_read_credential_file` and never deletes or overwrites it. No test explicitly asserts `operator.json` bytes/mtime remain unchanged.

---

## Review 2 — Persistent Session Security

- **[VERIFIED] Expiration and concurrent validation/revocation safety:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L161-L190) (`test_session_expiration_and_concurrent_validation_revocation`) verifies idle TTL expiration and concurrent 4-thread `Barrier` execution of `store.revoke(tok)` and `store.get(tok)`.
- **[VERIFIED] Session rotation on login and password change + restart survival:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L109-L158) (`test_persistent_sessions_rotation_expiration_and_disabled_rejection`) verifies re-login rotates the cookie and invalidates the prior token, password change requires CSRF (`403` without header), rotates the session token, invalidates the old token, and the rotated session survives app restart (`GET /api/auth/me` -> `200`). Also verified by [test_web_api.py](file:///C:/GitHub/Chinescan/tests/unit/test_web_api.py#L1880-L1890).
- **[VERIFIED] Account disablement invalidates existing sessions:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L367-L382) verifies disabling an invited user via `PATCH /api/auth/users/{user_id}/status` immediately causes their active session to receive `401` on `GET /api/organizations` and blocks subsequent login (`401`).
- **[VERIFIED] CSRF and loopback protections:** [test_route_security_inventory.py](file:///C:/GitHub/Chinescan/tests/unit/test_route_security_inventory.py#L37-L93) verifies all authenticated mutating routes reject missing CSRF headers (`401`/`403`).
- **[INSPECTED] Cryptographic unpredictability and DB disclosure protection:** `SessionStore.create` ([accounts.py](file:///C:/GitHub/Chinescan/chinescan/core/accounts.py#L619-L630)) generates `secrets.token_urlsafe(32)` for both the session token and CSRF token, and persists only SHA-256 (`hashlib.sha256`) digests in `user_sessions.token_hash`.
- **[INSPECTED] Logout revocation, absolute TTL in DB mode, and `"revoked"` status:** `/api/auth/logout` ([app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py#L1819-L1829)) requires CSRF and calls `sessions.revoke(token)`. Absolute TTL (`expires_at <= now`) is checked alongside idle TTL in `SessionStore.get` ([accounts.py](file:///C:/GitHub/Chinescan/chinescan/core/accounts.py#L696-L705)), and `set_account_status` revokes sessions for any status != `"active"` ([identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py#L603-L617)). Missing targeted Phase 2C regression tests: explicit DB-mode absolute-TTL expiry test, explicit `"revoked"` status test, and concurrent `rotate()` contention test.

---

## Review 3 — Invitation Lifecycle

- **[VERIFIED] Role authorization and cross-organization isolation:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L227-L304) verifies `owner` invitations are rejected (`422`), an invited org `admin` can create invitations in their own organization (`201`), and receives `404` when attempting to invite into a second organization.
- **[VERIFIED] Atomic one-use acceptance and concurrency safety:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L247-L270) runs concurrent `accept_invitation` calls behind a 2-thread `Barrier`, asserting 1 success + 1 `IdentityError`, and asserts subsequent replay raises `IdentityError`.
- **[VERIFIED] Expiration, revocation, and existing-user handling:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L306-L365) verifies revoked (`400`) and expired (`400`) invitations are rejected, and inviting an existing active user requires either their current password or matching active session (`400` on wrong password, `200` with matching active session) without creating a duplicate user.
- **[INSPECTED] Token storage security:** `create_invitation` ([identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py#L646-L657)) generates `secrets.token_urlsafe(32)` and stores only SHA-256 `_token_hash(token)` in `organization_invitations.token_hash`.
- **[INSPECTED] Invitation audit events:** `create_invitation`, `revoke_invitation`, and `accept_invitation` ([identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py#L667-L674)) emit `invitation.created`, `invitation.revoked`, `invitation.expired`, and `invitation.accepted` via `OrganizationService._audit(...)`. Missing regression test: no test queries `organization_audit_events` to assert those invitation audit rows.

---

## Review 4 — Account Lifecycle & Tenant Boundaries

- **[VERIFIED] Organization admins cannot acquire global account-management privileges:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L297-L304) verifies an invited org `admin` receives `404` on `PATCH /api/auth/users/{op_id}/status`.
- **[VERIFIED] Disabled users cannot continue using existing sessions:** [test_phase2c_identity_sessions.py](file:///C:/GitHub/Chinescan/tests/unit/test_phase2c_identity_sessions.py#L367-L382).
- **[VERIFIED] Phase 2B fail-closed repository and route boundaries remain intact:** [test_organizations.py](file:///C:/GitHub/Chinescan/tests/unit/test_organizations.py#L575-L623) (`test_legacy_resources_are_restricted_to_local_operator_and_personal_org`) verifies non-operator users access `/api/organizations` (`200`) while `/api/projects` and `/api/tenant-probe/personal-only` return `403`, and [app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py#L1143-L1234) enforces `organization_context` / `member_context` with no unrestricted fallback.
- **[INSPECTED] Web TOTP lifecycle endpoints:** `GET /api/auth/totp`, `POST /api/auth/totp/enroll`, `POST /api/auth/totp/confirm`, `POST /api/auth/totp/disable`, and `POST /api/auth/totp/recovery-codes` ([app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py#L1917-L1976)) are protected by `current_session` and `require_csrf` (CSRF verified by `test_route_security_inventory.py`), but lack end-to-end HTTP happy-path tests in `test_phase2c_identity_sessions.py`.
- **[INSPECTED] Organization membership revocation:** Continues to be enforced via `OrganizationService.membership_context` and `OrganizationService.membership_role` ([app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py#L1191-L1234)).

---

## Review 5 — Migration & Recovery

- **[VERIFIED] Upgrade from `0013_governed_chain_trace`, downgrade behavior, and SQLite FK integrity:** [test_migration.py](file:///C:/GitHub/Chinescan/tests/unit/test_migration.py) (`7 passed`) verifies upgrade to `0014_multi_user_identity_sessions`, downgrade/upgrade roundtrips, and `test_repository_migration_preserves_records_and_enforces_tenant_binding` specifically exercises `users` table recreation while child rows in `organizations`, `organization_memberships`, `engagements`, and `engagement_assets` reference `users.id`.
- **[VERIFIED] Backup and restore structural verification:** [recovery.py](file:///C:/GitHub/Chinescan/chinescan/core/storage/recovery.py#L250-L355) recognizes `0014_multi_user_identity_sessions` and all 5 new tables (`user_credentials`, `user_recovery_codes`, `user_sessions`, `organization_invitations`, `auth_lockouts`), verified across `test_recovery.py`, `test_governed_malware.py`, `test_log_evidence.py`, `test_managed_malware.py`, `test_repository_assessment.py`, `test_engagement_security.py`, and `test_storage.py`.
- **[INSPECTED] Downgrade data-loss safeguard and recovery row preservation:** [0014_multi_user_identity_sessions.py](file:///C:/GitHub/Chinescan/migrations/versions/0014_multi_user_identity_sessions.py#L115-L122) raises `RuntimeError` if `disabled`, `revoked`, or `pending` users exist on downgrade; `backup_database` copies the complete SQLite database file (`recovery.py:1338-1341`). Neither the `0014` downgrade `RuntimeError` nor post-restore row queries on the 5 new tables are explicitly asserted in tests.

---

## Review 6 — Test Evidence

- **Python JUnit XML:** [phase2c-final-20261125-r2.xml](file:///C:/GitHub/Chinescan/artifacts/phase2c-final-20261125-r2.xml) records `tests="885" errors="0" failures="0" skipped="0" time="1250.185"` (matching the reported `885 passed, 5 deselected` full-suite run).
- **Frontend suite:** `npm test -- --run` (`77 passed` across 19 test files), `npx tsc --noEmit`, and `npm run build` (`check-csp.mjs`) all passed prior to this read-only review with no subsequent source/test edits.

---

## Review 7 — Repository Safety

- **Branch & HEAD:** `main` at `c09d3f150003421136790c42ffa96d570606da79`.
- **Staged changes:** None (`git diff --cached --name-only` is empty).
- **ARTEX & existing artifacts:** Preserved (`chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `scripts/make_cover.py`, `tests/unit/test_artex_integration.py`, and all Phase 2B reports/artifacts remain intact).
- **Working tree during review:** Strictly read-only except for creating this acceptance review report.

---

## Final Recommendation

**2. ACCEPT WITH DOCUMENTED LIMITATIONS.**

Phase 2C meets its security, isolation, persistence, migration, and recovery requirements with zero test failures (`885` Python tests passing, `77` frontend tests passing). The non-blocking coverage gaps identified above (fault-injected interrupted migration, web TOTP HTTP happy-path tests, invitation audit-row assertions, DB-mode absolute TTL / `"revoked"` status / `0014` downgrade-guard tests) should be added as follow-up regression tests without blocking Phase 2C acceptance.
