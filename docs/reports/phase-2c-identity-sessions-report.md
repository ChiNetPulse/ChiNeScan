# Phase 2C — Multi-User Identity, Persistent Sessions & Invitation-Only Account Lifecycle Report

**Date:** 2026-11-25
**Branch:** `main`
**Baseline HEAD:** `c09d3f150003421136790c42ffa96d570606da79`
**Alembic Head:** `0014_multi_user_identity_sessions`
**Status:** Complete (all verification checks passing; Phase 2D not started)

---

## 1. Baseline & Preliminary Investigation

Before Phase 2C edits, the repository was on `main` at `c09d3f150003421136790c42ffa96d570606da79` with Alembic head `0013_governed_chain_trace` and reported Phase 2B baseline `880 passed, 0 failed, 5 deselected`.

Preliminary inspection identified the following compatibility and security requirements:

- Single-operator credentials lived in `operator.json` (`chinescan/core/accounts.py`), using Argon2id password hashing, TOTP secret/replay counter (`totp_last_counter`), and Argon2id-hashed recovery codes.
- `SessionStore` and `ProgressiveLockout` in `chinescan/core/accounts.py` were in-memory only, causing sessions and lockouts to vanish on app restart.
- `OrganizationService.ensure_operator(...)` updated `users.auth_epoch` on startup/login, which would overwrite web-rotated `auth_epoch` values unless reconciled against migrated operator state.
- `chinescan/core/storage/recovery.py` validates exact table sets and Alembic revisions for backup/restore structural verification.
- Existing CLI workflows (`_local_cli_repository`) and Phase 2B tenant isolation / local-operator restrictions on legacy resources (`/api/projects`, `/api/tenant-probe/personal-only`) needed to remain intact.

---

## 2. Database Schema & Alembic Migration (`0014_multi_user_identity_sessions`)

Added [0014_multi_user_identity_sessions.py](file:///C:/GitHub/Chinescan/migrations/versions/0014_multi_user_identity_sessions.py) (`down_revision = "0013_governed_chain_trace"`) and matching SQLAlchemy table definitions in [sqlite.py](file:///C:/GitHub/Chinescan/chinescan/core/storage/sqlite.py):

- Expanded `ck_users_status` on `users` to `('active','suspended','archived','disabled','revoked','pending')`.
  - Uses `op.get_context().autocommit_block()` on SQLite to temporarily disable `PRAGMA foreign_keys` around `op.batch_alter_table("users", recreate="always")` and restore it in a `finally` block so existing child rows referencing `users.id` do not fail `DROP TABLE users`.
- Added `user_credentials` (`user_id` PK/FK, `password_hash`, `totp_enabled`, `totp_secret`, `totp_last_counter`, `totp_pending_secret`, `totp_enrollment_expires_at`, `totp_verify_failed_at`, `migrated_operator_epoch`, `password_updated_at`, timestamps).
- Added `user_recovery_codes` (`id` PK, `user_id` FK, `code_hash`, `used_at`, `created_at`).
- Added `user_sessions` (`id` PK, `token_hash` unique, `user_id` FK, `email_normalized`, `csrf_token`, `auth_epoch`, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`).
- Added `organization_invitations` (`id` PK, `organization_id` FK, `email_normalized`, `role` check `('admin','member','auditor','viewer')`, `token_hash` unique, `invited_by_user_id` FK, `status` check `('pending','accepted','revoked','expired')`, `expires_at`, `accepted_by_user_id`, `accepted_at`, `revoked_at`, `created_at`).
- Added `auth_lockouts` (`key_hash` PK, `failure_count`, `locked_until`, `updated_at`).
- Updated [recovery.py](file:///C:/GitHub/Chinescan/chinescan/core/storage/recovery.py) to recognize `0014_multi_user_identity_sessions` and the 5 new tables during backup/restore structural verification.

---

## 3. Database-Backed Identity, `operator.json` Migration & CLI Compatibility

Implemented [identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py) (`IdentityService`, `IdentityError`, `INVITABLE_ROLES`, `MANAGED_ACCOUNT_STATUSES`):

- **Idempotent operator migration (`migrate_operator_credentials`):** Migrates `operator.json` password hash, TOTP state (`totp_enabled`, `totp_secret`, `totp_last_counter`, pending enrollment), and recovery code hashes into `user_credentials` and `user_recovery_codes` without duplicating rows or resetting `totp_last_counter` to a lower value.
- **Auth epoch reconciliation (`active_auth_epoch_for_operator`):** Preserves DB-rotated `auth_epoch` (e.g., after web password change) when `migrated_operator_epoch == op_epoch`, while allowing offline CLI `reset-password` rotations (`migrated_operator_epoch != op_epoch`) to sync on startup/login.
- **Authentication & TOTP/recovery replay protection:** `authenticate` verifies Argon2id password hashes (with dummy verification on missing/inactive accounts), enforces persistent TOTP counter monotonicity (`totp_last_counter`) and rate limiting, and consumes one-way-hashed recovery codes atomically.

---

## 4. Persistent Sessions, Rotation, CSRF & Lockout Persistence

Updated `SessionStore` and `ProgressiveLockout` in [accounts.py](file:///C:/GitHub/Chinescan/chinescan/core/accounts.py) and wired them into [app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py):

- `SessionStore` persists SHA-256-hashed session tokens, CSRF tokens, `user_id`, `auth_epoch`, and expiry/revocation timestamps in `user_sessions` when `engine` is provided.
- Sessions survive application restarts, rotate on login / password change / invitation acceptance (`rotate()`), and invalidate immediately on `auth_epoch` mismatch or non-`active` account status (`disabled`, `revoked`, `suspended`, `archived`, `pending`).
- `ProgressiveLockout` persists failure counts and `locked_until` timestamps in `auth_lockouts` using `BEGIN IMMEDIATE` transactions so lockouts survive restarts.
- Existing CSRF (`X-CSRF-Token` + `Origin`) and loopback protections remain enforced on all authenticated mutating routes.

---

## 5. Invitation-Only Onboarding Lifecycle

Added invitation management and atomic acceptance across [identity.py](file:///C:/GitHub/Chinescan/chinescan/core/identity.py), [organization_api.py](file:///C:/GitHub/Chinescan/chinescan/web/organization_api.py), and [app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py):

- `GET /api/organizations/{organization_id}/invitations` and `POST /api/organizations/{organization_id}/invitations` (owner/admin scoped to that organization; rejects `owner` role).
- `POST /api/organizations/{organization_id}/invitations/{invitation_id}/revoke`.
- `POST /api/auth/invitations/accept`: unauthenticated endpoint (added to `auth_mutations` in [test_route_security_inventory.py](file:///C:/GitHub/Chinescan/tests/unit/test_route_security_inventory.py)) that atomically consumes pending, non-expired, non-revoked invitations using `BEGIN IMMEDIATE`, creates or verifies existing user credentials, binds organization membership with the invited role, and establishes a rotated session.
- Plaintext invitation tokens are returned once at creation and stored only as SHA-256 hashes.

---

## 6. Account Lifecycle, Password Change & TOTP Management

Added authenticated endpoints in [app.py](file:///C:/GitHub/Chinescan/chinescan/web/app.py):

- `POST /api/auth/password/change`: verifies current password, updates Argon2id hash, rotates `auth_epoch`, revokes prior sessions, and rotates the active session.
- `GET /api/auth/totp`, `POST /api/auth/totp/enroll`, `POST /api/auth/totp/confirm`, `POST /api/auth/totp/disable`, `POST /api/auth/totp/recovery-codes`: persistent per-user TOTP enrollment, confirmation with single-use recovery codes, disablement, and recovery-code regeneration.
- `PATCH /api/auth/users/{user_id}/status`: restricted strictly to the local operator for managing account status (`active`, `disabled`, `revoked`, `suspended`, `archived`); rejects non-operator users (`403`) and immediately invalidates sessions of disabled/revoked accounts.

---

## 7. Phase 2B Security Boundary Preservation

- Non-operator authenticated users can access `/api/organizations` (`200`) for organizations they belong to, while legacy operator-only resources (`/api/projects`, `/api/tenant-probe/personal-only`) remain restricted (`403`).
- Organization-scoped invitation endpoints enforce membership and role (`owner`/`admin`) within the target `organization_id` only.
- Existing Phase 2B tenant isolation, engagement scope/authorization, and worker context revalidation paths were preserved without modification.

---

## 8. Frontend Changes

Updated [types.ts](file:///C:/GitHub/Chinescan/frontend/src/types.ts), [api.ts](file:///C:/GitHub/Chinescan/frontend/src/api.ts), [App.tsx](file:///C:/GitHub/Chinescan/frontend/src/ui/App.tsx), and [OrganizationsWorkspace.tsx](file:///C:/GitHub/Chinescan/frontend/src/ui/OrganizationsWorkspace.tsx):

- Login view supports TOTP/recovery code input and an invitation acceptance form (`token`, `password`, `display_name`).
- `OrganizationsWorkspace` includes organization invitation creation/listing/revocation and an Account Security panel for password change and TOTP enrollment/confirmation/disablement/recovery-code regeneration.

---

## 9. Verification Results

All checks below were executed against the final state of the codebase:

1. **Full Python test suite:**
   - Command: `py -3.12 -m pytest -q --disable-warnings --tb=short --junitxml=artifacts/phase2c-final-20261125-r2.xml`
   - Exit code: `0`
   - Result: **885 passed, 5 deselected, 365 warnings in 1250.76s (0:20:50)**
   - Artifact: [phase2c-final-20261125-r2.xml](file:///C:/GitHub/Chinescan/artifacts/phase2c-final-20261125-r2.xml)
2. **Focused Phase 2C tests:**
   - Command: `py -3.12 -m pytest tests/unit/test_phase2c_identity_sessions.py tests/unit/test_web_api.py::test_session_cookie_persists_across_new_application_instance tests/unit/test_organizations.py::test_legacy_resources_are_restricted_to_local_operator_and_personal_org -q`
   - Exit code: `0` (`7 passed, 0 failed` in `37.49s`; all also included in the full suite run above)
3. **Migration tests:**
   - Command: `py -3.12 -m pytest tests/unit/test_migration.py -q --disable-warnings --tb=short`
   - Exit code: `0` (`7 passed, 7 warnings in 19.26s`; also included in the full suite run above)
4. **Frontend tests, TypeScript check & production build + CSP check:**
   - Command: `Set-Location frontend; npm test -- --run; npx tsc --noEmit; npm run build`
   - Exit code: `0` (`77 passed` across 19 test files, `tsc --noEmit` clean, `vite build` + `check-csp.mjs` passed)
5. **Static analysis & type checking (targeted Phase 2C modules):**
   - `py -3.12 -m ruff check chinescan/core/accounts.py chinescan/core/identity.py chinescan/web/organization_api.py tests/unit/test_phase2c_identity_sessions.py` -> exit `0` (`All checks passed!`)
   - `py -3.12 -m mypy chinescan/core/accounts.py chinescan/core/identity.py chinescan/core/storage/sqlite.py chinescan/web/organization_api.py` -> exit `0` (`Success: no issues found in 4 source files`)
   - `py -3.12 -m mypy chinescan/core/storage/recovery.py` -> exit `0` (`Success: no issues found in 1 source file`)
6. **Alembic heads & upgrade/downgrade:**
   - `py -3.12 -m alembic heads` -> `0014_multi_user_identity_sessions (head)`
   - Upgrade/downgrade/upgrade verified both directly on a temporary SQLite database and via `tests/unit/test_migration.py`.

---

## 10. Git Safety & Working Tree Status

- No files were staged, committed, reset, rebased, cleaned, stashed, or pushed.
- All pre-existing ARTEX changes, Phase 2B reports, and unrelated files were preserved.
- `git diff --check` exited `0` with no whitespace errors.

---

## 11. Residual Risks & Phase Boundary

- Deployment remains single-instance SQLite (`BEGIN IMMEDIATE` serialization); multi-node horizontal scaling is out of scope for Phase 2C.
- `0014_multi_user_identity_sessions` uses `autocommit_block()` around `batch_alter_table("users", recreate="always")` because SQLite requires `PRAGMA foreign_keys=OFF` outside a transaction when dropping a table referenced by foreign keys; this is expected SQLite behavior and is covered by `test_migration.py`.
- Phase 2D has **not** been started.
