# Phase 2F — Unified Frontend, Governed Workflows & Operational Visibility

**Report date:** 2026-11-25
**Branch:** `main`
**HEAD:** `c09d3f150003421136790c42ffa96d570606da79` (unchanged — no commits added in Phase 2F)
**Alembic head:** `0015_durable_job_leases_actions` (unchanged — no backend changes or migrations in Phase 2F)
**Phase 2G status:** Not started.

---

## 1. Initial Repository State

- **Branch:** `main`
- **HEAD:** `c09d3f150003421136790c42ffa96d570606da79`
- **Staged:** None (`git diff --cached --name-only` empty)
- **Baseline frontend:** 19 test files, 77 tests passed; `tsc -b`, `vite build`, and `check:csp` passing.
- **Unrelated work:** ARTEX integration, cover-generation scripts, and Phase 2B–2E backend/test/report work preserved untouched.

---

## 2. Frontend Architecture Inspected

Inspected `frontend/package.json`, `frontend/src/types.ts`, `frontend/src/api.ts`, `frontend/src/ui/App.tsx`, `frontend/src/ui/OrganizationsWorkspace.tsx`, `frontend/src/ui/EngagementSecurityWorkspace.tsx`, `frontend/src/ui/RepositoryAssessmentWorkspace.tsx`, `frontend/src/ui/EngagementLogEvidenceWorkspace.tsx`, `frontend/src/ui/SystemStatus.tsx`, and `frontend/src/ui/styles.css`.

**Gaps identified:**
1. No persistent organization/engagement context selector in `App.tsx`.
2. No unified engagement workspace uniting all 11 operational sections (`Overview`, `Scope & Assets`, `Authorization`, `Repository Assessments`, `Log Evidence`, `Malware Triage`, `Chain Tracing`, `Execution Jobs`, `Findings & Results`, `Reports`, `Audit History`).
3. `ExecutionJob['status']` in `types.ts` omitted `'reconciliation_required'`; no dedicated `UnifiedJobsMonitor` handled `reconciliation_required` warnings and no-auto-retry enforcement.
4. Governed malware evidence (`malware_evidence_api.py`), governed chain tracing (`execution_api.py`), organization quota (`.../executions/quota`), and local-operator diagnostics (`/api/diagnostics/execution-resources`) were not wired into `api.ts`.
5. No dedicated `AccountSecurityWorkspace` view in main navigation.

---

## 3. Pages and Components Implemented

- **`frontend/src/ui/UnifiedEngagementWorkspace.tsx`** (new): Unified engagement workspace with section tabs for Overview, Scope & Assets, Authorization, Repository Assessments, Log Evidence, Malware Triage (explicitly static-only), Chain Tracing (local import vs approved provider lookup), Execution Jobs, Findings & Results, Reports, and Audit History. Clears all previous org/engagement state immediately on context change.
- **`frontend/src/ui/UnifiedJobsMonitor.tsx`** (new): Unified durable job monitor supporting all 8 states (`queued`, `claimed`, `running`, `completed`, `failed`, `blocked`, `cancelled`, `reconciliation_required`), queue wait & execution durations, cancellation, provenance inspection, organization quota strip, and `reconciliation_required` alert banner with no automatic retry/resubmit action.
- **`frontend/src/ui/AccountSecurityWorkspace.tsx`** (new): Profile/status display, password change (with CSRF rotation), TOTP enroll/confirm/disable, recovery-code regeneration (never persisted in browser storage), and invitation acceptance.
- **`frontend/src/ui/App.tsx`** (modified): Persistent Organization & Engagement Context Bar, consolidated navigation (`Engagements`, `Governed Jobs`, `Account security`, plus legacy-tool banner linking into governed workflows), mobile navigation drawer toggle, and local-operator-only `ExecutionResourceDiagnosticsPanel`.
- **`frontend/src/ui/styles.css`** (modified): Responsive mobile sidebar drawer, context bar, section tabs, quota strip, status pills, reconciliation warning styles, and `:focus-visible` keyboard focus indicators.

---

## 4. APIs Integrated

Updated `frontend/src/types.ts` and `frontend/src/api.ts` with:
- `api.executionQuota(org, engagement)` (`GET .../executions/quota`)
- `api.executionResourceDiagnostics()` (`GET /api/diagnostics/execution-resources`)
- `api.malwareEvidence`, `api.registerMalwareEvidence`, `api.startGovernedMalwareTriage`, `api.holdMalwareEvidence`, `api.deleteMalwareEvidence`
- `api.startGovernedChainImport` (`POST .../chain-traces/imports`) & `api.startGovernedChainProviderLookup` (`POST .../chain-traces/provider-lookups`)
- Existing Phase 2B–2E APIs retained (`organizations`, `organizationEngagements`, `engagementAssignments`, `engagementAssets`, `scopeRevisions`, `authorizationRecords`, `approvalRequests`, `governedExecutions`, `governedExecutionProvenance`, `cancelGovernedExecution`, `engagementAudit`, `changePassword`, `totp*`, `acceptInvitation`).

---

## 5. Navigation, Context, Workflows, Jobs & Resource Visibility

- **Navigation & Context:** Switching organization clears `contextEngagements`, `selectedEngId`, and `contextAssignments` immediately before fetching fresh backend data. `UnifiedEngagementWorkspace` and `UnifiedJobsMonitor` purge prior state on `organizationId`/`engagementId` change.
- **Governed Workflows:**
  - *Repository assessment:* Reuses `RepositoryAssessmentWorkspace` via `EngagementSecurityWorkspace`.
  - *Log analysis:* Reuses `EngagementLogEvidenceWorkspace`.
  - *Malware triage:* Uses `api.startGovernedMalwareTriage`; labeled static-only, passive, never executing/detonating/sandboxing.
  - *Chain tracing:* Separates passive `chain_trace_import` from sensitive `chain_provider_lookup` (requires selecting an approved one-use approval).
- **Job Monitoring:** All 8 durable states supported; active polling (`1500ms`) cleans up on unmount/context switch and handles `UnauthorizedError` by signing out. `reconciliation_required` jobs cannot be retried or resubmitted.
- **Resource Visibility:** Organization quota strip uses server-authoritative `api.executionQuota`; global execution resource diagnostics (`api.executionResourceDiagnostics`) are shown only when authorized for the local operator and hidden on 403/denial.

---

## 6. Security Boundaries Preserved

- Backend remains sole authority for identity, roles, assignments, scope, approvals, quotas, and job states.
- No unscoped repository requests or frontend-only privileged context.
- No cross-organization cached state leakage on context switch.
- No automatic retry of sensitive operations.
- No secrets, tokens, or recovery codes persisted in `localStorage`/`sessionStorage`.
- CSRF protection and strict CSP compliance preserved (`npm run check:csp` passed).

---

## 7. Claims Classification

### Implemented and Tested
- Unified job monitor rendering all 8 durable states, `reconciliation_required` alert without retry/resubmit button, cancellation (`api.cancelGovernedExecution`), and quota strip (`test 1` in `Phase2FUnifiedWorkspace.test.tsx`).
- Context switching purging stale tenant/engagement records and submitting static-only malware triage (`test 2` in `Phase2FUnifiedWorkspace.test.tsx`).
- `App.tsx` organization/engagement selector switching and hiding local-operator diagnostics when denied (`test 3` in `Phase2FUnifiedWorkspace.test.tsx`).
- `AccountSecurityWorkspace` password change, TOTP enrollment, and session expiry handling (`test 4` in `Phase2FUnifiedWorkspace.test.tsx`).
- All 19 pre-existing frontend test files (77 tests) passing unchanged.

### Implemented but Not Directly Tested
- Direct form submission of `chain_trace_import` and `chain_provider_lookup` inside `UnifiedEngagementWorkspace` (wired to `api.startGovernedChainImport` / `api.startGovernedChainProviderLookup` and typechecked).
- Direct UI interaction with `UnifiedEngagementWorkspace` Audit History tab and Reports tab link (wired and typechecked).
- Mobile drawer CSS breakpoint rendering (`@media(max-width:900px)`) in a real mobile viewport (covered by CSS + `tsc` + `vite build`, not Playwright E2E).

### Inspected and Retained
- Existing `OrganizationsWorkspace`, `EngagementSecurityWorkspace`, `RepositoryAssessmentWorkspace`, `EngagementLogEvidenceWorkspace`, `CasesWorkspace`, `SystemStatus`, and legacy workspaces.

### Not Implemented / Blocked by Existing Backend Limitations
- Manual operator reconciliation UI action for `reconciliation_required` jobs (no backend reconciliation endpoint exists in Phases 2D/2E).
- Dedicated engagement-scoped `/reports` list endpoint (engagement Reports tab links into existing server-authorized `CasesWorkspace`).

---

## 8. Tests & Checks Executed

| Check | Command | Result |
|---|---|---|
| Frontend full suite | `npm test` (`vitest run`) | **20 test files passed, 81 tests passed** (46.26s) |
| TypeScript check | `tsc -b` (via `npm run build`) | **Passed (0 errors)** |
| Production bundle | `vite build` (via `npm run build`) | **Built 44 modules in 1.12s** |
| Strict CSP check | `npm run check:csp` (via `npm run build`) | **Passed** |

---

## 9. Files Modified & Final Git State

- **New:** `frontend/src/ui/UnifiedEngagementWorkspace.tsx`, `frontend/src/ui/UnifiedJobsMonitor.tsx`, `frontend/src/ui/AccountSecurityWorkspace.tsx`, `frontend/src/ui/Phase2FUnifiedWorkspace.test.tsx`, `docs/reports/phase-2f-unified-frontend-report.md`
- **Modified:** `frontend/src/types.ts`, `frontend/src/api.ts`, `frontend/src/ui/App.tsx`, `frontend/src/ui/styles.css`
- **Final Git State:** Branch `main`, HEAD `c09d3f150003421136790c42ffa96d570606da79`, staged: none, Phase 2G not started.
