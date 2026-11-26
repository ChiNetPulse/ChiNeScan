# Phase 2B Authorization Matrix

Status: policy-derived disposition with API and service regression coverage; this is not a full Cartesian product. The matrix records only combinations allowed by the existing authorization code. No role/assignment combination is implicitly valid: an assignment applies only to an active organization member and active engagement.

## Policy sources

- Organization role and assignment read policy: `chinescan/core/organizations.py::_can_read_engagement`.
- Engagement security policy: `chinescan/core/engagement_security.py::_can_read`, `_can_manage`, `_can_operate`, and `_can_review`.
- Repository record read/write policy: `chinescan/core/storage/sqlite.py::_owned_record`, `member_context`, and write methods.
- HTTP principal establishment and verb gate: `chinescan/web/app.py` organization middleware.
- Resource-specific checks: scan/case/finding/report handlers, `malware_evidence_api.py`, and governed execution admission/cancellation handlers.

## Organization-role disposition

| Active organization role | List/read organization resources | Write ordinary records | Manage engagement/scope | Submit governed execution | Review/approve | Evidence/report export |
|---|---|---|---|---|---|---|
| Owner | Allowed; engagement association still checked by resource-specific policy | Allowed | Allowed | Requires lead/assessor assignment for that engagement | Allowed | Allowed subject to engagement resource authorization |
| Admin | Allowed; engagement association still checked by resource-specific policy | Allowed | Allowed | Requires lead/assessor assignment for that engagement | Allowed | Allowed subject to engagement resource authorization |
| Member | Requires active engagement assignment for engagement-owned resources | Requires active assignment; record layer accepts lead/assessor/reviewer | Requires lead assignment | Requires lead or assessor assignment | Requires lead or reviewer assignment | Requires engagement read access |
| Auditor | Read-only; organization-wide where resource policy permits | Denied | Denied | Denied | Denied | Read/export only where report route permits |
| Viewer | Read-only; organization-wide where resource policy permits | Denied | Denied | Denied | Denied | Read/export only where report route permits |

Note: Owner/admin organization-wide record access does not override governed-execution admission's lead/assessor assignment rule. An unassigned ordinary member has no engagement-owned record access. Route middleware rejects unauthenticated or inactive identity/membership; inaccessible foreign or unassigned resources use not-found behavior on resource routes where disclosure would reveal existence.

## Engagement-assignment disposition for active Member

| Assignment | Read engagement resources | Ordinary record write | Manage engagement/scope | Submit execution | Review/approve |
|---|---|---|---|---|---|
| Lead | Allowed | Allowed | Allowed | Allowed | Allowed |
| Assessor | Allowed | Allowed | Denied | Allowed | Denied |
| Reviewer | Allowed | Allowed at repository record layer and supported case routes | Denied | Denied | Allowed |
| Observer | Allowed | Denied | Denied | Denied | Denied |
| No active assignment | Denied for engagement-owned resources | Denied | Denied | Denied | Denied |

## Resource and operation coverage

| Resource / operation | Authorization boundary | API/regression evidence |
|---|---|---|
| Scans: list/read | Authenticated active membership; tenant ownership; member assignment when applicable; list and total share scoped predicate | `tests/unit/test_tenant_repository_security.py::test_authenticated_members_access_assigned_scans_without_operator_identity` |
| Scans: create/update/delete | Organization write role plus repository write context and ownership; assignment rules apply to member | `tests/unit/test_tenant_repository_security.py::test_member_access_is_assignment_scoped_and_writes_require_assignment_role`; `tests/unit/test_web_api.py` |
| Cases: create/read/report | Authenticated membership, scoped scan/case ownership, write role and engagement access | `test_authenticated_members_access_assigned_scans_without_operator_identity` |
| Findings: read/list | Same tenant ownership and assignment boundary; foreign IDs are non-disclosing | `test_authenticated_members_access_assigned_scans_without_operator_identity` |
| Reports: JSON/Markdown/JSONL | Same membership and engagement resource boundary; response streaming captures authenticated context and does not grant system access | `test_authenticated_members_access_assigned_scans_without_operator_identity`; `tests/unit/test_reporting.py` |
| Evidence and malware evidence | User identity passed to service; active read authorization before fetch; writes/hold/delete and job admission require authorized operation and tenant ownership | `tests/unit/test_governed_malware.py`; `tests/unit/test_engagement_security.py::test_cross_organization_api_ids_cannot_read_assets_authorizations_approvals_or_documents` |
| Execution jobs/results | Persisted job organization/requester/context; job admission requires lead/assessor; cancellation requester or authorized lead/owner/admin; result provenance bound to job | `tests/unit/test_engagement_security.py::test_execution_cancellation_api_is_authenticated_scoped_and_idempotent`; `test_cancellation_rejects_non_owner_and_cross_organization_job_access`; governed worker tests |
| Approval decisions | Reviewer/lead or owner/admin; requester cannot self-approve; approval remains one-use and action-bound | `tests/unit/test_engagement_security.py::test_approval_decision_api_requires_reviewer_or_lead_assignment`; approval lifecycle tests |
| Engagement resources | Active organization membership; assignment filtering for members; owners/admin/auditor/viewer see list according to read policy | `tests/unit/test_organizations.py`; engagement security route tests |

## Distinct route-level decisions exercised

API tests cover allowed and denied cases for assigned assessor, observer, lead, reviewer, owner, admin, auditor and viewer, plus unassigned member, revoked assignment, revoked membership, and foreign organization identifiers. They exercise HTTP authentication, membership, context establishment, service checks, and repository filtering. The reviewer approval API test verifies denied assessor/observer requests leave approval pending and successful reviewer action changes it. Cancellation tests verify denied cross-organization/non-owner access and idempotent authorized cancellation. Report access tests include authorized download/JSONL and foreign or unassigned not-found responses.

## Exclusions and remaining coverage limits

The product has no separate route-level update/delete API for every listed resource; where no route exists, no synthetic permission claim is made. Not every role × assignment × resource × verb combination is instantiated because organization-wide roles do not require an engagement assignment and invalid/inapplicable combinations would be misleading. The current tests are behavior-oriented representatives for each distinct policy boundary. A future route added for a currently absent operation must add route-level permission tests before exposure. Malware evidence and chain-trace endpoints have narrower operation-specific policies and are not treated as ordinary record CRUD.

## 2026-11-25 closure verification

Review found that assignment checks in `_can_operate`, `_can_manage`, `_can_review`, and `decide_approval` could allow a Viewer or Auditor membership to gain write/review authority from a Lead, Assessor, or Reviewer assignment. Effective permissions now intersect organization role and engagement assignment: Owner/Admin retain the existing elevated policy; Member requires the corresponding assignment; Auditor/Viewer remain read-only regardless of assignment. Assignment rows may still exist for read visibility, but do not elevate these roles.

API regression coverage: `tests/unit/test_engagement_security.py::test_approval_decision_api_requires_reviewer_or_lead_assignment` now verifies a Viewer with Reviewer assignment cannot decide an approval and leaves it pending; `test_viewer_with_assessor_assignment_cannot_submit_execution_job` verifies a Viewer with Assessor assignment cannot create a job and that the job table is unchanged. Existing member Reviewer allowed and Member Assessor/Observer denied cases remain in the same API test. Targeted result: 61 passed across engagement security, governed malware, and tenant repository security.

The matrix is not a Cartesian product of every resource/verb and every assignment. It documents current product policy and gives API-level proof for the distinct role-intersection behavior; routes that do not exist remain explicitly excluded. Other resource families are covered by the cited suite tests, but exhaustive role-by-resource coverage is not claimed.
# 2026-11-25 closure delta: assignment must not elevate read-only roles

Source review found that assignment-specific checks in `OrganizationService._has_assignment` and `RepositoryAssessmentService._is_lead_connection` accepted any active organization membership. This meant an active Viewer/Auditor with Lead assignment could reach some management paths despite the organization role being read-only. The assignment predicates now require organization role `member` for assignment-derived capabilities. Explicit Owner/Admin branches remain governed by their existing role checks.

The same rule is applied when previously approved work is revalidated: both `EngagementSecurityService._decision` and `ExecutionGovernanceService._validate_context` now require an Owner/Admin role or Member role together with active Lead/Reviewer assignment. This prevents a reviewer whose membership was downgraded to Viewer from authorizing queued work at claim time.

| Organization role | Assignment | Operation boundary | Expected and implemented result | Regression evidence |
|---|---|---|---|---|
| Viewer | Lead | PATCH engagement / assignment list and update | Deny; assignment cannot elevate the organization role | `test_read_only_role_with_lead_assignment_cannot_manage_engagement_api[viewer]` |
| Auditor | Lead | PATCH engagement / assignment list and update | Deny; auditor remains read-only | `test_read_only_role_with_lead_assignment_cannot_manage_engagement_api[auditor]` |
| Viewer | Lead | Create repository asset | Deny; lead-bound repository write requires write-capable org role | `test_read_only_lead_assignment_cannot_create_repository_asset_api[viewer]` |
| Auditor | Lead | Create repository asset | Deny; lead assignment does not grant mutation authority | `test_read_only_lead_assignment_cannot_create_repository_asset_api[auditor]` |
| Viewer | Reviewer | Decide approval | Deny; approval stays pending | `test_approval_decision_api_requires_reviewer_or_lead_assignment` |
| Viewer | Assessor | Submit governed execution | Deny before job creation | `test_viewer_with_assessor_assignment_cannot_submit_execution_job` |
| Viewer after approval | Reviewer | Worker revalidation / consume approval | Deny; no consumption or external action | `test_sensitive_job_rejects_invalidated_approval_before_action[reviewer_role_downgrade]` |

This is a closure delta, not a complete Cartesian role/assignment/resource/operation test matrix. The existing matrix and earlier API tests cover other boundaries; the cases above close the newly demonstrated assignment elevation paths. Unexercised combinations remain unproven, especially direct HTTP coverage for every role across report, evidence, job management and export operations. Do not infer Phase 2B completion from this delta alone.
