# ARTEX bridge — Milestone 1

## Scope and defaults

Milestone 1 implements a disabled-by-default, health-only bridge. It does not
support authenticated ARTEX routes because ARTEX has no verified least-privilege
service identity. Task metadata, findings, export, reports, active operations,
logs, workspace, MCP, traffic bodies, and evidence archives remain unavailable.
The outbound compile-time allowlist contains only `GET /api/health`.

ARTEX data is external and untrusted. The Chinescan API requires an authenticated
local operator session. The health endpoint performs one request per call, never
retries, never follows redirects, validates JSON and a strict three-field shape,
and bounds the response. Non-loopback connections require HTTPS. Restrict network
egress to the configured ARTEX service at deployment time.

## Explicit health enablement

The operator must configure every condition below; all defaults are disabled:

- `integrations.artex.enabled = true`
- `integrations.artex.mode = "health_only"`
- `integrations.artex.health_enabled = true`
- A pinned `release_id` and an absolute `base_url` without user info, path, query,
  or fragment
- `sensitive_data_acknowledged = true` and `retention_policy_acknowledged = true`

No ARTEX credential is accepted or stored. Any authenticated feature flag set to
true is rejected during configuration validation. Environment overrides use
`CHINESCAN_INTEGRATIONS__ARTEX__<FIELD>` (for example `...__ENABLED`).

## Chinescan endpoints

- `GET /api/integrations/artex/status`: authenticated local status; does not
  contact ARTEX.
- `GET /api/integrations/artex/health`: authenticated explicit health check. It
  returns `available` with the validated health object, or a stable error code
  and `unavailable`/`invalid` state. Rate limits are enforced per local client.

Both endpoints are local dashboard routes. Do not expose the dashboard beyond
loopback. The UI must label this data “External ARTEX data”, “Read-only”, and
“Active operations disabled” if a UI is added in a later milestone.

## Persistence and audit

SQLite's existing generic `records` table stores only health sync state under
`artex_sync_state/artex:sync:health`, plus append-style unique audit records under
`artex_audit_event/artex:audit:<uuid>`. The profile and task/finding reference
Pydantic types are secret-free schema definitions; task and finding references
are not populated in this milestone. No schema migration is required. Audit
payloads contain operator identity, correlation ID, configured release ID,
upstream version, outcome, and stable error code; they exclude URL credentials,
headers, and response bodies.

## Failure behavior

Disabled or invalid configuration prevents the request. Connection, HTTP,
content-type, size, JSON, and schema failures return an explicit error/unknown
state and do not imply task completion or findings validity. No raw upstream
error body is returned or logged. Operators should disable the feature and
remove persisted health status/audit data using the approved local retention
procedure when retiring an ARTEX instance.
