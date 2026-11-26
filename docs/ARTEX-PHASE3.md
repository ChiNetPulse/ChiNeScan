# ARTEX Phase 3 Security and Operations

Phase 3 keeps ARTEX as a disabled-by-default, health-only integration. It does
not add scanning, findings, exports, task execution, malware detonation, or an
upstream credential protocol.

## Outbound destination policy

`chinescan.integrations.artex.network` is the single destination-policy and
transport boundary. Before a request is opened it:

- accepts only `http` or `https` URLs without credentials, path, query, or
  fragment components;
- permits HTTP and arbitrary ports only for an explicit loopback destination
  used by local tests/development;
- requires HTTPS on port 443 for non-loopback destinations;
- normalizes hostnames with IDNA and rejects malformed names;
- resolves every DNS answer and rejects any loopback, private, link-local,
  unspecified, multicast, reserved, IPv4-mapped-private, or other non-global
  address;
- rejects a mixed public/private answer set rather than selecting a seemingly
  safe answer; and
- connects directly to the validated socket address with a pinned transport.

The pinned HTTPS transport retains the configured hostname for the HTTP `Host`
header and TLS SNI/certificate verification. It does not ask the HTTP client to
resolve the hostname again. A fresh connection performs fresh resolution and
validation. Redirects remain rejected by the ARTEX client.

The policy deliberately does not provide a deployment switch for private
network destinations. Deployments that need an internal ARTEX service must
place a controlled public-facing endpoint or an explicitly reviewed local
loopback proxy in front of it; this release does not silently broaden the
allowlist.

## Authentication and status

The current ARTEX contract exposes only a read-only health endpoint and no
supported service authentication scheme. The client therefore sends no
credentials and does not invent an authorization protocol. The authenticated
status endpoint and dashboard panel report only safe state (`disabled`,
`unknown`, `available`, `unavailable`, or `invalid`), configuration readiness,
the health-only capability, and an explicit `unsupported_health_only`
authentication marker. Credentials, authorization headers, raw upstream bodies,
and configured URLs are not returned or logged.

If a future ARTEX release defines authentication, it must be added as a typed
secret-management/configuration change with rotation and redaction tests before
the integration is enabled for anything beyond health checks. Missing or
invalid configuration continues to fail closed.

## Reconciliation of uncertain actions

Governed execution now exposes a narrow reconciliation workflow for an action
that may have reached the external system:

- only organization managers can list reconciliation-required jobs;
- only the owning organization and engagement can be addressed;
- a resolution must be `confirmed_success` or `confirmed_failure` and include
  a short operator evidence reference;
- every accepted or rejected attempt is audit logged; and
- raw execution context and upstream response bodies are never returned.

The service does not claim exactly-once external execution. An uncertain action
is not automatically retried. A confirmed failure retains the uncertain action
attempt and records the operator classification so the original ambiguity and
audit trail remain intact.

## Operator checks and recovery

Use the authenticated system-status panel or `GET
/api/integrations/artex/status` to distinguish disabled, misconfigured,
unavailable, and healthy states. `GET /api/integrations/artex/health` performs
one read-only check only after explicit enablement and rate limiting. Keep
egress restricted to the configured ARTEX host and port 443, and monitor the
audit events `health_requested`, `health_succeeded`, `health_failed`, and
`execution.reconciliation_*` without exposing their secret material.

SQLite remains the supported single-instance deployment baseline. Back up the
database and managed evidence according to the deployment runbook before
performing operator reconciliation. No distributed worker or PostgreSQL
deployment is introduced by Phase 3.
