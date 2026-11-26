# Phase 4 Nmap execution foundation

Phase 4 adds a deliberately narrow, governed Nmap adapter. It reuses the
existing engagement policy, immutable scope revision, execution job, worker
lease, action-attempt, audit, provenance, and repository ownership boundaries.
It does not create a second authorization or job system.

## Enablement

Nmap is disabled by default. An administrator must explicitly configure the
`integrations.nmap` settings and provide an already-installed Nmap binary. The
application never downloads or installs Nmap. The configured binary is checked
with `nmap --version` immediately before each execution; an optional expected
major version can be pinned.

## Target and profile policy

The first foundation accepts only registered `ip` and bounded `cidr` assets.
Hostnames are rejected intentionally: resolving a hostname safely requires
binding every answer immediately before execution and handling rebinding, which
is reserved for a separately reviewed resolver design. Targets are normalized
with `ipaddress`, reject shell/control characters, and cannot be supplied as a
free-form scan target.

Only three fixed profiles are available: `host_discovery`,
`basic_port_assessment`, and `service_identification`. Ports are integer values
validated against each profile's bound; arbitrary flags, NSE scripts, output
paths, UDP/aggressive modes, timing controls, and target expressions are not
accepted. Arguments are passed as an argv list with `shell=False` and a `--`
terminator.

## Execution and results

Admission persists the normalized profile and ports inside the immutable
execution context and includes them in the request digest. Worker revalidation
checks the digest, adapter identity, target canonicalization, and parameters
before dispatch. The existing durable lease and action-attempt lifecycle is
used; uncertain outcomes remain subject to the existing reconciliation path.

The subprocess has an explicit timeout and drains stdout through a bounded pipe;
the worker terminates the process when the configured output bound is exceeded.
stderr is discarded rather than exposed.
Nmap XML is parsed with entity/DOCTYPE rejection, host and port limits, strict
IP-address validation, and bounded service strings. Results are stored as
tenant-owned `evidence` records with `evidence_type=nmap_result`, linked to the
execution provenance and a normal `scan` summary. Nmap reconnaissance output is
not a vulnerability verdict.

## API boundary

Authenticated members can inspect fixed profiles and submit a scan only through
the organization/engagement Nmap routes. Submission delegates to
`ExecutionGovernanceService`; membership, engagement assignment, scope,
authorization, idempotency, and policy checks therefore remain server-side.
Cross-organization identifiers return the same not-found/denied behavior as
other governed execution routes. Result retrieval is tenant-scoped through the
existing repository context.

## Deployment limitations

Application validation constrains the target and command. Host firewall,
container, service-account, and egress controls remain deployment
responsibilities; this SQLite single-instance foundation does not claim a
complete OS sandbox or arbitrary network namespace isolation. Operators should
run the worker with least privilege, restrict egress to approved assessment
networks, and keep the Nmap binary and worker filesystem outside application
secret paths. Exactly-once external execution is not claimed.
