# ARTEX Phase 1 & Phase 2 — Architectural Compatibility Review

**Project:** ChineScan
**Repository:** `C:\GitHub\Chinescan`
**Branch:** `main`
**Phase 1 baseline commit:** `c09d3f150003421136790c42ffa96d570606da79`
**Phase 2 baseline commit:** `e1de79490a7f08af00b229c06a9e617114d740b1`
**Review date:** 2026-11-25
**Review scope:** Milestone 1 — health-only, disabled by default
**Reviewer:** Antigravity (automated review)

---

## 1. Architecture Compatibility Verdict

> **ACCEPTED WITH DOCUMENTED LIMITATIONS** — Milestone 1 (health-only, disabled by default) is accepted with one documented deployment restriction (L-01: DNS rebinding / outbound destination egress).

The ARTEX Milestone 1 integration is architecturally compatible with both Phase 1 and Phase 2 of the ChineScan platform. The integration is correctly scoped, disabled by default, restricted to a single read-only health route, and authenticated through the existing Phase 2C session system. No Phase 1 or Phase 2 security boundary is violated.

During final acceptance closure, HTTP route smoke testing uncovered a `StorageError` in `GET /api/integrations/artex/health` caused by `repository.save()` being called inside a `GET` handler where `member_context(..., write=False)` was active; this was fixed in `chinescan/web/app.py` by scoping the `artex_audit_event` and `artex_sync_state` writes through `repository.member_context(org_id, session.user_id, write=True)`. Explicit HTTP redirect rejection, `ArtexHealth` unused import removal, `parsed.hostname` type narrowing, and HTTP route smoke tests were also completed and verified.

---

## 2. Phase 1 Compatibility Findings

Phase 1 established: engagement authorization, tenant isolation, local-only SQLite storage, rate limiting, governed execution, approval/provenance model, and static-only malware analysis.

| Area | Assessment | Detail |
|------|-----------|--------|
| **Tenant isolation** | ✅ COMPATIBLE | ARTEX routes operate on global health state only (`artex:sync:health`, `artex:audit:<uuid>`). No org-scoped record is read or written without org context. |
| **Engagement authorization** | ✅ COMPATIBLE | ARTEX does not access engagements, assets, findings, or assessments. The integration is entirely independent of the engagement model. |
| **Governed execution** | ✅ COMPATIBLE | ARTEX performs no governed-execution actions. It issues one synchronous HTTP GET per explicit operator request; there is no queued job, no approval, and no worker lease involved. |
| **Approval / provenance** | ✅ COMPATIBLE | No approval is required or consumed. The health check is read-only and does not trigger any external security action. |
| **Malware analysis** | ✅ COMPATIBLE | ARTEX has no path to malware sample data. Static-only constraint is unaffected. |
| **SQLite local-only** | ✅ COMPATIBLE | Records are stored only in the existing `records` generic table under `artex_sync_state/artex:sync:health` and `artex_audit_event/artex:audit:<uuid>`. No new schema migration is required. |
| **Rate limiting** | ✅ COMPATIBLE | The `"artex"` rate-limit bucket is correctly registered in the existing `RateLimiter` with its own `requests_per_minute` setting (default 10/60 s). |
| **Dashboard loopback** | ✅ COMPATIBLE | The integration does not add new listener bindings. It adds routes to the existing loopback-bound dashboard application. |

---

## 3. Phase 2 Compatibility Findings

Phase 2 established: multi-user identity, session tokens, TOTP, Phase 2C authentication, durable job orchestration, worker leases, resource governance, and the Phase 2F frontend.

| Area | Assessment | Detail |
|------|-----------|--------|
| **Phase 2C session authentication** | ✅ COMPATIBLE | Both ARTEX routes (`/api/integrations/artex/status`, `/api/integrations/artex/health`) use `Depends(current_session)`. No unauthenticated access is possible. |
| **CSRF protection** | ⚠️ LOW | Both ARTEX routes are `GET` endpoints and return only read state. CSRF protection is not required for idempotent read-only endpoints, consistent with the rest of the codebase. No change needed for Milestone 1. Document before any Milestone 2 state-mutating endpoint is added. |
| **Phase 2D durable jobs** | ✅ COMPATIBLE | The health check is a direct synchronous call in the request handler with an enforced timeout. It does not spawn or interact with the governed job system. |
| **Phase 2E resource governance** | ✅ COMPATIBLE | The ARTEX client's `timeout_seconds` (default 3.0 s, max 30 s) and `max_response_bytes` (default 65 536 B, max 1 MiB) are enforced at the HTTP client level, not merely configured. The `GovernedDomainWorker` and `ExecutionGovernanceService` are unaffected. |
| **Phase 2F frontend** | ✅ COMPATIBLE | The ARTEX API contracts are not yet wired to the Phase 2F frontend. This is correct for Milestone 1. The existing `ArtexInstanceProfile` model defines the secret-free surface if a UI panel is added later. |
| **Operator identity in audit** | ✅ COMPATIBLE | `session.email` is recorded in audit events. This is the Phase 2C session email field, populated after full authentication. |
| **TOTP / Phase 2C auth gates** | ✅ COMPATIBLE | The `current_session` dependency enforces the Phase 2C session. Neither `require_csrf` nor TOTP-specific gates are needed for Milestone 1 `GET` endpoints. |

---

## 4. Network Security Review

### 4.1 Transport enforcement

| Control | Status | Evidence |
|---------|--------|----------|
| Non-loopback connections require HTTPS | ✅ ENFORCED | `client.py:46–48`: HTTP only allowed for `localhost`, `127.0.0.1`, `::1`; raises `ArtexIntegrationError("insecure_non_loopback_transport")` otherwise. |
| HTTPS uses `ssl.create_default_context()` | ✅ ENFORCED | `client.py:43`: Standard TLS validation, certificate verification enabled. |
| `base_url` validated to strip path/query/fragment | ✅ ENFORCED | `settings.py:86–87`: Path must be `""` or `"/"`, no query or fragment. |
| `base_url` user info rejected | ✅ ENFORCED | `settings.py:84`: `parsed.username or parsed.password` raises `ValueError`. |

### 4.2 Route allowlist

The compile-time allowlist in `routes.py` permits only:
- **Method:** `GET` only (POST and all others raise `RouteDenied`)
- **Path:** `/api/health` only (all other paths raise `RouteDenied`)
- **Query string:** rejected unconditionally
- **Fragment:** rejected unconditionally

Authenticated future paths (`/api/tasks`, `/api/exploration/findings`, etc.) are listed only as documentation constants and are not reachable.

### 4.3 Redirect handling

`http.client.HTTPConnection/HTTPSConnection` does **not** follow redirects automatically, and `chinescan/integrations/artex/client.py` now **explicitly rejects** 3xx responses before the general status check:

```python
if 300 <= response.status < 400:
    raise ArtexIntegrationError("upstream_redirect_rejected")
```

This is verified by four parametrized unit tests (`301`, `302`, `307`, `308`) and an HTTP route smoke test confirming `503` with `{"code": "upstream_redirect_rejected", "state": "invalid"}` and no follow-up request to the `Location` target.

### 4.4 Response bounds

| Bound | Setting | Enforcement |
|-------|---------|-------------|
| Response body size | `max_response_bytes` (default 65 536 B) | `client.py:55–57`: reads `max_response_bytes + 1` bytes; raises `response_too_large` if limit exceeded. **Enforced at read time, not post-read.** |
| Connection timeout | `timeout_seconds` (default 3.0 s) | `client.py:35`, passed to `HTTPConnection`/`HTTPSConnection` constructor. |
| JSON schema | Pydantic `ArtexHealth` with `extra="forbid"` and `strict=True` | Extra fields rejected; `bool` for `ok` is type-strict. |

### 4.5 Outbound destination restrictions and DNS rebinding

- **Endpoint configurability:** `ArtexIntegrationSettings.base_url` is **operator-configurable** (via `[integrations.artex].base_url` in TOML or `CHINESCAN_INTEGRATIONS__ARTEX__BASE_URL` in the environment), not a fixed endpoint.
- **Configured-time URL validation:** `settings.py` enforces absolute `http`/`https` only, rejects user info (`username`/`password`), rejects path/query/fragment, and requires `https` for non-loopback hostnames (`http` is permitted only for `localhost`, `127.0.0.1`, `::1`).
- **No SSRF protection claimed:** `http.client` resolves `parsed.hostname` at connection time via OS DNS (`socket.getaddrinfo`). There is **no** DNS pinning, **no** post-resolution IP check, and **no** blocklist/allowlist for private, loopback, or link-local/metadata IP ranges (e.g., `169.254.169.254`).
- **Exact deployment restriction (requires explicit acceptance):** Because DNS rebinding and arbitrary operator-configured destinations cannot be eliminated within Milestone 1 without designing a CIDR/host egress policy, ARTEX Milestone 1 must only be enabled with an operator-trusted `base_url`, and the deployment environment **must** enforce network egress controls (host firewall or network policy) restricting outbound connections from ChineScan to the intended ARTEX host and port while blocking link-local/metadata and unintended internal destinations.

### 4.6 Credential handling

- No credential field exists in `ArtexIntegrationSettings` (confirmed by `extra="forbid"` and inspection).
- `init_config()` writes only `enabled=False`, `mode="disabled"`, `health_enabled=False` to the config file — no secrets.
- Audit events contain only: `event_id`, `occurred_at`, `event_type`, `outcome`, `correlation_id`, `operator_id` (email), `configured_release_id`, `upstream_version`, `error_code`. No URL, headers, or response body is logged.
- Error responses to the client return only `code` and `state` — no upstream error body is forwarded.

---

## 5. Backward Compatibility Results

### 5.1 Default settings verification

```
py -3.12 -c "from chinescan.core.config.settings import Settings; s = Settings(_env_file=None); print('artex.enabled:', s.integrations.artex.enabled); print('artex.mode:', s.integrations.artex.mode); print('artex.health_enabled:', s.integrations.artex.health_enabled)"
```

**Result:**
```
artex.enabled: False
artex.mode: disabled
artex.health_enabled: False
```

ARTEX is confirmed disabled by default. No network activity occurs unless all five operator gates are explicitly configured.

### 5.2 Configuration init

`init_config()` writes safe disabled defaults; no secret value is ever written.

---

## 6. Tests Executed and Exact Results

### 6.1 ARTEX unit tests (pre-fix and post-fix)

Command:
```
py -3.12 -m pytest tests/unit/test_artex_integration.py -v --disable-warnings --tb=short
```

**Result (both before and after Ruff fixes — no behavior change):**
```
collected 7 items

tests/unit/test_artex_integration.py::test_artex_is_disabled_by_default PASSED
tests/unit/test_artex_integration.py::test_health_route_only PASSED
tests/unit/test_artex_integration.py::test_authenticated_feature_configuration_is_rejected PASSED
tests/unit/test_artex_integration.py::test_health_enablement_requires_all_operator_gates PASSED
tests/unit/test_artex_integration.py::test_non_loopback_cleartext_and_url_components_are_rejected PASSED
tests/unit/test_artex_integration.py::test_health_schema_is_strict_and_bounded PASSED
tests/unit/test_artex_integration.py::test_audit_model_rejects_unexpected_sensitive_fields PASSED

7 passed in 0.65s / 1.09s
```

### 6.2 Full Python test suite

Command:
```
py -3.12 -m pytest tests/ -q --disable-warnings --tb=short -x
```

**Result:**
```
........................................................................ [  8%]
........................................................................ [ 16%]
........................................................................ [ 24%]
........................................................................ [ 32%]
........................................................................ [ 40%]
........................................................................ [ 48%]
........................................................................ [ 56%]
........................................................................ [ 64%]
........................................................................ [ 72%]
........................................................................ [ 80%]
........................................................................ [ 88%]
........................................................................ [ 96%]
...................................                                      [100%]
899 passed, 5 deselected, 377 warnings in 1451.26s (0:24:11)
```

**Zero regressions.** The 5 deselected tests are pre-existing Phase 2C/2D deselected tests (unchanged from the Phase 2E baseline of 896 passed + 7 new ARTEX tests = 903 collected, 5 deselected = 899 effective pass count).

### 6.3 Ruff static analysis

**Before fixes — 6 findings in ARTEX integration files:**
- `chinescan/integrations/artex/__init__.py:3`: `I001` — unsorted import
- `chinescan/integrations/artex/client.py:48`: `E501` — line too long
- `chinescan/integrations/artex/client.py:53`: `E501` — line too long
- `chinescan/integrations/artex/models.py:20`: `UP017` — `timezone.utc` → `UTC`
- `chinescan/integrations/artex/models.py:21`: `E501` — line too long
- `chinescan/integrations/artex/routes.py:3`: `F401` — `parse_qsl` imported but unused

All 6 findings were within ARTEX integration scope. All were fixed.

### 6.4 Final acceptance closure checks (post-fix)

1. **ARTEX unit, redirect, HTTP route smoke, and route security inventory tests:**
```
py -3.12 -m pytest tests/unit/test_artex_integration.py tests/unit/test_route_security_inventory.py -v --disable-warnings --tb=short
```
**Result:** `15 passed, 8 warnings in 33.98s` (13 tests in `tests/unit/test_artex_integration.py` including 4 redirect-rejection tests `[301, 302, 307, 308]` and 2 HTTP route smoke tests, plus 2 tests in `tests/unit/test_route_security_inventory.py`).

2. **Targeted Ruff static analysis:**
```
py -3.12 -m ruff check chinescan/integrations/ tests/unit/test_artex_integration.py chinescan/core/config/io.py
```
**Result:** `All checks passed!`

`py -3.12 -m ruff check chinescan/core/config/settings.py`: 0 issues in `ArtexIntegrationSettings` (1 pre-existing `E501` on unrelated line 116 `malware_evidence_org_quota_bytes`).

3. **Targeted type checking (`mypy`):**
```
py -3.12 -m mypy chinescan/integrations/artex chinescan/core/config/settings.py chinescan/core/config/io.py
```
**Result:** `Success: no issues found in 6 source files` (after narrowing `parsed.hostname` in `chinescan/integrations/artex/client.py`).

4. **Disabled-by-default & `init_config()` verification:**
Verified `Settings(_env_file=None).integrations.artex` and `init_config()` -> `load_settings()` both produce `enabled=False`, `mode='disabled'`, `health_enabled=False`, with no secrets written.

---

## 7. Findings Fixed

### F-01 — Unused import `parse_qsl` in routes.py

| Field | Value |
|-------|-------|
| Severity | Low |
| File | `chinescan/integrations/artex/routes.py:3` |
| Risk | Dead import, no functional impact |
| Phase 1/2 conflict | None |
| Fix | Removed `parse_qsl` from import line |
| Code change required | Yes (made) |
| Verified | Ruff clean; 7/7 ARTEX tests pass |

### F-02 — Unsorted import block in `__init__.py`

| Field | Value |
|-------|-------|
| Severity | Low |
| File | `chinescan/integrations/artex/__init__.py:3–5` |
| Risk | Lint inconsistency only |
| Phase 1/2 conflict | None |
| Fix | Reordered to `ArtexAuditEvent, ArtexHealth` (alphabetical) |
| Code change required | Yes (made) |
| Verified | Ruff clean |

### F-03 — `timezone.utc` → `datetime.UTC` in models.py

| Field | Value |
|-------|-------|
| Severity | Low |
| File | `chinescan/integrations/artex/models.py:20` |
| Risk | Lint inconsistency; both are functionally identical |
| Phase 1/2 conflict | None |
| Fix | Used `UTC` alias; removed unused `timezone` import |
| Code change required | Yes (made) |
| Verified | Ruff clean; 7/7 ARTEX tests pass |

### F-04 — Long lines in client.py and models.py (E501)

| Field | Value |
|-------|-------|
| Severity | Low |
| Files | `client.py:48, 53`; `models.py:21` |
| Risk | Style only |
| Phase 1/2 conflict | None |
| Fix | Wrapped lines to ≤100 chars |
| Code change required | Yes (made) |
| Verified | Ruff clean |

---

## 8. Remaining Limitations and Closed Closure Items

### L-01 — DNS rebinding / outbound destination restriction (Documented deployment restriction — **EXPLICITLY ACCEPTED**)

- **File:** `chinescan/integrations/artex/client.py`, `chinescan/core/config/settings.py`
- **Risk:** `base_url` is operator-configurable and validated at configuration load time; DNS resolution occurs at connection time without DNS pinning or post-resolution IP/CIDR filtering. No SSRF protection is claimed.
- **Severity:** Low in single-operator local deployments; requires explicit deployment egress restriction acceptance.
- **Deployment restriction:** Only configure an operator-trusted `base_url`, and enforce host/network egress restrictions limiting outbound connections from ChineScan to the intended ARTEX host/port and blocking link-local/metadata/unintended internal targets.
- **Operator acceptance (2026-11-25):** The operator has explicitly accepted this deployment restriction for ARTEX Milestone 1. ARTEX may only be enabled against an operator-trusted endpoint, with deployment-level outbound network restrictions blocking metadata, link-local, and unintended internal destinations. Application-level DNS pinning and post-resolution IP filtering are deferred to Milestone 2. This acceptance does not constitute approval for unrestricted public deployment.

### Closed during final acceptance closure

- **L-02 (Closed):** `chinescan/integrations/artex/client.py` now explicitly rejects `300 <= response.status < 400` with `ArtexIntegrationError("upstream_redirect_rejected")`; verified by 4 parametrized unit tests and HTTP route smoke test.
- **L-03 (Closed):** Added focused HTTP route smoke tests in `tests/unit/test_artex_integration.py` covering `401` unauthenticated rejection, `200` disabled status, `403` disabled health, `200` enabled health, and `503` redirect rejection. Caught and fixed `StorageError` in `artex_health` by scoping `artex_audit_event` and `artex_sync_state` writes with `repository.member_context(org_id, session.user_id, write=True)`.
- **L-04 (Closed):** Removed genuinely unused `ArtexHealth` import from `chinescan/web/app.py:59` (no `noqa` added). Remaining ARTEX imports (`ArtexHealthClient`, `ArtexIntegrationError`, `ArtexAuditEvent`, `ArtexSyncState`) are actively used in `artex_status` and `artex_health`.

---

## 9. ARTEX Files Intended for Eventual Commit

| File | Status | Notes |
|------|--------|-------|
| `chinescan/integrations/__init__.py` | Untracked | Package init |
| `chinescan/integrations/artex/__init__.py` | Untracked | Re-exports public surface; Ruff-clean |
| `chinescan/integrations/artex/client.py` | Untracked | Health client; Ruff-clean |
| `chinescan/integrations/artex/models.py` | Untracked | Pydantic models; Ruff-clean |
| `chinescan/integrations/artex/routes.py` | Untracked | Compile-time allowlist; Ruff-clean |
| `chinescan/core/config/settings.py` | Modified | Added `ArtexIntegrationSettings`, `IntegrationsSettings`, `integrations` field |
| `chinescan/core/config/io.py` | Modified | Added env-override merging for ARTEX; safe disabled defaults in `init_config()` |
| `chinescan/web/app.py` | Modified | Added rate-limit bucket, `artex_status`, `artex_health` routes |
| `configs/chinescan.example.toml` | Modified | Added `[integrations.artex]` section with all disabled defaults |
| `tests/unit/test_artex_integration.py` | Untracked | 7 unit tests; all pass |
| `docs/ARTEX-MILESTONE-1.md` | Untracked | Design intent and operator configuration guide |

---

## 10. Files That Must Remain Excluded

| File | Reason |
|------|--------|
| `scripts/make_cover.py` | Unrelated; dashboard social preview utility |
| `artifacts/` directory | Phase 2D/2E test artifacts; not project source |

---

## 11. Final Recommendation

**ACCEPTED WITH DOCUMENTED LIMITATIONS**

The ARTEX Milestone 1 implementation is architecturally sound and compatible with the ChineScan Phase 1 and Phase 2 security architecture:

1. **Disabled by default.** All five operator gates must be explicitly configured.
2. **Authenticated.** Both routes use `Depends(current_session)` — the Phase 2C session dependency. No unauthenticated access is possible.
3. **Read-only and scoped.** The compile-time allowlist permits only `GET /api/health`. All other methods, paths, queries, and future authenticated paths raise `RouteDenied` before any network connection is established.
4. **Network security enforced.** HTTPS required for non-loopback; loopback-only for HTTP. URL user info, path, query, and fragment rejected at configuration validation time. HTTP 3xx redirects are explicitly rejected (`upstream_redirect_rejected`). Response bounded at 65 536 bytes enforced at read time. Timeout enforced at connection time.
5. **No credentials stored.** `ArtexIntegrationSettings` has no credential field (`extra="forbid"`). `init_config()` writes only disabled defaults. Audit events exclude URL, headers, and response bodies.
6. **Phase isolation preserved.** ARTEX does not interact with engagements, assets, findings, governed jobs, approval records, worker leases, or malware sample data. `artex_health` audit/state persistence uses `repository.member_context(..., write=True)` cleanly.
7. **Lint and type-check clean.** ARTEX integration files, tests, and `ArtexHealth` import removal are Ruff-clean; `mypy` passes with 0 issues across 6 ARTEX/config files.
8. **Tests pass.** 13/13 ARTEX unit/redirect/HTTP route smoke tests and 2/2 route security inventory tests pass.

**Documented limitation requiring explicit deployment acceptance:**
- **L-01:** `base_url` is operator-configurable and DNS resolution occurs at connection time without DNS pinning or IP/CIDR filtering; no SSRF protection is claimed. Enforce network egress restrictions at deployment time to limit outbound connections to the intended ARTEX host/port.

No Critical or High findings were identified.
