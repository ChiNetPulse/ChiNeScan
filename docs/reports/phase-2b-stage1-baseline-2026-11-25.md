# Phase 2B Stage 1 Baseline — 2026-11-25

Baseline gate: PASSED. No source changes were made during this baseline stage.

- Branch / HEAD: `main` / `c09d3f150003421136790c42ffa96d570606da79`.
- Python: `py -3.12 -m pytest -q --junitxml=artifacts/phase2b-stage1-baseline-20261125-r1.xml` — **854 passed, 0 failed, 5 deselected**, 649 warnings, 1,152.41 seconds. This matches the reported baseline; the two tests above the prior 852 count are the closure regressions.
- Frontend: `npm test` — **77 passed** across 19 files.
- TypeScript: `npm run typecheck` — passed.
- Production build and CSP: `npm run build` — passed; strict-CSP source and built-asset check passed. Existing Vite large-chunk advisory remains.
- Targeted mypy: `sqlite.py`, `malware_evidence.py`, `engagement_security.py`, `malware_evidence_api.py` — success, no issues in four files.
- Alembic script heads: exactly one, `0013_governed_chain_trace`. The configured SQLite database was not accessed to inspect its current revision.
- `git diff --check` — passed (line-ending notices only).
- Stage 1 freeze: source tree unchanged. Verification artifacts used a previously nonexistent unique path.

No migration was added; no files were staged or committed.
