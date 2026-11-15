# Cover research notes

- Product: **ChiNeScan**, version `0.1.0`, Apache-2.0. Local-first security assessment workstation for code, logs, malware triage, investigations, and reports.
- Working workflows include heuristic Python/JavaScript/TypeScript code assessment, bounded local log parsing, static malware triage, local cases/reports, backup/recovery, and an authenticated loopback dashboard. Rust is an optional redaction extension; Python fallback is automatic.
- Dashboard entry is `frontend/src/main.tsx`; `App.tsx` owns the authenticated shell and sections for overview, projects, code assessments, logs, malware triage, on-chain tracing, scans, findings, cases, modules, and status. Overview combines scan/finding metrics, recent scans, severity breakdown, per-module scores, and alerts.
- Existing design uses Inter/Segoe UI, blue brand mark, light UI foundations with dark terminal/glass ambient panels, rounded 8–13px cards, navy/teal surfaces, green local status, and monospace labels. No bundled font files found.
- Dashboard development: `uv run chinescan web serve` and, in `frontend/`, `npm ci --no-audit && npm run dev`; the dashboard is authenticated and loopback-bound. `frontend/e2e/global-setup.ts` and `tests/browser/serve.py` provide isolated synthetic records and throwaway credentials.
- Existing decorative artwork `docs/assets/chinescan-cover.png` is replaced by the generated social preview; raw screenshots are under `assets/cover/raw/`.
