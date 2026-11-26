# Phase 2B Quality Report

Verification date: 2026-11-25. Commands were run from the repository root with Python 3.12.

## Final-three-stage closure rerun

After the role-intersection cleanup and local formatting in `engagement_security.py`, fresh `ruff check . --output-format=json` reports **386** findings: E501 366, F401 4, F821 2, F841 2, I001 9, UP017 1, UP047 1, B007 1. The previously reported 394 count used the earlier tree; the eight local E501 line-wrap cleanups account for the reduction in that same whole-tree scope. The same 14-file focused selection now reports **208** (E501 206, F401 1, I001 1), down from 216 after those wraps. `ruff check` on the changed authorization implementation and test files passes with **0 findings**. The remaining I001/F401 in the 14-file group are both in the existing ARTEX-integrated `chinescan/web/app.py` import block; unrelated ARTEX work was preserved.

Targeted mypy was rerun after closure edits on `engagement_security.py`, `execution_governance.py`, `organizations.py`, and `storage/sqlite.py`: **passed, 0 issues**. The four-file selection is explicit; broader mypy may include unrelated ARTEX diagnostics.

## Ruff counts and attribution

Fresh current whole-repository Ruff JSON run: **394 findings**: 374 E501, 9 I001, 4 F401, 2 UP017, 1 UP047, 2 F841, 1 B007, and 2 F821.

Fresh focused Phase 2B source/test selection (14 files: CLI commands, storage, engagement security, organizations, execution governance/adapters, repository assessment, malware evidence, web route modules, and the four related test modules): **216 findings**: 214 E501, 1 I001, and 1 F401. These are mostly pre-existing line-length findings in long legacy modules. A changed-line comparison of that selection against the current diff finds exactly one diagnostic on an added/changed line: `F401 chinescan/web/app.py:58 ArtexHealth`. That import belongs to the pre-existing ARTEX integration and was left untouched. The selection has no Phase 2B-attributable finding on newly added lines. Existing lint findings in the selected legacy files are not claimed as fixed.

One direct Phase 2B cleanup was made in `tests/unit/test_recovery.py` (import ordering); the newly added CLI helper line-length diagnostic was also fixed. `chinescan/core/engagement_security.py` import ordering was fixed. No global suppressions or broad formatting changes were applied.

## Reconciling reported counts

The earlier **258** figure was produced by a 12-file focused Ruff selection, not a repository-wide run; it was labeled inconsistently as repository-wide in a later prompt. A later closure report recorded 395 repository-wide and 241 for an expanded 17-file selection. The current focused selection is a different, explicitly listed 14-file selection, so its 216 count is not directly comparable with 241. The current full-repository count is 394, one lower than the last reported 395 after the targeted import cleanup. The expanded-selection 241 count refers to an earlier point-in-time file list and working tree; it is not represented as a fresh current result.

The 394 repository findings include pre-existing ARTEX, migration, generated/acceptance helper, and unrelated legacy/test diagnostics. ARTEX findings are not edited in this pass. The only changed-line finding in the focused Phase 2B selection is the pre-existing ARTEX import in `web/app.py`.

## Mypy

A fresh targeted mypy run remains pending after the final repository/test edits. No success is claimed here until rerun.

## Artifacts

Final fresh JSON output: `artifacts/phase2b-ruff-final-r3.json`; the focused selection output is `artifacts/phase2b-ruff-targeted-final-r2.json`. The changed-line attribution found one `F401` in the pre-existing ARTEX import in `chinescan/web/app.py`; no Phase 2B added line has a Ruff finding. Note: the earlier untracked artifact `artifacts/phase2b-ruff-final.json` was overwritten during this pass before its prior contents were preserved. Source files were not affected by that artifact overwrite. The replacement current evidence is in the uniquely named `*-r2.json` files.
