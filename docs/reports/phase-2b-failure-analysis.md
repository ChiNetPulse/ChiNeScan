# Phase 2B Failure Analysis

**Reproduction:** `py -3.12 -m pytest -q --disable-warnings --tb=short --junitxml=artifacts/phase2b-junit.xml`
**Result:** 118 failed, 730 passed, 5 deselected (1,049.54 s).

This is a traceback-based classification of the reproduced run. The vast majority are a compatibility consequence of preserving fail-closed repository defaults: the old caller has not established a principal. They are not evidence that repository denial should be relaxed. The source line of each case is listed below as its first meaningful available stack frame.

| Failure group | Count | Failure mode | Correct repair |
|---|---:|---|---|
| Repository/service/test caller missing an explicit principal | 103 | `chinescan.core.errors.StorageError: Repository access requires an authorized organization context.` | Establish the intended organization, local operator, or job-bound worker principal at the caller boundary; keep repository denial as-is. |
| CLI credential bootstrap / local principal resolution | 9 | `AssertionError: ` | Repair CLI test setup with a real synthetic operator credential and ensure command entry establishes the personal-org principal only after verification. |
| Worker thread execution or context propagation | 1 | `assert False` | Reconstruct scoped authorization within the worker thread from trusted job/operator state; diagnose swallowed worker exception and preserve cleanup. |
| Worker/application startup with missing local operator scope | 5 | `chinescan.core.errors.StorageError: Local operator authorization is unavailable.` | Treat operator bootstrap as a required, explicit prerequisite for local workers; keep diagnostics/startup available when absent and do not fabricate a principal. |

## Representative stack traces

### Repository/service/test caller missing an explicit principal

```text
tests\unit\test_chain_trace.py:1368: in test_chain_web_auth_csrf_validation_and_network_gate
chinescan\core\storage\sqlite.py:1251: in save
chinescan\core\storage\sqlite.py:1047: in _owned_record
```

Principal at failure: no valid scope was established by the caller (the exception paths confirm this for context failures). Expected: denial until a correct principal is established. Actual: denial; the legacy test or local workflow expected unscoped access. Root cause: principal establishment has not yet been propagated to that entry point. Proposed correction: Establish the intended organization, local operator, or job-bound worker principal at the caller boundary; keep repository denial as-is.

### CLI credential bootstrap / local principal resolution

```text
tests\unit\test_chain_trace.py:1470: in test_chain_cli_label_file_loads_provenance_and_downgrades_only_labeled_lead
tests\unit\test_chain_trace.py:1460: in run
```

Principal at failure: no valid scope was established by the caller (the exception paths confirm this for context failures). Expected: denial until a correct principal is established. Actual: denial; the legacy test or local workflow expected unscoped access. Root cause: principal establishment has not yet been propagated to that entry point. Proposed correction: Repair CLI test setup with a real synthetic operator credential and ensure command entry establishes the personal-org principal only after verification.

### Worker thread execution or context propagation

```text
tests\unit\test_chain_trace.py:1577: in test_chain_web_fake_provider_job_graph_and_exports
```

Principal at failure: no valid scope was established by the caller (the exception paths confirm this for context failures). Expected: denial until a correct principal is established. Actual: denial; the legacy test or local workflow expected unscoped access. Root cause: principal establishment has not yet been propagated to that entry point. Proposed correction: Reconstruct scoped authorization within the worker thread from trusted job/operator state; diagnose swallowed worker exception and preserve cleanup.

### Worker/application startup with missing local operator scope

```text
tests\unit\test_code_jobs.py:208: in test_completed_code_job_saves_reports
chinescan\web\code_jobs.py:70: in start
chinescan\core\storage\sqlite.py:1006: in local_operator_context
```

Principal at failure: no valid scope was established by the caller (the exception paths confirm this for context failures). Expected: denial until a correct principal is established. Actual: denial; the legacy test or local workflow expected unscoped access. Root cause: principal establishment has not yet been propagated to that entry point. Proposed correction: Treat operator bootstrap as a required, explicit prerequisite for local workers; keep diagnostics/startup available when absent and do not fabricate a principal.

## Per-test failure inventory

Each item records test, classified operation, failure signal, and first meaningful stack frames. Test-only setup should use explicit fixture principals; application callers should use their actual authenticated operator/member/job principal.

### Repository/service/test caller missing an explicit principal (103)

- `tests.unit.test_chain_trace::test_chain_web_auth_csrf_validation_and_network_gate` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_code_jobs::test_queue_bound_and_restart_interruption` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_code_scan::test_oversized_scan_persists_failed_verdict_and_coverage_gap` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_code_scan::test_orchestration_deduplicates_isolates_and_persists` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_dashboard_alerts::test_malware_triage_is_scored_and_persisted_alert_refresh_is_idempotent` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_diagnostics::test_report_is_path_free_and_checks_database_read_only` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_engagement_security::test_governed_result_records_keep_immutable_job_provenance[complete-completed]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_engagement_security::test_governed_result_records_keep_immutable_job_provenance[partial-failed]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_preview_is_network_free_session_bound_expiring_and_single_use` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_local_bare_repository_import_verifies_sha_and_removes_git` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_api_preview_then_import_job_is_session_bound_and_path_free` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_committed_symlink_is_neutralized_by_core_symlinks_false` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_pinned_sha_uses_shallow_fetch_and_records_exact_commit` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_submodule_entry_is_not_fetched_and_lfs_pointer_is_not_smudged` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_oversized_and_too_many_project_files_fail_quota[files0-128-50000]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_oversized_and_too_many_project_files_fail_quota[files1-1024-2]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_windows_reserved_trailing_and_ads_names_are_rejected[CON]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_windows_reserved_trailing_and_ads_names_are_rejected[trailing.]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_windows_reserved_trailing_and_ads_names_are_rejected[ads:stream]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_overlong_repository_path_is_rejected` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_timeout_cancel_and_quota_terminate_the_started_process[timeout]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_timeout_cancel_and_quota_terminate_the_started_process[cancel]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_timeout_cancel_and_quota_terminate_the_started_process[quota]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_timeout_cancel_and_quota_terminate_the_started_process[file_count]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_import_queue_is_bounded_without_starting_more_than_one_worker` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_poisoned_clone_path_cleanup_refuses_outside_directory` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_git_stderr_canary_and_internal_path_never_escape_error_or_logs` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_import::test_ads_is_detected_and_incomplete_when_a_tracked_file_vanishes` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_projects::test_github_project_cap_counts_projects_not_completed_jobs` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_projects::test_replacement_keeps_old_clone_until_verified_replacement_registers` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_github_projects::test_github_project_resolution_rechecks_clone_after_junction_swap` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_ack_tokens_are_hashed_bound_expiring_and_single_use` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_ack_consume_is_atomic_for_concurrent_requests` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_ack_rejects_expired_and_unconfirmed_requests` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_scanner_finds_static_leads_and_preserves_project_files` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_terminal_job_and_finish_audit_commit_together` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_each_scan_bound_marks_partial_with_skipped_counts[malware_max_files-files0]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_each_scan_bound_marks_partial_with_skipped_counts[malware_max_total_bytes-files1]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_each_scan_bound_marks_partial_with_skipped_counts[malware_max_file_bytes-files2]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_each_scan_bound_marks_partial_with_skipped_counts[malware_per_file_seconds-files3]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_each_scan_bound_marks_partial_with_skipped_counts[malware_max_depth-files4]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_each_scan_bound_marks_partial_with_skipped_counts[malware_job_deadline_seconds-files5]` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_scanner_skips_linked_directories_and_ignored_tree` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_scanner_rechecks_project_policy_after_root_is_replaced_with_link` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_scanner_rechecks_policy_after_project_root_junction_swap` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_scanner_benign_tree_has_no_high_findings` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_scanner_detects_powershell_workflow_and_exfiltration_patterns` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_known_hash_typosquat_and_bounded_local_rule_are_reported` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_adversarial_regex_input_is_rejected_and_scan_stays_inside_file_bound` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_project_malware_api_acknowledgement_poll_and_sample_deprecation` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_malware_project_scan::test_project_malware_cli_requires_vm_risk_and_uses_core_scanner` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_backend_factory_uses_explicit_setting_and_protected_roots` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_intake_copies_without_modifying_original_and_uses_opaque_key` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_intake_rejects_source_change_and_published_object_mutation` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_intake_detects_source_mutation_during_bounded_copy` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_oversized_intake_is_rejected_before_publication` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_queue_has_one_active_and_four_waiting_slots` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_active_analysis_submission_for_same_sample_is_idempotently_rejected` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_sqlite_claim_allows_only_one_active_job_across_managers` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_publication_failure_leaves_reconcilable_orphan` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_restart_marks_missing_managed_object_unavailable` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_recovery_keeps_metadata_but_does_not_reconstruct_missing_sample` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_job_execution_fails_closed_when_job_object_controls_are_unavailable` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_run_one_persists_partial_analysis_without_claiming_clean` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_managed_malware::test_actual_windows_manager_persists_contained_synthetic_analysis` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_migration::test_malware_backend_revision_upgrades_existing_records_without_rewrite` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_projects::test_project_logs_api_end_to_end` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_projects::test_project_suggestions_do_not_open_candidate_files` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_projects::test_external_log_location_requires_allowed_root_and_hard_deny_wins` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_projects::test_project_api_create_show_remove_keeps_files_scans_findings_and_cases` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_backup_verify_and_restore_preserve_a_complete_case_recovery_drill` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_backup_includes_committed_wal_data_and_never_creates_missing_source` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_backup_refuses_existing_destination_and_cleans_cancelled_stage` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_verification_separates_checksum_corruption_and_unsupported_schema` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_cancelled_restore_and_stale_sidecars_leave_no_destination` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_verifier_reports_dangling_links_and_invalid_payloads_without_repair` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_restore_upgrades_only_the_copy_and_rejects_existing_or_active_destinations` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_unversioned_supported_schema_verifies_read_only_and_migrates_restored_copy` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_retention_preview_uses_manifests_and_skips_unrelated_and_symlink_entries` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_cli_database_commands_and_case_export_never_overwrite` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_cli_cutover_and_rollback_drill_uses_explicit_paths_and_preserves_divergence` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_failed_backup_verification_blocks_restore_and_preserves_original` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_recovery::test_case_export_publication_failure_cleans_temporary_output` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_reporting::test_jsonl_iterator_retrieves_more_than_legacy_cap_exactly_once` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_reporting::test_jsonl_iterator_streams_beyond_legacy_byte_cap_with_bounded_records` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_reporting::test_cli_jsonl_is_machine_readable_and_has_completion_marker` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_reporting::test_jsonl_stops_without_completion_for_missing_or_unsafe_records` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_reporting::test_case_create_show_update_and_compare` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_binding_attestation_snapshot_and_governed_execution` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_snapshot_is_deterministic_and_excludes_nested_git` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_binding_rejects_nonlead_unknown_project_and_raw_path` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_snapshot_rejects_linked_entries_and_releases_failed_quota_reservation` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_snapshot_limits_are_enforced_and_failed_copy_leaves_no_accounting` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_concurrent_snapshot_reservations_cannot_exceed_organization_quota` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_scope_revision_change_denies_existing_repository_binding` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_retention_hold_blocks_then_allows_explicit_deletion` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_backup_includes_snapshot_and_database_only_bundle_is_incomplete` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_repository_api_requires_session_and_never_returns_registered_roots` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_governed_cli_executes_bound_snapshot_and_records_provenance` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_repository_assessment::test_governed_cli_denial_never_falls_back_to_standalone_scan` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_route_security_inventory::test_mutating_routes_reject_missing_csrf_and_wrong_typed_record_ids` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_storage::test_legacy_initial_schema_is_stamped_without_losing_records` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.
- `tests.unit.test_trends::test_trends_cli_reads_local_records_without_target_values` — chinescan.core.errors.StorageError: Repository access requires an authorized organization context.; first useful frame: `chinescan\core\storage\sqlite.py:1047: in _owned_record`.

### CLI credential bootstrap / local principal resolution (9)

- `tests.unit.test_chain_trace::test_chain_cli_label_file_loads_provenance_and_downgrades_only_labeled_lead` — AssertionError: ; first useful frame: `tests\unit\test_chain_trace.py:1460: in run`.
- `tests.unit.test_code_scan::test_code_cli_json_summary` — AssertionError: ; first useful frame: `tests\unit\test_code_scan.py:301: in test_code_cli_json_summary`.
- `tests.unit.test_code_scan::test_code_cli_no_save_report_and_fail_on_gaps` — AssertionError: ; first useful frame: `tests\unit\test_code_scan.py:316: in test_code_cli_no_save_report_and_fail_on_gaps`.
- `tests.unit.test_code_scan::test_code_cli_report_store_warning_keeps_exit_code` — AssertionError: assert 1 == 0; first useful frame: `tests\unit\test_code_scan.py:336: in test_code_cli_report_store_warning_keeps_exit_code`.
- `tests.unit.test_code_scan::test_code_cli_severity_threshold_is_configurable` — AssertionError: assert 'Failing threshold high' in ''; first useful frame: `tests\unit\test_code_scan.py:346: in test_code_cli_severity_threshold_is_configurable`.
- `tests.unit.test_github_import::test_cli_import_requires_yes_after_printing_path_free_preview` — AssertionError: assert 1 == 2; first useful frame: `tests\unit\test_github_import.py:743: in test_cli_import_requires_yes_after_printing_path_free_preview`.
- `tests.unit.test_github_import::test_cli_preview_matches_api_canonical_url_and_ref` — AssertionError: ; first useful frame: `tests\unit\test_github_import.py:767: in test_cli_preview_matches_api_canonical_url_and_ref`.
- `tests.unit.test_log_analysis::test_logs_cli_summary_and_malformed_partial_exit` — AssertionError: ; first useful frame: `tests\unit\test_log_analysis.py:831: in test_logs_cli_summary_and_malformed_partial_exit`.
- `tests.unit.test_projects_cli::test_projects_cli_add_and_api_list_share_core_state` — AssertionError: ; first useful frame: `tests\unit\test_projects_cli.py:39: in test_projects_cli_add_and_api_list_share_core_state`.

### Worker thread execution or context propagation (1)

- `tests.unit.test_chain_trace::test_chain_web_fake_provider_job_graph_and_exports` — assert False; first useful frame: `tests\unit\test_chain_trace.py:1577: in test_chain_web_fake_provider_job_graph_and_exports`.

### Worker/application startup with missing local operator scope (5)

- `tests.unit.test_code_jobs::test_completed_code_job_saves_reports` — chinescan.core.errors.StorageError: Local operator authorization is unavailable.; first useful frame: `chinescan\core\storage\sqlite.py:1006: in local_operator_context`.
- `tests.unit.test_code_jobs::test_report_store_failure_warns_without_failing_completed_job` — chinescan.core.errors.StorageError: Local operator authorization is unavailable.; first useful frame: `chinescan\core\storage\sqlite.py:1006: in local_operator_context`.
- `tests.unit.test_code_jobs::test_scanner_and_persistence_failures_have_distinct_persisted_outcomes` — chinescan.core.errors.StorageError: Local operator authorization is unavailable.; first useful frame: `chinescan\core\storage\sqlite.py:1006: in local_operator_context`.
- `tests.unit.test_code_jobs::test_shutdown_waits_for_active_scan_and_persists_terminal_state` — chinescan.core.errors.StorageError: Local operator authorization is unavailable.; first useful frame: `chinescan\core\storage\sqlite.py:1006: in local_operator_context`.
- `tests.unit.test_diagnostics::test_ready_fails_for_corrupt_credentials_unwritable_database_missing_dirs_and_frontend` — chinescan.core.errors.StorageError: Local operator authorization is unavailable.; first useful frame: `chinescan\core\storage\sqlite.py:1006: in local_operator_context`.

## Resolution update after implementation

The inventory above records the original 118-failure run; it is retained as the historical backlog. After the first caller repairs, a complete rerun narrowed the failures to **18**:

| Residual failure group | Count | Evidence / correction |
|---|---:|---|
| Caller/test accessed an owned record without a principal | 17 | 12 repository-assessment paths lacked local-operator scope when querying the local project registry; one chain route test, dashboard fixture, migration test, route-security fixture, and storage migration test also used unscoped repository calls or expected legacy global reads. Corrections established explicit scope at authorized callers or changed legacy assertions to prove the row remains stored but inaccessible without ownership. |
| Worker thread failed to execute a queued chain job | 1 | Thread target called `_run_local_operator()` directly, so it did not execute `run()`'s local operator context. Thread startup now targets `run()`, which establishes the authorized personal-organization scope inside that thread. |

The repository-assessment correction is in the service boundary: project registry reads occur after `_is_lead`/`_validate_binding` verifies the exact active organization engagement and lead assignment, and use that organization context only during the internal registry operation. The web route does not manufacture a member or operator principal. The worker correction is in `ChainTraceJobManager`; ContextVars are not assumed to propagate across threads.

After those corrections, the complete Python suite reported **851 passed, 0 failed, 5 deselected**. A further security review found that failed-CSRF and repeated-login-alert flows invoked a full dashboard refresh, which reads tenant records; those flows were narrowed to persist only the supplied security signal without repository access. The final complete run after that production change reported **852 passed, 0 failed, 5 deselected**. The Phase 1 baseline of 844 passes differs by eight new Phase 2B regression tests. Subsequent extension of the route matrix assertions was independently verified: **1 passed**.

The initial 118 failures are therefore resolved in the current tree; no test was removed or weakened. The remaining Phase 2B limitations and non-green Ruff/ARTEX mypy checks are documented in `docs/reports/phase-2b-tenant-isolation-report.md`.


## Closure-pass evidence update

The direct-SQL AST inventory counted 381 call sites across 12 application modules (338 SQLAlchemy execute calls and 43 driver execute calls). This is an inventory of call sites with module-level classification; SQLite does not provide row-level security, and a stored query-by-query review artifact was not produced. The current evidence therefore demonstrates scoped representative paths and broad code inspection but does not satisfy the strict “exhaustive query-by-query classification” acceptance wording.

A newly verified malware-evidence route case proved both an unassigned same-organization member and a member from another organization receive 404 when requesting execution of a registered evidence asset; the execution_jobs rows are unchanged. This regression runs through the authenticated API and actual SQL/service path.

The fresh full run completed on the implementation source tree: **852 passed, 0 failed, 5 deselected**. The later import-order cleanup was followed by another focused tenant/malware run (**12 passed**). Route tests remain representative rather than a complete role × assignment × resource × verb product matrix. The remaining repository-wide Ruff findings are **395**, the expanded Phase 2B implementation/test set has **241** findings, and the exact prior 12-file set has **241**; these largely reflect legacy E501 and pre-existing import findings, including the ARTEX-containing `web/app.py` import block.

**Decision: PHASE 2B remains INCOMPLETE.** Remaining acceptance gaps are the auditable query-by-query direct-SQL classification and exhaustive route permission cross-product coverage. The test, frontend, targeted type, and Alembic checks passed; these results do not substitute for those missing verification artifacts.

## Targeted closure follow-up — 2026-11-25

Focused caller review found additional assignment-based escalation cases not represented in the earlier failure classification: `OrganizationService._has_assignment` permitted Viewer/Auditor + Lead into engagement/assignment management, `RepositoryAssessmentService._is_lead_connection` permitted read-only Lead asset creation, and stale approval revalidation accepted an assigned Reviewer after organization role downgrade. These are now denied at the SQL/service authorization predicates and covered by API/worker regressions in `test_organizations.py`, `test_repository_assessment.py`, and `test_engagement_security.py`. The three focused modules completed with 85 passed.

The direct diagnostics aggregate (`SQL-024`) also read status payloads across organizations while its routes were in the identity API exemption. The handler now requires `session.user_id == organization_service.operator_user_id`; a route-level negative test verifies a different identity gets 404. The diagnostics subset passed after correcting its test client to use a loopback address.

Inventory correction: the latest query register contains 381 call sites as 380 SQL executions plus one governed adapter invocation. Earlier prose in this analysis reported 338 SQLAlchemy and 43 driver execute calls; that categorization is not directly comparable to the current AST count, and must not be used as a substitute for reconciling all individual register rows. The remaining SAFE caller-path audit and comprehensive route matrix remain unresolved. The latest complete suite run reported 859 passed, 2 failed, 5 deselected; both failures were Windows `whoami.exe`/`icacls.exe` fixture setup timeouts and both tests passed in isolated rerun. The complete run still does not meet zero-failure acceptance.
## Closure verification update — 2026-11-25

The latest implementation exposed 18 failures in the first full rerun. Classification from the emitted XML showed 17 failures shared one root cause: authenticated operator-only API families (projects, code, logs, malware, chain, GitHub) passed the local-operator and personal-organization gates but entered a read-only organization context before making legitimate scoped writes. One malware recovery test also used a bare organization context for a maintenance write after restore. These are caller-boundary/principal propagation defects, not reasons to relax the repository default.

Correction: operator-only routes now establish a database-validated membership context only after the existing local-operator identity gate and personal-organization restriction; write HTTP methods receive write context, reads remain read-only. The restored malware test reconstructs the active persisted owner membership and requests a write-capable member context explicitly. The 23 directly affected route/service tests passed after the correction. A subsequent full Python run completed with 854 passed, 0 failed, 5 deselected.

A separate earlier five-module focused run hit a Windows `icacls.exe` 5-second timeout during parallel temporary-directory cleanup. The exact ACL-sensitive test passed when run alone. The successful final full suite did not reproduce that failure. The ACL requirement was not weakened.
# Closure-pass delta — 2026-11-25

The fresh baseline rerun remained 854 passed, 0 failed, 5 deselected. Subsequent caller-policy inspection found an additional distinct role-composition defect not represented in the earlier failure groups: engagement assignment checks were not intersected with read-only organization roles in execution, management, and approval decisions. The correction is in `chinescan/core/engagement_security.py`; API regressions are in `tests/unit/test_engagement_security.py`. The focused security selection passed 61 tests. This does not change the historical 118-failure classification: no claim is made that these new tests were among those failures.

The SQL inventory remains 381 execute/adapter sites, but the existing SAFE row notes do not yet provide complete per-site caller traces for tenant-sensitive queries. That evidence gap is an unresolved acceptance blocker rather than a newly counted test failure.
