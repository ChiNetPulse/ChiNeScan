"""Focused unit tests for optional native report rendering and signing key checks."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from chinescan.core import native_reporting
from chinescan.malware_analysis.process import WorkerFailure


def test_local_intel_handles_missing_invalid_and_valid_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CHINESCAN_REPORTER_LOCAL_DATA", raising=False)
    assert native_reporting._local_intel() == {}

    missing = tmp_path / "missing.json"
    monkeypatch.setenv("CHINESCAN_REPORTER_LOCAL_DATA", str(missing))
    assert native_reporting._local_intel() == {}

    bad = tmp_path / "bad.json"
    bad.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("CHINESCAN_REPORTER_LOCAL_DATA", str(bad))
    assert native_reporting._local_intel() == {}

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    monkeypatch.setenv("CHINESCAN_REPORTER_LOCAL_DATA", str(wrong_shape))
    assert native_reporting._local_intel() == {}

    valid = tmp_path / "intel.json"
    valid.write_text(
        json.dumps(
            {
                "cwe": {"CWE-79": "XSS", "bad": 123},
                "epss_by_rule": {"R1": 0.75, "R2": 2.5},
                "kev_rules": ["R1", 999],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHINESCAN_REPORTER_LOCAL_DATA", str(valid))
    assert native_reporting._local_intel() == {
        "cwe_map": {"CWE-79": "XSS"},
        "epss_by_rule": {"R1": 0.75},
        "kev_rules": ["R1"],
    }


def test_render_native_report_modes_and_enrichment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHINESCAN_RUST_REPORTER", "off")
    assert native_reporting.render_native_report({"findings": []}) is None

    monkeypatch.setenv("CHINESCAN_RUST_REPORTER", "on")
    monkeypatch.setattr(native_reporting.importlib.util, "find_spec", lambda _name: None)
    assert native_reporting.render_native_report({"findings": []}) is None

    monkeypatch.setattr(native_reporting.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(
        native_reporting.importlib,
        "import_module",
        lambda _name: SimpleNamespace(render_report_json=lambda *_a: None),
    )

    intel = tmp_path / "intel.json"
    intel.write_text(
        json.dumps({"cwe": {}, "epss_by_rule": {"R1": 0.5}, "kev_rules": ["R1"]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHINESCAN_REPORTER_LOCAL_DATA", str(intel))

    captured: list[bytes] = []

    def fake_worker(mode: str, payload: bytes) -> dict[str, object]:
        assert mode == "report"
        captured.append(payload)
        return {"report": "rendered-report"}

    monkeypatch.setattr(native_reporting, "run_native_parser_worker", fake_worker)
    rendered = native_reporting.render_native_report({"findings": [{"rule_id": "R1"}]})
    assert rendered == "rendered-report"
    enriched = json.loads(captured[0].decode("utf-8"))
    assert enriched["findings"][0]["epss"] == 0.5
    assert enriched["findings"][0]["kev"] is True

    def failing_worker(_mode: str, _payload: bytes) -> dict[str, object]:
        raise WorkerFailure("boom")

    monkeypatch.setattr(native_reporting, "run_native_parser_worker", failing_worker)
    assert native_reporting.render_native_report({"findings": []}) is None


def test_load_operator_seed_rejects_missing_config_and_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CHINESCAN_REPORT_SIGNING_KEY", raising=False)
    with pytest.raises(native_reporting.ReportSigningError, match="not configured"):
        native_reporting._load_operator_seed()

    with pytest.raises(native_reporting.ReportSigningError, match="missing"):
        native_reporting._load_operator_seed(tmp_path / "no-key.bin")
