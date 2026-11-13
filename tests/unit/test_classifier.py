from __future__ import annotations

from copy import deepcopy

import pytest

from security_patch_validator.patch_analysis.classifier import classify_patch


BASE = "a" * 40
PATCHED = "b" * 40
TARGET_HEADER = "==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000010\n"
TARGET_FRAME = "    #0 0x400abc in parse_input /project/src/parser.c:45:7\n"
OTHER_HEADER = "==42==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000010\n"
OTHER_FRAME = "    #0 0x400fff in process_request /project/src/worker.c:30:7\n"


def run(test_id: str, version: str, *, build: str = "asan", target: bool = False,
        other: bool = False, exit_code: int = 0, stdout: str = "") -> dict:
    stderr = ""
    if target:
        stderr += TARGET_HEADER + TARGET_FRAME
    if other:
        stderr += OTHER_HEADER + OTHER_FRAME
    return {
        "test_id": test_id, "version": version,
        "build_type": build, "commit_hash": BASE if version == "base" else PATCHED,
        "exit_code": exit_code, "signal": None, "timeout": False,
        "stdout": stdout, "stderr": stderr,
    }


def repeat(test_id: str, version: str, **kwargs) -> list[dict]:
    return [run(test_id, version, **kwargs) for _ in range(3)]


def suite(*, alt: bool = False) -> dict:
    tests = [
        {
            "test_id": "SEC-ORIGINAL", "kind": "security", "role": "original",
            "build_type": "asan", "expected_patched": {"exit_code": 1, "stdout": "rejected\n"},
            "executions": repeat("SEC-ORIGINAL", "base", target=True, exit_code=1) +
                          repeat("SEC-ORIGINAL", "patched", exit_code=1, stdout="rejected\n"),
        },
        {
            "test_id": "FUN-VALID", "kind": "functional", "validity": "valid",
            "build_type": "release", "reference": {"exit_code": 0, "stdout": "accepted\n"},
            "executions": repeat("FUN-VALID", "base", build="release", stdout="accepted\n") +
                          repeat("FUN-VALID", "patched", build="release", stdout="accepted\n"),
        },
    ]
    if alt:
        tests.append({
            "test_id": "SEC-ALTERNATE", "kind": "security", "role": "alternate",
            "build_type": "asan", "expected_patched": {"exit_code": 1, "stdout": "rejected\n"},
            "executions": repeat("SEC-ALTERNATE", "base", target=True, exit_code=1) +
                          repeat("SEC-ALTERNATE", "patched", exit_code=1, stdout="rejected\n"),
        })
    return {
        "schema_version": "1.0", "target_id": "synthetic-parser",
        "target_issue": {
            "id": "CWE-787-demo",
            "signature": {"error_type": "heap-buffer-overflow", "file": "src/parser.c", "function": "parse_input"},
        },
        "completion": {
            k: {"status": "passed", "evidence": f"synthetic-{k}-test"}
            for k in ("hardening", "test_matrix", "reproducer")
        },
        "tests": tests,
    }


def diff() -> dict:
    return {
        "analysis_type": "git_diff_analysis",
        "comparison": {"base": {"commit": BASE}, "patched": {"commit": PATCHED}},
        "files": [{"old_path": "src/parser.c", "new_path": "src/parser.c",
                   "hunks": [{"removed_lines": [{"line_number": 45, "content": "old"}],
                              "added_lines": [{"line_number": 45, "content": "new"}]}]}],
    }


def test_fixed_with_complete_evidence():
    report = classify_patch(suite(), diff_report=diff(), source_roots=["/project"])
    assert report["statuses"] == ["FIXED"]
    assert report["security_status"] == "FIXED"
    assert report["suggested_exit_code"] == 0
    assert report["complete"] is True
    assert report["tests"][0]["correlations"]["base"]["summary"]["changed_line_overlaps"] == 1


def test_original_input_still_crashes_is_incomplete_fix():
    data = suite()
    data["tests"][0]["executions"][-3:] = repeat("SEC-ORIGINAL", "patched", target=True, exit_code=1)
    report = classify_patch(data, diff_report=diff())
    assert report["security_status"] == "INCOMPLETE_FIX"
    assert report["suggested_exit_code"] == 10


def test_bypass_input_still_crashes_is_incomplete_fix():
    data = suite(alt=True)
    data["tests"][-1]["executions"][-3:] = repeat("SEC-ALTERNATE", "patched", target=True, exit_code=1)
    report = classify_patch(data, diff_report=diff())
    assert "INCOMPLETE_FIX" in report["statuses"]
    assert report["suggested_exit_code"] == 10


def test_fixed_and_regression_have_independent_statuses():
    data = suite()
    data["tests"][1]["executions"][-3:] = repeat("FUN-VALID", "patched", build="release", stdout="broken\n")
    report = classify_patch(data, diff_report=diff())
    assert report["statuses"] == ["FIXED", "FUNCTIONAL_REGRESSION"]
    assert report["suggested_exit_code"] == 20


def test_unreproduced_base_cannot_be_fixed():
    data = suite()
    data["tests"][0]["executions"][:3] = repeat("SEC-ORIGINAL", "base")
    report = classify_patch(data, diff_report=diff())
    assert report["security_status"] == "INCONCLUSIVE"
    assert report["suggested_exit_code"] == 40


def test_missing_replays_is_inconclusive():
    data = suite()
    data["tests"][0]["executions"] = [data["tests"][0]["executions"][0], data["tests"][0]["executions"][3]]
    report = classify_patch(data, diff_report=diff())
    assert report["suggested_exit_code"] == 40
    assert any("fewer than" in reason for reason in report["inconclusive_reasons"])


def test_flaky_bug_is_inconclusive():
    data = suite()
    data["tests"][0]["executions"][1] = run("SEC-ORIGINAL", "base", exit_code=0)
    report = classify_patch(data, diff_report=diff())
    assert report["suggested_exit_code"] == 40


def test_unmatched_commit_rejected():
    data = suite()
    data["tests"][0]["executions"][0]["commit_hash"] = "c" * 40
    with pytest.raises(ValueError, match="mismatched"):
        classify_patch(data, diff_report=diff())


def test_no_diff_cannot_claim_end_to_end_pass():
    report = classify_patch(suite())
    assert report["security_status"] == "FIXED"
    assert report["suggested_exit_code"] == 40


def test_missing_hardening_attestation_prevents_pass():
    data = suite()
    del data["completion"]["hardening"]
    report = classify_patch(data, diff_report=diff())
    assert report["suggested_exit_code"] == 40


def test_reference_not_matching_base_is_not_regression():
    data = suite()
    data["tests"][1]["executions"][:3] = repeat("FUN-VALID", "base", build="release", stdout="unexpected\n")
    report = classify_patch(data, diff_report=diff())
    assert "FUNCTIONAL_REGRESSION" not in report["statuses"]
    assert report["suggested_exit_code"] == 40


def test_unknown_sanitizer_type_cannot_prove_target_fix():
    data = suite()
    data["tests"][0]["executions"][-3:] = [
        {**r, "stderr": "==42==ERROR: AddressSanitizer: custom mysterious error\n"}
        for r in data["tests"][0]["executions"][-3:]
    ]
    report = classify_patch(data, diff_report=diff())
    assert report["suggested_exit_code"] == 40


def test_invalid_input_requires_declared_rejection_oracle():
    data = suite()
    del data["tests"][0]["expected_patched"]
    with pytest.raises(ValueError, match="expected_patched"):
        classify_patch(data, diff_report=diff())


def test_security_signature_requires_specific_location_anchor():
    data = suite()
    del data["target_issue"]["signature"]["function"]
    with pytest.raises(ValueError, match="location anchor"):
        classify_patch(data, diff_report=diff())


def test_new_finding_is_reported_separately():
    data = suite(alt=True)
    data["tests"][-1]["executions"][-3:] = repeat("SEC-ALTERNATE", "patched", other=True, exit_code=1)
    report = classify_patch(data, diff_report=diff())
    assert "NEW_ISSUE" in report["statuses"]
    assert report["new_issues"][0]["fingerprint"][0] == "heap-use-after-free"
    assert report["suggested_exit_code"] == 10


def test_configured_source_root_is_applied_to_correlation():
    report = classify_patch(suite(), diff_report=diff(), source_roots=["/project"])
    matches = report["tests"][0]["correlations"]["base"]["findings"][0]["matches"]
    assert any(m["path_match_method"] == "configured_source_root" for m in matches)


def test_target_error_only_on_patched_alternate_is_not_automatically_incomplete():
    data = suite(alt=True)
    data["tests"][-1]["executions"][:3] = repeat("SEC-ALTERNATE", "base")
    data["tests"][-1]["executions"][-3:] = repeat("SEC-ALTERNATE", "patched", target=True, exit_code=1)
    report = classify_patch(data, diff_report=diff())
    assert "INCOMPLETE_FIX" not in report["statuses"]
    assert report["suggested_exit_code"] == 40


def test_incompatible_sanitizer_output_is_inconclusive():
    data = suite()
    for raw in data["tests"][0]["executions"][:3]:
        raw["stderr"] = "src/parser.c:45:7: runtime error: signed integer overflow: 1 + 2147483647\n"
    report = classify_patch(data, diff_report=diff())
    assert report["suggested_exit_code"] == 40
    assert any("sanitizer diagnostics do not match" in reason for reason in report["inconclusive_reasons"])


def test_truncated_logs_prevent_pass():
    data = suite()
    data["tests"][0]["executions"][0]["stderr_truncated"] = True
    report = classify_patch(data, diff_report=diff())
    assert report["suggested_exit_code"] == 40


def test_new_issue_plus_regression_has_exit_code_20():
    data = suite(alt=True)
    data["tests"][-1]["executions"][-3:] = repeat("SEC-ALTERNATE", "patched", other=True, exit_code=1)
    data["tests"][1]["executions"][-3:] = repeat("FUN-VALID", "patched", build="release", stdout="broken\n")
    report = classify_patch(data, diff_report=diff())
    assert "NEW_ISSUE" in report["statuses"]
    assert "FUNCTIONAL_REGRESSION" in report["statuses"]
    assert report["suggested_exit_code"] == 20


def test_existing_diagnostic_under_other_build_root_is_not_new():
    data = suite(alt=True)
    for raw in data["tests"][-1]["executions"][:3]:
        raw["stderr"] = OTHER_HEADER + "    #0 0x400fff in process_request /tmp/base/src/worker.c:30:7\n"
    for raw in data["tests"][-1]["executions"][-3:]:
        raw["stderr"] = OTHER_HEADER + "    #0 0x400fff in process_request /tmp/patched/src/worker.c:30:7\n"
        raw["exit_code"] = 1
    report = classify_patch(data, diff_report=diff())
    assert "NEW_ISSUE" not in report["statuses"]
    assert report["suggested_exit_code"] == 40


def test_cli_returns_classifier_exit_code(tmp_path, monkeypatch, capsys):
    import json
    from security_patch_validator import cli

    suite_path = tmp_path / "suite.json"
    suite_path.write_text(json.dumps(suite()), encoding="utf-8")
    monkeypatch.setattr(cli, "analyze_diff", lambda repo, base, patched: diff())
    monkeypatch.setattr(cli.sys, "argv", [
        "spv", "classify", "--repo", str(tmp_path), "--base", BASE,
        "--patched", PATCHED, "--suite", str(suite_path),
    ])
    assert cli.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["statuses"] == ["FIXED"]


def test_cli_returns_30_for_invalid_suite(tmp_path, monkeypatch, capsys):
    from security_patch_validator import cli

    suite_path = tmp_path / "missing.json"
    monkeypatch.setattr(cli, "analyze_diff", lambda repo, base, patched: diff())
    monkeypatch.setattr(cli.sys, "argv", [
        "spv", "classify", "--repo", str(tmp_path), "--base", BASE,
        "--patched", PATCHED, "--suite", str(suite_path),
    ])
    assert cli.main() == 30
    assert "error" in capsys.readouterr().err
