"""Evidence-based classification of security patches using paired executions.

The classifier never infers a repair from Git Diff alone. It uses a pre-declared
issue signature, independent functional oracle, and repeated matching runs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
import posixpath

from security_patch_validator.patch_analysis.correlation import correlate_execution
from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result


STATUSES = {"FIXED", "INCOMPLETE_FIX", "NEW_ISSUE", "FUNCTIONAL_REGRESSION", "INCONCLUSIVE"}
KNOWN_SECURITY_TYPES = {
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "heap-use-after-free", "stack-use-after-return", "stack-use-after-scope",
    "use-after-free", "double-free", "alloc-dealloc-mismatch",
    "stack-overflow", "container-overflow", "signed-integer-overflow",
    "division-by-zero", "null-pointer-access", "out-of-bounds",
    "misaligned-access", "invalid-shift", "memory-leak",
}
EXIT_CODES = {"PASS": 0, "SECURITY": 10, "REGRESSION": 20, "CONFIG_ERROR": 30, "INCONCLUSIVE": 40}


def _path(value: str) -> str:
    return posixpath.normpath(value.replace("\\", "/"))


def _path_matches(observed: str | None, declared: str) -> bool:
    if not isinstance(observed, str) or not observed:
        return False
    candidate = _path(observed)
    expected = _path(declared)
    return candidate == expected or candidate.endswith("/" + expected)


def _primary_locations(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for frame in finding.get("stack_trace") or []:
        if isinstance(frame, Mapping):
            locations.append(dict(frame))
    primary = finding.get("location")
    if isinstance(primary, Mapping):
        locations.append(dict(primary))
    return locations


def _matches_target(finding: Mapping[str, Any], signature: Mapping[str, Any]) -> bool:
    if finding.get("error_type") != signature["error_type"]:
        return False
    for location in _primary_locations(finding):
        if not _path_matches(location.get("file"), signature["file"]):
            continue
        if "function" in signature and location.get("function") != signature["function"]:
            continue
        if "line" in signature and location.get("line") != signature["line"]:
            continue
        return True
    return False


def _fingerprint(finding: Mapping[str, Any]) -> tuple[str, str, str]:
    for entry in _primary_locations(finding):
        if entry.get("file"):
            # Use function rather than line when present; line shifts across patches.
            place = entry.get("function") or str(entry.get("line") or "")
            return (str(finding["error_type"]), _path(entry["file"]), place)
    return (str(finding.get("error_type")), "", "")


def _parse_and_validate_runs(test: Mapping[str, Any], version: str, *,
                             expected_commit: str | None) -> list[dict[str, Any]]:
    result = []
    for run in test["executions"]:
        if run["version"] != version:
            continue
        if run.get("test_id") != test["test_id"]:
            raise ValueError(f"Mismatched test_id in execution for {test['test_id']!r}")
        if run.get("build_type") != test["build_type"]:
            raise ValueError(f"Mismatched build_type in execution for {test['test_id']!r}")
        commit = run.get("commit_hash") or run.get("commit")
        if expected_commit is not None and commit != expected_commit:
            raise ValueError(f"Execution commit is missing or mismatched for {test['test_id']!r} ({version})")
        parsed = parse_execution_result(run)
        result.append({"raw": run, "parsed": parsed})
    return result


def _abnormal_termination(run: Mapping[str, Any], *, expected: Mapping[str, Any] | None = None) -> bool:
    termination = run["parsed"]["termination"]
    if termination["timeout"] or termination["signal"] is not None:
        return True
    code = termination["exit_code"]
    if code is None:
        return True
    if expected is not None and "exit_code" in expected:
        return code != expected["exit_code"]
    return code != 0


def _oracle_matches(run: Mapping[str, Any], oracle: Mapping[str, Any]) -> bool:
    if _abnormal_termination(run, expected=oracle):
        return False
    raw = run["raw"]
    for field in ("stdout", "stderr"):
        if field in oracle and raw.get(field) != oracle[field]:
            return False
    return True


def _target_flags(runs: Sequence[Mapping[str, Any]], signature: Mapping[str, Any]) -> list[bool]:
    return [any(_matches_target(f, signature) for f in run["parsed"]["findings"]) for run in runs]


def _new_finding_fingerprints(base: Sequence[Mapping[str, Any]],
                              patched: Sequence[Mapping[str, Any]],
                              signature: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    existing = {_fingerprint(f) for run in base for f in run["parsed"]["findings"]
                if f.get("error_type") in KNOWN_SECURITY_TYPES}
    # All repetitions must show the same specific new diagnostic; partial
    # recurrence is flagged as unstable, not silently marked as a new issue.
    patched_sets = [
        {_fingerprint(f) for f in run["parsed"]["findings"]
         if f.get("error_type") in KNOWN_SECURITY_TYPES and not _matches_target(f, signature)}
        for run in patched
    ]
    if not patched_sets:
        return []
    common = set.intersection(*patched_sets) - existing
    # Debug roots may differ between Base and Patched. The same filename,
    # function, and sanitizer type should not become a false NEW_ISSUE merely
    # because its absolute build-directory prefix changed.
    return sorted(fp for fp in common if not any(
        fp[0] == old[0] and fp[2] and fp[2] == old[2] and
        posixpath.basename(fp[1]) == posixpath.basename(old[1])
        for old in existing
    ))


def _validate_suite(suite: Mapping[str, Any]) -> None:
    if not isinstance(suite, Mapping) or not isinstance(suite.get("tests"), list):
        raise ValueError("Suite must be a JSON object containing a tests array.")
    if not suite["tests"]:
        raise ValueError("Suite must contain at least one test.")
    issue = suite.get("target_issue")
    if not isinstance(issue, Mapping) or not isinstance(issue.get("id"), str) or not issue["id"]:
        raise ValueError("Suite must declare target_issue.id.")
    signature = issue.get("signature")
    if not isinstance(signature, Mapping) or signature.get("error_type") not in KNOWN_SECURITY_TYPES:
        raise ValueError("Target signature must specify a recognized error_type.")
    if not isinstance(signature.get("file"), str) or not signature["file"]:
        raise ValueError("Target signature must specify file.")
    if not isinstance(signature.get("function"), str) and not isinstance(signature.get("line"), int):
        raise ValueError("Target signature must specify function and/or line as a location anchor.")
    ids = set()
    for test in suite["tests"]:
        if not isinstance(test, Mapping) or not isinstance(test.get("test_id"), str) or not test["test_id"]:
            raise ValueError("Every test needs a nonempty test_id.")
        if test["test_id"] in ids:
            raise ValueError(f"Duplicate test_id: {test['test_id']}")
        ids.add(test["test_id"])
        if test.get("kind") not in {"security", "functional"}:
            raise ValueError(f"Invalid kind for {test['test_id']}.")
        if not isinstance(test.get("build_type"), str) or not test["build_type"]:
            raise ValueError(f"Missing build_type for {test['test_id']}.")
        if not isinstance(test.get("executions"), list):
            raise ValueError(f"Missing executions for {test['test_id']}.")
        for run in test["executions"]:
            if not isinstance(run, Mapping) or run.get("version") not in {"base", "patched"}:
                raise ValueError(f"Invalid execution version in {test['test_id']}.")
        if test["kind"] == "security":
            if test.get("role") not in {"original", "alternate"}:
                raise ValueError(f"Security test {test['test_id']} needs original/alternate role.")
            if test["build_type"] not in {"asan", "ubsan", "lsan", "asan_ubsan"}:
                raise ValueError(f"Security test {test['test_id']} needs a sanitized build.")
            oracle = test.get("expected_patched")
            if not isinstance(oracle, Mapping) or not isinstance(oracle.get("exit_code"), int):
                raise ValueError(f"Security test {test['test_id']} needs expected_patched.exit_code.")
        else:
            if test.get("validity") != "valid" or test["build_type"] != "release":
                raise ValueError(f"Functional test {test['test_id']} must be valid and use a release build.")
            oracle = test.get("reference")
            if not isinstance(oracle, Mapping) or not isinstance(oracle.get("exit_code"), int) or "stdout" not in oracle:
                raise ValueError(f"Functional test {test['test_id']} needs independent reference exit_code and stdout.")


def classify_patch(
    suite: Mapping[str, Any],
    *,
    diff_report: Mapping[str, Any] | None = None,
    source_roots: Sequence[str] = (),
    min_replays: int = 3,
) -> dict[str, Any]:
    """Classify a paired test suite without pretending to prove global safety.

    Input is a group-approved oracle and raw Person-2 runner results. A result
    may contain *multiple* independent statuses, e.g. FIXED + REGRESSION.
    Exit-code guidance follows project precedence: 40, 20, 10, 30, 0.
    """
    _validate_suite(suite)
    if not isinstance(min_replays, int) or isinstance(min_replays, bool) or min_replays < 3:
        raise ValueError("Minimum replays must be >= 3 for confirmed results.")
    if isinstance(source_roots, (str, bytes)):
        raise TypeError("source_roots must be a sequence of strings.")

    expected_commits = None
    if diff_report is not None:
        if diff_report.get("analysis_type") != "git_diff_analysis":
            raise ValueError("Expected analyze_diff() report.")
        expected_commits = {v: diff_report["comparison"][v]["commit"] for v in ("base", "patched")}

    signature = suite["target_issue"]["signature"]
    per_test: list[dict[str, Any]] = []
    reasons: list[str] = []
    security_tests = []
    functional_tests = []
    new_issues: list[dict[str, Any]] = []
    has_regression = False

    for test in suite["tests"]:
        tid = test["test_id"]
        runs = {version: _parse_and_validate_runs(
            test, version, expected_commit=expected_commits[version] if expected_commits else None,
        ) for version in ("base", "patched")}
        enough = all(len(runs[v]) >= min_replays for v in ("base", "patched"))
        test_result: dict[str, Any] = {
            "test_id": tid, "kind": test["kind"], "build_type": test["build_type"],
            "replays": {v: len(runs[v]) for v in ("base", "patched")},
            "sufficient_replays": enough,
            "findings": [],
        }
        if not enough:
            reasons.append(f"{tid}: fewer than {min_replays} paired repetitions.")

        for version in ("base", "patched"):
            for i, run in enumerate(runs[version]):
                if run["raw"].get("logs_truncated") or run["raw"].get("stdout_truncated") or run["raw"].get("stderr_truncated"):
                    reasons.append(f"{tid}: runner logs were truncated ({version}, replay {i + 1}).")
                mechanisms = {f["detection_mechanism"] for f in run["parsed"]["findings"]}
                expected_mechanisms = {
                    "asan": {"asan", "lsan"}, "ubsan": {"ubsan"},
                    "lsan": {"lsan"}, "asan_ubsan": {"asan", "ubsan", "lsan"},
                    "release": set(),
                }[test["build_type"]]
                if mechanisms - expected_mechanisms:
                    reasons.append(f"{tid}: sanitizer diagnostics do not match {test['build_type']} build ({version}).")
                if run["parsed"]["summary"]["has_sanitizer_finding"]:
                    test_result["findings"].append({
                        "version": version, "replay": i + 1,
                        "diagnostics": [{
                            "error_type": f["error_type"],
                            "detection_mechanism": f["detection_mechanism"],
                            "matches_target": _matches_target(f, signature),
                            "location": f["location"],
                        } for f in run["parsed"]["findings"]],
                    })
                if diff_report is not None and run["parsed"]["findings"] and i == 0:
                    correlation = correlate_execution(
                        diff_report, run["raw"], version=version, source_roots=source_roots,
                    )
                    test_result.setdefault("correlations", {})[version] = {
                        "summary": correlation["summary"],
                        "findings": correlation["findings"],
                    }

        if test["kind"] == "security":
            base_flags = _target_flags(runs["base"], signature)
            patch_flags = _target_flags(runs["patched"], signature)
            base_confirmed = enough and all(base_flags)
            patch_confirmed = enough and all(patch_flags)
            patched_rejection_ok = enough and all(_oracle_matches(r, test["expected_patched"]) for r in runs["patched"])
            # Only identified target findings may be considered in the
            # original-vulnerability question; other findings are tracked separately.
            unknown_diagnostics = any(
                f["error_type"] not in KNOWN_SECURITY_TYPES
                for version in ("base", "patched") for run in runs[version]
                for f in run["parsed"]["findings"]
            )
            stable = enough and len(set(base_flags)) == 1 and len(set(patch_flags)) == 1
            if not stable or unknown_diagnostics:
                reasons.append(f"{tid}: unstable or unclassified security evidence.")
            if any(_abnormal_termination(r) and not r["parsed"]["findings"] for r in runs["base"]):
                # A baseline nonzero/timeout cannot be used as proof of the target
                # issue without a confirmed matching sanitizer finding.
                if not base_confirmed:
                    reasons.append(f"{tid}: baseline termination has no confirmed target diagnostic.")
            if any(_abnormal_termination(r, expected=test["expected_patched"])
                   and not r["parsed"]["findings"] for r in runs["patched"]):
                reasons.append(f"{tid}: patched termination violates the declared oracle.")

            new_fps = _new_finding_fingerprints(runs["base"], runs["patched"], signature)
            if new_fps and enough:
                for fingerprint in new_fps:
                    new_issues.append({"test_id": tid, "fingerprint": list(fingerprint)})
            elif any(
                f["error_type"] in KNOWN_SECURITY_TYPES and not _matches_target(f, signature)
                for r in runs["patched"] for f in r["parsed"]["findings"]
            ) and not new_fps:
                reasons.append(f"{tid}: a non-target sanitizer finding requires stability/identity review.")

            test_result.update({
                "role": test["role"], "base_target_reproduced": base_confirmed,
                "patched_target_reproduced": patch_confirmed,
                "patched_expected_behavior": patched_rejection_ok,
                "stable_target_observation": stable,
            })
            security_tests.append(test_result)
        else:
            oracle = test["reference"]
            baseline = enough and all(_oracle_matches(r, oracle) for r in runs["base"])
            patched = enough and all(_oracle_matches(r, oracle) for r in runs["patched"])
            if not baseline:
                reasons.append(f"{tid}: independent functional baseline could not be confirmed.")
            if baseline and not patched:
                if all(not _oracle_matches(r, oracle) for r in runs["patched"]):
                    has_regression = True
                    test_result["status"] = "FUNCTIONAL_REGRESSION"
                else:
                    reasons.append(f"{tid}: patched functional result is unstable.")
                    test_result["status"] = "INCONCLUSIVE"
            else:
                test_result["status"] = "PASS" if baseline and patched else "INCONCLUSIVE"
            test_result.update({"base_matches_reference": baseline, "patched_matches_reference": patched})
            functional_tests.append(test_result)
        per_test.append(test_result)

    if not security_tests or not any(t["role"] == "original" for t in security_tests):
        reasons.append("Missing original security test for the target issue.")
    if not functional_tests:
        reasons.append("Missing valid functional reference tests.")
    original = [t for t in security_tests if t["role"] == "original"]
    if original and not all(t["base_target_reproduced"] for t in original):
        reasons.append("Target vulnerability was not stably reproduced on Base for every original input.")

    security_status = None
    if original and all(t["base_target_reproduced"] for t in original):
        if any(t["patched_target_reproduced"] for t in security_tests):
            if all(t["base_target_reproduced"] for t in security_tests if t["patched_target_reproduced"]):
                security_status = "INCOMPLETE_FIX"
            else:
                reasons.append("A target-like error appeared on Patched for an input that did not reproduce it on Base; identity remains uncertain.")
        elif all(t["stable_target_observation"] and t["patched_expected_behavior"]
                 for t in security_tests):
            security_status = "FIXED"
        else:
            confirmed_new_issue_tests = {item["test_id"] for item in new_issues}
            if any(not t["stable_target_observation"] or
                   (not t["patched_expected_behavior"] and t["test_id"] not in confirmed_new_issue_tests)
                   for t in security_tests):
                reasons.append("Patched security behavior is not complete or stable.")

    statuses: list[str] = []
    if security_status:
        statuses.append(security_status)
    if new_issues:
        statuses.append("NEW_ISSUE")
    if has_regression:
        statuses.append("FUNCTIONAL_REGRESSION")

    # The integration owner must provide independently verified completion
    # markers; this standalone classifier does not conduct binary hardening,
    # test-matrix review, or reproducer validation itself.
    required = ("hardening", "test_matrix", "reproducer")
    for key in required:
        check = suite.get("completion", {}).get(key) if isinstance(suite.get("completion"), Mapping) else None
        if not isinstance(check, Mapping) or check.get("status") != "passed" or not check.get("evidence"):
            reasons.append(f"Required independent check {key!r} has no verified completion evidence.")

    if diff_report is None:
        reasons.append("Diff correlation not supplied; end-to-end patch verification is incomplete.")

    if reasons or (not security_status and not (new_issues or has_regression)):
        statuses.append("INCONCLUSIVE")
    statuses = [status for status in ("FIXED", "INCOMPLETE_FIX", "NEW_ISSUE", "FUNCTIONAL_REGRESSION", "INCONCLUSIVE")
                if status in statuses]

    if "INCONCLUSIVE" in statuses:
        code = 40
    elif "FUNCTIONAL_REGRESSION" in statuses:
        code = 20
    elif "INCOMPLETE_FIX" in statuses or "NEW_ISSUE" in statuses:
        code = 10
    else:
        code = 0

    return {
        "schema_version": "1.0",
        "analysis_type": "patch_classification",
        "target_id": suite.get("target_id"),
        "target_issue_id": suite["target_issue"]["id"],
        "statuses": statuses,
        "security_status": security_status or "INCONCLUSIVE",
        "functional_status": "FUNCTIONAL_REGRESSION" if has_regression else ("PASS" if functional_tests and
                               all(t.get("status") == "PASS" for t in functional_tests) else "INCONCLUSIVE"),
        "new_issues": new_issues,
        "tests": per_test,
        "complete": not reasons and bool(security_status or new_issues or has_regression),
        "inconclusive_reasons": sorted(set(reasons)),
        "suggested_exit_code": code,
        "exit_code_policy": "40 > 20 > 10 > 30 > 0; tool configuration errors are handled by CLI/integration layer.",
        "limitations": [
            "FIXED means not observed in the configured tests; it does not prove the absence of all vulnerabilities.",
            "Newly observed sanitizer findings are not automatically caused by the patch.",
            "The target issue signature and independent functional oracles must be approved outside the classifier.",
            "Completion attestations are supplied by other modules and are not independently verified here.",
        ],
    }
