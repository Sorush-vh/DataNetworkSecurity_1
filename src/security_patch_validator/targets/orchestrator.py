"""End-to-end evaluation of one target scenario.

The orchestrator is deliberately thin: it prepares a deterministic Git
snapshot, delegates building and execution to the execution module, delegates
classification to the patch-analysis module, and adds the Module 4 hardening
and reference-oracle checks.  It never invents a result that is not backed by
an execution record.
"""

from __future__ import annotations

import json
import posixpath
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from security_patch_validator.execution import load_config, run_suite
from security_patch_validator.hardening import (
    HardeningError,
    check_requirements,
    compare_hardening,
    inspect_binary,
)
from security_patch_validator.patch_analysis.classifier import classify_patch
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff

from .manifest import (
    Target,
    TargetError,
    load_reference_tests,
    load_target,
    materialize_execution_config,
    prepare_git_repo,
)

EXIT_PRIORITY = (40, 20, 10, 30, 0)


def _path(value: str) -> str:
    return posixpath.normpath(value.replace("\\", "/"))


def _finding_matches(finding: dict[str, Any], signature: dict[str, Any]) -> bool:
    if finding.get("error_type") != signature.get("error_type"):
        return False
    locations = []
    if isinstance(finding.get("location"), dict):
        locations.append(finding["location"])
    for frame in finding.get("stack_trace") or []:
        if isinstance(frame, dict):
            locations.append(frame)
    for location in locations:
        observed = location.get("file")
        if not isinstance(observed, str) or not observed:
            continue
        if _path(observed) != _path(signature["file"]) and not _path(observed).endswith("/" + _path(signature["file"])):
            continue
        if "function" in signature and location.get("function") != signature["function"]:
            continue
        if "line" in signature and location.get("line") != signature["line"]:
            continue
        return True
    return False


def _build_for(execution_report: dict[str, Any], version: str, build_type: str) -> dict[str, Any] | None:
    for build in execution_report.get("builds", []):
        if build.get("version") == version and build.get("build_type") == build_type:
            return build
    return None


def _runs_for(execution_report: dict[str, Any], test_id: str, version: str, build_type: str) -> list[dict[str, Any]]:
    return [
        run for run in execution_report.get("executions", [])
        if run.get("test_id") == test_id
        and run.get("version") == version
        and run.get("build_type") == build_type
    ]


def _hardening_analysis(target: Target, execution_report: dict[str, Any]) -> dict[str, Any]:
    reports = {}
    errors = []
    for version in ("base", "patched"):
        build = _build_for(execution_report, version, "release")
        if build is None or build.get("status") != "built" or not build.get("binary"):
            errors.append(f"No successful release build for {version}.")
            continue
        try:
            reports[version] = inspect_binary(build["binary"])
        except HardeningError as exc:
            errors.append(f"{version}: {exc}")
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "analysis_type": "target_hardening",
        "reports": reports,
        "errors": errors,
    }
    if "base" in reports and "patched" in reports:
        result["comparison"] = compare_hardening(reports["base"], reports["patched"])
        result["requirements"] = {
            "base": check_requirements(reports["base"], target.hardening.get("required", {})),
            "patched": check_requirements(reports["patched"], target.hardening.get("required", {})),
        }
    return result


def _reference_verification(
    target: Target,
    execution_report: dict[str, Any],
    patched_label: str,
) -> dict[str, Any]:
    suite = load_reference_tests(target)
    signature = target.vulnerability["signature"]
    checks = []
    mismatches = []
    for test in suite["tests"]:
        test_id = test["id"]
        build_type = "asan_ubsan" if test.get("kind") == "security" else "release"
        for version, label in (("base", "base"), ("patched", patched_label)):
            runs = _runs_for(execution_report, test_id, version, build_type)
            if not runs:
                observed = "missing"
            elif any(_finding_matches(finding, signature) for run in runs for finding in run.get("findings", [])):
                observed = "vulnerable"
            elif test.get("kind") == "security":
                expected_behavior = test.get("expected", {})
                fixed = all(
                    run.get("exit_code") == expected_behavior.get("exit_code")
                    and ("stdout" not in expected_behavior or run.get("stdout") == expected_behavior["stdout"])
                    and not run.get("signal")
                    and not run.get("timeout")
                    for run in runs
                )
                observed = "fixed" if fixed else "error"
            elif all(run.get("expectation", {}).get("status") == "pass" for run in runs):
                observed = "pass"
            elif any(run.get("expectation", {}).get("status") == "fail" for run in runs):
                observed = "fail"
            elif any(run.get("expectation", {}).get("status") == "runtime_error" for run in runs):
                observed = "error"
            else:
                observed = "inconclusive"
            expected = test.get("expected_by_version", {}).get(label)
            check = {
                "test_id": test_id,
                "version": version,
                "version_label": label,
                "expected": expected,
                "observed": observed,
                "matches": expected == observed,
            }
            checks.append(check)
            if expected is not None and expected != observed:
                mismatches.append(check)
    return {
        "schema_version": "1.0",
        "analysis_type": "reference_oracle_verification",
        "checks": checks,
        "mismatches": mismatches,
        "verified_versions": ["base", patched_label],
    }


def _classifier_suite(
    target: Target,
    execution_report: dict[str, Any],
    *,
    hardening_evidence: str,
    test_matrix_evidence: str,
    reproducer_evidence: str,
    reproducer_passed: bool,
) -> dict[str, Any]:
    tests = []
    for test in target.execution["tests"]:
        metadata = test.get("classifier")
        if not isinstance(metadata, dict):
            continue
        build_type = metadata["build_type"]
        entry: dict[str, Any] = {
            "test_id": test["id"],
            "kind": metadata["kind"],
            "build_type": build_type,
            "executions": [
                run for run in execution_report.get("executions", [])
                if run.get("test_id") == test["id"] and run.get("build_type") == build_type
            ],
        }
        if metadata["kind"] == "security":
            entry["role"] = metadata["role"]
            entry["expected_patched"] = metadata["expected_patched"]
        else:
            entry["validity"] = metadata["validity"]
            entry["reference"] = metadata["reference"]
        tests.append(entry)

    return {
        "schema_version": "1.0",
        "target_id": target.target_id,
        "target_issue": {
            "id": target.vulnerability["id"],
            "signature": target.vulnerability["signature"],
        },
        "completion": {
            "hardening": {"status": "passed", "evidence": hardening_evidence},
            "test_matrix": {"status": "passed", "evidence": test_matrix_evidence},
            "reproducer": {
                "status": "passed" if reproducer_passed else "failed",
                "evidence": reproducer_evidence,
            },
        },
        "tests": tests,
    }


def _test_matrix_evidence(execution_report: dict[str, Any], suite: dict[str, Any], repetitions: int) -> tuple[str, bool]:
    if execution_report.get("status") != "completed":
        return f"execution status is {execution_report.get('status')!r}", False
    for test in suite["tests"]:
        for version in ("base", "patched"):
            count = sum(1 for run in test["executions"] if run.get("version") == version)
            if count < 3:
                return f"{test['test_id']} has only {count} {version} executions", False
    return f"{len(suite['tests'])} classifier tests with {repetitions} repetitions per version", True


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def format_scenario_summary(report: dict[str, Any]) -> str:
    """Render a short developer-facing summary of a scenario report."""
    if report.get("analysis_type") == "target_scenario_matrix":
        lines = [
            f"Target: {report.get('target_id')}",
            f"All scenarios match expected exit codes: {report.get('all_scenarios_match_expected')}",
        ]
        for scenario, item in report.get("scenarios", {}).items():
            lines.append(
                f"  {scenario:10s} expected={item['expected_exit_code']:<3d} "
                f"observed={item['observed_exit_code']:<3d} statuses={', '.join(item['statuses'])}"
            )
        return "\n".join(lines)

    classification = report.get("classification", {})
    hardening = report.get("hardening", {})
    lines = [
        f"Target: {report.get('target_id')} ({report.get('target_name')})",
        f"Scenario: {report.get('scenario')} -> {report.get('patched_version')}",
        f"Exit code: expected {report.get('expected_exit_code')}, "
        f"observed {report.get('observed_exit_code')}",
        f"Statuses: {', '.join(classification.get('statuses', []))}",
        f"Security: {classification.get('security_status')}  "
        f"Functional: {classification.get('functional_status')}",
    ]
    reasons = classification.get("inconclusive_reasons") or []
    if reasons:
        lines.append("Inconclusive reasons:")
        lines.extend(f"  - {reason}" for reason in reasons)
    warnings = hardening.get("comparison", {}).get("warnings", [])
    if warnings:
        lines.append("Hardening warnings:")
        lines.extend(f"  - {warning}" for warning in warnings)
    bundles = report.get("reproducers", {}).get("bundles", [])
    if bundles:
        lines.append(f"Reproducers: {len(bundles)} confirmed input(s)")
        for bundle in bundles:
            minimized = bundle.get("minimized", {})
            lines.append(
                f"  {bundle['test_id']}: {minimized.get('original_size')} -> "
                f"{minimized.get('minimized_size')} bytes, regression test "
                f"{bundle.get('regression_validation')}"
            )
    mismatches = report.get("reference_verification", {}).get("mismatches", [])
    if mismatches:
        lines.append(f"Reference-oracle mismatches: {len(mismatches)}")
    persisted = report.get("persistent_regressions", {}).get("summary")
    if persisted and persisted.get("total"):
        lines.append(
            f"Persistent regression suite: {persisted['total']} test(s), "
            f"passed={persisted.get('PASS', 0)}, "
            f"vulnerable={persisted.get('VULN_REMAINS', 0)}, "
            f"failed={persisted.get('FAIL', 0)}, "
            f"inconclusive={persisted.get('INCONCLUSIVE', 0)}"
        )
    return "\n".join(lines)


def run_scenario(
    target_path: str | Path,
    scenario: str,
    *,
    artifacts_dir: str | Path,
    output_path: str | Path | None = None,
    repetitions: int = 3,
    skip_reproducer: bool = False,
    patched_source_dir: str | Path | None = None,
    patched_label: str | None = None,
) -> dict[str, Any]:
    """Run one target scenario and return a structured evaluation report.

    ``patched_source_dir`` evaluates an arbitrary (for example, instructor
    supplied, unseen) patched source tree without editing the manifest.  The
    manifest's expected exit code is then reported as not applicable because
    the override has no declared scenario expectation.
    """
    target = load_target(target_path)
    if scenario not in target.scenarios:
        raise TargetError(f"Unknown scenario: {scenario}")
    if type(repetitions) is not int or repetitions < 3:
        raise TargetError("repetitions must be at least 3 for a conclusive evaluation.")

    overridden = patched_source_dir is not None
    if overridden:
        label = patched_label or target.scenarios[scenario]["patched_version"]
        if label not in target.versions or label == "base":
            raise TargetError(f"patched_label must name a non-base version: {label!r}")
        source = Path(patched_source_dir).expanduser().resolve()
        if not source.is_dir():
            raise TargetError(f"patched source directory does not exist: {source}")
        versions = dict(target.versions)
        versions[label] = replace(versions[label], source_dir=source, commit_hash=None)
        target = replace(target, versions=versions)

    artifacts = Path(artifacts_dir).expanduser().resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"spv-{target.target_id}-{scenario}-", dir=artifacts))
    hashes = prepare_git_repo(target, work)
    config_path = materialize_execution_config(
        target, scenario, work / "execution-config.json", commit_hashes=hashes,
    )
    config = load_config(config_path)
    execution_report = run_suite(config, artifacts_dir=work / "execution", repetitions=repetitions)
    _write_json(work / "execution.json", execution_report)

    patched_label = target.scenarios[scenario]["patched_version"]
    hardening = _hardening_analysis(target, execution_report)
    _write_json(work / "hardening.json", hardening)
    reference = _reference_verification(target, execution_report, patched_label)
    _write_json(work / "reference-verification.json", reference)

    diff_report = analyze_diff(work / "repo", hashes["base"], hashes[patched_label])
    _write_json(work / "diff.json", diff_report)

    source_roots = []
    for version in ("base", "patched"):
        build = _build_for(execution_report, version, "asan_ubsan")
        if build and build.get("source_root"):
            source_roots.append(build["source_root"])

    hardening_evidence = (
        f"hardening inspected for base and patched release binaries; "
        f"warnings={len(hardening.get('comparison', {}).get('warnings', []))}"
    )
    persistent_dir = Path(__file__).resolve().parents[3] / "regression" / target.target_id
    reproducer_evidence = "reproducer generation not requested"
    reproducer_passed = False
    reproducers: dict[str, Any] = {}
    if not skip_reproducer:
        from .reproducer import generate_reproducers

        reproducers = generate_reproducers(
            target, scenario, config, execution_report, work / "reproducers",
            persistent_dir=persistent_dir,
        )
        reproducer_passed = bool(reproducers.get("bundles"))
        reproducer_evidence = (
            f"{len(reproducers.get('bundles', []))} reproducer bundle(s) with "
            f"{reproducers.get('repetitions', 0)} replays"
        )

    from .reproducer import validate_persisted_regressions

    persistent_regressions = validate_persisted_regressions(
        target, execution_report, persistent_dir,
    )
    _write_json(work / "persistent-regressions.json", persistent_regressions)
    if persistent_regressions.get("summary", {}).get("total", 0) > 0:
        reproducer_passed = True
        reproducer_evidence = (
            f"{reproducer_evidence}; persistent regression suite: "
            f"{persistent_regressions['summary']}"
        )

    suite = _classifier_suite(
        target, execution_report,
        hardening_evidence=hardening_evidence,
        test_matrix_evidence="pending",
        reproducer_evidence=reproducer_evidence,
        reproducer_passed=reproducer_passed,
    )
    matrix_evidence, matrix_ok = _test_matrix_evidence(execution_report, suite, repetitions)
    suite["completion"]["test_matrix"] = {
        "status": "passed" if matrix_ok else "failed",
        "evidence": matrix_evidence,
    }
    _write_json(work / "classifier-suite.json", suite)

    classification = classify_patch(
        suite,
        diff_report=diff_report,
        source_roots=source_roots,
        min_replays=3,
    )
    _write_json(work / "classification.json", classification)

    expected = target.scenarios[scenario]
    observed_code = classification["suggested_exit_code"]
    if execution_report.get("status") == "build_or_config_error":
        observed_code = 30
    elif not matrix_ok:
        observed_code = 40
    elif reference["mismatches"] and not overridden:
        observed_code = 40

    report = {
        "schema_version": "1.0",
        "analysis_type": "target_scenario_evaluation",
        "target_id": target.target_id,
        "target_name": target.name,
        "scenario": scenario,
        "patched_version": patched_label,
        "patched_source_overridden": overridden,
        "expected_exit_code": None if overridden else expected["expected_exit_code"],
        "expected_statuses": expected["expected_statuses"],
        "observed_exit_code": observed_code,
        "matches_expected_exit_code": (
            None if overridden else observed_code == expected["expected_exit_code"]
        ),
        "classification": classification,
        "hardening": hardening,
        "reference_verification": reference,
        "reproducers": reproducers,
        "persistent_regressions": persistent_regressions,
        "diff_summary": diff_report.get("summary"),
        "execution_summary": {
            "status": execution_report.get("status"),
            "builds": [
                {
                    "version": build.get("version"),
                    "build_type": build.get("build_type"),
                    "status": build.get("status"),
                    "binary_sha256": build.get("binary_sha256"),
                    "error": build.get("error"),
                }
                for build in execution_report.get("builds", [])
            ],
            "executions": len(execution_report.get("executions", [])),
            "skipped": len(execution_report.get("skipped", [])),
        },
        "artifacts": {
            "workspace": str(work),
            "execution": str(work / "execution.json"),
            "hardening": str(work / "hardening.json"),
            "diff": str(work / "diff.json"),
            "classification": str(work / "classification.json"),
            "classifier_suite": str(work / "classifier-suite.json"),
            "reference_verification": str(work / "reference-verification.json"),
            "persistent_regressions": str(work / "persistent-regressions.json"),
        },
        "limitations": [
            "A FIXED result means the target issue was not observed in the configured tests; it does not prove global safety.",
            "Hardening warnings describe the built binaries and do not by themselves prove exploitability.",
            "The reference oracle is independent of the patched program's output, but it is limited to the configured tests.",
        ],
    }
    if output_path is not None:
        _write_json(Path(output_path).expanduser().resolve(), report)
    return report
