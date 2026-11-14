"""Reproducer bundles, input minimization, and regression-test generation.

This module is the integration point between Module 4 and Module 3.  It reuses
Module 3's bundle writer, replay helper, delta debugger, and regression-test
generator, and adds the target-specific predicate that decides whether a
candidate input still triggers the *same* finding.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from security_patch_validator.execution.config import Config, TestCase
from security_patch_validator.execution.process import run_process
from security_patch_validator.patch_analysis.stacktrace_parser import parse_sanitizer_output

from .manifest import Target


def _member3() -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[3]
    member3 = repo_root / "member3"
    if not member3.is_dir():
        raise RuntimeError(f"Module 3 directory not found: {member3}")
    if str(member3) not in sys.path:
        sys.path.insert(0, str(member3))
    from modules.minimizer.delta_debugging import delta_debug_with_report
    from modules.regression.regression import generate_regression_test
    from modules.reproducer.bundle import create_bundle

    return {
        "delta_debug_with_report": delta_debug_with_report,
        "generate_regression_test": generate_regression_test,
        "create_bundle": create_bundle,
    }


def _path(value: str) -> str:
    return value.replace("\\", "/")


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


def _findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    return parse_sanitizer_output(result.get("stderr", ""), result.get("stdout", ""))


def _case_for(config: Config, test_id: str) -> TestCase:
    for case in config.tests:
        if case.test_id == test_id:
            return case
    raise KeyError(f"Unknown test id: {test_id}")


def _run_candidate(
    binary: str,
    case: TestCase,
    data: bytes,
    *,
    environment: dict[str, str],
    timeout: float,
    max_output_bytes: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="spv-min-") as directory:
        cwd = Path(directory)
        if case.mode == "file":
            name = case.input_name or "input.bin"
            path = cwd / name
            path.write_bytes(data)
            args = [arg.replace("{input}", str(path)) for arg in case.args]
            return run_process(
                [binary, *args], cwd=cwd, env=environment, timeout=timeout,
                max_output_bytes=max_output_bytes,
            )
        if case.mode == "stdin":
            return run_process(
                [binary, *case.args], cwd=cwd, env=environment, timeout=timeout,
                max_output_bytes=max_output_bytes, stdin=data,
            )
        # argv mode: the candidate replaces the first argument.
        args = list(case.args)
        if args:
            args[0] = data.decode("utf-8", errors="replace")
        return run_process(
            [binary, *args], cwd=cwd, env=environment, timeout=timeout,
            max_output_bytes=max_output_bytes,
        )


def _command_for(binary: str, case: TestCase, input_path: Path) -> list[str]:
    if case.mode == "file":
        return [binary, *[arg.replace("{input}", str(input_path)) for arg in case.args]]
    return [binary, *case.args]


def _normalize_log(text: str) -> str:
    import re

    text = re.sub(r"==\d+==", "==<pid>==", text)
    text = re.sub(r"0x[0-9a-fA-F]+", "<address>", text)
    text = re.sub(r"\bpid[=: ]+\d+\b", "pid=<number>", text, flags=re.IGNORECASE)
    # ASan's shadow-memory dump shifts with stack alignment between runs.  It
    # is diagnostic decoration, not part of the finding identity.
    lines = []
    skipping = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Shadow bytes around the buggy address:"):
            skipping = True
            continue
        if stripped.startswith("Shadow byte legend"):
            skipping = True
            continue
        if skipping:
            if not stripped:
                skipping = False
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _replay(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
    input_data: bytes | None,
    max_output_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    """Run a command three times and report a normalized stability verdict.

    Module 3's replay helper is used for the regression-test manifest, but its
    stability signature does not normalize the ``==PID==`` prefix or the ASan
    shadow-memory dump.  This wrapper normalizes both before comparing.
    """
    results = []
    signatures = []
    for _ in range(3):
        observation = run_process(
            command, cwd=cwd, env=environment, timeout=timeout,
            max_output_bytes=max_output_bytes, stdin=input_data,
        )
        result = {
            "command": command,
            "returncode": observation["exit_code"],
            "signal": observation["signal"],
            "stdout": observation["stdout"],
            "stderr": observation["stderr"],
            "timed_out": observation["timeout"],
            "error_type": (
                "TIMEOUT" if observation["timeout"]
                else observation["signal"] or (
                    f"EXIT_CODE_{observation['exit_code']}"
                    if observation["exit_code"] not in (0, None) else None
                )
            ),
        }
        results.append(result)
        signatures.append((
            result["returncode"], result["signal"], result["timed_out"],
            _normalize_log(result["stdout"]), _normalize_log(result["stderr"]),
        ))
    stable = len(set(signatures)) == 1
    return {
        "repetitions": 3,
        "status": "STABLE" if stable else "FLAKY",
        "results": results,
    }


def _bundle(
    member3: dict[str, Any],
    *,
    binary: str,
    input_path: Path,
    command: list[str],
    commit_hash: str | None,
    build: dict[str, Any],
    environment: dict[str, str],
    output_dir: Path,
    replay_result: dict[str, Any],
    working_directory: Path,
) -> Path:
    metadata_path = member3["create_bundle"](
        binary_path=binary,
        input_path=input_path,
        command=command,
        commit_hash=commit_hash,
        build_settings={
            "build_type": build.get("build_type"),
            "flags": build.get("flags"),
            "environment": build.get("environment"),
            "compiler_audit": build.get("compiler_audit"),
        },
        environment=environment,
        output_dir=output_dir,
        replay_results=replay_result,
    )
    # Module 3 records os.getcwd(); replace it with the actual run directory so
    # re-executing the bundle uses the same relative input path.
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["working_directory"] = str(working_directory)
        metadata_path.write_text(json.dumps(metadata, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError):
        pass
    return metadata_path


def _validate_regression(
    member3: dict[str, Any],
    *,
    base_binary: str,
    patched_binary: str,
    case: TestCase,
    minimized_path: Path,
    signature: dict[str, Any],
    expected_patched: dict[str, Any],
    environment: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    base_command = _command_for(base_binary, case, minimized_path)
    patched_command = _command_for(patched_binary, case, minimized_path)
    input_data = minimized_path.read_bytes() if case.mode == "stdin" else None
    base_replay = _replay(
        base_command, cwd=minimized_path.parent, environment=environment,
        timeout=timeout, input_data=input_data,
    )
    patched_replay = _replay(
        patched_command, cwd=minimized_path.parent, environment=environment,
        timeout=timeout, input_data=input_data,
    )

    def base_matches(result: dict[str, Any]) -> bool:
        return any(_finding_matches(finding, signature) for finding in _findings(result))

    def patched_matches(result: dict[str, Any]) -> bool:
        if any(_finding_matches(finding, signature) for finding in _findings(result)):
            return False
        if result.get("timed_out"):
            return False
        if result.get("returncode") != expected_patched.get("exit_code"):
            return False
        if "stdout" in expected_patched and result.get("stdout") != expected_patched["stdout"]:
            return False
        return True

    base_ok = base_replay["status"] == "STABLE" and all(base_matches(r) for r in base_replay["results"])
    patched_ok = patched_replay["status"] == "STABLE" and all(patched_matches(r) for r in patched_replay["results"])
    stable = base_replay["status"] == "STABLE" and patched_replay["status"] == "STABLE"
    if not stable:
        status = "INCONCLUSIVE"
    elif base_ok and patched_ok:
        status = "PASS"
    elif base_ok and not patched_ok:
        status = "VULN_REMAINS"
    else:
        status = "FAIL"
    return {
        "status": status,
        "stability": {
            "base": base_replay["status"],
            "patched": patched_replay["status"],
            "overall": "STABLE" if stable else "FLAKY",
        },
        "base": {
            "matches_expected_error": base_ok,
            "results": base_replay["results"],
        },
        "patched": {
            "same_error_absent": all(
                not any(_finding_matches(finding, signature) for finding in _findings(r))
                for r in patched_replay["results"]
            ),
            "expected_behavior": patched_ok,
            "results": patched_replay["results"],
        },
    }


def _record_regression_entry(
    manifest_path: Path,
    name: str,
    *,
    target: Target,
    test_id: str,
    case: TestCase,
    expected_patched: dict[str, Any],
) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    for entry in manifest.get("tests", []):
        if entry.get("name") == name:
            entry.update({
                "target_id": target.target_id,
                "test_id": test_id,
                "mode": case.mode,
                "args": list(case.args),
                "input_name": case.input_name or entry.get("input_file"),
                "expected_patched": expected_patched,
                "signature": target.vulnerability["signature"],
            })
            break
    manifest_path.write_text(json.dumps(manifest, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")


def _persistent_regression_input(
    member3: dict[str, Any],
    *,
    name: str,
    minimized_input: Path,
    error_type: str,
    persistent_dir: Path,
    target: Target,
    test_id: str,
    case: TestCase,
    expected_patched: dict[str, Any],
) -> Path:
    persistent_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = persistent_dir / "regression_tests.json"
    existing = None
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            existing = next(
                (entry for entry in manifest.get("tests", []) if entry.get("name") == name),
                None,
            )
        except (OSError, json.JSONDecodeError):
            existing = None
    if existing is not None:
        input_path = persistent_dir / existing["input_file"]
        if not input_path.is_file():
            input_path = member3["generate_regression_test"](
                minimized_input, name, error_type, persistent_dir,
            )
    else:
        input_path = member3["generate_regression_test"](
            minimized_input, name, error_type, persistent_dir,
        )
    _record_regression_entry(
        manifest_path, name, target=target, test_id=test_id,
        case=case, expected_patched=expected_patched,
    )
    return Path(input_path)


def validate_persisted_regressions(
    target: Target,
    execution_report: dict[str, Any],
    persistent_dir: str | Path,
) -> dict[str, Any]:
    """Run the persisted regression inputs against the current binaries."""
    directory = Path(persistent_dir).expanduser().resolve()
    manifest_path = directory / "regression_tests.json"
    if not manifest_path.is_file():
        return {
            "schema_version": "1.0",
            "analysis_type": "persistent_regression_suite",
            "tests": [],
            "summary": {"total": 0, "passed": 0, "vulnerable": 0, "failed": 0, "inconclusive": 0},
        }
    member3 = _member3()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base_build = next(
        (build for build in execution_report.get("builds", [])
         if build.get("version") == "base" and build.get("build_type") == "asan_ubsan"
         and build.get("status") == "built"),
        None,
    )
    patched_build = next(
        (build for build in execution_report.get("builds", [])
         if build.get("version") == "patched" and build.get("build_type") == "asan_ubsan"
         and build.get("status") == "built"),
        None,
    )
    if base_build is None or patched_build is None:
        return {
            "schema_version": "1.0",
            "analysis_type": "persistent_regression_suite",
            "tests": [],
            "error": "missing sanitized build",
        }

    reference_run = next(
        (run for run in execution_report.get("executions", [])
         if run.get("build_type") == "asan_ubsan" and run.get("version") == "base"),
        None,
    )
    environment = (
        reference_run["environment"] if reference_run is not None
        else {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
              "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=1:detect_leaks=0",
              "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
    )
    timeout = reference_run["timeout_seconds"] if reference_run is not None else 10

    results = []
    for entry in manifest.get("tests", []):
        input_path = directory / entry["input_file"]
        if not input_path.is_file():
            results.append({
                "name": entry.get("name"),
                "status": "INCONCLUSIVE",
                "reason": "persisted input file is missing",
            })
            continue
        args = tuple(entry.get("args", ["{input}"]))
        case = TestCase(
            test_id=entry.get("test_id", entry.get("name", "regression")),
            category="invalid",
            mode=entry.get("mode", "file"),
            args=args,
            data=None,
            input_path=input_path,
            input_name=entry.get("input_name", input_path.name),
            expected={},
            reference="persisted regression suite",
        )
        validation = _validate_regression(
            member3,
            base_binary=base_build["binary"],
            patched_binary=patched_build["binary"],
            case=case,
            minimized_path=input_path,
            signature=entry.get("signature", target.vulnerability["signature"]),
            expected_patched=entry.get("expected_patched", {"exit_code": 0, "stdout": ""}),
            environment=environment,
            timeout=timeout,
        )
        results.append({
            "name": entry.get("name"),
            "test_id": entry.get("test_id"),
            "input": str(input_path),
            "status": validation["status"],
            "validation": validation,
        })

    counts = {"PASS": 0, "VULN_REMAINS": 0, "FAIL": 0, "INCONCLUSIVE": 0}
    for result in results:
        counts[result.get("status", "INCONCLUSIVE")] = counts.get(result.get("status", "INCONCLUSIVE"), 0) + 1
    return {
        "schema_version": "1.0",
        "analysis_type": "persistent_regression_suite",
        "tests": results,
        "summary": {"total": len(results), **counts},
    }


def generate_reproducers(
    target: Target,
    scenario: str,
    config: Config,
    execution_report: dict[str, Any],
    output_dir: str | Path,
    *,
    persistent_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Create bundles, minimize inputs, and generate regression tests."""
    member3 = _member3()
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    persistent = Path(persistent_dir).expanduser().resolve() if persistent_dir else None
    signature = target.vulnerability["signature"]
    patched_label = target.scenarios[scenario]["patched_version"]

    base_build = next(
        (build for build in execution_report.get("builds", [])
         if build.get("version") == "base" and build.get("build_type") == "asan_ubsan"
         and build.get("status") == "built"),
        None,
    )
    patched_build = next(
        (build for build in execution_report.get("builds", [])
         if build.get("version") == "patched" and build.get("build_type") == "asan_ubsan"
         and build.get("status") == "built"),
        None,
    )
    if base_build is None or patched_build is None:
        return {"bundles": [], "repetitions": 3, "error": "missing sanitized build"}

    bundles = []
    regression_tests = []
    for test in target.execution["tests"]:
        metadata = test.get("classifier")
        if not isinstance(metadata, dict) or metadata.get("kind") != "security":
            continue
        test_id = test["id"]
        runs = [
            run for run in execution_report.get("executions", [])
            if run.get("test_id") == test_id
            and run.get("version") == "base"
            and run.get("build_type") == "asan_ubsan"
        ]
        confirmed = next(
            (run for run in runs if any(_finding_matches(f, signature) for f in run.get("findings", []))),
            None,
        )
        if confirmed is None:
            continue
        case = _case_for(config, test_id)
        if case.data is None:
            continue
        test_dir = output / test_id
        original_dir = test_dir / "original"
        minimized_dir = test_dir / "minimized"
        original_dir.mkdir(parents=True, exist_ok=True)
        minimized_dir.mkdir(parents=True, exist_ok=True)
        original_input = original_dir / (case.input_name or "input.bin")
        original_input.write_bytes(case.data)

        original_replay = _replay(
            confirmed["command"],
            cwd=Path(confirmed["cwd"]),
            environment=confirmed["environment"],
            timeout=confirmed["timeout_seconds"],
            input_data=case.data if case.mode == "stdin" else None,
        )
        original_metadata = _bundle(
            member3,
            binary=base_build["binary"],
            input_path=original_input,
            command=confirmed["command"],
            commit_hash=base_build.get("commit_hash"),
            build=base_build,
            environment=confirmed["environment"],
            output_dir=original_dir,
            replay_result=original_replay,
            working_directory=Path(confirmed["cwd"]),
        )

        def predicate(candidate: bytes) -> bool:
            result = _run_candidate(
                base_build["binary"], case, candidate,
                environment=confirmed["environment"],
                timeout=confirmed["timeout_seconds"],
                max_output_bytes=confirmed["max_output_bytes_per_stream"],
            )
            return any(_finding_matches(finding, signature) for finding in _findings(result))

        minimization = member3["delta_debug_with_report"](case.data, predicate)
        minimized_input = minimized_dir / (case.input_name or "input.bin")
        minimized_input.write_bytes(minimization["minimized"])
        minimized_command = _command_for(base_build["binary"], case, minimized_input)
        minimized_replay = _replay(
            minimized_command,
            cwd=minimized_dir,
            environment=confirmed["environment"],
            timeout=confirmed["timeout_seconds"],
            input_data=minimization["minimized"] if case.mode == "stdin" else None,
        )
        minimized_metadata = _bundle(
            member3,
            binary=base_build["binary"],
            input_path=minimized_input,
            command=minimized_command,
            commit_hash=base_build.get("commit_hash"),
            build=base_build,
            environment=confirmed["environment"],
            output_dir=minimized_dir,
            replay_result=minimized_replay,
            working_directory=minimized_dir,
        )

        regression_name = f"{target.target_id}-{test_id}"
        if persistent is not None:
            regression_input = _persistent_regression_input(
                member3,
                name=regression_name,
                minimized_input=minimized_input,
                error_type=signature["error_type"],
                persistent_dir=persistent,
                target=target,
                test_id=test_id,
                case=case,
                expected_patched=metadata["expected_patched"],
            )
        else:
            regression_dir = output / "regression"
            regression_input = member3["generate_regression_test"](
                minimized_input,
                regression_name,
                signature["error_type"],
                regression_dir,
            )
        validation = _validate_regression(
            member3,
            base_binary=base_build["binary"],
            patched_binary=patched_build["binary"],
            case=case,
            minimized_path=Path(regression_input),
            signature=signature,
            expected_patched=metadata["expected_patched"],
            environment=confirmed["environment"],
            timeout=confirmed["timeout_seconds"],
        )
        regression_tests.append({
            "test_id": test_id,
            "input": str(regression_input),
            "validation": validation,
        })
        bundles.append({
            "test_id": test_id,
            "original": {
                "input": str(original_input),
                "metadata": str(original_metadata),
                "replay_status": original_replay["status"],
            },
            "minimized": {
                "input": str(minimized_input),
                "metadata": str(minimized_metadata),
                "replay_status": minimized_replay["status"],
                "original_size": minimization["original_size"],
                "minimized_size": minimization["minimized_size"],
                "reduction_ratio": minimization["reduction_ratio"],
                "test_count": minimization["test_count"],
                "validated": minimization["validated"],
            },
            "regression_test": str(regression_input),
            "regression_validation": validation["status"],
        })

    summary = {
        "schema_version": "1.0",
        "analysis_type": "target_reproducers",
        "target_id": target.target_id,
        "scenario": scenario,
        "repetitions": 3,
        "bundles": bundles,
        "regression_tests": regression_tests,
    }
    (output / "reproducers.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
