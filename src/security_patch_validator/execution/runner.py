"""Build paired local C/C++ targets and collect structured execution evidence."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result

from .config import BUILD_TYPES, VERSIONS, Config, TestCase, Version
from .compiler import prepare_compiler_audit, verify_compiler_audit
from .process import run_process

BUILD_FLAGS = {
    "release": ("-O2", "-DNDEBUG"),
    "asan_ubsan": (
        "-O1", "-g", "-fno-omit-frame-pointer", "-fno-optimize-sibling-calls",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
    ),
}
SANITIZER_ENV = {
    "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=1:detect_leaks=0",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}
SIGNAL_TYPES = {
    "SIGSEGV": "segmentation-fault",
    "SIGBUS": "bus-error",
    "SIGILL": "illegal-instruction",
    "SIGFPE": "arithmetic-fault",
    "SIGABRT": "process-abort",
}
STACK_PROTECTOR = re.compile(
    r"^\*\*\* stack smashing detected \*\*\*:\s*(?:.*\s+)?terminated\s*$", re.MULTILINE,
)
FORTIFY = re.compile(
    r"^\*\*\* buffer overflow detected \*\*\*:\s*(?:.*\s+)?terminated\s*$", re.MULTILINE,
)
SANITIZER_SETUP_ERROR = re.compile(
    r"^(?:==\d+==)?(?:ASan runtime does not come first|"
    r"Shadow memory range interleaves|AddressSanitizer failed to allocate)",
    re.MULTILINE,
)


def _environment(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home), "TMPDIR": str(home), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
    }


def _expand_command(parts: tuple[str, ...], flags: tuple[str, ...], binary: Path) -> list[str]:
    command = []
    for part in parts:
        if part == "{flags}":
            command.extend(flags)
        else:
            command.append(part.replace("{binary}", str(binary)))
    return command


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_binary(path: Path) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("The build did not produce the configured executable.")
    with path.open("rb") as stream:
        header = stream.read(64)
    # ELF64, little-endian, current version, ET_EXEC or ET_DYN, EM_X86_64.
    if (
        len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(header[16:18], "little") not in (2, 3)
        or int.from_bytes(header[18:20], "little") != 62
        or int.from_bytes(header[24:32], "little") == 0
    ):
        raise ValueError("Expected an executable Linux x86_64 ELF.")


def _binary_in_tree(source: Path, binary: Path) -> Path:
    resolved = (source / binary).resolve()
    if not resolved.is_relative_to(source):
        raise ValueError("build.binary resolves outside its source snapshot.")
    return resolved


def _verify_sanitizers(binary: Path, cwd: Path, env: dict[str, str]) -> tuple[dict, dict]:
    # The compiler driver can ignore CFLAGS, e.g. in a custom build system.
    # Check that the executable references ASan and UBSan runtime hooks.
    evidence = run_process(
        ["readelf", "--wide", "--symbols", "--dynamic", str(binary)],
        cwd=cwd, env=env, timeout=10, max_output_bytes=8 * 1024 * 1024,
    )
    if evidence["exit_code"] != 0 or evidence["runner_stop"]:
        raise ValueError("Could not inspect sanitizer linkage with readelf.")
    output = evidence["stdout"]
    checks = {
        "asan": re.search(r"\b__asan_init\b|\blibasan\.so\b", output) is not None,
        "ubsan": re.search(r"\b__ubsan_handle_\w+|\blibubsan\.so\b", output) is not None,
    }
    return checks, {"command": ["readelf", "--wide", "--symbols", "--dynamic", str(binary)],
                    "symbols_or_libraries_found": checks}


def _remove_compiled_artifacts(source: Path) -> list[str]:
    """Remove copied build products, without following links out of the snapshot.

    Deleting only the final executable lets incremental builds reuse objects
    compiled with another profile. Recognize native objects/archives by content
    too, since their names need not have a conventional extension.
    """
    suffixes = {".o", ".obj", ".lo", ".a", ".la", ".so", ".gch", ".pch", ".bc"}
    magic = (b"\x7fELF", b"!<arch>\n", b"!<thin>\n", b"BC\xc0\xde", b"\xde\xc0\x17\x0b", b"gpch")
    removed = []
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            if path.is_symlink() and not path.resolve().is_relative_to(source):
                raise ValueError(f"Source symlink escapes its snapshot: {path.relative_to(source)}")
        for name in sorted(files):
            path = Path(directory) / name
            compiled = path.suffix in suffixes
            if not compiled and path.is_file():
                with path.open("rb") as stream:
                    compiled = stream.read(8).startswith(magic)
            if compiled:
                path.unlink()
                removed.append(str(path.relative_to(source)))
    return sorted(removed)


def _build(
    config: Config, label: str, version: Version, build_type: str, snapshot: Path, work: Path,
) -> dict[str, Any]:
    directory = work / "builds" / label / build_type
    source = directory / "source"
    home = directory / "home"
    home.mkdir(parents=True)
    flags = BUILD_FLAGS[build_type]
    env = _environment(home)
    env.update(CFLAGS=" ".join(flags), CXXFLAGS=" ".join(flags))
    env["LDFLAGS"] = "-fsanitize=address,undefined" if build_type == "asan_ubsan" else ""
    result = {
        "version": label, "build_type": build_type, "commit_hash": version.commit_hash,
        "source_root": str(source), "flags": list(flags), "environment": env,
        "timeout_seconds": config.build_timeout, "commands": [], "status": "failed",
        "binary": None, "binary_sha256": None, "removed_build_artifacts": [],
    }
    try:
        shutil.copytree(snapshot, source, symlinks=True)
        deadline = time.monotonic() + config.build_timeout
        result["removed_build_artifacts"] = _remove_compiled_artifacts(source)
        audit_directory = directory / "compiler-audit"
        compiler_mapping = {}
        if build_type == "asan_ubsan":
            compiler_mapping = prepare_compiler_audit(audit_directory, env, flags)
        binary = _binary_in_tree(source, config.binary)
        # Force the recipe to create this binary even if the source includes it.
        binary.unlink(missing_ok=True)
        commands = [("clean", parts) for parts in config.clean_commands]
        commands.extend(("build", parts) for parts in config.build_commands)
        for phase, parts in commands:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Build exceeded its time budget.")
            if phase == "build":
                # A clean recipe may remove the entire output directory.
                binary = _binary_in_tree(source, config.binary)
                binary.parent.mkdir(parents=True, exist_ok=True)
            command = _expand_command(parts, flags, binary)
            if os.path.isabs(command[0]):
                command[0] = compiler_mapping.get(str(Path(command[0]).resolve()), command[0])
            observation = run_process(command, cwd=source, env=env, timeout=remaining,
                                      max_output_bytes=config.max_output_bytes)
            result["commands"].append({"phase": phase, "argv": command, **observation})
            if observation["launch_error"]:
                raise ValueError(observation["launch_error"])
            if observation["runner_stop"]:
                raise ValueError(f"Build stopped: {observation['runner_stop']}.")
            if observation["exit_code"] != 0:
                raise ValueError(f"{phase.capitalize()} command failed.")
        binary = _binary_in_tree(source, config.binary)
        _validate_binary(binary)
        if build_type == "asan_ubsan":
            result["compiler_audit"] = verify_compiler_audit(audit_directory, source, config.translation_units)
            if result["compiler_audit"]["status"] != "verified":
                missing = [unit["source"] for unit in result["compiler_audit"]["translation_units"]
                           if not unit["verified"]]
                raise ValueError("Sanitizer compilation not verified for target translation units: "
                                 + (", ".join(missing) or "no C/C++ sources identified")
                                 + ". Route every compilation through CC/CXX or the audited PATH compilers.")
        checks, evidence = _verify_sanitizers(binary, source, env)
        result["instrumentation"] = evidence
        if build_type == "asan_ubsan" and not all(checks.values()):
            raise ValueError("The sanitized build did not provide evidence for both runtimes.")
        if build_type == "release" and any(checks.values()):
            raise ValueError("The release build references a sanitizer runtime.")
        result.update(status="built", binary=str(binary), binary_sha256=_sha256_file(binary))
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
    return result


def _classify_observation(result: dict) -> None:
    findings = []
    sanitized = result["build_type"] == "asan_ubsan"
    if sanitized and SANITIZER_SETUP_ERROR.search(result["stderr"]):
        result["launch_error"] = "Sanitizer runtime initialization failed."
    if sanitized and not result["launch_error"]:
        findings = parse_execution_result(result)["findings"]
    if result["signal"] == "SIGABRT" and not result["runner_stop"]:
        for pattern, error_type, mechanism in (
            (STACK_PROTECTOR, "stack-smashing", "stack-canary"),
            (FORTIFY, "buffer-overflow-detected", "fortify"),
        ):
            match = pattern.search(result["stderr"])
            if match:
                findings.append({"error_type": error_type, "detection_mechanism": mechanism,
                                 "log_source": "stderr", "evidence_lines": [match.group().strip()]})
    if result["signal"] and not result["runner_stop"]:
        findings.append({
            "error_type": SIGNAL_TYPES.get(result["signal"], "unclassified-signal"),
            "detection_mechanism": "os-signal",
            "evidence_lines": [result["signal"]],
        })
    result["findings"] = findings


def _check_expected(result: dict, expected: dict) -> dict:
    if result["launch_error"] or result["runner_stop"] or result["resource_limit"]:
        return {"status": "inconclusive", "mismatches": []}
    if result["findings"]:
        return {"status": "runtime_error", "mismatches": []}
    mismatches = [field for field, value in expected.items() if result[field] != value
                  or f"{field}_base64" in result]
    return {"status": "fail" if mismatches else "pass", "mismatches": mismatches}


def _input_metadata(case: TestCase) -> dict:
    return {
        "mode": case.mode, "args": list(case.args), "filename": case.input_name,
        "source_path": str(case.input_path) if case.input_path else None,
        "size_bytes": len(case.data) if case.data is not None else None,
        "sha256": hashlib.sha256(case.data).hexdigest() if case.data is not None else None,
    }


def _run_case(config: Config, case: TestCase, build: dict, work: Path) -> dict[str, Any]:
    cwd = Path(tempfile.mkdtemp(prefix="run-", dir=work))
    args = list(case.args)
    if case.mode == "file":
        assert case.input_name is not None and case.data is not None
        (cwd / case.input_name).write_bytes(case.data)
        args[args.index("{input}")] = f"./{case.input_name}"
    env = _environment(cwd)
    if build["build_type"] == "asan_ubsan":
        env.update(SANITIZER_ENV)
    command = [build["binary"], *args]
    result = {
        "test_id": case.test_id, "category": case.category,
        "version": build["version"], "commit_hash": build["commit_hash"],
        "build_type": build["build_type"], "binary_sha256": build["binary_sha256"],
        "command": command, "cwd": str(cwd), "source_root": build["source_root"],
        "environment": env, "timeout_seconds": config.timeout,
        "max_output_bytes_per_stream": config.max_output_bytes,
        **run_process(command, cwd=cwd, env=env, timeout=config.timeout,
                      max_output_bytes=config.max_output_bytes,
                      stdin=case.data if case.mode == "stdin" else None),
    }
    _classify_observation(result)
    result["expectation"] = _check_expected(result, case.expected)
    return result


def _run_matrix(config: Config, work: Path, *, retained: bool, repetitions: int = 1) -> dict[str, Any]:
    if any(work.is_relative_to(version.source_dir) for version in config.versions.values()):
        raise ValueError("The artifact workspace must be outside both target source trees.")
    snapshots = {}
    for label, version in config.versions.items():
        snapshot = work / "snapshots" / label
        shutil.copytree(version.source_dir, snapshot, symlinks=True,
                        ignore=shutil.ignore_patterns(".git"))
        snapshots[label] = snapshot
    builds = {}
    executions = []
    skipped = []
    for build_type in BUILD_TYPES:
        for label in VERSIONS:
            builds[label, build_type] = _build(
                config, label, config.versions[label], build_type, snapshots[label], work,
            )
        pair = [builds[label, build_type] for label in VERSIONS]
        for case in config.tests:
            for build in pair:
                if build["status"] == "built":
                    for _ in range(repetitions):
                        executions.append(_run_case(config, case, build, work))
                else:
                    skipped.append({"test_id": case.test_id, "version": build["version"],
                                    "build_type": build_type, "reason": "build_failed"})
    if skipped or any(run["launch_error"] for run in executions):
        status = "build_or_config_error"
    elif any(run["runner_stop"] or run["resource_limit"] for run in executions):
        status = "incomplete"
    else:
        status = "completed"
    return {
        "schema_version": "1.0", "analysis_type": "dynamic_execution",
        "target_id": config.target_id, "status": status,
        "repetitions": repetitions,
        "artifacts_retained": retained, "artifact_workspace": str(work) if retained else None,
        "builds": list(builds.values()),
        "tests": [{"test_id": case.test_id, "category": case.category, "reference": case.reference,
                   "expected": case.expected, "input": _input_metadata(case)} for case in config.tests],
        "executions": executions, "skipped": skipped,
    }


def run_suite(config: Config, *, artifacts_dir: str | Path | None = None,
              repetitions: int = 1) -> dict[str, Any]:
    """Build and run one observation per (build type, case, version).

    ``repetitions`` repeats every observation without rebuilding.  The default
    of one preserves the original single-observation contract; the classifier
    integration uses at least three repetitions.
    """
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be a positive integer.")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Dynamic execution requires Linux x86_64.")
    if artifacts_dir is not None:
        parent = Path(artifacts_dir).resolve()
        if any(parent.is_relative_to(v.source_dir) for v in config.versions.values()):
            raise ValueError("The artifact directory must be outside both target source trees.")
        parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="spv-execution-", dir=parent))
        return _run_matrix(config, work, retained=True, repetitions=repetitions)
    with tempfile.TemporaryDirectory(prefix="spv-execution-") as temporary:
        return _run_matrix(config, Path(temporary).resolve(), retained=False, repetitions=repetitions)
