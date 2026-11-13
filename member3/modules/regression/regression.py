
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from modules.reproducer.runner import execute_once, replay

def generate_regression_test(
    minimized_input,
    test_name,
    error_type,
    output_dir
):
    source = Path(minimized_input).resolve()

    if not source.is_file():
        raise FileNotFoundError(f"Input not found: {source}")

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", test_name)

    if not safe_name:
        raise ValueError("Test name cannot be empty")

    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    test_file = output / f"{safe_name}.input"
    manifest_path = output / "regression_tests.json"

    if manifest_path.exists():
        with open(manifest_path, encoding="utf-8") as file:
            manifest = json.load(file)
    else:
        manifest = {"tests": []}

    if any(test["name"] == safe_name for test in manifest["tests"]):
        raise ValueError(f"Test already exists: {safe_name}")

    shutil.copy2(source, test_file)

    sha256 = hashlib.sha256(test_file.read_bytes()).hexdigest()

    manifest["tests"].append({
        "name": safe_name,
        "input_file": test_file.name,
        "sha256": sha256,
        "error_type": error_type,
        "expected_on_base": True,
        "expected_on_patched": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    with open(manifest_path, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4, ensure_ascii=False)

    return test_file


def _normalize_error_type(error_type):
    if error_type is None:
        return None

    value = str(error_type).upper().replace("-", "_").replace(" ", "_")

    aliases = {
        "ADDRESSSANITIZER": "ADDRESS_SANITIZER",
        "ASAN": "ADDRESS_SANITIZER",
        "UBSAN": "UNDEFINED_BEHAVIOR_SANITIZER",
        "STACKSMASHING": "STACK_SMASHING",
        "SIGSEGV": "SIGSEGV",
        "SEGFAULT": "SEGMENTATION_FAULT"
    }

    return aliases.get(value, value)


def _prepare_command(command, input_file):
    if not isinstance(command, list) or not command:
        raise ValueError("Command must be a non-empty list")

    return [
        str(argument).replace("{input}", str(input_file))
        for argument in command
    ]


def validate_regression_test(
    input_file,
    base_command,
    patched_command,
    expected_error_type,
    timeout=5,
    environment=None,
    cwd=None,
    expected_location=None,
    repetitions=3
):
    input_path = Path(input_file).resolve()

    if not input_path.is_file():
        raise FileNotFoundError(f"Input not found: {input_path}")

    if not expected_error_type:
        raise ValueError("Expected error type cannot be empty")

    if repetitions < 3:
        raise ValueError("At least 3 repetitions are required")

    input_data = input_path.read_bytes()

    base_uses_input_file = any(
        "{input}" in str(argument)
        for argument in base_command
    )

    patched_uses_input_file = any(
        "{input}" in str(argument)
        for argument in patched_command
    )

    base_cmd = _prepare_command(base_command, input_path)
    patched_cmd = _prepare_command(patched_command, input_path)

    base_replay = replay(
        command=base_cmd,
        repetitions=repetitions,
        input_data=None if base_uses_input_file else input_data,
        timeout=timeout,
        environment=environment,
        cwd=cwd
    )

    patched_replay = replay(
        command=patched_cmd,
        repetitions=repetitions,
        input_data=None if patched_uses_input_file else input_data,
        timeout=timeout,
        environment=environment,
        cwd=cwd
    )

    expected = _normalize_error_type(expected_error_type)

    def evaluate_base(result):
        error = _normalize_error_type(result["error_type"])
        matches = error == expected

        if expected_location:
            matches = (
                matches
                and expected_location.lower() in result["stderr"].lower()
            )

        return matches

    def evaluate_patched(result):
        error = _normalize_error_type(result["error_type"])

        return (
            error != expected
            and result["returncode"] == 0
            and not result["timed_out"]
        )

    base_checks = [
        evaluate_base(result)
        for result in base_replay["results"]
    ]

    patched_checks = [
        evaluate_patched(result)
        for result in patched_replay["results"]
    ]

    base_matches = (
        base_replay["status"] == "STABLE"
        and all(base_checks)
    )

    patched_fixed = (
        patched_replay["status"] == "STABLE"
        and all(patched_checks)
    )

    stable = (
        base_replay["status"] == "STABLE"
        and patched_replay["status"] == "STABLE"
    )

    if not stable:
        status = "INCONCLUSIVE"
    elif base_matches and patched_fixed:
        status = "PASS"
    else:
        status = "FAIL"

    return {
        "test_file": str(input_path),
        "expected_error_type": expected,
        "repetitions": repetitions,
        "stability": {
            "base": base_replay["status"],
            "patched": patched_replay["status"],
            "overall": "STABLE" if stable else "FLAKY"
        },
        "base": {
            "results": base_replay["results"],
            "matches_expected_error": base_matches
        },
        "patched": {
            "results": patched_replay["results"],
            "same_error_absent": all(
                _normalize_error_type(result["error_type"]) != expected
                for result in patched_replay["results"]
            ),
            "expected_behavior": patched_fixed
        },
        "status": status,
        "validated_at": datetime.now(timezone.utc).isoformat()
    }
