"""Configuration for paired runs with explicit test inputs and oracles."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VERSIONS = ("base", "patched")
BUILD_TYPES = ("release", "asan_ubsan")
CATEGORIES = ("valid", "boundary", "invalid")
MAX_INPUT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class Version:
    source_dir: Path
    commit_hash: str | None


@dataclass(frozen=True)
class TestCase:
    test_id: str
    category: str
    mode: str
    args: tuple[str, ...]
    data: bytes | None
    input_path: Path | None
    input_name: str | None
    expected: dict[str, Any]
    reference: str


@dataclass(frozen=True)
class Config:
    target_id: str
    versions: dict[str, Version]
    binary: Path
    build_commands: tuple[tuple[str, ...], ...]
    build_timeout: float
    timeout: float
    max_output_bytes: int
    tests: tuple[TestCase, ...]
    clean_commands: tuple[tuple[str, ...], ...] = ()
    translation_units: tuple[str, ...] | None = None


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"{label} must be a nonempty string without NUL characters.")
    return value


def _argv(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(part, str) or "\0" in part for part in value
    ):
        raise ValueError(f"{label} must be an array of strings without NUL characters.")
    return tuple(value)


def _timeout(value: Any, label: str, *, maximum: int) -> float:
    if type(value) not in (int, float) or not 0 < value <= maximum:
        raise ValueError(f"{label} must be a number in (0, {maximum}].")
    return float(value)


def _read_input(spec: dict, root: Path) -> tuple[bytes, Path | None]:
    if ("text" in spec) == ("path" in spec):
        raise ValueError("File and stdin inputs require exactly one of text or path.")
    path = None
    if "path" in spec:
        path = (root / _string(spec["path"], "input.path")).resolve()
        if not path.is_file():
            raise ValueError(f"Test input is not a regular file: {path}")
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
    else:
        if not isinstance(spec["text"], str):
            raise ValueError("input.text must be a string.")
        data = spec["text"].encode("utf-8")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"Test input exceeds {MAX_INPUT_BYTES} bytes.")
    return data, path


def _load_case(raw: Any, root: Path) -> TestCase:
    case = _object(raw, "Test case")
    test_id = _string(case.get("id"), "test.id")
    category = case.get("category")
    if category not in CATEGORIES:
        raise ValueError(f"{test_id}: category must be valid, boundary or invalid.")
    spec = _object(case.get("input"), f"{test_id}.input")
    mode = spec.get("mode")
    if mode not in ("argv", "stdin", "file"):
        raise ValueError(f"{test_id}: input.mode must be argv, stdin or file.")
    args = _argv(case.get("args", []), f"{test_id}.args")
    placeholders = args.count("{input}")
    if placeholders != int(mode == "file"):
        raise ValueError(f"{test_id}: use exactly one standalone {{input}} for file input.")
    data = path = name = None
    if mode in ("file", "stdin"):
        data, path = _read_input(spec, root)
    elif "path" in spec or "text" in spec:
        raise ValueError(f"{test_id}: supply argv input through args.")
    if mode == "file":
        name = _string(spec.get("name", path.name if path else "input.bin"), "input.name")
        if Path(name).name != name or name in (".", ".."):
            raise ValueError(f"{test_id}: input.name must be a single filename.")
    expected = _object(case.get("expected"), f"{test_id}.expected")
    if set(expected) - {"exit_code", "stdout", "stderr"}:
        raise ValueError(f"{test_id}: unrecognized expected field.")
    code = expected.get("exit_code")
    if type(code) is not int or not 0 <= code <= 255:
        raise ValueError(f"{test_id}: expected.exit_code must be in [0, 255].")
    if not isinstance(expected.get("stdout"), str) or (
        "stderr" in expected and not isinstance(expected["stderr"], str)
    ):
        raise ValueError(f"{test_id}: expected.stdout and optional stderr must be strings.")
    return TestCase(test_id, category, mode, args, data, path, name, dict(expected),
                    _string(case.get("reference"), f"{test_id}.reference"))


def load_config(path: str | Path) -> Config:
    """Read a JSON manifest and freeze the fixture bytes once for both versions."""
    path = Path(path).resolve()
    root = path.parent
    raw = _object(json.loads(path.read_text(encoding="utf-8")), "Configuration")
    versions = {}
    declared_versions = _object(raw.get("versions"), "versions")
    for label in VERSIONS:
        version = _object(declared_versions.get(label), f"versions.{label}")
        source = (root / _string(version.get("source_dir"), f"{label}.source_dir")).resolve()
        if not source.is_dir():
            raise ValueError(f"{label}: source directory does not exist: {source}")
        commit = version.get("commit_hash")
        if commit is not None and (
            not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit)
        ):
            raise ValueError(f"{label}: use a full Git commit hash.")
        versions[label] = Version(source, commit.lower() if commit else None)

    build = _object(raw.get("build"), "build")
    binary = Path(_string(build.get("binary"), "build.binary"))
    if binary.is_absolute() or ".." in binary.parts or binary == Path("."):
        raise ValueError("build.binary must be a relative path inside the source snapshot.")
    commands = build.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("build.commands must be a nonempty array of argv arrays.")
    build_commands = tuple(_argv(command, "build command") for command in commands)
    if any(not command or not command[0] for command in build_commands):
        raise ValueError("Each build command needs an executable.")
    clean = build.get("clean_commands", [])
    if not isinstance(clean, list):
        raise ValueError("build.clean_commands must be an array of argv arrays.")
    clean_commands = tuple(_argv(command, "clean command") for command in clean)
    if any(not command or not command[0] for command in clean_commands):
        raise ValueError("Each clean command needs an executable.")
    units = build.get("translation_units")
    if units is not None:
        if not isinstance(units, list) or not units:
            raise ValueError("build.translation_units must be a nonempty array of source paths.")
        units = tuple(_string(unit, "translation unit") for unit in units)
        if len(set(units)) != len(units) or any(
            Path(unit).is_absolute() or ".." in Path(unit).parts or Path(unit) == Path(".") for unit in units
        ):
            raise ValueError("Translation units must be unique relative source paths inside the snapshot.")

    limits = _object(raw.get("limits", {}), "limits")
    max_output = limits.get("max_output_bytes", 1024 * 1024)
    if type(max_output) is not int or not 1 <= max_output <= 16 * 1024 * 1024:
        raise ValueError("limits.max_output_bytes must be in [1, 16777216].")
    cases = raw.get("tests")
    if not isinstance(cases, list) or not cases:
        raise ValueError("tests must be a nonempty array.")
    tests = tuple(_load_case(case, root) for case in cases)
    if len({case.test_id for case in tests}) != len(tests):
        raise ValueError("Test IDs must be unique.")
    return Config(
        _string(raw.get("target_id"), "target_id"), versions, binary, build_commands,
        _timeout(limits.get("build_timeout", 120), "limits.build_timeout", maximum=3600),
        _timeout(limits.get("timeout", 5), "limits.timeout", maximum=300),
        max_output, tests, clean_commands, units,
    )
