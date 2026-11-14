"""Target manifests, scenario materialization, and deterministic Git snapshots.

A target manifest is the single source of truth for one C/C++ application:
its four source versions, build recipe, test suite, hardening requirements,
vulnerability signature, and expected scenario outcomes.  The execution
module's own JSON schema is reused unchanged; this module only materializes a
base/patched pair for one scenario.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCENARIOS = ("correct", "incomplete", "regression")
VERSION_LABELS = ("base", "correct", "incomplete", "regression")
EXIT_CODES = {0, 10, 20, 30, 40}
_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_FIXED_DATE = "2000-01-01T00:00:00 +0000"
_GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Security Patch Validator",
    "GIT_AUTHOR_EMAIL": "spv@example.invalid",
    "GIT_COMMITTER_NAME": "Security Patch Validator",
    "GIT_COMMITTER_EMAIL": "spv@example.invalid",
    "GIT_AUTHOR_DATE": _FIXED_DATE,
    "GIT_COMMITTER_DATE": _FIXED_DATE,
}


class TargetError(ValueError):
    """Raised when a target manifest is invalid or cannot be prepared."""


@dataclass(frozen=True)
class TargetVersion:
    label: str
    source_dir: Path
    commit_hash: str | None
    role: str


@dataclass(frozen=True)
class Target:
    path: Path
    target_id: str
    name: str
    description: str
    real_world: bool
    upstream: dict[str, Any]
    vulnerability: dict[str, Any]
    versions: dict[str, TargetVersion]
    execution: dict[str, Any]
    hardening: dict[str, Any]
    scenarios: dict[str, dict[str, Any]]
    reference_tests: Path


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TargetError(f"{label} must be a JSON object.")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TargetError(f"{label} must be a nonempty string.")
    return value


def _load_reference_tests(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise TargetError(f"Reference test suite does not exist: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TargetError(f"Reference test suite is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tests"), list) or not data["tests"]:
        raise TargetError("Reference test suite must contain a nonempty tests array.")
    return data


def load_target(path: str | Path) -> Target:
    """Load and validate a target manifest."""
    manifest_path = Path(path).expanduser().resolve()
    if not manifest_path.is_file():
        raise TargetError(f"Target manifest does not exist: {manifest_path}")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TargetError(f"Target manifest is not valid JSON: {exc}") from exc
    raw = _object(raw, "Target manifest")
    if raw.get("schema_version") != "1.0":
        raise TargetError("Target manifest schema_version must be '1.0'.")

    root = manifest_path.parent
    target_id = _string(raw.get("target_id"), "target_id")
    name = _string(raw.get("name"), "name")
    description = _string(raw.get("description"), "description")
    real_world = raw.get("real_world")
    if not isinstance(real_world, bool):
        raise TargetError("real_world must be a boolean.")

    upstream = _object(raw.get("upstream", {}), "upstream")
    vulnerability = _object(raw.get("vulnerability"), "vulnerability")
    signature = _object(vulnerability.get("signature"), "vulnerability.signature")
    _string(signature.get("error_type"), "vulnerability.signature.error_type")
    _string(signature.get("file"), "vulnerability.signature.file")
    if not isinstance(signature.get("function"), str) and not isinstance(signature.get("line"), int):
        raise TargetError("vulnerability.signature needs function and/or line.")

    declared_versions = _object(raw.get("versions"), "versions")
    versions: dict[str, TargetVersion] = {}
    for label in VERSION_LABELS:
        entry = _object(declared_versions.get(label), f"versions.{label}")
        source = (root / _string(entry.get("source_dir"), f"versions.{label}.source_dir")).resolve()
        if not source.is_dir():
            raise TargetError(f"versions.{label}.source_dir does not exist: {source}")
        commit = entry.get("commit_hash")
        if commit is not None and (not isinstance(commit, str) or not _FULL_COMMIT.fullmatch(commit)):
            raise TargetError(f"versions.{label}.commit_hash must be a full Git commit hash.")
        role = _string(entry.get("role", "vulnerable" if label == "base" else "patched"),
                       f"versions.{label}.role")
        versions[label] = TargetVersion(label, source, commit.lower() if commit else None, role)

    execution = _object(raw.get("execution"), "execution")
    for key in ("build", "tests"):
        if key not in execution:
            raise TargetError(f"execution.{key} is required.")
    if not isinstance(execution["tests"], list) or not execution["tests"]:
        raise TargetError("execution.tests must be a nonempty array.")

    hardening = _object(raw.get("hardening", {}), "hardening")
    required = _object(hardening.get("required", {}), "hardening.required")
    for protection, status in required.items():
        if protection not in {"relro", "pie", "nx", "stack_canary"}:
            raise TargetError(f"Unknown hardening protection: {protection}")
        if not isinstance(status, str) or not status:
            raise TargetError(f"hardening.required.{protection} must be a string.")

    declared_scenarios = _object(raw.get("scenarios"), "scenarios")
    scenarios: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        entry = _object(declared_scenarios.get(scenario), f"scenarios.{scenario}")
        patched_version = _string(entry.get("patched_version"), f"scenarios.{scenario}.patched_version")
        if patched_version not in versions or patched_version == "base":
            raise TargetError(f"scenarios.{scenario}.patched_version must name a patched version.")
        expected_code = entry.get("expected_exit_code")
        if type(expected_code) is not int or expected_code not in EXIT_CODES:
            raise TargetError(f"scenarios.{scenario}.expected_exit_code must be one of {sorted(EXIT_CODES)}.")
        statuses = entry.get("expected_statuses")
        if not isinstance(statuses, list) or not statuses or any(not isinstance(item, str) for item in statuses):
            raise TargetError(f"scenarios.{scenario}.expected_statuses must be a nonempty string array.")
        scenarios[scenario] = {
            "patched_version": patched_version,
            "expected_exit_code": expected_code,
            "expected_statuses": statuses,
        }

    reference_tests = (root / _string(raw.get("reference_tests"), "reference_tests")).resolve()
    _load_reference_tests(reference_tests)

    return Target(
        path=manifest_path,
        target_id=target_id,
        name=name,
        description=description,
        real_world=real_world,
        upstream=upstream,
        vulnerability=vulnerability,
        versions=versions,
        execution=execution,
        hardening=hardening,
        scenarios=scenarios,
        reference_tests=reference_tests,
    )


def materialize_execution_config(
    target: Target,
    scenario: str,
    output_path: str | Path,
    *,
    commit_hashes: dict[str, str] | None = None,
    relative_inputs: bool = False,
) -> Path:
    """Write a base/patched execution config for one scenario.

    Input paths in the manifest are relative to the target directory.  They are
    rewritten for the output config: absolute by default (used by the
    orchestrator) or relative to the output file when ``relative_inputs`` is
    true (used for checked-in configs).
    """
    if scenario not in target.scenarios:
        raise TargetError(f"Unknown scenario: {scenario}")
    patched_label = target.scenarios[scenario]["patched_version"]
    hashes = commit_hashes or {}
    path = Path(output_path).expanduser().resolve()

    def version_entry(label: str) -> dict[str, Any]:
        version = target.versions[label]
        commit = hashes.get(label) or version.commit_hash
        source = str(version.source_dir)
        if relative_inputs:
            source = os.path.relpath(version.source_dir, path.parent)
        entry: dict[str, Any] = {"source_dir": source}
        if commit:
            entry["commit_hash"] = commit
        return entry

    tests = []
    for test in target.execution["tests"]:
        copied = json.loads(json.dumps(test))
        input_spec = copied.get("input")
        if isinstance(input_spec, dict) and isinstance(input_spec.get("path"), str):
            resolved = (target.path.parent / input_spec["path"]).resolve()
            if relative_inputs:
                input_spec["path"] = os.path.relpath(resolved, path.parent)
            else:
                input_spec["path"] = str(resolved)
        tests.append(copied)

    config = {
        "target_id": target.target_id,
        "versions": {
            "base": version_entry("base"),
            "patched": version_entry(patched_label),
        },
        "build": target.execution["build"],
        "limits": target.execution.get("limits", {}),
        "tests": tests,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    merged = os.environ.copy()
    for key in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX",
        "GIT_SHALLOW_FILE",
    ):
        merged.pop(key, None)
    merged.update(_GIT_IDENTITY)
    merged["GIT_CONFIG_NOSYSTEM"] = "1"
    if env:
        merged.update(env)
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=merged,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise TargetError(f"Git command failed ({result.returncode}): {message}")
    return result.stdout


def _clear_worktree(repo: Path) -> None:
    for entry in repo.iterdir():
        if entry.name == ".git":
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def _copy_version(source: Path, repo: Path) -> None:
    for entry in source.iterdir():
        if entry.name == ".git":
            continue
        destination = repo / entry.name
        if entry.is_dir() and not entry.is_symlink():
            shutil.copytree(entry, destination, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, destination, follow_symlinks=False)


def prepare_git_repo(target: Target, work_dir: str | Path) -> dict[str, str]:
    """Create a deterministic Git repository with one commit per version.

    Each patched version is committed as a direct child of the base commit, so
    ``git diff base patched`` is the standalone patch for that scenario.  Fixed
    identities and dates make the commit hashes reproducible across runs.
    """
    repo = Path(work_dir).expanduser().resolve() / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", _GIT_IDENTITY["GIT_AUTHOR_NAME"])
    _git(repo, "config", "user.email", _GIT_IDENTITY["GIT_AUTHOR_EMAIL"])

    _copy_version(target.versions["base"].source_dir, repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base_hash = _git(repo, "rev-parse", "HEAD").strip()
    hashes = {"base": base_hash}

    for label in ("correct", "incomplete", "regression"):
        _git(repo, "checkout", "-q", "-B", label, base_hash)
        _clear_worktree(repo)
        _copy_version(target.versions[label].source_dir, repo)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"{label} patch")
        hashes[label] = _git(repo, "rev-parse", "HEAD").strip()

    _git(repo, "checkout", "-q", "main")
    return hashes


def load_reference_tests(target: Target) -> dict[str, Any]:
    return _load_reference_tests(target.reference_tests)


def reference_test_map(target: Target) -> dict[str, dict[str, Any]]:
    suite = load_reference_tests(target)
    result = {}
    for test in suite["tests"]:
        if not isinstance(test, dict) or not isinstance(test.get("id"), str):
            raise TargetError("Every reference test needs a string id.")
        if test["id"] in result:
            raise TargetError(f"Duplicate reference test id: {test['id']}")
        result[test["id"]] = test
    return result
