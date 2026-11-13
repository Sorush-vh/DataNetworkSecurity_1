"""Compare two committed versions of a Git repository."""

from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class VersionComparisonError(RuntimeError):
    """Raised when Git metadata cannot be resolved or compared."""


@dataclass(frozen=True)
class CommitInfo:
    commit: str
    short_commit: str
    author_name: str
    author_email: str
    authored_at: str
    subject: str


@dataclass(frozen=True)
class ChangedFile:
    status: str
    change_type: str
    old_path: str | None
    new_path: str | None
    similarity: int | None = None


def _run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    git_env = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_PREFIX",
        "GIT_SHALLOW_FILE",
    ):
        git_env.pop(key, None)

    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=git_env,
        )
    except FileNotFoundError as exc:
        raise VersionComparisonError(
            "Git executable was not found. Install Git and make sure it is available on PATH."
        ) from exc

    if check and result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unknown Git error"
        raise VersionComparisonError(f"Git command failed ({result.returncode}): {message}")

    return result


def _resolve_commit(repo: Path, revision: str) -> str:
    if not revision or revision.startswith("-"):
        raise VersionComparisonError(f"Invalid Git revision: {revision!r}")

    result = _run_git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}")
    commit = result.stdout.strip()

    if len(commit) not in {40, 64} or any(char not in "0123456789abcdefABCDEF" for char in commit):
        raise VersionComparisonError(f"Git did not resolve {revision!r} to a valid commit hash.")

    return commit.lower()


def _get_commit_info(repo: Path, commit: str) -> CommitInfo:
    result = _run_git(
        repo,
        "show",
        "-s",
        "--format=%H%x00%h%x00%an%x00%ae%x00%aI%x00%s",
        commit,
    )
    fields = result.stdout.rstrip("\n").split("\x00")

    if len(fields) != 6:
        raise VersionComparisonError(f"Could not parse metadata for commit {commit}.")

    return CommitInfo(
        commit=fields[0],
        short_commit=fields[1],
        author_name=fields[2],
        author_email=fields[3],
        authored_at=fields[4],
        subject=fields[5],
    )


def _parse_name_status(output: str) -> list[ChangedFile]:
    tokens = output.split("\x00")
    if tokens and tokens[-1] == "":
        tokens.pop()

    changes: list[ChangedFile] = []
    index = 0

    while index < len(tokens):
        status_token = tokens[index]
        index += 1

        if not status_token:
            continue

        status_code = status_token[0]
        similarity = int(status_token[1:]) if status_token[1:].isdigit() else None

        if status_code in {"R", "C"}:
            if index + 1 >= len(tokens):
                raise VersionComparisonError("Malformed Git rename/copy diff output.")
            old_path, new_path = tokens[index], tokens[index + 1]
            index += 2
        else:
            if index >= len(tokens):
                raise VersionComparisonError("Malformed Git name-status diff output.")
            path = tokens[index]
            index += 1
            old_path = path if status_code != "A" else None
            new_path = path if status_code != "D" else None

        change_type = {
            "A": "added",
            "M": "modified",
            "D": "deleted",
            "R": "renamed",
            "C": "copied",
            "T": "type_changed",
            "U": "unmerged",
        }.get(status_code, "unknown")

        changes.append(
            ChangedFile(
                status=status_token,
                change_type=change_type,
                old_path=old_path,
                new_path=new_path,
                similarity=similarity,
            )
        )

    return changes


def compare_versions(
    repo_path: str | Path,
    base_revision: str,
    patched_revision: str,
) -> dict[str, Any]:
    """Compare two committed snapshots and return a JSON-serializable report.

    `repo_path` must point to the Git working-tree root.
    """
    repo = Path(repo_path).expanduser().resolve()

    if not repo.exists() or not repo.is_dir():
        raise VersionComparisonError(f"Repository path does not exist or is not a directory: {repo}")

    top_level = Path(_run_git(repo, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top_level != repo:
        raise VersionComparisonError(
            f"Repository path must be the Git working-tree root. "
            f"Provided path: {repo}; detected root: {top_level}"
        )

    base_commit = _resolve_commit(repo, base_revision)
    patched_commit = _resolve_commit(repo, patched_revision)

    if base_commit == patched_commit:
        changes: list[ChangedFile] = []
    else:
        diff = _run_git(
            repo,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--find-renames",
            "--name-status",
            "-z",
            base_commit,
            patched_commit,
            "--",
        )
        changes = _parse_name_status(diff.stdout)

    counts = {
        "added": 0,
        "modified": 0,
        "deleted": 0,
        "renamed": 0,
        "copied": 0,
        "type_changed": 0,
        "unmerged": 0,
        "unknown": 0,
    }
    for item in changes:
        counts[item.change_type] += 1

    ancestry = _run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        base_commit,
        patched_commit,
        check=False,
    )
    if ancestry.returncode == 0:
        base_is_ancestor_of_patched = True
    elif ancestry.returncode == 1:
        base_is_ancestor_of_patched = False
    else:
        message = ancestry.stderr.strip() or "Could not determine commit ancestry."
        raise VersionComparisonError(message)

    return {
        "schema_version": "1.0",
        "analysis_type": "version_comparison",
        "repository": str(repo),
        "comparison": {
            "direction": "base_to_patched",
            "base": asdict(_get_commit_info(repo, base_commit)),
            "patched": asdict(_get_commit_info(repo, patched_commit)),
            "base_is_ancestor_of_patched": base_is_ancestor_of_patched,
            "same_commit": base_commit == patched_commit,
        },
        "summary": {
            "files_changed": len(changes),
            **counts,
        },
        "changed_files": [asdict(item) for item in changes],
        "limitations": [
            "This report compares committed Git snapshots, not uncommitted working-tree changes.",
            "File-level changes are reported here; line-level hunks are handled by the Diff Analyzer.",
            "A changed file or nearby line does not by itself prove that a runtime finding is caused by the patch.",
        ],
    }
