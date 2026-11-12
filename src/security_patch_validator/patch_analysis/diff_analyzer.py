"""Extract line-level changes from Git Diff between two committed versions."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

from security_patch_validator.patch_analysis.version_comparator import (
    VersionComparisonError,
    compare_versions,
)


_HUNK_HEADER = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?: ?(?P<section>.*))?$"
)


def _run_git(repo: Path, *args: str) -> str:
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

    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unknown Git error"
        raise VersionComparisonError(f"Git command failed ({result.returncode}): {message}")

    return result.stdout


def _parse_patch(patch: str) -> tuple[list[dict[str, Any]], bool, bool]:
    """Parse zero-context unified Diff hunks for a single file."""
    lines = patch.splitlines()
    hunks: list[dict[str, Any]] = []
    binary = any(
        line.startswith("Binary files ") or line == "GIT binary patch"
        for line in lines
    )
    mode_changed = any(
        line.startswith(("old mode ", "new mode ", "new file mode ", "deleted file mode "))
        for line in lines
    )

    current: dict[str, Any] | None = None
    old_line = 0
    new_line = 0

    for line in lines:
        match = _HUNK_HEADER.match(line)
        if match:
            old_start = int(match.group("old_start"))
            old_count = int(match.group("old_count") or 1)
            new_start = int(match.group("new_start"))
            new_count = int(match.group("new_count") or 1)

            current = {
                "old_start": old_start,
                "old_count": old_count,
                "new_start": new_start,
                "new_count": new_count,
                "section": match.group("section") or "",
                "removed_lines": [],
                "added_lines": [],
            }
            hunks.append(current)
            old_line = old_start
            new_line = new_start
            continue

        if current is None or line.startswith("\\ No newline at end of file"):
            continue

        if line.startswith("-"):
            current["removed_lines"].append(
                {"line_number": old_line, "content": line[1:]}
            )
            old_line += 1
        elif line.startswith("+"):
            current["added_lines"].append(
                {"line_number": new_line, "content": line[1:]}
            )
            new_line += 1
        elif line.startswith(" "):
            old_line += 1
            new_line += 1

    return hunks, binary, mode_changed


def analyze_diff(
    repo_path: str | Path,
    base_revision: str,
    patched_revision: str,
) -> dict[str, Any]:
    """Analyze file-level and line-level changes between two Git commits.

    Removed line numbers refer to Base. Added line numbers refer to Patched.
    """
    comparison = compare_versions(repo_path, base_revision, patched_revision)
    repo = Path(comparison["repository"])
    base_commit = comparison["comparison"]["base"]["commit"]
    patched_commit = comparison["comparison"]["patched"]["commit"]

    analyzed_files: list[dict[str, Any]] = []
    totals = {
        "files_analyzed": 0,
        "files_with_text_changes": 0,
        "binary_files": 0,
        "mode_changed_files": 0,
        "hunks": 0,
        "added_lines": 0,
        "removed_lines": 0,
    }

    for changed_file in comparison["changed_files"]:
        paths = list(dict.fromkeys(
            path
            for path in (changed_file["old_path"], changed_file["new_path"])
            if path is not None
        ))
        pathspecs = [f":(literal){path}" for path in paths]

        patch = _run_git(
            repo,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--find-renames",
            "--unified=0",
            base_commit,
            patched_commit,
            "--",
            *pathspecs,
        )

        hunks, is_binary, mode_changed = _parse_patch(patch)
        additions = sum(len(hunk["added_lines"]) for hunk in hunks)
        deletions = sum(len(hunk["removed_lines"]) for hunk in hunks)

        analyzed_files.append({
            **changed_file,
            "is_binary": is_binary,
            "mode_changed": mode_changed,
            "hunk_count": len(hunks),
            "additions": additions,
            "deletions": deletions,
            "hunks": hunks,
        })

        totals["files_analyzed"] += 1
        totals["files_with_text_changes"] += int(bool(hunks))
        totals["binary_files"] += int(is_binary)
        totals["mode_changed_files"] += int(mode_changed)
        totals["hunks"] += len(hunks)
        totals["added_lines"] += additions
        totals["removed_lines"] += deletions

    return {
        "schema_version": "1.0",
        "analysis_type": "git_diff_analysis",
        "repository": str(repo),
        "comparison": comparison["comparison"],
        "summary": totals,
        "files": analyzed_files,
        "line_number_convention": {
            "removed_lines": "Line numbers refer to the Base version.",
            "added_lines": "Line numbers refer to the Patched version.",
            "hunk_ranges": "Git unified-diff ranges; zero counts are preserved for pure insertions and deletions.",
        },
        "limitations": [
            "The analysis compares committed snapshots, not uncommitted working-tree changes.",
            "Binary files are identified but their contents are not interpreted as source lines.",
            "Diff correlation alone does not prove that a patch fixes or causes a runtime issue.",
        ],
    }
