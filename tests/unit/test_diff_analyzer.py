from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def source_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "source repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.name", "Diff Analyzer Test")
    git(repo, "config", "user.email", "diff-test@example.invalid")
    (repo / "parser.c").write_text(
        "int parse(void) {\n"
        "    int length = 10;\n"
        "    return length;\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "remove_me.c").write_text("int old_value(void) { return 1; }\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    return repo


def test_extracts_added_and_removed_lines(source_repo: Path) -> None:
    base = git(source_repo, "rev-parse", "HEAD")
    (source_repo / "parser.c").write_text(
        "int parse(void) {\n"
        "    int length = 20;\n"
        "    int safe = 1;\n"
        "    return length + safe;\n"
        "}\n",
        encoding="utf-8",
    )
    git(source_repo, "add", ".")
    git(source_repo, "commit", "-m", "patch parser")
    patched = git(source_repo, "rev-parse", "HEAD")

    report = analyze_diff(source_repo, base, patched)

    assert report["summary"]["files_analyzed"] == 1
    assert report["summary"]["added_lines"] == 3
    assert report["summary"]["removed_lines"] == 2
    parser = report["files"][0]
    assert parser["new_path"] == "parser.c"
    assert parser["hunk_count"] == 1
    assert parser["hunks"][0]["removed_lines"][0] == {
        "line_number": 2, "content": "    int length = 10;"
    }
    assert parser["hunks"][0]["added_lines"][0] == {
        "line_number": 2, "content": "    int length = 20;"
    }
    assert parser["hunks"][0]["added_lines"][-1]["line_number"] == 4


def test_detects_added_and_deleted_files(source_repo: Path) -> None:
    base = git(source_repo, "rev-parse", "HEAD")
    (source_repo / "remove_me.c").unlink()
    (source_repo / "new_file.c").write_text("int added(void) { return 7; }\n", encoding="utf-8")
    git(source_repo, "add", "-A")
    git(source_repo, "commit", "-m", "add and delete files")
    patched = git(source_repo, "rev-parse", "HEAD")

    report = analyze_diff(source_repo, base, patched)

    assert report["summary"]["files_analyzed"] == 2
    assert report["summary"]["added_lines"] == 1
    assert report["summary"]["removed_lines"] == 1
    assert {item["change_type"] for item in report["files"]} == {"added", "deleted"}


def test_detects_renamed_file_with_content_change(source_repo: Path) -> None:
    base = git(source_repo, "rev-parse", "HEAD")
    git(source_repo, "mv", "parser.c", "renamed_parser.c")
    (source_repo / "renamed_parser.c").write_text(
        "int parse(void) {\n"
        "    int length = 99;\n"
        "    return length;\n"
        "}\n",
        encoding="utf-8",
    )
    git(source_repo, "add", "-A")
    git(source_repo, "commit", "-m", "rename and update")
    patched = git(source_repo, "rev-parse", "HEAD")

    report = analyze_diff(source_repo, base, patched)
    renamed = next(item for item in report["files"] if item["change_type"] == "renamed")
    assert renamed["old_path"] == "parser.c"
    assert renamed["new_path"] == "renamed_parser.c"
    assert renamed["additions"] == 1
    assert renamed["deletions"] == 1


def test_handles_filenames_with_spaces(source_repo: Path) -> None:
    base = git(source_repo, "rev-parse", "HEAD")
    (source_repo / "file with spaces.c").write_text("int spaced = 1;\n", encoding="utf-8")
    git(source_repo, "add", ".")
    git(source_repo, "commit", "-m", "add spaced path")
    patched = git(source_repo, "rev-parse", "HEAD")

    report = analyze_diff(source_repo, base, patched)
    assert report["files"][0]["new_path"] == "file with spaces.c"
    assert report["files"][0]["additions"] == 1


def test_same_commit_has_empty_diff(source_repo: Path) -> None:
    commit = git(source_repo, "rev-parse", "HEAD")
    report = analyze_diff(source_repo, commit, commit)
    assert report["summary"]["files_analyzed"] == 0
    assert report["files"] == []


def test_reports_binary_file_without_parsing_contents(source_repo: Path) -> None:
    base = git(source_repo, "rev-parse", "HEAD")
    (source_repo / "payload.bin").write_bytes(b"\x00\x01\x02\xff\x00")
    git(source_repo, "add", ".")
    git(source_repo, "commit", "-m", "add binary payload")
    patched = git(source_repo, "rev-parse", "HEAD")

    report = analyze_diff(source_repo, base, patched)
    assert report["summary"]["binary_files"] == 1
    assert report["files"][0]["is_binary"] is True
    assert report["files"][0]["hunks"] == []


def test_tracks_pure_insertion_at_start(source_repo: Path) -> None:
    base = git(source_repo, "rev-parse", "HEAD")
    original = (source_repo / "parser.c").read_text(encoding="utf-8")
    (source_repo / "parser.c").write_text("// added header\n" + original, encoding="utf-8")
    git(source_repo, "add", ".")
    git(source_repo, "commit", "-m", "insert header")
    patched = git(source_repo, "rev-parse", "HEAD")

    report = analyze_diff(source_repo, base, patched)
    hunk = report["files"][0]["hunks"][0]
    assert hunk["old_start"] == 0
    assert hunk["old_count"] == 0
    assert hunk["new_start"] == 1
    assert hunk["new_count"] == 1
    assert hunk["added_lines"][0]["line_number"] == 1
