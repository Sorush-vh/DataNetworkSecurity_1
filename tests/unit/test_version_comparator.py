from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security_patch_validator.patch_analysis.version_comparator import (
    VersionComparisonError,
    compare_versions,
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "sample-repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.name", "SPV Test")
    git(repo, "config", "user.email", "spv-test@example.invalid")
    (repo / "modified.c").write_text("int value(void) { return 1; }\n", encoding="utf-8")
    (repo / "deleted.c").write_text("int old_function(void) { return 0; }\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base version")
    return repo


def test_detects_modified_added_and_deleted_files(git_repo: Path) -> None:
    base = git(git_repo, "rev-parse", "HEAD")
    (git_repo / "modified.c").write_text("int value(void) { return 2; }\n", encoding="utf-8")
    (git_repo / "deleted.c").unlink()
    (git_repo / "added.c").write_text("int new_function(void) { return 3; }\n", encoding="utf-8")
    git(git_repo, "add", "-A")
    git(git_repo, "commit", "-m", "patched version")
    patched = git(git_repo, "rev-parse", "HEAD")

    report = compare_versions(git_repo, base, patched)
    assert report["summary"]["files_changed"] == 3
    assert report["summary"]["modified"] == 1
    assert report["summary"]["added"] == 1
    assert report["summary"]["deleted"] == 1
    assert report["comparison"]["base_is_ancestor_of_patched"] is True


def test_same_commit_has_no_changes(git_repo: Path) -> None:
    commit = git(git_repo, "rev-parse", "HEAD")
    report = compare_versions(git_repo, commit, commit)
    assert report["comparison"]["same_commit"] is True
    assert report["summary"]["files_changed"] == 0
    assert report["changed_files"] == []


def test_rejects_unknown_revision(git_repo: Path) -> None:
    base = git(git_repo, "rev-parse", "HEAD")
    with pytest.raises(VersionComparisonError):
        compare_versions(git_repo, base, "not-a-real-commit")


def test_rejects_non_repository_path(tmp_path: Path) -> None:
    with pytest.raises(VersionComparisonError):
        compare_versions(tmp_path, "HEAD", "HEAD")


def test_paths_with_spaces_are_preserved(git_repo: Path) -> None:
    base = git(git_repo, "rev-parse", "HEAD")
    (git_repo / "file with spaces.c").write_text("int x = 1;\n", encoding="utf-8")
    git(git_repo, "add", ".")
    git(git_repo, "commit", "-m", "add spaced filename")
    patched = git(git_repo, "rev-parse", "HEAD")
    report = compare_versions(git_repo, base, patched)
    assert report["changed_files"][0]["new_path"] == "file with spaces.c"


def test_detects_renamed_file(git_repo: Path) -> None:
    base = git(git_repo, "rev-parse", "HEAD")
    git(git_repo, "mv", "modified.c", "renamed.c")
    git(git_repo, "commit", "-m", "rename source file")
    patched = git(git_repo, "rev-parse", "HEAD")
    report = compare_versions(git_repo, base, patched)
    assert report["summary"]["renamed"] == 1
    renamed = next(item for item in report["changed_files"] if item["change_type"] == "renamed")
    assert renamed["old_path"] == "modified.c"
    assert renamed["new_path"] == "renamed.c"
    assert renamed["similarity"] == 100


def test_rejects_repository_subdirectory(git_repo: Path) -> None:
    base = git(git_repo, "rev-parse", "HEAD")
    nested = git_repo / "nested"
    nested.mkdir()
    with pytest.raises(VersionComparisonError):
        compare_versions(nested, base, base)
