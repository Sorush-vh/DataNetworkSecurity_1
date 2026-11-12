"""Synthetic end-to-end demonstration; no target executable is run."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from security_patch_validator.patch_analysis.classifier import classify_patch
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True).stdout.strip()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="spv-classifier-demo-") as folder:
        repo = Path(folder)
        git(repo, "init")
        git(repo, "config", "user.name", "SPV Demo")
        git(repo, "config", "user.email", "demo@example.invalid")
        source = repo / "src"
        source.mkdir()
        c_file = source / "parser.c"
        c_file.write_text("\n".join(["// synthetic source"] * 44 + ["int old_parse = 1;"]) + "\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "-m", "synthetic base")
        base = git(repo, "rev-parse", "HEAD")

        c_file.write_text("\n".join(["// synthetic source"] * 44 + ["int old_parse = 0;"]) + "\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "-m", "synthetic patch")
        patched = git(repo, "rev-parse", "HEAD")

        trace = ("==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345678\n"
                 "    #0 0x400abc in parse_input /project/src/parser.c:45:7\n")

        def run(test_id: str, version: str, *, sanitized: bool) -> dict:
            return {
                "test_id": test_id, "version": version,
                "commit_hash": base if version == "base" else patched,
                "build_type": "asan" if sanitized else "release",
                "exit_code": 1 if sanitized else 0,
                "signal": None, "timeout": False,
                "stdout": ("" if version == "base" else "rejected\n") if sanitized else "accepted\n",
                "stderr": trace if sanitized and version == "base" else "",
            }

        suite = {
            "schema_version": "1.0", "target_id": "synthetic-demonstration",
            "target_issue": {"id": "demo-issue", "signature": {
                "error_type": "heap-buffer-overflow", "file": "src/parser.c", "function": "parse_input"}},
            "completion": {key: {"status": "passed", "evidence": "synthetic-only"}
                           for key in ("hardening", "test_matrix", "reproducer")},
            "tests": [
                {"test_id": "SEC-ORIGINAL", "kind": "security", "role": "original", "build_type": "asan",
                 "expected_patched": {"exit_code": 1, "stdout": "rejected\n"},
                 "executions": [run("SEC-ORIGINAL", version, sanitized=True)
                                for version in ("base", "patched") for _ in range(3)]},
                {"test_id": "FUN-VALID", "kind": "functional", "validity": "valid", "build_type": "release",
                 "reference": {"exit_code": 0, "stdout": "accepted\n"},
                 "executions": [run("FUN-VALID", version, sanitized=False)
                                for version in ("base", "patched") for _ in range(3)]},
            ],
        }
        report = classify_patch(suite, diff_report=analyze_diff(repo, base, patched), source_roots=["/project"])
        print("SYNTHETIC DEMO – not a real ASan/ELF validation")
        print(json.dumps({"statuses": report["statuses"], "security_status": report["security_status"],
                          "suggested_exit_code": report["suggested_exit_code"],
                          "diff_overlaps": report["tests"][0]["correlations"]["base"]["summary"]}, indent=2))


if __name__ == "__main__":
    main()
