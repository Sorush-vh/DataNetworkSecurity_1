# Patch Classification Contract v1.0 (Person 1)

The classifier consumes a **paired** test suite with externally approved target
issue and expected behavior. It combines Person 1's Git Diff / correlation
output with the Person 2 execution JSON and emits an evidence-based JSON report.
It does **not** execute target programs or claim a globally safe patch.

## Invocation

```powershell
.\.venv\Scripts\python.exe -m security_patch_validator.cli classify --repo . --base BASE_COMMIT --patched PATCH_COMMIT --suite configs/suite.json --source-root /project --output reports/local/classification.json --pretty
```

The CLI exit code is the suggested pipeline code. Non-zero classification codes
are **expected** when a patch is incomplete or tests are inconclusive. The
integration owner (Person 3) decides how to surface them in CI.

## Required suite schema

```json
{
  "schema_version": "1.0",
  "target_id": "example-target",
  "target_issue": {
    "id": "ISSUE-001",
    "signature": {
      "error_type": "heap-buffer-overflow",
      "file": "src/parser.c",
      "function": "parse_input"
    }
  },
  "completion": {
    "hardening": {"status": "passed", "evidence": "artifact-id-from-person-4"},
    "test_matrix": {"status": "passed", "evidence": "artifact-id-from-person-2"},
    "reproducer": {"status": "passed", "evidence": "artifact-id-from-person-3"}
  },
  "tests": [
    {
      "test_id": "SEC-001",
      "kind": "security",
      "role": "original",
      "build_type": "asan",
      "expected_patched": {"exit_code": 1, "stdout": "rejected\n"},
      "executions": [
        {"test_id": "SEC-001", "version": "base", "build_type": "asan", "commit_hash": "FULL_BASE_COMMIT_HASH", "exit_code": 1, "signal": null, "timeout": false, "stdout": "", "stderr": "SANITIZER_DIAGNOSTIC"},
        {"test_id": "SEC-001", "version": "patched", "build_type": "asan", "commit_hash": "FULL_PATCH_COMMIT_HASH", "exit_code": 1, "signal": null, "timeout": false, "stdout": "rejected\n", "stderr": ""}
      ]
    },
    {
      "test_id": "FUN-001",
      "kind": "functional",
      "validity": "valid",
      "build_type": "release",
      "reference": {"exit_code": 0, "stdout": "accepted\n"},
      "executions": [
        {"test_id": "FUN-001", "version": "base", "build_type": "release", "commit_hash": "FULL_BASE_COMMIT_HASH", "exit_code": 0, "signal": null, "timeout": false, "stdout": "accepted\n", "stderr": ""},
        {"test_id": "FUN-001", "version": "patched", "build_type": "release", "commit_hash": "FULL_PATCH_COMMIT_HASH", "exit_code": 0, "signal": null, "timeout": false, "stdout": "accepted\n", "stderr": ""}
      ]
    }
  ]
}
```

The example abbreviates repetitions for readability; **each test and version
needs at least three execution entries** for a conclusive classifier result.
The execution JSON objects should come from Person 2 rather than be constructed
from expectations. Both versions must receive **identical** inputs and
compatible build flags / resource limits, documented by Person 2's test matrix.

`completion` entries are **external attestations**, not checks implemented by
this component. They require real artifacts and verification from the owning
module. Supplying arbitrary nonempty strings does not constitute proof.

## Security test semantics

- `target_issue.signature.error_type` is the normalized ASan/UBSan type.
- `signature.file` is the path of the fault location (relative to target root).
- `signature.function` and/or `signature.line` disambiguates the **same** issue.
  Do not use only an error type to identify the vulnerability.
- `role=original` identifies the original reproducer; use `role=alternate` for
  an independently tested bypass input. Include both for Incomplete Patch.
- `expected_patched` comes from the program specification, not merely copying
  the patched program's output. Invalid input may validly exit non-zero.
- Sanitized build labels: `asan`, `ubsan`, `lsan`, `asan_ubsan`.
- The full 40-/64-hex Git commit hash must match the Diff report when provided.
- A file path in a sanitizer log can refer to a build root; `--source-root` may
  be repeated to map a runtime source prefix to repository-relative paths.
- Abnormal unclassified termination, unstable results, truncated logs,
  missing runs, and missing completion evidence prevent an end-to-end PASS.

## Functional regression semantics

- `kind=functional`, `validity=valid`, `build_type=release`.
- `reference` must be **independently defined** before patch evaluation.
- The Base must satisfy the reference oracle, and the Patched must consistently
  violate it to report `FUNCTIONAL_REGRESSION`.
- A failure already present in Base is **not** a patch-introduced regression.

## Statuses and exit codes

The report may contain **multiple statuses**:

- `FIXED`: original issue was reproducible in Base and was not observed on
  Patched within test scope, with valid expected patched behavior.
- `INCOMPLETE_FIX`: original issue remains reproducible on Patched, including
  via an alternate input known to reproduce the same issue in Base.
- `NEW_ISSUE`: a specific sanitizer finding appears in the Patched test that
  was not observed in corresponding Base runs. This does **not** prove patch
  causality.
- `FUNCTIONAL_REGRESSION`: valid independent baseline succeeds in Base and
  fails in Patched.
- `INCONCLUSIVE`: missing/unstable observations or incomplete obligatory checks.

Project-wide exit-code precedence: **40 > 20 > 10 > 30 > 0**:

- `0` PASS only if all required checks are complete and conclusive;
- `10` VULN_REMAINS / NEW_ISSUE;
- `20` FUNC_REGRESSION;
- `30` BUILD_OR_CONFIG_ERROR (CLI returns 30 for malformed input / Git errors);
- `40` INCONCLUSIVE, including missing compulsory checks.

`results[].correlations` contains evidence of which patch lines overlap runtime
locations. A changed-line overlap does not independently prove repair or
causation.

## Remaining group-level validation

Real ELF target executables, repeated runs under isolation, approved oracle,
ASan/UBSan outputs, binary-hardening reports, independent reproducers,
regression-test generation, and unseen-patch testing must be supplied by the
other components and verified in end-to-end tests.
