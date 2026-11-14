# Target Applications and Binary Hardening (Module 4)

This guide covers the target-application layer, the ELF hardening analysis, and
the scenario orchestrator. It does not replace the contracts in
[execution.md](execution.md) and [classifier-contract.md](classifier-contract.md).

## 1. What Module 4 adds

| Piece | Location |
|---|---|
| ELF hardening inspection | `src/security_patch_validator/hardening/` |
| Target manifest loader / validator | `src/security_patch_validator/targets/manifest.py` |
| Scenario orchestrator | `src/security_patch_validator/targets/orchestrator.py` |
| Reproducer integration | `src/security_patch_validator/targets/reproducer.py` |
| Two target applications (four versions each) | `targets/bzip2/`, `targets/tlvparse/` |
| Checked-in execution configs | `configs/bzip2/`, `configs/tlvparse/` |
| Reference oracles | `targets/*/reference-tests.json` |
| CLI commands | `spv hardening`, `spv targets ...` |

The existing execution schema is reused unchanged. A scenario is always a
base/patched pair, so the four-version target is represented by three
configs, one per patched version.

## 2. Target manifest schema

`targets/<id>/target.json` is the single source of truth for one application.
Relative paths are resolved against the manifest directory.

```json
{
  "schema_version": "1.0",
  "target_id": "example",
  "name": "Example 1.0",
  "description": "What the application does.",
  "real_world": true,
  "upstream": {"project": "example", "version": "1.0", "url": "...", "license": "..."},
  "vulnerability": {
    "id": "CVE-XXXX-YYYY",
    "description": "Root cause and observable effect.",
    "signature": {"error_type": "heap-buffer-overflow", "file": "src/parser.c", "function": "parse"}
  },
  "versions": {
    "base":       {"source_dir": "versions/base",       "role": "vulnerable"},
    "correct":    {"source_dir": "versions/correct",    "role": "patched"},
    "incomplete": {"source_dir": "versions/incomplete", "role": "patched"},
    "regression": {"source_dir": "versions/regression", "role": "patched"}
  },
  "execution": {
    "build": {
      "binary": "example",
      "commands": [["sh", "build.sh"]],
      "translation_units": ["src/parser.c", "src/main.c"]
    },
    "limits": {"build_timeout": 120, "timeout": 10, "max_output_bytes": 1048576},
    "tests": [
      {
        "id": "SEC-001",
        "category": "invalid",
        "input": {"mode": "file", "path": "inputs/poc.bin", "name": "poc.bin"},
        "args": ["{input}"],
        "expected": {"exit_code": 2, "stdout": ""},
        "reference": "targets/example/reference-tests.json#SEC-001",
        "classifier": {
          "kind": "security",
          "role": "original",
          "build_type": "asan_ubsan",
          "expected_patched": {"exit_code": 2, "stdout": ""}
        }
      }
    ]
  },
  "hardening": {
    "required": {"relro": "full", "pie": "enabled", "nx": "enabled", "stack_canary": "present"}
  },
  "scenarios": {
    "correct":    {"patched_version": "correct",    "expected_exit_code": 0,  "expected_statuses": ["FIXED"]},
    "incomplete": {"patched_version": "incomplete", "expected_exit_code": 10, "expected_statuses": ["INCOMPLETE_FIX"]},
    "regression": {"patched_version": "regression", "expected_exit_code": 20, "expected_statuses": ["FUNCTIONAL_REGRESSION"]}
  },
  "reference_tests": "reference-tests.json"
}
```

### Test metadata

The execution runner ignores unknown fields, so the `classifier` object is
carried in the manifest and consumed by the orchestrator:

* Security tests: `kind=security`, `role=original|alternate`, `build_type` must
  be a sanitizer label, and `expected_patched` is the oracle for the patched
  version.
* Functional tests: `kind=functional`, `validity=valid`, `build_type=release`,
  and `reference` is the independent oracle.
* Invalid/boundary tests without a `classifier` object still run and are
  checked by the execution expectation and the reference verification, but they
  are not part of the classifier suite.

### Adding a new target

1. Create `targets/<id>/versions/{base,correct,incomplete,regression}`.
2. Add `targets/<id>/target.json` and `reference-tests.json`.
3. Add build commands. The harness supplies `CFLAGS`, `CXXFLAGS`, `LDFLAGS`,
   and (for sanitized builds) an audited `CC`/`CXX` wrapper.
4. Add `translation_units` for every C/C++ file linked into the target.
5. Run `spv targets validate --target targets/<id>/target.json`.
6. Run `spv targets run --target ... --scenario correct` and the other two
   scenarios.

No core Python code needs to change.

## 3. Deterministic Git snapshots

The repository contains four working-tree directories, not four commits. To
produce real Git Diff evidence, `prepare_git_repo()` creates a temporary
repository, commits the base tree, then commits each patched version as a
**direct child of base** on its own branch. The identity and dates are fixed,
so the commit hashes are reproducible. The execution config receives those
hashes, and the classifier verifies that every execution carries the expected
commit.

`git diff base patched` is therefore the standalone patch for the scenario, not
the cumulative history of all four versions.

## 4. Hardening inspection

`inspect_binary(path)` runs `readelf -hW`, `readelf -lW`, `readelf -dW`,
`readelf -sW`, and (in deep mode) `objdump -d`. It never infers protections
from compiler flags.

| Protection | Evidence | Classification |
|---|---|---|
| RELRO | `GNU_RELRO` program header + `BIND_NOW`/`NOW` dynamic flag | `none`, `partial`, `full` |
| PIE | ELF type + `INTERP` segment / `DF_1_PIE` | `enabled`, `disabled`, `shared-object`, `unknown` |
| NX | `GNU_STACK` program-header flags | `enabled` when not `RWE`, `disabled` when `RWE`, `unknown` when absent |
| Stack canary | `__stack_chk_fail`/`__stack_chk_guard` symbol and `%fs:0x28` instruction | `present`, `absent` |

`compare_hardening(base, patched)` reports every changed protection and flags
regressions. A warning is evidence, not proof of exploitability:
PIE does not prove ASLR is enabled, and a canary symbol does not prove every
function is protected.

CLI:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli hardening \
  --binary artifacts/.../builds/base/release/source/bzip2 \
  --compare artifacts/.../builds/patched/release/source/bzip2 \
  --require relro=full --require pie=enabled --require nx=enabled \
  --require stack_canary=present --pretty
```

Exit code is 0 when the inspection completes and the requirements (if any) are
met, 40 when a requirement is not met, and 30 when the binary cannot be
inspected.

## 5. End-to-end scenario flow

```bash
# Validate the manifest and the four source directories.
PYTHONPATH=src python3 -m security_patch_validator.cli targets validate \
  --target targets/bzip2/target.json --pretty

# Materialize a checked-in execution config (optional; the orchestrator does
# this automatically with absolute paths and deterministic commit hashes).
PYTHONPATH=src python3 -m security_patch_validator.cli targets materialize \
  --target targets/bzip2/target.json --scenario correct \
  --output configs/bzip2/correct.json --relative

# Run one scenario end to end.
PYTHONPATH=src python3 -m security_patch_validator.cli targets run \
  --target targets/bzip2/target.json --scenario correct \
  --artifacts-dir artifacts/bzip2-correct \
  --output reports/bzip2-correct.json --summary --pretty

# Run all three scenarios and summarize.
PYTHONPATH=src python3 -m security_patch_validator.cli targets run-all \
  --target targets/bzip2/target.json --artifacts-dir artifacts/bzip2 \
  --output reports/bzip2-matrix.json --summary --pretty
```

`--summary` prints a short developer-facing report (exit code, statuses,
hardening warnings, reproducer sizes) while the JSON report is still written to
`--output`.

### Evaluating an unseen patch

The instructor may supply a patched source tree that is not one of the four
declared versions. Evaluate it without editing the manifest:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets run \
  --target targets/bzip2/target.json --scenario correct \
  --patched-dir /path/to/unseen-patched-tree \
  --artifacts-dir artifacts/bzip2-unseen \
  --output reports/bzip2-unseen.json --summary --pretty
```

The override is committed as the scenario's patched version, built with the
same recipe and tests, and evaluated with the same evidence rules. The
manifest's `expected_exit_code` is reported as `null` because the override has
no declared expectation; `matches_expected_exit_code` is also `null`. The
observed exit code and classifier statuses are still produced.

This is how the tool generalizes to patches that were not part of development:
the decision comes from the execution evidence, the independent oracle, and the
Git Diff, not from the patch filename or a hardcoded scenario.

`targets run` performs:

1. Load and validate the manifest.
2. Create deterministic Git commits for base and the scenario's patched version.
3. Materialize an execution config with the real commit hashes.
4. Build release and ASan/UBSan binaries for both versions.
5. Execute every test three times per version and build type.
6. Inspect and compare ELF hardening on the release binaries.
7. Verify the observed results against `reference-tests.json`.
8. Build the classifier suite and run `classify_patch` with the Git Diff.
9. For confirmed baseline findings: write a reproducer bundle, replay three
   times, minimize with Module 3's delta debugger, write a minimized bundle,
   generate a regression test, and validate it against both versions.
10. Validate the persisted regression suite
    (`regression/<target>/regression_tests.json`) against the current base and
    patched binaries. This runs even with `--skip-reproducer`, so a subsequent
    pipeline execution re-checks previously discovered inputs.
11. Write the scenario report and return the project exit code.

Artifacts are retained under
`artifacts/<target>-<scenario>/spv-.../`:

| File | Content |
|---|---|
| `execution-config.json` | Exact config used, including commit hashes |
| `execution.json` | Raw builds and executions |
| `hardening.json` | Protection evidence and comparison |
| `diff.json` | Git Diff report |
| `reference-verification.json` | Independent-oracle checks |
| `classifier-suite.json` | Paired suite passed to the classifier |
| `classification.json` | Classifier statuses and evidence |
| `reproducers/` | Original/minimized bundles and regression inputs |
| `persistent-regressions.json` | Re-check of the version-controlled regression suite |

### Persistent regression suite

Minimized inputs are also written to `regression/<target>/` and recorded in
`regression/<target>/regression_tests.json` with the input hash, mode, args,
expected patched behavior, and finding signature. They are **not** transient
artifacts: every later `spv targets run` re-validates them against the current
base and patched binaries, even with `--skip-reproducer`. A persisted test that
no longer triggers on base is reported as inconclusive, and one that still
triggers on patched is reported as `VULN_REMAINS`; neither is silently treated
as a pass.

Because this suite supplies reproducible evidence, a subsequent run can use
`--skip-reproducer` to skip the expensive re-minimization while still satisfying
the classifier's reproducer completion check.

## 6. Exit codes and the scenario matrix

The final exit code follows the project order `40 > 20 > 10 > 30 > 0`.

* `0` — correct patch: baseline vulnerability reproduced, not observed on the
  patched version, functional tests pass, hardening and reproducer checks
  completed.
* `10` — incomplete patch: the target signature remains reproducible on the
  patched version through an alternate input.
* `20` — regression patch: a valid functional test passes on base and fails on
  patched.
* `30` — build/config error (including an invalid manifest).
* `40` — inconclusive, including missing mandatory checks, unstable findings,
  or a reference-oracle mismatch that prevents a conclusion.

Hardening warnings are reported independently. A warning does not by itself
change the security/functional exit code; the target's required protection
list is checked and reported.

## 7. Isolation

Dynamic execution requires Linux x86_64. The provided image is
`docker/targets.Dockerfile` (Debian bookworm, gcc/g++, make, binutils, git,
python3). Run with no network and a read-only repository mount where possible:

```bash
docker build --platform linux/amd64 -f docker/targets.Dockerfile -t spv-targets .
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:/project" -w /project -e PYTHONPATH=src spv-targets \
  python3 -m security_patch_validator.cli targets validate \
  --target targets/bzip2/target.json --pretty
```

The `/project` mount must be writable for `artifacts/` and `reports/`. If the
repository itself must be read-only, mount a separate writable directory and
pass absolute artifact/output paths.

## 8. Known limitations

* The four versions are directories; the Git commits are synthesized
  deterministically by the orchestrator. The commit hash is reproducible but
  is not part of the parent repository's history.
* The bzip2 reproducer minimization is slow because the 2.3 KiB PoC is executed
  hundreds of times under ASan/UBSan.
* The reference oracle is independent of the patched output, but it only
  covers the configured tests. `FIXED` never means globally safe.
* Hardening analysis describes the binary; it does not prove runtime ASLR or
  per-function canary coverage.
