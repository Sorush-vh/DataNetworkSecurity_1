# End-to-end verification log

This file records the commands and observed results used to validate Module 4.
The host is macOS arm64; all dynamic execution runs inside the Debian bookworm
`linux/amd64` image from `docker/targets.Dockerfile` (Rosetta emulation). The
same commands run natively on a Linux x86_64 runner.

## Environment

```text
Host:        macOS, Apple Silicon
Container:   debian:bookworm-slim, linux/amd64
Toolchain:   gcc, g++, make, binutils (readelf, objdump), git, python3
Python:      3.11
```

## Test suite

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/project" -w /project \
  -e PYTHONPATH=src spv-targets \
  python3 -m pytest tests/unit tests/integration -q
```

Result:

```text
141 passed, 1 skipped in 64.46s
```

The skipped test is the opt-in target scenario test. It was run separately:

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/project" -w /project \
  -e PYTHONPATH=src -e SPV_TARGET_SCENARIOS=1 spv-targets \
  python3 -m pytest tests/integration/test_target_scenarios.py -q
```

Result:

```text
1 passed in 103.02s
```

## Scenario matrices

Each matrix builds release and ASan/UBSan binaries for the base and the
scenario's patched version, runs every test three times per build type, checks
the independent reference oracle, runs the classifier with a real Git Diff,
validates the persisted regression suite, and returns the project exit code.

### tlvparse

```bash
python3 -m security_patch_validator.cli targets run-all \
  --target targets/tlvparse/target.json \
  --artifacts-dir artifacts/tlvparse-matrix --skip-reproducer \
  --output reports/tlvparse-matrix.json --summary --pretty
```

| Scenario | Expected | Observed | Statuses |
|---|---:|---:|---|
| correct | 0 | 0 | `FIXED` |
| incomplete | 10 | 10 | `INCOMPLETE_FIX` |
| regression | 20 | 20 | `FIXED`, `FUNCTIONAL_REGRESSION` |

`all_scenarios_match_expected: true`

### bzip2

```bash
python3 -m security_patch_validator.cli targets run-all \
  --target targets/bzip2/target.json \
  --artifacts-dir artifacts/bzip2-matrix --skip-reproducer \
  --output reports/bzip2-matrix.json --summary --pretty
```

| Scenario | Expected | Observed | Statuses |
|---|---:|---:|---|
| correct | 0 | 0 | `FIXED` |
| incomplete | 10 | 10 | `INCOMPLETE_FIX` |
| regression | 20 | 20 | `FIXED`, `FUNCTIONAL_REGRESSION` |

`all_scenarios_match_expected: true`

### Full reproducer generation

The complete runs (without `--skip-reproducer`) were also executed:

| Target | Scenario | Exit | Reproducer result |
|---|---|---:|---|
| tlvparse | correct | 0 | 204 → 67 bytes, 68 → 66 bytes; regression tests PASS |
| tlvparse | incomplete | 10 | minimized inputs still trigger the incomplete patch (`VULN_REMAINS`) |
| tlvparse | regression | 20 | security tests PASS; block-size-9 valid input fails |
| bzip2 | correct | 0 | 4184 → 2274 bytes; regression tests PASS |
| bzip2 | incomplete | 10 | alternate selector count still triggers (`VULN_REMAINS`) |
| bzip2 | regression | 20 | security tests PASS; valid block-size-9 input fails |

The bzip2 minimization runs about 12,500 sanitized executions per input under
Rosetta, so a full bzip2 scenario takes roughly 15–20 minutes on this host.
On native x86_64 it is substantially faster.

### Hardening change detection

The bzip2 regression version intentionally drops PIE in `build.sh`. A
`--skip-reproducer` regression run (using the persisted regression suite to
satisfy the reproducer check) produced:

```text
Statuses: FIXED, FUNCTIONAL_REGRESSION
Exit code: expected 20, observed 20
Hardening warnings:
  - pie protection regressed from 'enabled' to 'disabled' between the base and patched binaries.
Persistent regression suite: 2 test(s), passed=2, vulnerable=0, failed=0, inconclusive=0
```

The standalone hardening CLI also returned exit code 40 when
`--require pie=enabled` was not met, while still writing the full evidence
report.

### Persistent regression suite

The minimized inputs are stored under `regression/<target>/`. Re-validating
them against the correct scenario produced:

```text
bzip2:   2 tests, PASS=2
tlvparse: 2 tests, PASS=2
```

This is what allows a subsequent pipeline run with `--skip-reproducer` to pass
the reproducer completion check without re-minimizing.

## Unseen patch override

The `--patched-dir` path was exercised by evaluating
`targets/tlvparse/versions/incomplete` as an override for the `correct`
scenario:

```bash
python3 -m security_patch_validator.cli targets run \
  --target targets/tlvparse/target.json --scenario correct \
  --patched-dir targets/tlvparse/versions/incomplete --skip-reproducer \
  --artifacts-dir artifacts/tlvparse-unseen \
  --output reports/tlvparse-unseen.json --summary --pretty
```

The report shows `patched_source_overridden: true`, `expected_exit_code:
null`, `observed_exit_code: 40` (reproducer skipped, so inconclusive), and
`INCOMPLETE_FIX` among the statuses. With the persisted suite present, the same
run without `--skip-reproducer` reaches the incomplete-fix conclusion from
runtime evidence rather than the manifest's expected code.

## Artifacts

Reports are committed under `reports/`. Full artifacts (source snapshots,
binaries, run logs, bundles) are retained under `artifacts/` and are ignored by
Git because they are large and regenerable. The report files contain the
paths and hashes needed to locate them.
