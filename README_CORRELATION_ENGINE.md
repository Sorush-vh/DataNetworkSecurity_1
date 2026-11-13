# Correlation Engine — Person 1 / Stage 4

This stage extends the existing Git Diff Analyzer and Stack Trace Parser.
It links ASan/UBSan/LSan findings to modified files and changed source lines
without guessing patch validity.

## Install and test (Windows PowerShell)

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -v
```

## CLI

```powershell
.\.venv\Scripts\python.exe -m security_patch_validator.cli correlate --repo . --base BASE_COMMIT --patched PATCHED_COMMIT --trace examples/asan-execution-result.json --version base --source-root /project --pretty
```

**Important:** The existing example trace refers to `/project/src/parser.c`.
If your actual repository lacks that changed file, a `no_match` result is
correct and **not** a failure of the tool. For a deterministic demonstration,
use the included sample creator below:

```powershell
.\.venv\Scripts\python.exe examples\correlation_demo.py
```

The demo creates a temporary Git repo with two commits and a synthetic trace,
then runs the correlation engine. The synthetic trace is illustrative only:
this is **not** real ASan evidence and does **not** establish a vulnerability.

## Inputs and integration

The CLI reads one runner result or pre-parsed trace JSON, with `version` equal
to `base` or `patched`. If no full `commit_hash` is supplied by the runner, the
report explicitly says `execution_commit_verified=false`. Provide
`--source-root` once per relevant build-time path prefix. For a definitive
runtime-tested patch verdict, wait for paired execution evidence and the
Patch Classifier stage.

See `docs/correlation-contract.md` for the proposed contract with Person 2.
