# Patch Classifier – Person 1 (Stage 5)

This stage adds `patch_analysis/classifier.py` and a CLI command to the
Version Comparator, Diff Analyzer, Stack Trace Parser, and Correlation Engine.

## Install

Extract the ZIP into the **root of the existing repo**. It adds `classifier.py`
and a test module, updates `cli.py`, and adds a contract and synthetic demo.

No new runtime dependencies are needed. Existing development setup:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -v
```

## Synthetic demo (no real C program executed)

```powershell
.\.venv\Scripts\python.exe examples\classifier_demo.py
```

This script creates a temporary Git repository, commits Base and Patched source
files, and feeds **clearly synthetic** sanitizer reports into the actual
classifier and diff/correlation code. It illustrates integration, not proof that
a real target's vulnerability has been fixed.

## Real CLI invocation

```powershell
.\.venv\Scripts\python.exe -m security_patch_validator.cli classify --repo . --base BASE_COMMIT --patched PATCHED_COMMIT --suite configs\suite.json --source-root /project --output reports/local/classification.json --pretty
```

Use actual target commits from Person 4, real paired execution records from
Person 2 and validated completion artifacts from Persons 3 and 4.

Read `docs/classifier-contract.md` for the shared input schema and status rules.
This is the **last core Person-1 module**, but final scientific validation still
requires tests against the group's real targets and unfamiliar patches.
