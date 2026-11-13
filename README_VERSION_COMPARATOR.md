# Version Comparator - First Implementation

This module compares two committed snapshots in a Git repository.

## Requirements

- Python 3.10+
- Git available on `PATH`

## Install for development

From the repository root:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
spv compare --repo . --base <BASE_COMMIT_OR_TAG> --patched <PATCHED_COMMIT_OR_TAG> --pretty
```

Write the report to a file:

```bash
spv compare --repo . --base <BASE> --patched <PATCHED> --output reports/version-comparison.json --pretty
```

The module compares committed snapshots. It does not include uncommitted working-tree changes.

## Run tests

```bash
pytest
```

## Output

The JSON report contains:

- Resolved full commit hashes and commit metadata.
- Whether Base is an ancestor of Patched.
- Added, modified, deleted, renamed, copied, and type-changed files.
- A summary of file-level changes.
- Explicit limitations to prevent overclaiming.

Line-level Diff hunks, stack-trace parsing, finding correlation, and classification will be implemented in later modules.
