# Member 3 - Reproducibility, Minimization and Regression Testing

This module implements reproducibility, input minimization, regression test generation, and CLI reporting for the security patch validation project.

## Features

- SHA-256 calculation for binaries and input files.
- Reproducer bundle generation with execution metadata.
- Repeated execution of test cases with at least three repetitions.
- Basic detection of stable and flaky execution results.
- Delta debugging for minimizing inputs while preserving a failure condition defined by the caller.
- Generation of regression test files and JSON manifests.
- CLI support for status reporting, JSON reports, and exit codes.

## Project Structure

- `modules/reproducer/`: Reproducer bundle creation and repeated execution.
- `modules/minimizer/`: Delta debugging implementation.
- `modules/regression/`: Regression test generation.
- `modules/cli/`: CLI and JSON report generation.
- `tests/`: Unit tests for the implemented modules.

## Requirements

- Python 3.12 or newer.

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Test Results

All 13 current unit tests pass.

## Current Limitations

- Full integration with the other team modules is pending.
- Automatic validation of regression tests against base and patched versions is not yet integrated.
- Full CI/CD integration is pending.
