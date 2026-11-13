
# Member 3 - Reproducibility, Minimization and Regression Testing

This module implements reproducibility, input minimization, regression test generation, and CLI reporting for the Security Patch Validator project.

## Features

### 1. Reproducer Bundle

- SHA-256 calculation for binaries and input files.
- Reproducer bundle generation with execution metadata.
- Saving copies of the binary and input files.
- Recording commit hash, build settings, environment variables, execution command, and platform information.
- Redacting environment variables with sensitive names.
- Repeated execution of test cases with at least three repetitions.
- Detection and classification of stable and flaky execution results.
- Handling execution errors and timeouts.

### 2. Input Minimization

- Delta Debugging for minimizing test inputs.
- Caller-provided validation predicate to preserve the target failure.
- Validation of the final minimized input.
- Reporting original size, minimized size, reduction ratio, and test count.
- Reporting minimization and validation results.

### 3. Regression Testing

- Automatic generation of regression test input files.
- JSON manifest generation with SHA-256 hashes.
- Validation against vulnerable base and patched versions.
- Support for file-based and standard-input execution.
- At least three executions for both base and patched versions.
- Detection of stable and flaky regression results.
- Checking expected error type and optional error location.
- Reporting PASS, FAIL, and INCONCLUSIVE statuses.

### 4. CLI and Reporting

- Command-line interface for reporting validation results.
- JSON report generation.
- Regression result JSON input.
- Separate security, functional, and analysis statuses.
- Validation of regression evidence before reporting PASS.
- Appropriate exit codes for automated evaluation.

#### Exit Codes

| Exit Code | Status | Description |
|---|---|---|
| 0 | PASS | Validation passed |
| 10 | VULN_REMAINS | Vulnerability remains in the patched version |
| 20 | FUNC_REGRESSION | Functional regression detected |
| 30 | BUILD_OR_CONFIG_ERROR | Build or configuration error |
| 40 | INCONCLUSIVE | Evidence is insufficient or inconclusive |

## Project Structure

```text
member3/
├── main.py
├── README.md
├── requirements.txt
├── modules/
│   ├── cli/
│   │   ├── __init__.py
│   │   └── cli.py
│   ├── minimizer/
│   │   ├── __init__.py
│   │   └── delta_debugging.py
│   ├── regression/
│   │   ├── __init__.py
│   │   └── regression.py
│   └── reproducer/
│       ├── __init__.py
│       ├── bundle.py
│       └── runner.py
└── tests/
    ├── regression/
    │   ├── regression_tests.json
    │   └── stack_smashing_case_001.input
    ├── test_cli.py
    ├── test_minimizer.py
    ├── test_regression.py
    ├── test_reproducer.py
    └── test_runner.py
```

## Requirements

- Python 3.12 or newer.
- pytest for running the test suite.

Install dependencies:

```bash
pip install -r member3/requirements.txt
```

## Running the CLI

From the repository root:

```bash
PYTHONPATH=member3 python member3/main.py --help
```

## Running Tests

From the repository root:

```bash
PYTHONPATH=member3 python -m pytest member3/tests -q
```

## CI/CD Integration

A GitHub Actions workflow is provided at:

`.github/workflows/member3-tests.yml`

The workflow automatically runs the Member 3 test suite on pushes and pull requests that modify the `member3/` directory or the workflow file.

## Test Results

The current test suite contains 30 tests.

**Latest local test result: 30 passed.**

## Current Limitations

- Full integration with the other team members' modules and the main project pipeline remains pending.
- Delta Debugging relies on a caller-provided predicate to determine whether the target failure is preserved.
- Regression validation checks configured execution evidence and expected error behavior; it does not independently prove exploitability.
- Build settings and commit hashes are supplied by the caller rather than automatically discovered.
- The GitHub Actions workflow has been added, but its execution on GitHub Actions has not yet been verified.
