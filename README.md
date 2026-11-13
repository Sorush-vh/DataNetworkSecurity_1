# DataNetworkSecurity_1
part 1 of the team project for Data and Network Security course in Sharif University of Technology

Automated validation of security patches and regression testing for C/C++ ELF binaries using Git Diff analysis, dynamic execution, sanitizers, and reproducible test cases.

# Security Patch Validator

**Automated Security Patch Validation and Regression Testing for C/C++ Programs**

[![Language](https://img.shields.io/badge/Language-Python-blue.svg)](https://www.python.org/)
[![Target](https://img.shields.io/badge/Target-C%2FC%2B%2B-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow.svg)]()

## Overview

Security Patch Validator is an academic software security project focused on the automated evaluation of security patches and the detection of potential regressions in C/C++ programs.

Applying a security patch does not necessarily guarantee that a vulnerability has been completely eliminated. A patch may provide only a partial fix, introduce a new security issue, or negatively affect the normal functionality of the application.

The goal of this project is to develop a Python-based validation framework that compares vulnerable and patched program versions, executes controlled test cases, analyzes runtime errors, and correlates observed findings with source code changes.

The framework aims to provide reproducible evidence and structured reports to support the evaluation of security patches.

## Project Objectives

The main objectives are:

- Compare vulnerable and patched source code versions.
- Extract and analyze Git Diff information.
- Correlate runtime errors and stack traces with modified source code.
- Detect incomplete security fixes and potential new issues.
- Identify functional regressions introduced by patches.
- Execute valid, boundary, and invalid test cases.
- Support Release and Sanitized builds using AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).
- Preserve reproducible test cases and execution evidence.
- Generate structured JSON reports.
- Integrate the validation process into a CI/CD pipeline.

## Supported Targets and Technologies

### Target Programs

The framework is designed to evaluate:

- C and C++ programs.
- Linux ELF executables.
- x86_64 architecture.
- Programs accepting input through files, command-line arguments, or standard input (stdin).

Both vulnerable and patched source versions must be available and compilable.

### Implementation Technologies

| Technology | Purpose |
|---|---|
| Python | Main validation framework |
| C / C++ | Target applications |
| Git | Version comparison and Diff extraction |
| GCC / G++ | Compilation |
| AddressSanitizer | Memory error detection |
| UndefinedBehaviorSanitizer | Undefined behavior detection |
| JSON | Structured input and output |
| pytest | Automated testing |
| CI/CD | Automated validation pipeline |

## Core Components

The project is organized into four main development areas.

### 1. Patch Validation and Diff Analysis

- Compare Base and Patched versions.
- Extract modified, added, and deleted files.
- Analyze added and removed lines.
- Parse Git Diff hunks.
- Analyze stack traces and execution locations.
- Correlate runtime findings with patch modifications.
- Classify patch validation results.

### 2. Dynamic Execution and Error Detection

- Compile and execute C/C++ target programs.
- Generate Release and Sanitized builds.
- Execute valid, boundary, and invalid test cases.
- Detect memory errors and undefined behavior.
- Record exit codes, signals, stdout, stderr, and timeouts.

### 3. Reproducibility, Testcase Minimization, and CI/CD

- Generate Reproducer Bundles.
- Preserve failing inputs and execution metadata.
- Repeat tests at least three times to evaluate stability.
- Apply Delta Debugging to minimize failing inputs.
- Generate regression tests automatically.
- Provide CLI and JSON interfaces.
- Integrate validation modules into CI/CD.

### 4. Target Programs and Binary Hardening

- Prepare two independent C/C++ target programs.
- Provide Base, Correct Patch, Incomplete Patch, and Regression Patch versions.
- Design and document reference test cases.
- Inspect ELF security properties:
  - RELRO
  - PIE
  - NX
  - Stack Canary

## Patch Classification

The framework aims to distinguish the following outcomes:

| Classification | Description |
|---|---|
| Fixed | The original issue is reproduced in the Base version but is not observed in the patched version within the tested scope. |
| Incomplete Fix | The original issue remains reproducible through an alternative input or execution path. |
| New Issue | A new security or memory-related issue is detected in the patched version with sufficient evidence. |
| Functional Regression | Previously valid and expected program behavior is broken by the patch. |
| Inconclusive | Available evidence is insufficient for a reliable conclusion. |

Each finding should include its supporting execution evidence and its relationship to the relevant source code changes.

## Repository Structure

The repository follows a modular architecture:

- `src/` – Main Python implementation.
  - `common/` – Shared models and utilities.
  - `patch_analysis/` – Version comparison, Diff analysis, stack trace parsing, correlation, and classification.
  - `execution/` – Dynamic execution and error detection.
  - `reproducibility/` – Reproducer Bundles and testcase minimization.
  - `hardening/` – ELF security property inspection.
  - `reporting/` – JSON and human-readable reports.
- `configs/` – Target program configurations.
- `schemas/` – JSON input and output schemas.
- `targets/` – Target C/C++ applications and their versions.
- `tests/` – Unit and integration tests.
- `pipeline/` – CI/CD configurations.
- `reports/` – Validation reports and experimental results.
- `docs/` – Technical documentation and architecture descriptions.

## Development Workflow

The project uses a shared Git repository and a feature-branch workflow.

- `main` – Stable project version.
- `develop` – Integration branch.
- `feature/person1-patch-analysis` – Patch validation and Diff analysis.
- `feature/person2-execution` – Dynamic execution and error detection.
- `feature/person3-reproducibility` – Reproducibility and CI/CD.
- `feature/person4-targets` – Target programs and binary hardening.

Each contributor develops their assigned module independently and submits changes through Pull Requests.

## Testing and Validation Principles

- Base and patched versions must be evaluated under equivalent test conditions.
- Release and Sanitized build results must be reported separately.
- Confirmed failing inputs must be reproducible.
- Each confirmed failure must be replayed at least three times.
- Classification decisions must be supported by observable evidence.
- A crash alone does not establish an exploitable vulnerability.
- The absence of observed errors does not prove the absence of all vulnerabilities.

All experiments must be performed in an isolated environment and on authorized target programs.

## Project Status

**Currently under development.**

The framework is being developed incrementally by four contributors. Module integration, target selection, testing, and final validation will be completed throughout the project.

## Authors

**Seyed Ali (Sorush) Vakilzadeh Hatefi 401102789** — Student ID: `40102789`

**fill here**

## Academic Context

Developed as part of the **Data and Network Security** course.

Sharif University of Technology

**Project:** Automated Security Patch Validation and Regression Testing in CI/CD

---

*This project is intended for academic research, software security evaluation, and defensive testing.*
