# Setup and installation

This guide gets the project running from a fresh clone: the validation tool,
the two target applications, the reference tests, the ELF hardening checks, and
the end-to-end scenario matrix.

## 1. Requirements

| Component | Version / notes |
|---|---|
| Python | 3.10 or newer |
| C toolchain | GCC/G++ with AddressSanitizer and UndefinedBehaviorSanitizer |
| ELF tools | GNU binutils (`readelf`, `objdump`) |
| Build tools | `make`, `git` |
| OS for dynamic execution | Linux x86_64 |
| Container | Docker (recommended on macOS/arm64) |
| Tests | `pytest` (installed with the `dev` extra) |

Dynamic execution refuses to run on non-Linux-x86_64 hosts. Use the Docker image
on macOS, Windows, or arm64 Linux.

## 2. Get the code

```bash
git clone <repository-url> DataNetworkSecurity_1
cd DataNetworkSecurity_1
git switch feature/person4-targets
```

If you are on `main`, the Module 4 work is on `feature/person4-targets` until it
is merged.

## 3. Host setup (Linux x86_64)

Install the system packages first. On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y gcc g++ make binutils git python3 python3-venv python3-pip
```

Create a virtual environment and install the package in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

The `spv` entry point is now available. Without installing, use the module form:

```bash
export PYTHONPATH=src
python3 -m security_patch_validator.cli --help
```

## 4. Docker setup (macOS / arm64)

The provided image is Debian bookworm on `linux/amd64`, with gcc, g++, make,
binutils, git, python3, and pytest.

```bash
docker build --platform linux/amd64 -f docker/targets.Dockerfile -t spv-targets .
```

Build once, then reuse the image. Run commands from the repository root:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD:/project" -w /project -e PYTHONPATH=src \
  spv-targets python3 -m security_patch_validator.cli --help
```

The repository mount must be writable when the command writes `artifacts/` or
`reports/`. For a read-only source mount, point `--artifacts-dir` and
`--output` at a separate writable volume.

## 5. Verify the installation

Run the fast test suite:

```bash
# Host (Linux x86_64)
PYTHONPATH=src python3 -m pytest tests/unit tests/integration -q

# Or in Docker
docker run --rm --platform linux/amd64 -v "$PWD:/project" -w /project \
  -e PYTHONPATH=src spv-targets \
  python3 -m pytest tests/unit tests/integration -q
```

Expected result: all tests pass; the opt-in target scenario test is skipped.

Validate both target manifests:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets validate \
  --target targets/tlvparse/target.json --pretty

PYTHONPATH=src python3 -m security_patch_validator.cli targets validate \
  --target targets/bzip2/target.json --pretty
```

Regenerate the deterministic inputs (safe to repeat):

```bash
python3 targets/bzip2/tools/make_inputs.py
python3 targets/tlvparse/tools/make_inputs.py
```

## 6. Target layout

```text
targets/
├── README.md
├── bzip2/                     # real-world target (CVE-2019-12900)
│   ├── target.json            # manifest: versions, build, tests, hardening, scenarios
│   ├── reference-tests.json   # independent oracle per version
│   ├── inputs/                # valid, boundary, invalid and PoC inputs
│   ├── tools/make_inputs.py
│   └── versions/{base,correct,incomplete,regression}/
└── tlvparse/                  # second target (unchecked TLV length)
    └── ...
```

The checked-in execution configs live in `configs/<target>/`. They are
generated from the manifests, so edit the manifest and regenerate rather than
editing the configs by hand:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets materialize \
  --target targets/bzip2/target.json --scenario correct \
  --output configs/bzip2/correct.json --relative
```

## 7. Run the scenarios

One scenario, full evidence (build, execute, harden, diff, classify, reproduce,
minimize, regenerate regression tests):

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets run \
  --target targets/tlvparse/target.json --scenario correct \
  --artifacts-dir artifacts/tlvparse-correct \
  --output reports/tlvparse-correct.json --summary --pretty
```

All three scenarios and a matrix summary:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets run-all \
  --target targets/tlvparse/target.json \
  --artifacts-dir artifacts/tlvparse \
  --output reports/tlvparse-matrix.json --summary --pretty
```

A fast rerun after the persistent regression suite exists:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets run-all \
  --target targets/tlvparse/target.json \
  --artifacts-dir artifacts/tlvparse-fast \
  --skip-reproducer \
  --output reports/tlvparse-matrix.json --summary --pretty
```

`--skip-reproducer` skips only the expensive re-minimization. Previously
minimized inputs in `regression/<target>/` are still re-validated on every run.

Expected exit codes:

| Scenario | Exit |
|---|---:|
| Correct patch | 0 |
| Incomplete patch | 10 |
| Regression patch | 20 |
| Build/config error | 30 |
| Inconclusive | 40 |

### Evaluating an unseen patch

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets run \
  --target targets/tlvparse/target.json --scenario correct \
  --patched-dir /path/to/unseen-patched-tree \
  --artifacts-dir artifacts/unseen \
  --output reports/unseen.json --summary --pretty
```

The manifest's expected exit code is reported as `null` for an override; the
observed exit code and classifications still come from runtime evidence.

## 8. Hardening inspection

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli hardening \
  --binary artifacts/.../builds/base/release/source/bzip2 \
  --compare artifacts/.../builds/patched/release/source/bzip2 \
  --require relro=full --require pie=enabled --require nx=enabled \
  --require stack_canary=present --pretty
```

The command exits `0` when the inspection completes and the requirements are
met, `40` when a requirement is not met, and `30` when the binary cannot be
inspected (for example, `readelf` is missing).

## 9. CLI reference

| Command | Purpose |
|---|---|
| `spv compare --base A --patched B` | Compare two committed Git snapshots |
| `spv diff --base A --patched B` | Extract line-level hunks |
| `spv correlate --base A --patched B --trace file.json` | Correlate a runtime finding with the diff |
| `spv classify --base A --patched B --suite file.json` | Classify a paired suite |
| `spv execute --config file.json [--repetitions N]` | Build and execute a base/patched pair |
| `spv hardening --binary ELF [--compare ELF] [--require name=status]` | Inspect ELF protections |
| `spv targets validate --target targets/<id>/target.json` | Validate a manifest |
| `spv targets materialize --target ... --scenario ... --output ...` | Generate an execution config |
| `spv targets run --target ... --scenario ...` | Run one scenario end to end |
| `spv targets run-all --target ...` | Run all three scenarios |

## 10. CI and local pipeline

- `.github/workflows/targets-e2e.yml` runs the unit/integration tests, the
  four-scenario matrix for both targets, and a Docker isolation smoke test.
- `pipeline/run_targets.sh` runs the matrix locally in Docker:

```bash
./pipeline/run_targets.sh tlvparse bzip2
```

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `Dynamic execution requires Linux x86_64` | Run inside the Docker image or a Linux x86_64 host. |
| `Required ELF inspection tool is not available: readelf` | Install `binutils`, or use the Docker image. |
| `exec format error` on macOS/arm64 | Build/run with `--platform linux/amd64`. |
| `pytest: command not found` | `python3 -m pip install -e ".[dev]"` or `python3 -m pytest`. |
| `pytest` cannot import `security_patch_validator` | Set `PYTHONPATH=src` or install the package. |
| bzip2 scenario takes 15–20 minutes under Rosetta | Use a native x86_64 runner, or run once to populate `regression/bzip2/`, then use `--skip-reproducer`. |
| `git` errors during `prepare_git_repo` | Install `git`; unset conflicting `GIT_DIR`/`GIT_WORK_TREE` variables. |
| `Sanitizer compilation not verified` | Route compilations through `$(CC)`/`$(CXX)` or the audited `PATH` compilers; see `docs/execution.md`. |

## 12. Where the evidence lives

| Path | Content |
|---|---|
| `reports/` | Committed JSON scenario and matrix reports |
| `artifacts/` | Retained source snapshots, binaries, run logs and bundles (ignored by Git, regenerable) |
| `regression/` | Version-controlled minimized inputs and manifests |
| `docs/targets.md` | Manifest schema, orchestrator flow and hardening evidence |
| `docs/verification.md` | Observed end-to-end results on this environment |
