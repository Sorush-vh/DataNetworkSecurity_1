# Target application index

Each directory is a self-contained target with four source versions, a
manifest, a reference oracle, and deterministic inputs.

| Directory | Real-world | Language | Finding | Expected scenarios |
|---|---|---|---|---|
| [`bzip2/`](bzip2/README.md) | yes | C | `out-of-bounds` in `BZ2_decompress` (CVE-2019-12900) | 0 / 10 / 20 |
| [`tlvparse/`](tlvparse/README.md) | no | C | `stack-buffer-overflow` in `parse_message` | 0 / 10 / 20 |

## Layout

```text
targets/<id>/
├── target.json             # manifest: versions, build, tests, hardening, scenarios
├── reference-tests.json    # independent expected behavior per version
├── README.md
├── inputs/                 # deterministic test inputs
├── tools/make_inputs.py    # input generator
└── versions/
    ├── base/
    ├── correct/
    ├── incomplete/
    └── regression/
```

The checked-in execution configs live in `configs/<id>/` and are generated from
the manifests. To regenerate them:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets materialize \
  --target targets/bzip2/target.json --scenario correct \
  --output configs/bzip2/correct.json --relative
```

Do not edit the generated configs by hand; edit the manifest and regenerate.

## Adding a target

1. Add the four source versions.
2. Add `target.json` and `reference-tests.json`.
3. Run `spv targets validate --target targets/<id>/target.json`.
4. Run `spv targets run-all --target targets/<id>/target.json --artifacts-dir artifacts/<id>`.

No Python code changes are required.
