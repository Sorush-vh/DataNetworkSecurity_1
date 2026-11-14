# Generated target execution configs

These files are generated from `targets/<id>/target.json` with:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets materialize \
  --target targets/<id>/target.json --scenario <scenario> \
  --output configs/<id>/<scenario>.json --relative
```

They use paths relative to this directory so they can be run directly:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli execute \
  --config configs/bzip2/correct.json --artifacts-dir artifacts/manual --pretty
```

The orchestrator does not read these files; it materializes an equivalent
config in the retained artifact workspace with absolute paths and deterministic
Git commit hashes. `tests/unit/test_targets.py` checks that the checked-in
configs still match their manifests.

Each scenario is a base/patched pair:

| File | Base | Patched |
|---|---|---|
| `correct.json` | `versions/base` | `versions/correct` |
| `incomplete.json` | `versions/base` | `versions/incomplete` |
| `regression.json` | `versions/base` | `versions/regression` |

The `classifier` object in each test is ignored by the execution module and
consumed by the scenario orchestrator.
