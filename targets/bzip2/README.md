# Target A: bzip2 1.0.6 (real-world)

This target is the real-world application required by the project. It is the
upstream bzip2 1.0.6 source tree, built as a normal Linux x86_64 ELF
executable, with four deliberately designed versions.

| Item | Value |
|---|---|
| Upstream | bzip2 1.0.6 (6 September 2010) |
| License | BSD-like (see `versions/base/LICENSE`) |
| Language | C |
| Input | `.bz2` file path via `bzip2 -dc FILE` |
| Vulnerability | CVE-2019-12900 |
| Finding signature | `out-of-bounds` in `decompress.c`, function `BZ2_decompress` |

## Versions

All four versions share the same `build.sh` (except the regression version,
which intentionally drops PIE) and the same source tree. The only source
difference is in `decompress.c`.

### `versions/base`

Pristine upstream 1.0.6. `BZ2_decompress` reads a 15-bit `nSelectors` value and
writes `nSelectors` entries into `s->selectorMtf[BZ_MAX_SELECTORS]` without a
bound. `BZ_MAX_SELECTORS` is `2 + (900000 / 50) = 18002`. The input
`inputs/selector-overflow.bz2` declares 32767 selectors and produces:

```text
decompress.c:299:24: runtime error: index 18002 out of bounds for type 'UChar [18002]'
    #0 ... in BZ2_decompress /tmp/base/decompress.c:299
```

### `versions/correct`

Applies the upstream 1.0.8 fix: the write is guarded by
`if (i < BZ_MAX_SELECTORS)` and `nSelectors` is clamped to
`BZ_MAX_SELECTORS` before the selector MTF undo loop. Both PoCs are rejected
with exit code 2 (data integrity error) and no sanitizer finding. Valid streams
decompress normally.

### `versions/incomplete`

Rejects only the exact selector count used by the public reproducer
(`nSelectors == 32767`) but does not bound the array write. The original input
is blocked; the alternate input with `nSelectors == 32766`
(`inputs/selector-overflow-alt.bz2`) still produces the same `out-of-bounds`
diagnostic. This is the intended negative control for the classifier's
`INCOMPLETE_FIX`.

### `versions/regression`

Contains the correct upstream fix plus a functional regression: it rejects any
valid stream whose block size is greater than 1
(`if (s->blockSize100k > 1) RETURN(BZ_DATA_ERROR);`). The security PoCs are
fixed, but a valid block-size-9 stream (`inputs/valid-block9.bz2`) now fails.
The regression version's `build.sh` also drops `-fPIE -pie`, so the hardening
comparison reports an unexpected PIE regression. This demonstrates the
hardening-change warning without changing the functional exit code.

## Inputs

Inputs are generated deterministically by `tools/make_inputs.py`:

| File | Purpose |
|---|---|
| `inputs/valid.txt` | Expected decompressed bytes (264 bytes) |
| `inputs/valid-block9.bz2` | Valid stream compressed with block size 9 |
| `inputs/valid-block1.bz2` | Valid stream compressed with block size 1 |
| `inputs/selector-overflow.bz2` | Original CVE-2019-12900 reproducer (32767 selectors) |
| `inputs/selector-overflow-alt.bz2` | Alternate reproducer (32766 selectors) |
| `inputs/invalid-magic.bz2` | Invalid magic header |
| `inputs/truncated.bz2` | Truncated valid stream |

Regenerate them with:

```bash
python3 targets/bzip2/tools/make_inputs.py
```

## Build

The execution harness supplies `CFLAGS`, `LDFLAGS`, and `CC` for the selected
profile. `build.sh` appends hardening flags and calls `make`:

```bash
sh build.sh
```

The release profile uses `-O2 -DNDEBUG`; the instrumented profile uses
AddressSanitizer and UndefinedBehaviorSanitizer. Both profiles are built by
`spv execute` and are reported separately.

## Reference oracle

`reference-tests.json` is the independent oracle. It is based on the bzip2
manual and the documented upstream fix, not on the patched program's output.
The expected result for each version is recorded per test.

| Test | Base | Correct | Incomplete | Regression |
|---|---|---|---|---|
| `FUN-VALID-9` | pass | pass | pass | **fail** |
| `FUN-VALID-1` | pass | pass | pass | pass |
| `INV-MAGIC` | pass | pass | pass | pass |
| `INV-TRUNCATED` | pass | pass | pass | pass |
| `SEC-ORIGINAL` | vulnerable | fixed | fixed | fixed |
| `SEC-ALTERNATE` | vulnerable | fixed | **vulnerable** | fixed |

## Expected scenario results

| Scenario | Patched version | Exit code | Statuses |
|---|---|---:|---|
| Correct patch | `versions/correct` | 0 | `FIXED` |
| Incomplete patch | `versions/incomplete` | 10 | `INCOMPLETE_FIX` |
| Regression patch | `versions/regression` | 20 | `FIXED`, `FUNCTIONAL_REGRESSION` |

Run one scenario:

```bash
PYTHONPATH=src python3 -m security_patch_validator.cli targets run \
  --target targets/bzip2/target.json --scenario correct \
  --artifacts-dir artifacts/bzip2-correct --output reports/bzip2-correct.json --pretty
```

The minimization step is the slow part for this target because the PoC is
about 2.3 KiB and the sanitized baseline is executed hundreds of times.
