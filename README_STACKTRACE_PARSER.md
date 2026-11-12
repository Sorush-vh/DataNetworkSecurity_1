# Stack Trace Parser – Stage 3

This extension parses **observed** AddressSanitizer, UndefinedBehaviorSanitizer,
and LeakSanitizer reports. It does not claim that an observed error is exploitable,
caused by a patch, or fixed by a patch. Those are separate analyses.

## New files

- `src/security_patch_validator/patch_analysis/stacktrace_parser.py`
- `tests/unit/test_stacktrace_parser.py`
- `tests/fixtures/*.log`
- `examples/asan-execution-result.json`
- `docs/stacktrace-contract.md`

It also updates `src/security_patch_validator/cli.py` without changing the
existing `compare` and `diff` commands.

## Run locally

From your repository root, on Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m security_patch_validator.cli parse-trace --input examples/asan-execution-result.json --pretty
.\.venv\Scripts\python.exe -m security_patch_validator.cli parse-trace --input examples/asan-execution-result.json --output reports/local/trace.json --pretty
```

The CLI's return code `0` here only indicates that **parsing succeeded**, not
that a security patch passed validation. Full project exit-code policy (0, 10,
20, 30, 40) belongs to the later integrated validation command.

## Important limits

- Parser covers representative, symbolized GCC/Clang-style ASan/UBSan output,
  but log formats vary by toolchain and platform. More real logs are necessary.
- The `location` field is the first available diagnostic source location or
  stack frame, **not** a verified root cause.
- Some sanitizers emit incomplete frames without debug symbols (`-g` and
  symbolization are recommended). These remain `null` rather than fabricated.
- Stack paths may refer to a container directory instead of repository-relative
  paths; correlation will need explicit path normalization.
- A crash with no sanitizer diagnostic remains **unclassified** here.

## Collaboration

Send `docs/stacktrace-contract.md` to the Dynamic Execution contributor so the
runner can emit compatible JSON. This contract is provisional until agreed.
