# Runtime Trace Parser – Contract Proposal v1.0

Person 2 (Dynamic Execution) sends one JSON object per execution. Suggested fields:

```json
{
  "test_id": "TEST-001",
  "version": "base",
  "build_type": "asan",
  "exit_code": 1,
  "signal": null,
  "timeout": false,
  "stdout": "",
  "stderr": "==123==ERROR: AddressSanitizer: heap-buffer-overflow ..."
}
```

`stderr` and `stdout` should be full strings, without truncation at the runner
interface if possible. If logs must be truncated, the runner must report that
fact; missing source lines or frames can otherwise make correlation inconclusive.

- `version`: a logical label, preferably paired with a commit hash from the
  target configuration, not inferred from the label alone.
- `build_type`: e.g. `release`, `asan`, `ubsan`, or a documented combination.
- `exit_code`: the raw process exit code when one exists; `null` otherwise.
- `signal`: `SIGSEGV`, `SIGABRT`, an integer signal, or `null`.
- `timeout`: true if execution was terminated due to the configured time limit.

The parser produces `analysis_type=runtime_trace_analysis`. Each finding includes:

- `detection_mechanism`: `asan`, `ubsan`, or `lsan`.
- `error_type`: a normalized type, or a generic type when evidence is insufficient.
- `location`: first location obtained from the report; `null` if unavailable.
- `stack_trace`: ordered frames with `index`, `address`, `function`, `file`,
  `line`, and `column`. Missing fields are `null`.
- `related_stacks`: separate allocation/free/thread-creation frames, where present.
  These must not be confused with the primary failure stack for correlation.
- `evidence_lines` and `log_source`: original diagnostic headers and summary lines.

Line numbers are as reported by the sanitizer's symbolized binary; to correlate
against the Git Diff, use matching source/commit/build information. Do not
assume that a path from a build container matches a repository-relative path.

The parser **does not** determine Fixed, Incomplete Fix, New Issue, or Regression.
Those require matching Base/Patched executions, reference expectations, and
validating that they refer to the same target issue.

A bare `runtime error: ...` application message is not sufficient UBSan evidence,
even in a sanitized build. A numbered logger prefix such as `validator:42:`
is not a source location. The location-based form requires a C/C++ source
filename together with a recognized diagnostic message, or a corroborating
native stack frame immediately following the diagnostic. Thus even
`validator.c:42: runtime error: input invalid` is left unclassified. Explicit
`ERROR: UndefinedBehaviorSanitizer:` / `SUMMARY: UndefinedBehaviorSanitizer:`
headers remain supported, including locationless reports. These rules apply to
both stdout and stderr. Text parsing is evidence extraction, not authentication
of a log's origin.

This is a draft interface until the group confirms its shared JSON schema.
