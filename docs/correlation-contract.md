# Patch-to-Finding Correlation Contract (v1.0, proposal)

This component joins **Git diff evidence** with a **single runtime sanitizer report**.
It deliberately does not decide whether a patch is Fixed, Incomplete Fix, a New Issue,
or a Functional Regression. Those require comparing matched test results across versions.

## Inputs

1. Output from `analyze_diff(repo, base, patched)`.
2. One Person-2 execution result (runner JSON) or the normalized output of `parse_execution_result`.
3. A version marker: `base` or `patched` in runner JSON, or `--version` (cannot conflict).
4. Optional source-root mappings, e.g. `/project`, used to map `/project/src/foo.c` to `src/foo.c`.
5. Recommended: runner-provided **full Git commit hash** (`commit_hash`) matching the selected Base or Patched commit.

Sanitizer reports may be from ASan, UBSan, or LSan. The parser must retain the
sanitizer diagnostic and the symbolized source frames. Allocation and free
stacks are *not* primary failure stack frames.

A suggested Person-2 raw runner input:

```json
{
  "test_id": "TEST-001",
  "version": "base",
  "commit_hash": "<full 40-hex SHA-1 commit, or 64-hex SHA-256 commit>",
  "build_type": "asan",
  "exit_code": 1,
  "signal": null,
  "timeout": false,
  "stdout": "",
  "stderr": "==11==ERROR: AddressSanitizer: heap-buffer-overflow ..."
}
```

## Output

- `analysis_type`: `patch_finding_correlation`.
- `expected_commit`: full Base or Patched commit hash.
- `execution_commit_verified`: true only if the runner supplied the matching full hash.
- `summary`: count of overlap, file-only, and unresolved findings.
- `findings[]`: one correlation result per observed sanitizer diagnostic.
- Each matched location contains `repository_path`, `reported_path`,
  `reported_line`, `diff_hunk_indices`, `source`, `frame_index`, `relation`,
  `path_match_method`, and `strength`.

`relation` distinguishes `changed_line_overlap` from `same_file_only`.
`strength` is **not** a probability or causal statement:

- `strong`: primary failure location exactly overlaps a changed line, the
  runtime commit is verified, and the file path is mapped exactly or through
  a configured source root.
- `medium`: changed-line overlap under weaker provenance (e.g., the runner
  did not provide the commit hash or path mapping relies on a unique suffix),
  or a verified caller-frame overlap.
- `weak`: file-level overlap without line overlap, or weak caller evidence.
- `none`: unresolved path, missing location, or unrelated location.

Suffix matching intentionally requires at least two path components. Basename
alone is insufficient; competing suffixes are reported as ambiguous.

## Limitations

- Identical build flags, equivalent inputs, and corresponding releases must be
  checked during paired validation, outside this component.
- A changed-line overlap is **not** proof of vulnerability causation, repair,
  or exploitability.
- A clean trace is not proof of a successful security fix.
- Source line numbers from inlined/optimized builds may not map cleanly.
- Automatic mapping of compiler/debug paths is conservative; use `--source-root`
  or extend the shared schema with explicit debug-prefix mappings.
- This stage extends `parse_execution_result` to retain `commit_hash`. The
  execution module should also preserve build flags and binary hashes in its
  own schema so that provenance can be verified end-to-end.
- Standalone CLI subcommands still return generic 0/1 status codes until the
  integration owner implements the assignment's combined 0/10/20/30/40 policy.
