"""Evidence-based correlation between sanitizer locations and Git patch hunks.

No patch outcome (Fixed/Incomplete Fix/etc.) is inferred from a single trace.
Only primary failure locations and primary stack frames are considered; allocation
and free stacks are intentionally excluded from patch-to-finding correlation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import posixpath
import re
from typing import Any

from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result


def _normalize_path(value: str) -> str:
    return posixpath.normpath(value.replace('\\', '/'))


def _match_file(path: str, file_paths: list[str], source_roots: Sequence[str]) -> tuple[str | None, str]:
    """Return (unique repository-relative path, match method).

    Exact relative paths and caller-specified source roots are authoritative.
    Absolute paths without source root can only provide unique suffix evidence
    with two or more path components, not a fully verified path mapping.
    """
    normalized = _normalize_path(path)
    if normalized in file_paths and not normalized.startswith('../'):
        return normalized, 'exact_relative'

    for root in source_roots:
        normalized_root = _normalize_path(root).rstrip('/') or '/'
        if normalized.startswith(normalized_root.rstrip('/') + '/'):
            relative = normalized[len(normalized_root):].lstrip('/')
            if relative in file_paths:
                return relative, 'configured_source_root'

    # Never guess based only on a basename. Require at least a 2-part suffix.
    matches = [p for p in file_paths if '/' in p and normalized.endswith('/' + p)]
    if len(matches) == 1:
        return matches[0], 'unique_suffix'
    if len(matches) > 1:
        return None, 'ambiguous_suffix'
    return None, 'unmapped'


def _locations(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Extract primary crash location and stack frames, without related stacks."""
    locations = []
    location = finding.get('location')
    if isinstance(location, Mapping) and location.get('file') and isinstance(location.get('line'), int):
        locations.append({
            'source': 'primary_location',
            'frame_index': None,
            'function': None,
            'file': location['file'],
            'line': location['line'],
        })
    frames = finding.get('stack_trace') or []
    for position, frame in enumerate(frames):
        if not isinstance(frame, Mapping) or not isinstance(frame.get('file'), str) or not isinstance(frame.get('line'), int):
            continue
        locations.append({
            'source': 'primary_stack_frame',
            'frame_index': frame.get('index', position),
            'function': frame.get('function'),
            'file': frame['file'],
            'line': frame['line'],
        })
    # Avoid counting the same location twice (location commonly repeats frame #0).
    seen: set[tuple[str, int]] = set()
    unique = []
    for entry in locations:
        identifier = (_normalize_path(entry['file']), entry['line'])
        if identifier in seen:
            continue
        seen.add(identifier)
        unique.append(entry)
    return unique


def _validate_inputs(diff_report: Mapping[str, Any], trace_report: Mapping[str, Any], version: str | None) -> tuple[str, str, str, bool]:
    if not isinstance(diff_report, Mapping) or diff_report.get('analysis_type') != 'git_diff_analysis':
        raise ValueError('Expected an analyze_diff() report (analysis_type=git_diff_analysis).')
    if not isinstance(trace_report, Mapping) or trace_report.get('analysis_type') != 'runtime_trace_analysis':
        raise ValueError('Expected a parsed execution report (analysis_type=runtime_trace_analysis).')
    actual_version = version or trace_report.get('version')
    if actual_version not in {'base', 'patched'}:
        raise ValueError('Execution version must be base or patched, supplied by trace metadata or --version.')
    if version is not None and trace_report.get('version') is not None and trace_report['version'] != version:
        raise ValueError('Explicit execution version conflicts with trace report version.')
    target_commit = diff_report['comparison'][actual_version]['commit']
    observed_commit = trace_report.get('commit_hash') or trace_report.get('commit')
    verified = False
    if observed_commit is not None:
        if not isinstance(observed_commit, str) or not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', observed_commit):
            raise ValueError('Execution commit must be a full 40- or 64-character hex commit hash.')
        if observed_commit.lower() != target_commit.lower():
            raise ValueError('Execution commit does not match the selected Base/Patched commit.')
        verified = True
    return actual_version, target_commit, observed_commit or '', verified


def correlate_findings(
    diff_report: Mapping[str, Any],
    trace_report: Mapping[str, Any],
    *,
    version: str | None = None,
    source_roots: Sequence[str] = (),
) -> dict[str, Any]:
    """Correlate runtime source locations against the correct side of the Git Diff.

    Confidence describes source overlap only, never vulnerability causation.
    Correlation does not determine patch validity or security classification.
    """
    side, commit, _, verified_commit = _validate_inputs(diff_report, trace_report, version)
    if isinstance(source_roots, (str, bytes)) or any(not isinstance(r, str) or not r for r in source_roots):
        raise TypeError('source_roots must be a sequence of nonempty path strings.')
    files = diff_report.get('files', [])
    changed_paths = [entry[f'{"old" if side == "base" else "new"}_path']
                     for entry in files if entry.get(f'{"old" if side == "base" else "new"}_path') is not None]
    if len(set(changed_paths)) != len(changed_paths):
        raise ValueError('Diff report contains duplicate file paths for the selected version.')
    finding_results: list[dict[str, Any]] = []

    for finding_index, finding in enumerate(trace_report.get('findings', [])):
        matched = []
        path_warnings = []
        locations = _locations(finding)
        for location in locations:
            matched_path, match_method = _match_file(location['file'], changed_paths, source_roots)
            if match_method == 'ambiguous_suffix':
                path_warnings.append({'file': location['file'], 'reason': 'ambiguous_path'})
                continue
            if matched_path is None:
                continue
            diff_file = next(item for item in files if item[f'{"old" if side == "base" else "new"}_path'] == matched_path)
            line_key = 'removed_lines' if side == 'base' else 'added_lines'
            hunk_numbers = [i for i, hunk in enumerate(diff_file.get('hunks', []))
                            if any(line.get('line_number') == location['line'] for line in hunk[line_key])]
            direct = bool(hunk_numbers)
            primary = location['source'] == 'primary_location'
            if direct and primary and match_method != 'unique_suffix' and verified_commit:
                strength = 'strong'
            elif direct and (primary or (location['frame_index'] == 0)):
                strength = 'medium'
            elif direct:
                strength = 'medium' if verified_commit and match_method != 'unique_suffix' else 'weak'
            else:
                strength = 'weak'

            matched.append({
                'relation': 'changed_line_overlap' if direct else 'same_file_only',
                'strength': strength,
                'reported_path': location['file'],
                'repository_path': matched_path,
                'path_match_method': match_method,
                'reported_line': location['line'],
                'source': location['source'],
                'frame_index': location['frame_index'],
                'function': location['function'],
                'diff_hunk_indices': hunk_numbers,
                'reason': ('Reported location overlaps a changed line on the correct side of the diff.'
                           if direct else 'The file changed, but this source line did not; causal link is unproven.'),
            })
        order = {'strong': 0, 'medium': 1, 'weak': 2}
        matched.sort(key=lambda m: (order[m['strength']], m['relation'] != 'changed_line_overlap',
                                     m['frame_index'] is not None, m['repository_path'], m['reported_line']))
        if matched:
            classification = 'changed_line_overlap' if any(m['relation'] == 'changed_line_overlap' for m in matched) else 'file_overlap_only'
            strongest = matched[0]['strength']
        elif path_warnings:
            classification, strongest = 'ambiguous_path', 'none'
        else:
            classification, strongest = ('no_source_location' if not locations else 'no_match'), 'none'
        finding_results.append({
            'finding_index': finding_index,
            'detection_mechanism': finding.get('detection_mechanism'),
            'error_type': finding.get('error_type'),
            'correlation_status': classification,
            'evidence_strength': strongest,
            'matches': matched,
            'path_warnings': path_warnings,
            'related_stacks_excluded': True,
        })

    return {
        'schema_version': '1.0',
        'analysis_type': 'patch_finding_correlation',
        'test_id': trace_report.get('test_id'),
        'build_type': trace_report.get('build_type'),
        'version': side,
        'expected_commit': commit,
        'execution_commit_verified': verified_commit,
        'source_roots': list(source_roots),
        'summary': {
            'findings': len(finding_results),
            'changed_line_overlaps': sum(f['correlation_status'] == 'changed_line_overlap' for f in finding_results),
            'file_only_overlaps': sum(f['correlation_status'] == 'file_overlap_only' for f in finding_results),
            'unresolved': sum(f['correlation_status'] in {'ambiguous_path', 'no_source_location', 'no_match'} for f in finding_results),
        },
        'findings': finding_results,
        'limitations': [
            'Overlapping a changed line does not prove the patch fixed or caused the vulnerability.',
            'A single execution cannot establish Fixed, Incomplete Fix, New Issue, or Functional Regression.',
            'Related allocation/free stacks are excluded from primary failure correlation.',
            'An unverified execution commit or suffix-only path match limits evidence strength.',
            'For authoritative results, include a full commit hash and configure source roots.',
        ],
    }


def correlate_execution(
    diff_report: Mapping[str, Any],
    execution: Mapping[str, Any],
    *,
    version: str | None = None,
    source_roots: Sequence[str] = (),
) -> dict[str, Any]:
    """Accept either raw runner result or pre-parsed trace report."""
    if not isinstance(execution, Mapping):
        raise TypeError('execution must be a JSON object')
    parsed = execution if execution.get('analysis_type') == 'runtime_trace_analysis' else parse_execution_result(execution)
    # The previous parser contract does not preserve commit hashes in parsed reports;
    # pass the verified value through if it was present in raw runner data.
    if parsed is not execution and (execution.get('commit_hash') or execution.get('commit')):
        parsed = {**parsed, 'commit_hash': execution.get('commit_hash') or execution.get('commit')}
    return correlate_findings(diff_report, parsed, version=version, source_roots=source_roots)
