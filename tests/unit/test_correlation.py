from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security_patch_validator.patch_analysis.correlation import correlate_execution, correlate_findings
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff
from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result


def git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True,
                          text=True, check=True).stdout.strip()


@pytest.fixture
def patch_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / 'target'
    (repo / 'src').mkdir(parents=True)
    git(repo, 'init')
    git(repo, 'config', 'user.name', 'Test Developer')
    git(repo, 'config', 'user.email', 'test@example.invalid')
    (repo / 'src/parser.c').write_text('int parse(void) {\n    int x = 1;\n    return x;\n}\n', encoding='utf-8')
    (repo / 'src/other.c').write_text('int other(void) { return 0; }\n', encoding='utf-8')
    git(repo, 'add', '.')
    git(repo, 'commit', '-m', 'base')
    base = git(repo, 'rev-parse', 'HEAD')
    (repo / 'src/parser.c').write_text('int parse(void) {\n    int x = 2;\n    return x;\n}\n', encoding='utf-8')
    git(repo, 'add', '.')
    git(repo, 'commit', '-m', 'patched')
    patched = git(repo, 'rev-parse', 'HEAD')
    return repo, base, patched


def raw_trace(line: int, *, version: str = 'base', commit: str | None = None,
              filename: str = '/project/src/parser.c', frame_path: str | None = None) -> dict:
    trace = {
        'test_id': 'T001', 'version': version, 'build_type': 'asan', 'exit_code': 1,
        'stdout': '', 'timeout': False,
        'stderr': (
            '==21==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x4\n'
            f'    #0 0x400aaa in parse {frame_path or filename}:{line}:2\n'
            f'SUMMARY: AddressSanitizer: heap-buffer-overflow {filename}:{line}:2 in parse\n'
        ),
    }
    if commit is not None:
        trace['commit_hash'] = commit
    return trace


def test_direct_overlap_verified_commit_strong(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched), raw_trace(2, commit=base), source_roots=['/project'])
    finding = report['findings'][0]
    assert report['execution_commit_verified'] is True
    assert finding['correlation_status'] == 'changed_line_overlap'
    assert finding['evidence_strength'] == 'strong'
    assert finding['matches'][0]['repository_path'] == 'src/parser.c'
    assert finding['matches'][0]['diff_hunk_indices'] == [0]
    assert finding['matches'][0]['path_match_method'] == 'configured_source_root'


def test_unknown_commit_caps_evidence_at_medium(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched), raw_trace(2), source_roots=['/project'])
    assert report['execution_commit_verified'] is False
    assert report['findings'][0]['evidence_strength'] == 'medium'


def test_suffix_only_does_not_yield_strong_evidence(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched), raw_trace(2, commit=base))
    assert report['findings'][0]['matches'][0]['path_match_method'] == 'unique_suffix'
    assert report['findings'][0]['evidence_strength'] == 'medium'


def test_file_only_overlap_is_weak(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched), raw_trace(3, commit=base), source_roots=['/project'])
    assert report['findings'][0]['correlation_status'] == 'file_overlap_only'
    assert report['findings'][0]['evidence_strength'] == 'weak'
    assert report['findings'][0]['matches'][0]['diff_hunk_indices'] == []


def test_unrelated_file_remains_unmatched(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched),
                                 raw_trace(2, commit=base, filename='/project/src/other.c'),
                                 source_roots=['/project'])
    assert report['findings'][0]['correlation_status'] == 'no_match'
    assert report['findings'][0]['matches'] == []


def test_base_and_patched_line_sides_are_separate(patch_repo):
    repo, base, patched = patch_repo
    diff = analyze_diff(repo, base, patched)
    correct = correlate_execution(diff, raw_trace(2, version='patched', commit=patched), source_roots=['/project'])
    unrelated = correlate_execution(diff, raw_trace(1, version='patched', commit=patched), source_roots=['/project'])
    assert correct['findings'][0]['correlation_status'] == 'changed_line_overlap'
    assert unrelated['findings'][0]['correlation_status'] == 'file_overlap_only'


def test_no_commit_mismatch_is_silently_accepted(patch_repo):
    repo, base, patched = patch_repo
    with pytest.raises(ValueError, match='does not match'):
        correlate_execution(analyze_diff(repo, base, patched), raw_trace(2, version='patched', commit=base),
                            source_roots=['/project'])


def test_version_conflict_rejected(patch_repo):
    repo, base, patched = patch_repo
    with pytest.raises(ValueError, match='conflicts'):
        correlate_execution(analyze_diff(repo, base, patched), raw_trace(2),
                            version='patched', source_roots=['/project'])


def test_raw_and_parsed_results_both_supported(patch_repo):
    repo, base, patched = patch_repo
    diff = analyze_diff(repo, base, patched)
    raw = raw_trace(2)
    parsed = parse_execution_result(raw)
    assert correlate_execution(diff, raw, source_roots=['/project'])['summary'] == \
           correlate_execution(diff, parsed, source_roots=['/project'])['summary']


def test_no_sanitizer_findings_not_interpreted_as_fixed(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched),
                                 {'version': 'patched', 'exit_code': 0, 'stderr': '', 'stdout': ''})
    assert report['summary']['findings'] == 0
    assert report['findings'] == []
    assert 'classification' not in report


def test_unsymbolized_trace_is_not_source_overlap(patch_repo):
    repo, base, patched = patch_repo
    trace = {'version': 'base', 'stderr': '==12==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x4 (/app/a.out+0x10)'}
    report = correlate_execution(analyze_diff(repo, base, patched), trace)
    assert report['findings'][0]['correlation_status'] == 'no_source_location'


def test_related_free_and_allocation_stacks_are_excluded(patch_repo):
    repo, base, patched = patch_repo
    raw = {
        'version': 'base', 'commit_hash': base,
        'stderr': ('==12==ERROR: AddressSanitizer: heap-use-after-free\n'
                   '    #0 0x11 in read /project/src/other.c:1:1\n'
                   'freed by thread T0 here:\n'
                   '    #0 0x22 in free /project/src/parser.c:2:1\n'
                   'previously allocated by thread T0 here:\n'
                   '    #0 0x33 in malloc /project/src/parser.c:2:1\n')
    }
    report = correlate_execution(analyze_diff(repo, base, patched), raw, source_roots=['/project'])
    assert report['findings'][0]['correlation_status'] == 'no_match'
    assert report['findings'][0]['related_stacks_excluded'] is True


def test_stack_caller_overlap_is_not_called_direct_failure(patch_repo):
    repo, base, patched = patch_repo
    trace = {
        'version': 'base', 'commit_hash': base,
        'stderr': ('==12==ERROR: AddressSanitizer: heap-buffer-overflow\n'
                   '    #0 0x11 in parse /project/src/other.c:1:1\n'
                   '    #1 0x22 in caller /project/src/parser.c:2:1\n')
    }
    result = correlate_execution(analyze_diff(repo, base, patched), trace, source_roots=['/project'])
    assert result['findings'][0]['correlation_status'] == 'changed_line_overlap'
    assert result['findings'][0]['evidence_strength'] == 'medium'
    assert result['findings'][0]['matches'][0]['frame_index'] == 1


def test_basename_only_does_not_match_nested_file(patch_repo):
    repo, base, patched = patch_repo
    report = correlate_execution(analyze_diff(repo, base, patched),
                                 raw_trace(2, filename='parser.c', commit=base))
    assert report['findings'][0]['correlation_status'] == 'no_match'


def test_ambiguous_suffix_is_unresolved(tmp_path: Path):
    repo = tmp_path / 'repo'
    (repo / 'src' / 'src').mkdir(parents=True)
    git(repo, 'init')
    git(repo, 'config', 'user.name', 'Test')
    git(repo, 'config', 'user.email', 'test@example.invalid')
    (repo / 'src' / 'parse.c').write_text('int x=1;\n', encoding='utf-8')
    (repo / 'src' / 'src' / 'parse.c').write_text('int x=1;\n', encoding='utf-8')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'base')
    base = git(repo, 'rev-parse', 'HEAD')
    (repo / 'src' / 'parse.c').write_text('int x=2;\n', encoding='utf-8')
    (repo / 'src' / 'src' / 'parse.c').write_text('int x=2;\n', encoding='utf-8')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'patched')
    patched = git(repo, 'rev-parse', 'HEAD')
    report = correlate_execution(analyze_diff(repo, base, patched),
                                 raw_trace(1, filename='/project/src/src/parse.c', commit=base))
    assert report['findings'][0]['correlation_status'] == 'ambiguous_path'
    assert report['findings'][0]['matches'] == []


def test_renamed_file_matches_correct_side(tmp_path: Path):
    repo = tmp_path / 'repo'
    (repo / 'src').mkdir(parents=True)
    git(repo, 'init'); git(repo, 'config', 'user.name', 'Test')
    git(repo, 'config', 'user.email', 'test@example.invalid')
    (repo / 'src/old_name.c').write_text('int f(void) {\n    return 1;\n}\n', encoding='utf-8')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'base')
    base = git(repo, 'rev-parse', 'HEAD')
    git(repo, 'mv', 'src/old_name.c', 'src/new_name.c')
    (repo / 'src/new_name.c').write_text('int f(void) {\n    return 2;\n}\n', encoding='utf-8')
    git(repo, 'add', '.'); git(repo, 'commit', '-m', 'patch')
    patched = git(repo, 'rev-parse', 'HEAD')
    diff = analyze_diff(repo, base, patched)
    before = correlate_execution(diff, raw_trace(2, filename='/project/src/old_name.c', commit=base),
                                 source_roots=['/project'])
    after = correlate_execution(diff, raw_trace(2, filename='/project/src/new_name.c',
                                                version='patched', commit=patched), source_roots=['/project'])
    assert before['findings'][0]['correlation_status'] == 'changed_line_overlap'
    assert after['findings'][0]['correlation_status'] == 'changed_line_overlap'


def test_cli_correlate_report_file(patch_repo, tmp_path: Path):
    repo, base, patched = patch_repo
    trace_path = tmp_path / 'trace.json'
    output_path = tmp_path / 'analysis.json'
    trace_path.write_text(json.dumps(raw_trace(2, commit=base)), encoding='utf-8')
    result = subprocess.run([sys.executable, '-m', 'security_patch_validator.cli', 'correlate',
                             '--repo', str(repo), '--base', base, '--patched', patched,
                             '--trace', str(trace_path), '--source-root', '/project',
                             '--output', str(output_path), '--pretty'],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(output_path.read_text(encoding='utf-8'))
    assert report['summary']['changed_line_overlaps'] == 1
    assert report['findings'][0]['evidence_strength'] == 'strong'


def test_invalid_version_is_rejected(patch_repo):
    repo, base, patched = patch_repo
    with pytest.raises(ValueError, match='base or patched'):
        correlate_execution(analyze_diff(repo, base, patched),
                            {'stderr': 'runtime error: division by zero', 'version': 'other'})


def test_preparsed_report_retains_commit_verification(patch_repo):
    repo, base, patched = patch_repo
    parsed = parse_execution_result(raw_trace(2, commit=base))
    assert parsed['commit_hash'] == base
    report = correlate_execution(analyze_diff(repo, base, patched), parsed, source_roots=['/project'])
    assert report['execution_commit_verified'] is True
    assert report['findings'][0]['evidence_strength'] == 'strong'


def test_cli_preparsed_trace_roundtrip(patch_repo, tmp_path: Path):
    repo, base, patched = patch_repo
    raw_path = tmp_path / 'raw.json'
    parsed_path = tmp_path / 'parsed.json'
    raw_path.write_text(json.dumps(raw_trace(2, commit=base)), encoding='utf-8')
    parse_result = subprocess.run(
        [sys.executable, '-m', 'security_patch_validator.cli', 'parse-trace',
         '--input', str(raw_path), '--output', str(parsed_path)],
        capture_output=True, text=True)
    assert parse_result.returncode == 0, parse_result.stderr
    result = subprocess.run(
        [sys.executable, '-m', 'security_patch_validator.cli', 'correlate',
         '--repo', str(repo), '--base', base, '--patched', patched,
         '--trace', str(parsed_path), '--source-root', '/project'],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['execution_commit_verified'] is True
