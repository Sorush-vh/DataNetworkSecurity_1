"""Command-line interface for Security Patch Validator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from security_patch_validator.execution import load_config, run_suite
from security_patch_validator.patch_analysis.classifier import classify_patch
from security_patch_validator.patch_analysis.correlation import correlate_execution
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff
from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result
from security_patch_validator.patch_analysis.version_comparator import (
    VersionComparisonError,
    compare_versions,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='spv', description='Security Patch Validator')
    subparsers = parser.add_subparsers(dest='command', required=True)

    for command, help_text in (
        ('compare', 'Compare Base and Patched commit snapshots.'),
        ('diff', 'Extract line-level Git Diff changes between two commits.'),
        ('correlate', 'Correlate a runtime sanitizer report with the Git Diff.'),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument('--repo', default='.', help='Git working-tree root.')
        command_parser.add_argument('--base', required=True, help='Base commit, tag, or branch.')
        command_parser.add_argument('--patched', required=True, help='Patched commit, tag, or branch.')
        command_parser.add_argument('--output', help='Optional output JSON file.')
        command_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')
        if command == 'correlate':
            command_parser.add_argument('--trace', required=True, help='Raw execution result or parsed trace JSON.')
            command_parser.add_argument('--version', choices=['base', 'patched'],
                                        help='Version used for the trace; defaults to trace metadata.')
            command_parser.add_argument('--source-root', action='append', default=[],
                                        help='Runtime source-tree prefix (repeatable), e.g. /project.')

    classify_parser = subparsers.add_parser('classify', help='Classify paired Base/Patched executions.')
    classify_parser.add_argument('--suite', required=True, help='JSON suite containing reference tests and paired runs.')
    classify_parser.add_argument('--repo', default='.', help='Git working-tree root.')
    classify_parser.add_argument('--base', required=True, help='Base revision.')
    classify_parser.add_argument('--patched', required=True, help='Patched revision.')
    classify_parser.add_argument('--source-root', action='append', default=[], help='Runtime source prefix (repeatable).')
    classify_parser.add_argument('--output', help='Optional output JSON file.')
    classify_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    execution_parser = subparsers.add_parser('execute', help='Build and run paired C/C++ tests.')
    execution_parser.add_argument('--config', required=True, help='Dynamic execution JSON manifest.')
    execution_parser.add_argument('--artifacts-dir', help='Retain source snapshots, binaries and run files here.')
    execution_parser.add_argument('--output', help='Optional output JSON file.')
    execution_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    trace_parser = subparsers.add_parser('parse-trace', help='Parse sanitizer output from runner JSON.')
    trace_parser.add_argument('--input', required=True, help='Path to runner result JSON.')
    trace_parser.add_argument('--output', help='Optional output JSON file.')
    trace_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == 'compare':
            report = compare_versions(args.repo, args.base, args.patched)
        elif args.command == 'diff':
            report = analyze_diff(args.repo, args.base, args.patched)
        elif args.command == 'classify':
            report = classify_patch(
                json.loads(Path(args.suite).read_text(encoding='utf-8')),
                diff_report=analyze_diff(args.repo, args.base, args.patched),
                source_roots=args.source_root,
            )
        elif args.command == 'execute':
            report = run_suite(load_config(args.config), artifacts_dir=args.artifacts_dir)
        elif args.command == 'parse-trace':
            report = parse_execution_result(json.loads(Path(args.input).read_text(encoding='utf-8')))
        elif args.command == 'correlate':
            diff = analyze_diff(args.repo, args.base, args.patched)
            execution = json.loads(Path(args.trace).read_text(encoding='utf-8'))
            report = correlate_execution(diff, execution, version=args.version, source_roots=args.source_root)
        else:
            parser.error('Unsupported command.')
            return 2
    except (VersionComparisonError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f'spv: error: {exc}', file=sys.stderr)
        if args.command != 'execute':
            return 30 if args.command == 'classify' else 1
        report = {'schema_version': '1.0', 'analysis_type': 'dynamic_execution',
                  'status': 'build_or_config_error', 'error': str(exc)}

    output = json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.output:
        output_path = Path(args.output).expanduser()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output + '\n', encoding='utf-8')
        except OSError as exc:
            if args.command != 'execute':
                raise
            print(f'spv: error: {exc}', file=sys.stderr)
            return 30
    else:
        print(output)
    if args.command == 'execute':
        return {'completed': 0, 'build_or_config_error': 30, 'incomplete': 40}[report['status']]
    return report['suggested_exit_code'] if args.command == 'classify' else 0


if __name__ == '__main__':
    raise SystemExit(main())
