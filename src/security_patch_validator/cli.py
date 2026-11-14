"""Command-line interface for Security Patch Validator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from security_patch_validator.execution import load_config, run_suite
from security_patch_validator.hardening import (
    HardeningError,
    check_requirements,
    compare_hardening,
    inspect_binary,
)
from security_patch_validator.patch_analysis.classifier import classify_patch
from security_patch_validator.patch_analysis.correlation import correlate_execution
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff
from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result
from security_patch_validator.patch_analysis.version_comparator import (
    VersionComparisonError,
    compare_versions,
)
from security_patch_validator.targets import (
    TargetError,
    format_scenario_summary,
    load_target,
    materialize_execution_config,
    run_scenario,
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
    execution_parser.add_argument('--repetitions', type=int, default=1,
                                  help='Repeat every test/version observation this many times (default: 1).')
    execution_parser.add_argument('--output', help='Optional output JSON file.')
    execution_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    hardening_parser = subparsers.add_parser('hardening', help='Inspect ELF hardening protections.')
    hardening_parser.add_argument('--binary', required=True, help='ELF executable to inspect.')
    hardening_parser.add_argument('--compare', help='Optional second ELF executable to compare against.')
    hardening_parser.add_argument('--require', action='append', default=[],
                                  metavar='NAME=STATUS',
                                  help='Required protection status, e.g. relro=full (repeatable).')
    hardening_parser.add_argument('--output', help='Optional output JSON file.')
    hardening_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    trace_parser = subparsers.add_parser('parse-trace', help='Parse sanitizer output from runner JSON.')
    trace_parser.add_argument('--input', required=True, help='Path to runner result JSON.')
    trace_parser.add_argument('--output', help='Optional output JSON file.')
    trace_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    targets_parser = subparsers.add_parser('targets', help='Validate and run target scenarios.')
    targets_sub = targets_parser.add_subparsers(dest='targets_command', required=True)

    validate_parser = targets_sub.add_parser('validate', help='Validate a target manifest.')
    validate_parser.add_argument('--target', required=True, help='Path to target.json.')
    validate_parser.add_argument('--output', help='Optional output JSON file.')
    validate_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    materialize_parser = targets_sub.add_parser('materialize', help='Write a scenario execution config.')
    materialize_parser.add_argument('--target', required=True, help='Path to target.json.')
    materialize_parser.add_argument('--scenario', required=True, choices=['correct', 'incomplete', 'regression'])
    materialize_parser.add_argument('--output', required=True, help='Output execution config path.')
    materialize_parser.add_argument('--relative', action='store_true',
                                    help='Write source and input paths relative to the output file.')
    materialize_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    run_parser = targets_sub.add_parser('run', help='Run one target scenario end to end.')
    run_parser.add_argument('--target', required=True, help='Path to target.json.')
    run_parser.add_argument('--scenario', required=True, choices=['correct', 'incomplete', 'regression'])
    run_parser.add_argument('--artifacts-dir', required=True, help='Directory for retained artifacts.')
    run_parser.add_argument('--repetitions', type=int, default=3, help='Replays per test/version (minimum 3).')
    run_parser.add_argument('--skip-reproducer', action='store_true', help='Skip bundle/minimization generation.')
    run_parser.add_argument('--patched-dir', help='Evaluate this source directory as an unseen patched version.')
    run_parser.add_argument('--patched-label', default=None,
                            help='Version label to assign to --patched-dir (default: the scenario target).')
    run_parser.add_argument('--summary', action='store_true', help='Print a developer-facing summary.')
    run_parser.add_argument('--output', help='Optional output JSON file.')
    run_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')

    run_all_parser = targets_sub.add_parser('run-all', help='Run all three scenarios for one target.')
    run_all_parser.add_argument('--target', required=True, help='Path to target.json.')
    run_all_parser.add_argument('--artifacts-dir', required=True, help='Directory for retained artifacts.')
    run_all_parser.add_argument('--repetitions', type=int, default=3, help='Replays per test/version (minimum 3).')
    run_all_parser.add_argument('--skip-reproducer', action='store_true', help='Skip bundle/minimization generation.')
    run_all_parser.add_argument('--summary', action='store_true', help='Print a developer-facing summary.')
    run_all_parser.add_argument('--output', help='Optional summary JSON file.')
    run_all_parser.add_argument('--pretty', action='store_true', help='Indent JSON output.')
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
            report = run_suite(load_config(args.config), artifacts_dir=args.artifacts_dir,
                               repetitions=args.repetitions)
        elif args.command == 'hardening':
            report = inspect_binary(args.binary)
            if args.compare:
                patched = inspect_binary(args.compare)
                report = {
                    'schema_version': '1.0',
                    'analysis_type': 'elf_hardening_pair',
                    'base': report,
                    'patched': patched,
                    'comparison': compare_hardening(report, patched),
                }
            if args.require:
                required = {}
                for item in args.require:
                    if '=' not in item:
                        raise ValueError(f'--require expects NAME=STATUS, got {item!r}.')
                    name, status = item.split('=', 1)
                    required[name.strip()] = status.strip()
                target = report['patched'] if args.compare else report
                report['requirements'] = check_requirements(target, required)
        elif args.command == 'parse-trace':
            report = parse_execution_result(json.loads(Path(args.input).read_text(encoding='utf-8')))
        elif args.command == 'correlate':
            diff = analyze_diff(args.repo, args.base, args.patched)
            execution = json.loads(Path(args.trace).read_text(encoding='utf-8'))
            report = correlate_execution(diff, execution, version=args.version, source_roots=args.source_root)
        elif args.command == 'targets':
            if args.targets_command == 'validate':
                target = load_target(args.target)
                report = {
                    'schema_version': '1.0',
                    'analysis_type': 'target_validation',
                    'target_id': target.target_id,
                    'name': target.name,
                    'real_world': target.real_world,
                    'versions': {label: str(version.source_dir) for label, version in target.versions.items()},
                    'scenarios': target.scenarios,
                    'hardening_required': target.hardening.get('required', {}),
                    'reference_tests': str(target.reference_tests),
                    'valid': True,
                }
            elif args.targets_command == 'materialize':
                target = load_target(args.target)
                path = materialize_execution_config(
                    target, args.scenario, args.output, relative_inputs=args.relative,
                )
                report = {
                    'schema_version': '1.0',
                    'analysis_type': 'target_materialization',
                    'target_id': target.target_id,
                    'scenario': args.scenario,
                    'config': str(path),
                }
            elif args.targets_command == 'run':
                report = run_scenario(
                    args.target, args.scenario,
                    artifacts_dir=args.artifacts_dir,
                    output_path=args.output,
                    repetitions=args.repetitions,
                    skip_reproducer=args.skip_reproducer,
                    patched_source_dir=args.patched_dir,
                    patched_label=args.patched_label,
                )
            elif args.targets_command == 'run-all':
                target = load_target(args.target)
                results = {}
                for scenario in ('correct', 'incomplete', 'regression'):
                    results[scenario] = run_scenario(
                        args.target, scenario,
                        artifacts_dir=Path(args.artifacts_dir) / scenario,
                        repetitions=args.repetitions,
                        skip_reproducer=args.skip_reproducer,
                    )
                all_match = all(
                    result['matches_expected_exit_code'] for result in results.values()
                )
                report = {
                    'schema_version': '1.0',
                    'analysis_type': 'target_scenario_matrix',
                    'target_id': target.target_id,
                    'all_scenarios_match_expected': all_match,
                    'scenarios': {
                        scenario: {
                            'expected_exit_code': result['expected_exit_code'],
                            'observed_exit_code': result['observed_exit_code'],
                            'matches_expected_exit_code': result['matches_expected_exit_code'],
                            'statuses': result['classification']['statuses'],
                            'artifacts': result['artifacts']['workspace'],
                        }
                        for scenario, result in results.items()
                    },
                }
            else:
                parser.error('Unsupported targets command.')
                return 2
        else:
            parser.error('Unsupported command.')
            return 2
    except (VersionComparisonError, HardeningError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f'spv: error: {exc}', file=sys.stderr)
        if args.command == 'hardening':
            return 30
        if args.command == 'targets':
            return 30
        if args.command != 'execute':
            return 30 if args.command == 'classify' else 1
        report = {'schema_version': '1.0', 'analysis_type': 'dynamic_execution',
                  'status': 'build_or_config_error', 'error': str(exc)}

    if args.command == 'targets' and getattr(args, 'summary', False):
        if args.targets_command in ('run', 'run-all'):
            print(format_scenario_summary(report), file=sys.stdout if args.output else sys.stderr)

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
    if args.command == 'hardening':
        requirements = report.get('requirements')
        return 0 if requirements is None or requirements['compliant'] else 40
    if args.command == 'targets':
        if args.targets_command in ('validate', 'materialize'):
            return 0
        if args.targets_command == 'run':
            return report['observed_exit_code']
        if args.targets_command == 'run-all':
            if report['all_scenarios_match_expected']:
                return 0
            observed = [item['observed_exit_code'] for item in report['scenarios'].values()]
            for code in (40, 20, 10, 30, 0):
                if code in observed:
                    return code
            return 40
    return report['suggested_exit_code'] if args.command == 'classify' else 0


if __name__ == '__main__':
    raise SystemExit(main())
