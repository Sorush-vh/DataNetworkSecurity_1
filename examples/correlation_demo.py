"""Create a disposable Git comparison and a synthetic ASan-style trace.

The diagnostic is simulated for parser validation, not a real C/ASan crash.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from security_patch_validator.patch_analysis.correlation import correlate_execution
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff


def git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True,
                          text=True, check=True).stdout.strip()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix='spv-correlation-') as temp:
        repo = Path(temp)
        (repo / 'src').mkdir()
        git(repo, 'init')
        git(repo, 'config', 'user.name', 'Demo')
        git(repo, 'config', 'user.email', 'demo@example.invalid')
        path = repo / 'src' / 'parser.c'
        path.write_text('int parse(void) {\n    int value = 1;\n    return value;\n}\n', encoding='utf-8')
        git(repo, 'add', '.'); git(repo, 'commit', '-m', 'base')
        base = git(repo, 'rev-parse', 'HEAD')
        path.write_text('int parse(void) {\n    int value = 2;\n    return value;\n}\n', encoding='utf-8')
        git(repo, 'add', '.'); git(repo, 'commit', '-m', 'patched')
        patched = git(repo, 'rev-parse', 'HEAD')
        diff = analyze_diff(repo, base, patched)
        synthetic_run = {
            'test_id': 'SYNTHETIC-DEMO-ONLY',
            'version': 'base',
            'commit_hash': base,
            'build_type': 'asan',
            'exit_code': 1,
            'stderr': ('==1==ERROR: AddressSanitizer: heap-buffer-overflow\n'
                       '    #0 0x400abc in parse /project/src/parser.c:2:2\n'
                       'SUMMARY: AddressSanitizer: heap-buffer-overflow /project/src/parser.c:2:2 in parse\n'),
        }
        result = correlate_execution(diff, synthetic_run, source_roots=['/project'])
        print(json.dumps(result, indent=2))
        print('\nNote: sanitizer trace is synthetic; this demonstrates correlation only.')


if __name__ == '__main__':
    main()
