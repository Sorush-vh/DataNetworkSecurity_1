from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from security_patch_validator.execution import load_config, run_suite
from security_patch_validator.execution.process import run_process
from security_patch_validator.execution.runner import (
    BUILD_FLAGS,
    SANITIZER_ENV,
    _classify_observation,
)
from security_patch_validator.patch_analysis.stacktrace_parser import parse_execution_result

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "execution"
TOOLCHAIN = all(shutil.which(tool) for tool in ("gcc", "g++", "readelf"))


class ProcessCaptureTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.cwd = Path(folder.name)

    def run_child(self, source, *, timeout=3, max_output=16384, stdin=None):
        return run_process(
            [sys.executable, "-c", source], cwd=self.cwd, env=dict(os.environ),
            timeout=timeout, max_output_bytes=max_output, stdin=stdin,
        )

    def test_streams_and_nonzero_exit(self):
        result = self.run_child(
            "import sys; print('out'); print('err', file=sys.stderr); sys.exit(2)"
        )
        self.assertEqual((result["exit_code"], result["signal"]), (2, None))
        self.assertEqual((result["stdout"], result["stderr"]), ("out\n", "err\n"))
        self.assertFalse(result["logs_truncated"])

    def test_signal_has_no_exit_code(self):
        result = self.run_child("import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual((result["exit_code"], result["signal"]), (None, "SIGTERM"))
        self.assertIsNone(result["runner_stop"])

    def test_timeout_preserves_logs_and_kills_group(self):
        result = self.run_child(
            "import os, time\n"
            "print('before timeout', flush=True)\n"
            "if os.fork() == 0:\n"
            "    time.sleep(0.8)\n"
            "    open('child-escaped', 'w').close()\n"
            "    os._exit(0)\n"
            "time.sleep(60)\n",
            timeout=0.3,
        )
        self.assertEqual(result["stdout"], "before timeout\n")
        self.assertEqual((result["timeout"], result["runner_stop"]), (True, "timeout"))
        self.assertEqual((result["exit_code"], result["signal"]), (None, "SIGKILL"))
        time.sleep(0.9)
        self.assertFalse((self.cwd / "child-escaped").exists())

    def test_output_limit_is_distinct_from_timeout(self):
        result = self.run_child("import os; os.write(1, b'a' * 8192)", max_output=64)
        self.assertEqual(result["stdout"], "a" * 64)
        self.assertTrue(result["stdout_truncated"])
        self.assertEqual((result["runner_stop"], result["resource_limit"]),
                         ("output-limit", "output"))
        self.assertFalse(result["timeout"])

    def test_binary_stdin_and_stdout_are_preserved(self):
        result = self.run_child(
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", stdin=b"a\0\xff"
        )
        self.assertEqual(result["stdout_base64"], "YQD/")
        self.assertFalse(result["logs_truncated"])

    def test_launch_error_does_not_invent_exit_code(self):
        result = run_process(
            [str(self.cwd / "missing")], cwd=self.cwd, env={},
            timeout=1, max_output_bytes=4096,
        )
        self.assertIn("FileNotFoundError", result["launch_error"])
        self.assertIsNone(result["exit_code"])
        self.assertIsNone(result["signal"])


class DiagnosticTests(unittest.TestCase):
    def diagnose(self, stderr, *, build_type="release", signal=None, stop=None):
        result = {
            "build_type": build_type, "stderr": stderr, "stdout": "", "exit_code": None,
            "signal": signal, "runner_stop": stop, "launch_error": None, "timeout": False,
        }
        _classify_observation(result)
        return result

    def test_stack_guard_and_os_signal_are_distinct(self):
        result = self.diagnose("*** stack smashing detected ***: terminated\n", signal="SIGABRT")
        self.assertEqual(
            [(f["detection_mechanism"], f["error_type"]) for f in result["findings"]],
            [("stack-canary", "stack-smashing"), ("os-signal", "process-abort")],
        )

    def test_sigsegv_alone_does_not_identify_null_pointer(self):
        result = self.diagnose("", signal="SIGSEGV")
        self.assertEqual(result["findings"][0]["error_type"], "segmentation-fault")

    def test_runner_kill_is_not_a_target_finding(self):
        self.assertEqual(self.diagnose("", signal="SIGKILL", stop="timeout")["findings"], [])

    def test_upstream_asan_log_preserves_frames(self):
        sample = json.loads((ROOT / "examples" / "asan-execution-result.json").read_text())
        result = self.diagnose(sample["stderr"], build_type="asan_ubsan")
        finding = result["findings"][0]
        self.assertEqual(finding["detection_mechanism"], "asan")
        self.assertEqual(finding["error_type"], "heap-buffer-overflow")
        self.assertEqual(finding["stack_trace"][0]["line"], 45)

    def test_sanitizer_initialization_failure_is_infrastructure(self):
        result = self.diagnose("==8==ASan runtime does not come first in initial library list\n",
                               build_type="asan_ubsan")
        self.assertTrue(result["launch_error"])
        self.assertEqual(result["findings"], [])

    def test_release_does_not_treat_plain_runtime_error_as_ubsan(self):
        self.assertEqual(self.diagnose("runtime error: input invalid\n")["findings"], [])


@unittest.skipUnless(TOOLCHAIN, "requires GCC, G++ and GNU readelf")
class ExecutionMatrixTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name)

    def write_example(self, *, cpp=False):
        config = json.loads((EXAMPLE / "config.json").read_text())
        for label in ("base", "patched"):
            config["versions"][label]["source_dir"] = str(EXAMPLE / label)
        if cpp:
            config["build"]["commands"][0][:2] = ["g++", "-std=c++17", "-x", "c++"]
        return config

    def load(self, manifest):
        path = self.work / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return load_config(path)

    def test_c_matrix_matches_reference_and_person1_contract(self):
        config = load_config(EXAMPLE / "config.json")
        report = run_suite(config, artifacts_dir=self.work)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(len(report["builds"]), 4)
        self.assertEqual(len(report["executions"]), 20)
        self.assertEqual(report["skipped"], [])
        matrix = {(run["test_id"], run["build_type"], run["version"]) for run in report["executions"]}
        self.assertEqual(len(matrix), 20)
        for build in report["builds"]:
            self.assertTrue(Path(build["binary"]).is_file())
            checks = build["instrumentation"]["symbols_or_libraries_found"]
            sanitized = build["build_type"] == "asan_ubsan"
            self.assertEqual(checks, {"asan": sanitized, "ubsan": sanitized})
            self.assertEqual(len(build["binary_sha256"]), 64)
        for run in report["executions"]:
            self.assertEqual(run["expectation"]["status"], "pass")
            parsed = parse_execution_result(run)
            self.assertEqual(parsed["build_type"], run["build_type"])
            self.assertEqual(parsed["termination"]["exit_code"], run["exit_code"])
            self.assertEqual(parsed["findings"], [])

    def test_cpp_manifest_detects_patched_output_mismatch(self):
        manifest = self.write_example(cpp=True)
        patched = self.work / "patched"
        shutil.copytree(EXAMPLE / "patched", patched)
        source = patched / "square.c"
        source.write_text(source.read_text().replace(
            "value * value);", "value * value + (value == 7));",
        ))
        manifest["versions"]["patched"]["source_dir"] = str(patched)
        report = run_suite(self.load(manifest))
        self.assertEqual(report["status"], "completed")
        outcomes = {(r["version"], r["expectation"]["status"]) for r in report["executions"]
                    if r["test_id"] == "argv-valid"}
        self.assertEqual(outcomes, {("base", "pass"), ("patched", "fail")})
        self.assertFalse(report["artifacts_retained"])

    def test_file_fixture_is_frozen_before_execution(self):
        manifest = self.write_example()
        fixture = self.work / "number.txt"
        fixture.write_bytes(b"0\n")
        case = manifest["tests"][1]
        case["input"] = {"mode": "file", "path": fixture.name}
        config = self.load(manifest)
        fixture.write_bytes(b"100\n")
        report = run_suite(config)
        file_runs = [r for r in report["executions"] if r["test_id"] == case["id"]]
        self.assertEqual({r["stdout"] for r in file_runs}, {"0\n"})

    def test_build_failure_preserves_diagnostics_and_skips_missing_runs(self):
        manifest = self.write_example()
        manifest["build"]["commands"][0][-3] = "missing-source.c"
        report = run_suite(self.load(manifest))
        self.assertEqual(report["status"], "build_or_config_error")
        self.assertEqual(len(report["skipped"]), 20)
        self.assertEqual(report["executions"], [])
        for build in report["builds"]:
            self.assertIn("missing-source.c", build["commands"][0]["stderr"])

    def test_execute_cli_reports_invalid_configuration(self):
        config = self.work / "invalid.json"
        output = self.work / "report.json"
        config.write_text("{", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "security_patch_validator.cli", "execute",
             "--config", str(config), "--output", str(output)],
            capture_output=True, cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )
        self.assertEqual(result.returncode, 30, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report["status"], "build_or_config_error")

    def test_invalid_manifest_fails_before_building(self):
        manifest = self.write_example()
        manifest["tests"][1]["args"] = ["--file"]
        with self.assertRaisesRegex(ValueError, "standalone"):
            self.load(manifest)

    def test_real_sanitizer_diagnostics_on_local_diagnostic_fixture(self):
        source = self.work / "diagnostic.c"
        source.write_text(
            "#include <limits.h>\n#include <signal.h>\n#include <stdio.h>\n"
            "int main(int argc, char **argv) {\n"
            "  if (argc > 1 && argv[1][0] == 's') return raise(SIGSEGV);\n"
            "  volatile int value = INT_MAX;\n"
            "  printf(\"%d\\n\", value + 1);\n"
            "  return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        binary = self.work / "diagnostic"
        subprocess.run(["gcc", *BUILD_FLAGS["asan_ubsan"], str(source), "-o", str(binary)],
                       check=True, capture_output=True)
        for arg, mechanism, error_type in (
            ("signal", "asan", "segmentation-fault"),
            ("arithmetic", "ubsan", "signed-integer-overflow"),
        ):
            with self.subTest(mechanism=mechanism):
                evidence = run_process([str(binary), arg], cwd=self.work,
                                       env={**os.environ, **SANITIZER_ENV}, timeout=3,
                                       max_output_bytes=65536)
                parsed = parse_execution_result(evidence)
                self.assertTrue(any(
                    (finding["detection_mechanism"], finding["error_type"]) == (mechanism, error_type)
                    for finding in parsed["findings"]
                ), evidence["stderr"])


if __name__ == "__main__":
    unittest.main()
