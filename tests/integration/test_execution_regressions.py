"""Native end-to-end regressions: build, execute, diagnose and check oracles."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from security_patch_validator.execution import load_config, run_suite
from security_patch_validator.patch_analysis.stacktrace_parser import parse_sanitizer_output


class ParserEvidenceTests(unittest.TestCase):
    def test_checked_in_sanitizer_fixtures(self):
        fixtures = Path(__file__).resolve().parents[1] / "fixtures"
        for name, mechanism, error_type in (
            ("asan_heap_buffer_overflow.log", "asan", "heap-buffer-overflow"),
            ("asan_use_after_free.log", "asan", "heap-use-after-free"),
            ("ubsan_signed_integer_overflow.log", "ubsan", "signed-integer-overflow"),
        ):
            with self.subTest(name=name):
                finding, = parse_sanitizer_output(stderr=(fixtures / name).read_text())
                self.assertEqual((finding["detection_mechanism"], finding["error_type"]),
                                 (mechanism, error_type))
                self.assertTrue(finding["stack_trace"])
                self.assertIsNotNone(finding["location"])
        self.assertEqual(parse_sanitizer_output(stderr=(fixtures / "clean_output.log").read_text()), [])

    def test_application_messages_in_either_stream_are_not_ubsan(self):
        for stream in ("stdout", "stderr"):
            for message in ("input invalid", "division by zero"):
                with self.subTest(stream=stream, message=message):
                    self.assertEqual(parse_sanitizer_output(
                        **{stream: f"runtime error: {message}\n"}), [])

    def test_located_and_explicit_locationless_ubsan_are_preserved(self):
        for diagnostic, location in (
            ("math.c:4:7: runtime error: division by zero", {"file": "math.c", "line": 4, "column": 7}),
            ("SUMMARY: UndefinedBehaviorSanitizer: division by zero", None),
        ):
            with self.subTest(diagnostic=diagnostic):
                finding, = parse_sanitizer_output(stderr=diagnostic)
                self.assertEqual(finding["error_type"], "division-by-zero")
                self.assertEqual(finding["location"], location)

    def test_numbered_application_logs_in_both_streams(self):
        for stream in ("stdout", "stderr"):
            for prefix in ("validator:42", "validator:42:3", "validator.c:42", "/tmp/validator.cpp:42:3"):
                with self.subTest(stream=stream, prefix=prefix):
                    self.assertEqual(parse_sanitizer_output(
                        **{stream: f"{prefix}: runtime error: input invalid\n"}), [])

    def test_unknown_ubsan_message_with_native_frame_is_preserved(self):
        log = "generated:42: runtime error: future compiler diagnostic\n" \
              "    #0 0x1234 in calculate /src/generated:42\n"
        finding, = parse_sanitizer_output(stderr=log)
        self.assertEqual(finding["detection_mechanism"], "ubsan")
        self.assertEqual(finding["location"]["file"], "generated")
        self.assertEqual(len(finding["stack_trace"]), 1)


NATIVE_MAIN = r'''
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void write_at(char *, int);
int read_at(char *, int);
int add_one(int);
int main(int argc, char **argv) {
    if (argc != 2) return 3;
    if (!strcmp(argv[1], "invalid")) {
        fputs("runtime error: input invalid\n", stderr);
        return 2;
    }
    if (!strcmp(argv[1], "integer-overflow")) {
#ifdef FIXED
        printf("%lld\n", (long long)INT_MAX + 1);
#else
        printf("%d\n", add_one(INT_MAX));
#endif
        return 0;
    }
    char *p = (char *)malloc(8);
    if (!p) return 4;
    write_at(p, 0);
    if (!strcmp(argv[1], "heap-overflow")) {
#ifdef FIXED
        write_at(p, 7);
#else
        write_at(p, 8);
#endif
        free(p);
    } else if (!strcmp(argv[1], "use-after-free")) {
#ifdef FIXED
        (void)read_at(p, 0);
        free(p);
#else
        free(p);
        (void)read_at(p, 0);
#endif
    } else {
        write_at(p, !strcmp(argv[1], "boundary") ? 7 : 3);
        free(p);
    }
    puts("ok");
    return 0;
}
'''

# Separate translation units prevent optimization from replacing the accesses
# with a constant or removing them before the sanitizer can instrument them.
NATIVE_HELPER = r'''
void write_at(char *p, int index) { ((volatile char *)p)[index] = 7; }
int read_at(char *p, int index) { return ((volatile char *)p)[index]; }
int add_one(int n) { volatile int value = n; return value + 1; }
'''


@unittest.skipUnless(all(shutil.which(t) for t in ("gcc", "g++", "readelf")),
                     "requires GCC, G++ and GNU readelf")
class NativeRegressionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name)

    def manifest(self, files, *, patched=None, commands=None, tests=None):
        versions = {}
        for label, contents in (("base", files), ("patched", patched or files)):
            source = self.work / label
            source.mkdir()
            for name, text in contents.items():
                (source / name).write_text(text, encoding="utf-8")
            versions[label] = {"source_dir": label}
        return {
            "target_id": "native-regression-fixture", "versions": versions,
            "build": {"binary": "app", "commands": commands or [
                ["gcc", "{flags}", "main.c", "-o", "{binary}"]]},
            "limits": {"timeout": 3, "build_timeout": 20, "max_output_bytes": 65536},
            "tests": tests or [self.case("probe", "valid", "", stdout="")],
        }

    @staticmethod
    def case(test_id, category, arg, *, stdout="ok\n", stderr="", code=0):
        return {"id": test_id, "category": category, "args": [arg] if arg else [],
                "input": {"mode": "argv"},
                "expected": {"exit_code": code, "stdout": stdout, "stderr": stderr},
                "reference": "docs/execution.md#native-regression-tests"}

    def execute(self, manifest):
        path = self.work / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return run_suite(load_config(path))

    def test_numbered_application_logs_are_not_ubsan_in_native_runs(self):
        messages = ["validator:42: runtime error: input invalid\n",
                    "validator.c:42: runtime error: input invalid\n",
                    "validator:42: runtime error: division by zero\n"]
        manifest = self.manifest({"main.c": '#include <stdio.h>\n'
            'int main(int argc,char **argv){volatile int n=argc; fputs(argv[1],stderr); return n+0;}\n'},
            tests=[self.case(str(i), "invalid", message, stdout="", stderr=message, code=2)
                   for i, message in enumerate(messages)])
        report = self.execute(manifest)
        self.assertEqual(report["status"], "completed", report["builds"])
        for run in report["executions"]:
            self.assertEqual(run["expectation"]["status"], "pass", run)
            self.assertEqual(run["findings"], [])

    @unittest.skipUnless(shutil.which("make"), "requires make")
    def test_makefile_ignoring_flags_cannot_silently_skip_sanitizers(self):
        manifest = self.manifest({
            "main.c": '#include <stdio.h>\nint calc(void); int main(int argc,char **argv) '
                      '{volatile int n=argc; if(n+1>0) printf("%d\\n",calc()); return 0;}\n',
            "helper.c": '#include <limits.h>\nint calc(void){volatile int n=INT_MAX; return n+1;}\n',
            "Makefile": 'app: main.o helper.o\n\t$(CC) $(CFLAGS) $(LDFLAGS) main.o helper.o -o app\n'
                        'main.o: main.c\n\t$(CC) $(CFLAGS) -c main.c -o main.o\n'
                        'helper.o: helper.c\n\tgcc -O2 -c helper.c -o helper.o\n',
        }, commands=[["make", "-j2"]], tests=[self.case("overflow", "boundary", "", stdout="-2147483648\n")])
        report = self.execute(manifest)
        self.assertEqual(report["status"], "completed", report["builds"])
        for run in report["executions"]:
            if run["build_type"] == "asan_ubsan":
                self.assertIn(("ubsan", "signed-integer-overflow"), [
                    (f["detection_mechanism"], f["error_type"]) for f in run["findings"]])
        for build in report["builds"]:
            if build["build_type"] == "asan_ubsan":
                audit = build["compiler_audit"]
                self.assertEqual(audit["status"], "verified")
                self.assertEqual({u["source"] for u in audit["translation_units"]}, {"main.c", "helper.c"})
                self.assertTrue(all(u["verified"] for u in audit["translation_units"]))
                self.assertEqual(len([r for r in audit["invocations"] if r["sources"]]), 2)

    @unittest.skipUnless(shutil.which("make"), "requires make")
    def test_absolute_compiler_bypassing_audit_fails_closed(self):
        manifest = self.manifest({
            "main.c": 'int helper(void); int main(int n,char **v){volatile int x=n; return x-1+helper();}\n',
            "helper.c": 'int helper(void){return 0;}\n',
            "Makefile": 'app: main.o helper.o\n\t$(CC) $(CFLAGS) main.o helper.o -o app\n'
                        'main.o: main.c\n\t$(CC) $(CFLAGS) -c main.c -o main.o\n'
                        f'helper.o: helper.c\n\t{shutil.which("gcc")} -c helper.c -o helper.o\n',
        }, commands=[["make"]])
        report = self.execute(manifest)
        self.assertEqual(report["status"], "build_or_config_error")
        self.assertEqual(len(report["executions"]), 2)
        self.assertTrue(all(r["build_type"] == "release" for r in report["executions"]))
        for build in report["builds"]:
            if build["build_type"] == "asan_ubsan":
                self.assertEqual(build["status"], "failed")
                self.assertEqual(build["compiler_audit"]["status"], "unverified")
                self.assertIn("helper.c", build["error"])

    def test_declared_units_can_exclude_unused_sources(self):
        manifest = self.manifest({"main.c": 'int main(int n,char **v){volatile int x=n; return x-1;}\n',
                                  "unused.c": 'this file is not part of the target\n'})
        manifest["build"]["translation_units"] = ["main.c"]
        # Direct absolute compiler paths in the manifest are routed through the audit too.
        manifest["build"]["commands"][0][0] = shutil.which("gcc")
        report = self.execute(manifest)
        self.assertEqual(report["status"], "completed", report["builds"])
        for build in report["builds"]:
            if build["build_type"] == "asan_ubsan":
                self.assertEqual(build["compiler_audit"]["scope"], "declared_translation_units")
                self.assertEqual([u["source"] for u in build["compiler_audit"]["translation_units"]], ["main.c"])

    def test_disabling_sanitizers_in_recipe_is_rejected(self):
        manifest = self.manifest({"main.c": 'int main(int n,char **v){volatile int x=n; return x-1;}\n'})
        manifest["build"]["commands"][0].append("-fno-sanitize=undefined")
        report = self.execute(manifest)
        self.assertEqual(report["status"], "build_or_config_error")
        self.assertEqual(len(report["skipped"]), 2)
        for build in report["builds"]:
            if build["build_type"] == "asan_ubsan":
                self.assertIn("not allowed", build["commands"][0]["stderr"])

    def test_response_file_cannot_hide_unaudited_compilation(self):
        manifest = self.manifest({"main.c": 'int main(int n,char **v){volatile int x=n; return x-1;}\n',
                                  "args.rsp": 'main.c'})
        manifest["build"]["commands"][0][2] = "@args.rsp"
        report = self.execute(manifest)
        self.assertEqual(report["status"], "build_or_config_error")
        self.assertEqual(len(report["skipped"]), 2)
        for build in report["builds"]:
            if build["build_type"] == "asan_ubsan":
                self.assertIn("response files are not supported", build["commands"][0]["stderr"])

    def test_invalid_translation_units_are_rejected(self):
        manifest = self.manifest({"main.c": "int main(void){return 0;}\n"})
        for units in ([], "main.c", ["../main.c"], ["/tmp/main.c"], ["main.c", "main.c"], [4]):
            with self.subTest(units=units), self.assertRaises(ValueError):
                manifest["build"]["translation_units"] = units
                self.execute(manifest)

    def check_native_errors(self, compiler, standard):
        manifest = self.manifest(
            {"main.c": NATIVE_MAIN, "helper.c": NATIVE_HELPER},
            patched={"main.c": "#define FIXED\n" + NATIVE_MAIN, "helper.c": NATIVE_HELPER},
            commands=[[compiler, standard, "{flags}", "main.c", "helper.c", "-o", "{binary}"]],
            tests=[
                self.case("valid", "valid", "valid"),
                self.case("boundary", "boundary", "boundary"),
                self.case("invalid", "invalid", "invalid", code=2, stdout="",
                          stderr="runtime error: input invalid\n"),
                self.case("heap-overflow", "invalid", "heap-overflow"),
                self.case("use-after-free", "invalid", "use-after-free"),
                self.case("integer-overflow", "boundary", "integer-overflow", stdout="2147483648\n"),
            ],
        )
        report = self.execute(manifest)
        self.assertEqual(report["status"], "completed", report["builds"])
        self.assertEqual(len(report["executions"]), 24)
        expected_findings = {
            "heap-overflow": ("asan", "heap-buffer-overflow"),
            "use-after-free": ("asan", "heap-use-after-free"),
            "integer-overflow": ("ubsan", "signed-integer-overflow"),
        }
        for run in report["executions"]:
            with self.subTest(compiler=compiler, version=run["version"],
                              build=run["build_type"], case=run["test_id"]):
                if run["version"] == "patched" or run["test_id"] not in expected_findings:
                    self.assertEqual(run["expectation"]["status"], "pass", run)
                    self.assertEqual(run["findings"], [])
                elif run["build_type"] == "asan_ubsan":
                    self.assertEqual(run["expectation"]["status"], "runtime_error", run)
                    matches = [f for f in run["findings"] if (
                        f["detection_mechanism"], f["error_type"]) == expected_findings[run["test_id"]]]
                    self.assertTrue(matches, run["stderr"])
                    self.assertTrue(matches[0]["stack_trace"], run["stderr"])
                    self.assertIsNotNone(matches[0]["location"])

    def test_c_memory_and_arithmetic_errors_through_full_matrix(self):
        self.check_native_errors("gcc", "-std=c11")

    def test_cpp_memory_and_arithmetic_errors_through_full_matrix(self):
        self.check_native_errors("g++", "-std=c++17")

    @unittest.skipUnless(shutil.which("make") and shutil.which("ar"), "requires make and ar")
    def test_stale_objects_and_archives_are_rebuilt_with_sanitizers(self):
        files = {
            "main.c": '#include <stdio.h>\nint calc(void); int main(int argc,char **argv) '
                      '{volatile int n=argc; if(n+1>0) printf("%d\\n",calc()); return 0;}\n',
            "helper.c": '#include <limits.h>\nint calc(void){volatile int n=INT_MAX; return n+1;}\n',
            "Makefile": 'app: main.o libhelper.a\n\t$(CC) $(CFLAGS) $(LDFLAGS) main.o libhelper.a -o app\n'
                        'main.o: main.c\n\t$(CC) $(CFLAGS) -c main.c -o main.o\n'
                        'helper.blob: helper.c\n\t$(CC) $(CFLAGS) -c helper.c -o helper.blob\n'
                        'libhelper.a: helper.blob\n\t$(AR) rcs libhelper.a helper.blob\n',
        }
        manifest = self.manifest(files, commands=[["make"]], tests=[
            self.case("overflow", "boundary", "", stdout="-2147483648\n")])
        originals = {}
        for label in ("base", "patched"):
            source = self.work / label
            subprocess.run(["gcc", "-O2", "-c", "helper.c", "-o", "helper.blob"], cwd=source,
                           check=True, capture_output=True)
            subprocess.run(["ar", "rcs", "libhelper.a", "helper.blob"], cwd=source,
                           check=True, capture_output=True)
            originals[label] = {name: (source / name).read_bytes() for name in ("helper.blob", "libhelper.a")}
        report = self.execute(manifest)
        self.assertEqual(report["status"], "completed", report["builds"])
        for build in report["builds"]:
            self.assertEqual(build["removed_build_artifacts"], ["helper.blob", "libhelper.a"])
        for run in report["executions"]:
            if run["build_type"] == "asan_ubsan":
                self.assertIn(("ubsan", "signed-integer-overflow"), [
                    (f["detection_mechanism"], f["error_type"]) for f in run["findings"]])
            else:
                self.assertEqual(run["expectation"]["status"], "pass")
        for label, files in originals.items():
            for name, data in files.items():
                self.assertEqual((self.work / label / name).read_bytes(), data)

    def test_clean_commands_run_before_build_and_are_reported(self):
        manifest = self.manifest({"main.c": "int main(int n,char **v){volatile int x=n; return x-1;}\n",
                                  "cached-profile": "old settings"})
        manifest["build"]["binary"] = "out/app"
        for label in ("base", "patched"):
            (self.work / label / "out").mkdir()
        manifest["build"]["clean_commands"] = [[sys.executable, "-c",
            "import shutil; from pathlib import Path; Path('cached-profile').unlink(); shutil.rmtree('out')"]]
        manifest["build"]["commands"].insert(0, [sys.executable, "-c",
            "from pathlib import Path; assert not Path('cached-profile').exists()"])
        report = self.execute(manifest)
        self.assertEqual(report["status"], "completed", report["builds"])
        for build in report["builds"]:
            self.assertEqual([c["phase"] for c in build["commands"]], ["clean", "build", "build"])
        self.assertTrue((self.work / "base" / "cached-profile").exists())

    def test_failed_clean_command_skips_executions_and_preserves_error(self):
        manifest = self.manifest({"main.c": "int main(void){return 0;}\n"})
        manifest["build"]["clean_commands"] = [[sys.executable, "-c",
            "import sys; print('clean failed', file=sys.stderr); sys.exit(7)"]]
        report = self.execute(manifest)
        self.assertEqual(report["status"], "build_or_config_error")
        self.assertEqual(report["executions"], [])
        self.assertEqual(len(report["skipped"]), 4)
        for build in report["builds"]:
            self.assertEqual(build["commands"][0]["exit_code"], 7)
            self.assertEqual(build["commands"][0]["stderr"], "clean failed\n")
            self.assertEqual(build["error"], "Clean command failed.")

    def test_invalid_clean_commands_are_rejected(self):
        manifest = self.manifest({"main.c": "int main(void){return 0;}\n"})
        for value in ("make clean", [[]], [[""]], [["make", 1]]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                manifest["build"]["clean_commands"] = value
                self.execute(manifest)

    def test_external_source_symlink_is_rejected_without_modifying_target(self):
        manifest = self.manifest({"main.c": "int main(void){return 0;}\n"})
        external = self.work / "outside.o"
        external.write_bytes(b"unchanged")
        for label in ("base", "patched"):
            (self.work / label / "external.o").symlink_to(external)
        report = self.execute(manifest)
        self.assertEqual(report["status"], "build_or_config_error")
        self.assertEqual(external.read_bytes(), b"unchanged")
        self.assertTrue(all("symlink escapes" in b["error"] for b in report["builds"]))

    def test_native_timeout_preserves_logs_in_both_build_profiles(self):
        source = '#include <stdio.h>\nint main(void){puts("started"); fflush(stdout);' \
                 'volatile unsigned int n=0;\n#ifndef FIXED\nfor(;;){n++;}\n#endif\nreturn (int)n;}\n'
        manifest = self.manifest({"main.c": source}, patched={"main.c": "#define FIXED\n" + source},
                                 tests=[self.case("timeout", "boundary", "", stdout="started\n")])
        manifest["limits"]["timeout"] = 0.2
        report = self.execute(manifest)
        self.assertEqual(report["status"], "incomplete", report["builds"])
        self.assertEqual(len(report["executions"]), 4)
        for run in report["executions"]:
            self.assertEqual(run["stdout"], "started\n")
            if run["version"] == "base":
                self.assertTrue(run["timeout"])
                self.assertEqual(run["signal"], "SIGKILL")
                self.assertIsNone(run["exit_code"])
                self.assertEqual(run["expectation"]["status"], "inconclusive")
                self.assertEqual(run["findings"], [])
            else:
                self.assertEqual(run["expectation"]["status"], "pass")


if __name__ == "__main__":
    unittest.main()
