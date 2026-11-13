from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_patch_validator.patch_analysis.stacktrace_parser import (
    parse_execution_result,
    parse_sanitizer_output,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_asan_overflow_extracts_type_stack_and_location() -> None:
    report = parse_execution_result({
        "test_id": "TEST-001", "version": "base", "build_type": "asan",
        "stderr": fixture("asan_heap_buffer_overflow.log"), "exit_code": 1,
    })
    assert report["summary"]["sanitizer_findings"] == 1
    finding = report["findings"][0]
    assert finding["detection_mechanism"] == "asan"
    assert finding["error_type"] == "heap-buffer-overflow"
    assert finding["location"] == {"file": "/project/src/parser.c", "line": 45, "column": 7}
    assert len(finding["stack_trace"]) == 2
    assert finding["stack_trace"][0] == {
        "index": 0, "address": "0x400abc", "function": "parse_input",
        "file": "/project/src/parser.c", "line": 45, "column": 7,
    }
    assert report["summary"]["unclassified_termination"] is False
    json.dumps(report)


def test_ubsan_signed_integer_overflow() -> None:
    result = parse_sanitizer_output(stderr=fixture("ubsan_signed_integer_overflow.log"))
    assert len(result) == 1
    finding = result[0]
    assert finding["detection_mechanism"] == "ubsan"
    assert finding["error_type"] == "signed-integer-overflow"
    assert finding["location"] == {"file": "/project/src/math.cpp", "line": 12, "column": 17}
    assert finding["stack_trace"][0]["function"] == "add_numbers"


def test_heap_use_after_free_classified() -> None:
    finding, = parse_sanitizer_output(stderr=fixture("asan_use_after_free.log"))
    assert finding["error_type"] == "heap-use-after-free"
    assert finding["location"]["line"] == 88


def test_clean_output_does_not_create_fake_finding() -> None:
    result = parse_execution_result({"stderr": fixture("clean_output.log"), "exit_code": 0})
    assert result["findings"] == []
    assert result["summary"]["has_sanitizer_finding"] is False
    assert result["summary"]["unclassified_termination"] is False


def test_nonzero_exit_without_diagnostic_is_not_vulnerability() -> None:
    report = parse_execution_result({"exit_code": 2, "stderr": "Unknown input"})
    assert report["findings"] == []
    assert report["summary"]["unclassified_termination"] is True


def test_signal_and_timeout_are_preserved_without_attributing_error() -> None:
    report = parse_execution_result({"signal": "SIGSEGV", "timeout": True, "stderr": ""})
    assert report["termination"] == {"exit_code": None, "signal": "SIGSEGV", "timeout": True}
    assert report["summary"]["unclassified_termination"] is True


def test_windows_paths_keep_drive_letter_and_line_numbers() -> None:
    log = (
        "C:\\workspace\\src\\math.cpp:14:5: runtime error: division by zero\n"
        "    #0 0x400abc in calculate C:\\workspace\\src\\math.cpp:14:5\n"
    )
    finding, = parse_sanitizer_output(stderr=log)
    assert finding["error_type"] == "division-by-zero"
    assert finding["location"]["file"] == r"C:\workspace\src\math.cpp"
    assert finding["stack_trace"][0]["function"] == "calculate"
    assert finding["stack_trace"][0]["line"] == 14


def test_unsymbolized_binary_frame_not_treated_as_source_location() -> None:
    log = "==12==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x40abcd (/app/program+0x5fa)\n"
    finding, = parse_sanitizer_output(stderr=log)
    frame, = finding["stack_trace"]
    assert frame["function"] is None
    assert frame["file"] is None
    assert frame["line"] is None
    assert finding["error_type"] == "segmentation-fault"


def test_multiple_ubsan_diagnostics_remain_separate() -> None:
    log = (
        "src/math.c:5:2: runtime error: signed integer overflow\n"
        "    #0 0x11 in f src/math.c:5:2\n"
        "src/math.c:20:9: runtime error: division by zero\n"
        "    #0 0x22 in g src/math.c:20:9\n"
    )
    findings = parse_sanitizer_output(stderr=log)
    assert [f["error_type"] for f in findings] == ["signed-integer-overflow", "division-by-zero"]
    assert [f["stack_trace"][0]["function"] for f in findings] == ["f", "g"]


def test_leak_sanitizer_report() -> None:
    log = "==55==ERROR: LeakSanitizer: detected memory leaks\n    #0 0x41 in allocate /src/memory.c:8:2\n"
    finding, = parse_sanitizer_output(stderr=log)
    assert finding["detection_mechanism"] == "lsan"
    assert finding["error_type"] == "memory-leak"
    assert finding["location"]["line"] == 8


def test_stdout_asan_report_is_supported() -> None:
    finding, = parse_sanitizer_output(stdout="SUMMARY: AddressSanitizer: stack-buffer-overflow /src/a.c:7:2 in main")
    assert finding["log_source"] == "stdout"
    assert finding["error_type"] == "stack-buffer-overflow"
    assert finding["location"]["file"] == "/src/a.c"
    assert finding["location"]["line"] == 7


def test_asan_deadlysignal_with_detailed_header_not_duplicated() -> None:
    log = (
        "AddressSanitizer:DEADLYSIGNAL\n"
        "==123==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
        "    #0 0x42 in main /src/app.c:22:4\n"
    )
    findings = parse_sanitizer_output(stderr=log)
    assert len(findings) == 1
    assert findings[0]["error_type"] == "segmentation-fault"
    assert findings[0]["location"]["line"] == 22


def test_asan_deadlysignal_alone_is_reported_without_guessing_root_cause() -> None:
    findings = parse_sanitizer_output(stderr="AddressSanitizer:DEADLYSIGNAL")
    assert len(findings) == 1
    assert findings[0]["error_type"] == "segmentation-fault"
    assert findings[0]["location"] is None


@pytest.mark.parametrize("message", ["input invalid", "division by zero"])
def test_bare_runtime_error_without_location_is_not_sanitizer_evidence(message: str) -> None:
    assert parse_sanitizer_output(stderr=f"runtime error: {message}") == []


def test_explicit_ubsan_summary_without_location() -> None:
    finding, = parse_sanitizer_output(stderr="SUMMARY: UndefinedBehaviorSanitizer: division by zero")
    assert finding["detection_mechanism"] == "ubsan"
    assert finding["location"] is None


def test_invalid_stderr_type_rejected() -> None:
    with pytest.raises(TypeError):
        parse_execution_result({"stderr": ["should", "not", "be", "a", "list"]})


def test_invalid_termination_fields_rejected() -> None:
    with pytest.raises(TypeError):
        parse_execution_result({"timeout": "false"})
    with pytest.raises(TypeError):
        parse_execution_result({"exit_code": True})


def test_ub_sanitizer_error_header() -> None:
    finding, = parse_sanitizer_output(stderr="==44==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address")
    assert finding["detection_mechanism"] == "ubsan"
    assert finding["error_type"] == "segmentation-fault"


def test_context_does_not_require_file_in_frame() -> None:
    log = "==13==ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0xaaa in foo (/app/target+0x111)\n"
    finding, = parse_sanitizer_output(stderr=log)
    assert finding["stack_trace"][0]["function"] == "foo"
    assert finding["stack_trace"][0]["file"] is None


def test_cli_parse_trace(tmp_path: Path) -> None:
    import subprocess
    import sys

    source = Path(__file__).resolve().parents[2] / "examples" / "asan-execution-result.json"
    target = tmp_path / "result.json"
    result = subprocess.run(
        [sys.executable, "-m", "security_patch_validator.cli", "parse-trace",
         "--input", str(source), "--output", str(target), "--pretty"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["summary"]["sanitizer_findings"] == 1
    assert report["findings"][0]["error_type"] == "heap-buffer-overflow"


def test_empty_list_is_not_valid_stderr() -> None:
    with pytest.raises(TypeError):
        parse_execution_result({"stderr": []})


def test_summary_only_location_and_filename_without_directories() -> None:
    finding, = parse_sanitizer_output(stderr="SUMMARY: AddressSanitizer: heap-buffer-overflow parser.c:7:4 in parse")
    assert finding["location"] == {"file": "parser.c", "line": 7, "column": 4}


def test_invalid_json_input_cli(tmp_path: Path) -> None:
    import subprocess
    import sys

    invalid = tmp_path / "broken.json"
    invalid.write_text("{not-json}", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "security_patch_validator.cli", "parse-trace",
         "--input", str(invalid)], capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "error" in result.stderr.lower()


def test_related_allocation_and_free_stacks_are_not_primary_frames() -> None:
    log = (
        "==11==ERROR: AddressSanitizer: heap-use-after-free on address 0x60\n"
        "    #0 0x11 in unsafe_read /project/read.c:20:1\n"
        "freed by thread T0 here:\n"
        "    #0 0x22 in free /project/lib.c:5:2\n"
        "previously allocated by thread T0 here:\n"
        "    #0 0x33 in allocate /project/alloc.c:9:3\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free /project/read.c:20:1 in unsafe_read\n"
    )
    finding, = parse_sanitizer_output(stderr=log)
    assert [f["function"] for f in finding["stack_trace"]] == ["unsafe_read"]
    assert [f["function"] for f in finding["related_stacks"]["free"]] == ["free"]
    assert [f["function"] for f in finding["related_stacks"]["allocation"]] == ["allocate"]
    assert finding["location"]["file"] == "/project/read.c"
