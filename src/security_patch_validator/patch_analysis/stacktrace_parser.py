"""Parse ASan, UBSan and LSan diagnostics into structured runtime evidence.

This module deliberately does not classify patch outcomes or infer exploitability.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


_SANITIZER_HEADER = re.compile(
    r"^(?:==\d+==)?\s*ERROR:\s*"
    r"(?P<sanitizer>AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer):\s*"
    r"(?P<message>.+)$"
)
_SUMMARY = re.compile(
    r"^SUMMARY:\s*(?P<sanitizer>AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer):\s*(?P<message>.+)$"
)
_DEADLY_SIGNAL = re.compile(r"^(?:==\d+==)?\s*AddressSanitizer:DEADLYSIGNAL\s*$")
_UBSAN_LOCATION = re.compile(
    r"^(?:(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?:\s*)?runtime error:\s*(?P<message>.+)$"
)
_FRAME = re.compile(r"^\s*#(?P<index>\d+)\s+(?P<address>0x[0-9a-fA-F]+)(?:\s+in\s+(?P<function_and_location>.+)|\s+(?P<other>.+))?$", re.ASCII)
# Only accept source-looking filenames at the end of a symbolized frame. Binary
# modules and +0x offsets must not be mistaken for source locations.
_SOURCE_LOCATION = re.compile(
    r"(?P<file>(?:[A-Za-z]:[/\\]|/|\.\.?[/\\]|[A-Za-z0-9_.-]+[/\\])[^:\r\n]*?"
    r"|[A-Za-z0-9_.-]+\.(?:c|cc|cpp|cxx|h|hpp|hh))"
    r":(?P<line>\d+)(?::(?P<column>\d+))?$"
)


def _error_type(message: str, mechanism: str) -> str:
    lower = message.lower()
    for token in (
        "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
        "heap-use-after-free", "stack-use-after-return", "stack-use-after-scope",
        "use-after-free", "double-free", "alloc-dealloc-mismatch", "stack-overflow",
        "container-overflow", "initialization-order-fiasco",
    ):
        if token in lower:
            return token
    if "signed integer overflow" in lower:
        return "signed-integer-overflow"
    if "unsigned integer overflow" in lower:
        return "unsigned-integer-overflow"
    if "division by zero" in lower or "divide by zero" in lower:
        return "division-by-zero"
    if "null pointer" in lower:
        return "null-pointer-access"
    if "out of bounds" in lower:
        return "out-of-bounds"
    if "misaligned" in lower or "alignment" in lower:
        return "misaligned-access"
    if "shift exponent" in lower or "shift base" in lower:
        return "invalid-shift"
    if "memory leak" in lower or "detected memory leaks" in lower:
        return "memory-leak"
    if re.search(r"\bsegv\b|deadlysignal", lower):
        return "segmentation-fault"
    return "undefined-behavior" if mechanism == "ubsan" else "unclassified-sanitizer-error"


def _source_location(text: str) -> tuple[dict[str, Any] | None, str]:
    match = _SOURCE_LOCATION.search(text)
    if not match:
        return None, text.strip()
    location = {
        "file": match.group("file"),
        "line": int(match.group("line")),
        "column": int(match.group("column")) if match.group("column") is not None else None,
    }
    return location, text[:match.start()].strip()


def _parse_frame(line: str) -> dict[str, Any] | None:
    match = _FRAME.match(line)
    if not match:
        return None

    text = (match.group("function_and_location") or match.group("other") or "").strip()
    location, symbol = _source_location(text)
    # An unsymbolized binary offset is not a filename or a stack function.
    symbol = re.sub(
        r"\s*\([^()]*\+0x[0-9a-fA-F]+\)(?:\s+\(BuildId:[^)]*\))?\s*$",
        "", symbol,
    ).strip()
    if symbol.startswith("("):
        symbol = ""
    return {
        "index": int(match.group("index")),
        "address": match.group("address"),
        "function": symbol or None,
        "file": location["file"] if location else None,
        "line": location["line"] if location else None,
        "column": location["column"] if location else None,
    }


def _new_finding(mechanism: str, message: str, source: str, evidence: str,
                 location: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "detection_mechanism": mechanism,
        "error_type": _error_type(message, mechanism),
        "message": message.strip(),
        "log_source": source,
        "location": location,
        "stack_trace": [],
        "related_stacks": {},
        "evidence_lines": [evidence],
    }


def parse_sanitizer_output(stderr: str = "", stdout: str = "") -> list[dict[str, Any]]:
    """Extract explicit sanitizer diagnostics and their symbolized stack frames.

    It deliberately ignores an isolated nonzero exit code and arbitrary frames
    without a diagnostic header. Each finding is observational evidence only.
    """
    if not isinstance(stderr, str) or not isinstance(stdout, str):
        raise TypeError("stdout and stderr must be strings")

    findings: list[dict[str, Any]] = []
    sanitizer_names = {
        "AddressSanitizer": "asan",
        "UndefinedBehaviorSanitizer": "ubsan",
        "LeakSanitizer": "lsan",
    }

    for source, log in (("stderr", stderr), ("stdout", stdout)):
        current: dict[str, Any] | None = None
        frame_group = "stack_trace"
        lines = log.splitlines()
        for position, original in enumerate(lines):
            line = original.strip()
            if not line:
                continue

            header = _SANITIZER_HEADER.match(line)
            if header:
                mechanism = sanitizer_names[header.group("sanitizer")]
                message = header.group("message")
                # Standalone ASan DEADLYSIGNAL sometimes precedes a detailed
                # ERROR report; don't return two findings for that one event.
                if current and current["message"] == "DEADLYSIGNAL" and current["detection_mechanism"] == mechanism:
                    current.update({"message": message, "error_type": _error_type(message, mechanism)})
                    current["evidence_lines"].append(original)
                else:
                    current = _new_finding(mechanism, message, source, original)
                    findings.append(current)
                frame_group = "stack_trace"
                continue

            ubsan = _UBSAN_LOCATION.match(line)
            if ubsan:
                file = ubsan.group("file")
                location = None
                if file:
                    location = {
                        "file": file,
                        "line": int(ubsan.group("line")),
                        "column": int(ubsan.group("column")) if ubsan.group("column") is not None else None,
                    }
                current = _new_finding("ubsan", ubsan.group("message"), source, original, location)
                findings.append(current)
                frame_group = "stack_trace"
                continue

            if _DEADLY_SIGNAL.match(line):
                if current and current["detection_mechanism"] == "asan":
                    continue
                # A more specific error header may be present immediately below.
                if any(_SANITIZER_HEADER.match(candidate.strip()) for candidate in lines[position + 1:position + 5]):
                    continue
                current = _new_finding("asan", "DEADLYSIGNAL", source, original)
                findings.append(current)
                frame_group = "stack_trace"
                continue

            summary = _SUMMARY.match(line)
            if summary:
                mechanism = sanitizer_names[summary.group("sanitizer")]
                if current and current["detection_mechanism"] == mechanism:
                    current["evidence_lines"].append(original)
                    if current["location"] is None:
                        location, _ = _source_location(summary.group("message").split(" in ", 1)[0])
                        if location:
                            current["location"] = location
                else:
                    current = _new_finding(mechanism, summary.group("message"), source, original)
                    current["location"], _ = _source_location(summary.group("message").split(" in ", 1)[0])
                    findings.append(current)
                current = None
                continue

            if current is not None:
                if line.startswith("freed by thread "):
                    frame_group = "free"
                    continue
                if line.startswith(("previously allocated by thread ", "allocated by thread ")):
                    frame_group = "allocation"
                    continue
                if re.match(r"Thread T\d+ created by", line):
                    frame_group = "thread_creation"
                    continue

            frame = _parse_frame(original)
            if frame is not None and current is not None:
                if frame_group == "stack_trace":
                    current["stack_trace"].append(frame)
                    if current["location"] is None and frame["file"] is not None:
                        current["location"] = {
                            "file": frame["file"], "line": frame["line"], "column": frame["column"]
                        }
                else:
                    current["related_stacks"].setdefault(frame_group, []).append(frame)
                continue

            if line.startswith("==") and line.endswith("==ABORTING"):
                current = None

    return findings


def parse_execution_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a runner's result and collect sanitizer evidence.

    Required runner fields are intentionally minimal; upstream contract can
    add metadata without breaking this module. Exit status is preserved, not
    used to assert that an exploitable vulnerability exists.
    """
    if not isinstance(result, Mapping):
        raise TypeError("execution result must be a JSON-like mapping")

    stderr = result.get("stderr")
    stdout = result.get("stdout")
    if stderr is None:
        stderr = ""
    if stdout is None:
        stdout = ""
    findings = parse_sanitizer_output(stderr=stderr, stdout=stdout)
    timeout = result.get("timeout", False)
    exit_code = result.get("exit_code")
    signal = result.get("signal")

    if not isinstance(timeout, bool):
        raise TypeError("timeout must be a boolean")
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        raise TypeError("exit_code must be an integer or null")
    if signal is not None and not isinstance(signal, (str, int)):
        raise TypeError("signal must be a string, integer, or null")

    return {
        "schema_version": "1.0",
        "analysis_type": "runtime_trace_analysis",
        "test_id": result.get("test_id"),
        "version": result.get("version"),
        "build_type": result.get("build_type"),
        "commit_hash": result.get("commit_hash") or result.get("commit"),
        "termination": {"exit_code": exit_code, "signal": signal, "timeout": timeout},
        "summary": {
            "sanitizer_findings": len(findings),
            "has_sanitizer_finding": bool(findings),
            "unclassified_termination": not findings and (timeout or signal is not None or exit_code not in (0, None)),
        },
        "findings": findings,
        "limitations": [
            "An observed sanitizer diagnostic is not proof of exploitability or patch causality.",
            "A nonzero exit code, signal, or timeout alone does not identify a vulnerability type.",
            "The first symbolized stack frame is not necessarily the root cause or modified patch location.",
        ],
    }
