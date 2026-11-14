"""Unit tests for ELF hardening parsing and comparison."""

from __future__ import annotations

import unittest
from unittest import mock

from security_patch_validator.hardening import elf
from security_patch_validator.hardening.elf import (
    HardeningError,
    check_requirements,
    compare_hardening,
    inspect_binary,
)


PROGRAM_HEADERS = """\
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1060
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0002d8 0x0002d8 R   0x8
  INTERP         0x000318 0x0000000000000318 0x0000000000000318 0x00001c 0x00001c R   0x1
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0006b0 0x0006b0 R   0x1000
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x002dd0 0x0000000000002dd0 0x0000000000002dd0 0x000230 0x000230 R   0x1
"""

DYNAMIC_FULL = """\
Dynamic section at offset 0x2dc8 contains 27 entries:
  0x000000000000001e (FLAGS)              BIND_NOW
  0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
"""

DYNAMIC_PARTIAL = """\
Dynamic section at offset 0x2dc8 contains 27 entries:
  0x000000006ffffffb (FLAGS_1)            Flags: PIE
"""

SYMBOLS = """\
Symbol table '.dynsym' contains 7 entries:
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (2)
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
"""

SYMBOLS_EMPTY = """\
Symbol table '.dynsym' contains 7 entries:
     1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
"""


def _report(relro: str, pie: str, nx: str, canary: str) -> dict:
    return {
        "binary_sha256": f"sha-{relro}-{pie}-{nx}-{canary}",
        "protections": {
            "relro": {"status": relro, "reason": "", "evidence": {}},
            "pie": {"status": pie, "reason": "", "evidence": {}},
            "nx": {"status": nx, "reason": "", "evidence": {}},
            "stack_canary": {"status": canary, "reason": "", "evidence": {}},
        },
    }


class ParsingTests(unittest.TestCase):
    def test_program_headers_detect_relro_interp_and_stack(self):
        parsed = elf._parse_program_headers(PROGRAM_HEADERS)
        self.assertTrue(parsed["has_gnu_relro"])
        self.assertTrue(parsed["has_interp"])
        self.assertEqual(parsed["gnu_stack_flags"], "RW")

    def test_relro_full(self):
        program = elf._parse_program_headers(PROGRAM_HEADERS)
        dynamic = elf._parse_dynamic(DYNAMIC_FULL)
        self.assertEqual(elf._relro_status(program, dynamic)["status"], "full")

    def test_relro_partial(self):
        program = elf._parse_program_headers(PROGRAM_HEADERS)
        dynamic = elf._parse_dynamic(DYNAMIC_PARTIAL)
        self.assertEqual(elf._relro_status(program, dynamic)["status"], "partial")

    def test_relro_none(self):
        program = elf._parse_program_headers(PROGRAM_HEADERS.replace("GNU_RELRO", "NOTE     "))
        dynamic = elf._parse_dynamic(DYNAMIC_FULL)
        self.assertEqual(elf._relro_status(program, dynamic)["status"], "none")

    def test_pie_enabled_from_dyn_and_interp(self):
        header = {"type": "DYN (Position-Independent Executable file)"}
        program = elf._parse_program_headers(PROGRAM_HEADERS)
        dynamic = elf._parse_dynamic(DYNAMIC_PARTIAL)
        self.assertEqual(elf._pie_status(header, program, dynamic)["status"], "enabled")

    def test_pie_disabled_for_exec(self):
        header = {"type": "EXEC (Executable file)"}
        program = elf._parse_program_headers(PROGRAM_HEADERS)
        dynamic = elf._parse_dynamic(DYNAMIC_PARTIAL)
        self.assertEqual(elf._pie_status(header, program, dynamic)["status"], "disabled")

    def test_nx_enabled_and_disabled(self):
        enabled = elf._parse_program_headers(PROGRAM_HEADERS)
        self.assertEqual(elf._nx_status(enabled)["status"], "enabled")
        disabled = elf._parse_program_headers(PROGRAM_HEADERS.replace(" RW  0x10", " RWE 0x10"))
        self.assertEqual(elf._nx_status(disabled)["status"], "disabled")

    def test_canary_symbol(self):
        symbols = elf._parse_symbols(SYMBOLS)
        instructions = {"canary_instruction_count": 0, "has_canary_instruction": False}
        self.assertEqual(elf._canary_status(symbols, instructions)["status"], "present")

    def test_canary_absent(self):
        symbols = elf._parse_symbols(SYMBOLS_EMPTY)
        instructions = {"canary_instruction_count": 0, "has_canary_instruction": False}
        self.assertEqual(elf._canary_status(symbols, instructions)["status"], "absent")


class ComparisonTests(unittest.TestCase):
    def test_regression_is_warned(self):
        base = _report("full", "enabled", "enabled", "present")
        patched = _report("full", "disabled", "enabled", "present")
        comparison = compare_hardening(base, patched)
        self.assertEqual(len(comparison["unexpected_changes"]), 1)
        self.assertEqual(comparison["unexpected_changes"][0]["protection"], "pie")
        self.assertTrue(comparison["warnings"])

    def test_requirement_check(self):
        report = _report("full", "enabled", "enabled", "present")
        result = check_requirements(
            report,
            {"relro": "full", "pie": "enabled", "nx": "enabled", "stack_canary": "present"},
        )
        self.assertTrue(result["compliant"])
        failed = check_requirements(report, {"pie": "disabled"})
        self.assertFalse(failed["compliant"])


class ToolFailureTests(unittest.TestCase):
    def test_missing_tool_is_reported(self):
        with mock.patch.object(elf.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(HardeningError):
                inspect_binary("/bin/true")


if __name__ == "__main__":
    unittest.main()
