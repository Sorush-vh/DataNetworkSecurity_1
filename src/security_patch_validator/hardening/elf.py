"""Inspect ELF hardening protections with established binutils tools.

The module deliberately parses the output of ``readelf`` and ``objdump``
instead of inferring protections from compiler flags.  A compiler flag can be
ignored by a build system, and a linked binary is the only authoritative
artifact for the final application.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import Any


class HardeningError(RuntimeError):
    """Raised when the ELF binary cannot be inspected."""


_TOOL_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
}

_RELRO_SEGMENT = re.compile(r"^\s*GNU_RELRO\s+", re.MULTILINE)
_STACK_SEGMENT = re.compile(r"^\s*GNU_STACK\s+(?P<rest>.+)$", re.MULTILINE)
_INTERP_SEGMENT = re.compile(r"^\s*INTERP\s+", re.MULTILINE)
_LOAD_SEGMENT = re.compile(r"^\s*LOAD\s+(?P<rest>.+)$", re.MULTILINE)
_DYNAMIC_FLAGS = re.compile(r"\(FLAGS\)\s+(?P<flags>.+)$", re.MULTILINE)
_DYNAMIC_FLAGS_1 = re.compile(r"\(FLAGS_1\)\s+Flags:\s*(?P<flags>.+)$", re.MULTILINE)
_HEADER_TYPE = re.compile(r"^\s*Type:\s+(?P<type>.+)$", re.MULTILINE)
_HEADER_MACHINE = re.compile(r"^\s*Machine:\s+(?P<machine>.+)$", re.MULTILINE)
_HEADER_CLASS = re.compile(r"^\s*Class:\s+(?P<value>.+)$", re.MULTILINE)
_HEADER_DATA = re.compile(r"^\s*Data:\s+(?P<value>.+)$", re.MULTILINE)
_CANARY_SYMBOL = re.compile(
    r"^\s*\d+:\s+.*?"
    r"(?P<name>__stack_chk_fail(?:@\S+)?|__stack_chk_guard(?:@\S+)?|__stack_chk_fail_local(?:@\S+)?)"
    r"(?:\s|$)",
    re.MULTILINE,
)
_CANARY_INSTRUCTION = re.compile(r"%fs:0x28|%gs:0x14")


def _run_tool(argv: list[str], *, timeout: float = 30.0) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_TOOL_ENV,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise HardeningError(
            f"Required ELF inspection tool is not available: {argv[0]}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HardeningError(f"ELF inspection timed out: {' '.join(argv)}") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise HardeningError(f"{argv[0]} failed ({result.returncode}): {message}")
    return result.stdout


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _program_header_flags(rest: str) -> str:
    """Return the flags column from a wide ``readelf -l`` entry.

    A wide entry is ``Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align``.
    The flags column is the second-to-last token.
    """
    tokens = rest.split()
    if len(tokens) < 2:
        return ""
    return tokens[-2]


def _parse_header(output: str) -> dict[str, Any]:
    type_match = _HEADER_TYPE.search(output)
    machine_match = _HEADER_MACHINE.search(output)
    class_match = _HEADER_CLASS.search(output)
    data_match = _HEADER_DATA.search(output)
    return {
        "class": class_match.group("value").strip() if class_match else None,
        "data": data_match.group("value").strip() if data_match else None,
        "type": type_match.group("type").strip() if type_match else None,
        "machine": machine_match.group("machine").strip() if machine_match else None,
    }


def _parse_program_headers(output: str) -> dict[str, Any]:
    stack_match = _STACK_SEGMENT.search(output)
    stack_flags = _program_header_flags(stack_match.group("rest")) if stack_match else None
    return {
        "has_gnu_relro": bool(_RELRO_SEGMENT.search(output)),
        "has_interp": bool(_INTERP_SEGMENT.search(output)),
        "gnu_stack_flags": stack_flags,
        "load_segments": len(_LOAD_SEGMENT.findall(output)),
    }


def _parse_dynamic(output: str) -> dict[str, Any]:
    flags = _DYNAMIC_FLAGS.search(output)
    flags_1 = _DYNAMIC_FLAGS_1.search(output)
    flag_tokens = set()
    if flags:
        flag_tokens.update(flags.group("flags").split())
    if flags_1:
        flag_tokens.update(flags_1.group("flags").split())
    return {
        "bind_now": "BIND_NOW" in flag_tokens or "NOW" in flag_tokens,
        "pie_flag": "PIE" in flag_tokens,
        "flags": sorted(flag_tokens),
    }


def _parse_symbols(output: str) -> dict[str, Any]:
    names = sorted({match.group("name").split("@", 1)[0] for match in _CANARY_SYMBOL.finditer(output)})
    return {
        "stack_canary_symbols": names,
        "has_stack_canary_symbol": bool(names),
    }


def _parse_canary_instructions(output: str) -> dict[str, Any]:
    matches = _CANARY_INSTRUCTION.findall(output)
    return {
        "canary_instruction_count": len(matches),
        "has_canary_instruction": bool(matches),
    }


def _relro_status(program: dict[str, Any], dynamic: dict[str, Any]) -> dict[str, Any]:
    if not program["has_gnu_relro"]:
        status = "none"
        reason = "No GNU_RELRO program header was found."
    elif dynamic["bind_now"]:
        status = "full"
        reason = "GNU_RELRO is present and the dynamic section requests immediate binding (BIND_NOW/NOW)."
    else:
        status = "partial"
        reason = "GNU_RELRO is present but immediate binding is not requested."
    return {
        "status": status,
        "reason": reason,
        "evidence": {
            "gnu_relro_segment": program["has_gnu_relro"],
            "bind_now": dynamic["bind_now"],
            "dynamic_flags": dynamic["flags"],
        },
    }


def _pie_status(header: dict[str, Any], program: dict[str, Any], dynamic: dict[str, Any]) -> dict[str, Any]:
    elf_type = (header.get("type") or "").upper()
    if "DYN" in elf_type and program["has_interp"]:
        status = "enabled"
        reason = "The ELF is ET_DYN and contains an interpreter, which is the PIE executable layout."
    elif "DYN" in elf_type and dynamic["pie_flag"]:
        status = "enabled"
        reason = "The ELF is ET_DYN and the dynamic section carries the PIE flag."
    elif "EXEC" in elf_type:
        status = "disabled"
        reason = "The ELF is ET_EXEC, a fixed-address executable."
    elif "DYN" in elf_type:
        status = "shared-object"
        reason = "The ELF is ET_DYN without an interpreter; it is a shared object, not a PIE executable."
    else:
        status = "unknown"
        reason = "The ELF type could not be classified."
    return {
        "status": status,
        "reason": reason,
        "evidence": {
            "elf_type": header.get("type"),
            "has_interp": program["has_interp"],
            "pie_dynamic_flag": dynamic["pie_flag"],
        },
    }


def _nx_status(program: dict[str, Any]) -> dict[str, Any]:
    flags = program["gnu_stack_flags"]
    if flags is None:
        return {
            "status": "unknown",
            "reason": "No GNU_STACK program header was found; the runtime stack permissions are not declared by the binary.",
            "evidence": {"gnu_stack_flags": None},
        }
    executable = "E" in flags
    return {
        "status": "disabled" if executable else "enabled",
        "reason": (
            "The GNU_STACK segment is marked executable (RWE)."
            if executable
            else "The GNU_STACK segment is not marked executable."
        ),
        "evidence": {"gnu_stack_flags": flags},
    }


def _canary_status(symbols: dict[str, Any], instructions: dict[str, Any]) -> dict[str, Any]:
    if symbols["has_stack_canary_symbol"]:
        status = "present"
        reason = "The binary references the stack-protector runtime symbol."
    elif instructions["has_canary_instruction"]:
        status = "present"
        reason = "The disassembly contains a stack-canary load, but no runtime symbol was found."
    else:
        status = "absent"
        reason = "No stack-protector symbol or canary instruction was found."
    return {
        "status": status,
        "reason": reason,
        "evidence": {
            "symbols": symbols["stack_canary_symbols"],
            "canary_instruction_count": instructions["canary_instruction_count"],
        },
    }


def inspect_binary(binary: str | Path, *, deep: bool = True) -> dict[str, Any]:
    """Inspect one ELF executable and return structured hardening evidence.

    ``deep`` additionally disassembles the binary to look for the x86 stack
    canary load.  Symbol evidence alone is reported as present but is not a
    proof that every function is protected.
    """
    path = Path(binary).expanduser().resolve()
    if not path.is_file():
        raise HardeningError(f"Binary does not exist: {path}")
    if not os.access(path, os.X_OK):
        raise HardeningError(f"Binary is not executable: {path}")

    header_output = _run_tool(["readelf", "-hW", str(path)])
    program_output = _run_tool(["readelf", "-lW", str(path)])
    dynamic_output = _run_tool(["readelf", "-dW", str(path)])
    symbol_output = _run_tool(["readelf", "-sW", str(path)])

    header = _parse_header(header_output)
    program = _parse_program_headers(program_output)
    dynamic = _parse_dynamic(dynamic_output)
    symbols = _parse_symbols(symbol_output)

    instructions = {"canary_instruction_count": 0, "has_canary_instruction": False}
    commands = [
        ["readelf", "-hW", str(path)],
        ["readelf", "-lW", str(path)],
        ["readelf", "-dW", str(path)],
        ["readelf", "-sW", str(path)],
    ]
    if deep:
        disassembly = _run_tool(["objdump", "-d", "--no-show-raw-insn", str(path)], timeout=60.0)
        instructions = _parse_canary_instructions(disassembly)
        commands.append(["objdump", "-d", "--no-show-raw-insn", str(path)])

    protections = {
        "relro": _relro_status(program, dynamic),
        "pie": _pie_status(header, program, dynamic),
        "nx": _nx_status(program),
        "stack_canary": _canary_status(symbols, instructions),
    }

    return {
        "schema_version": "1.0",
        "analysis_type": "elf_hardening",
        "binary": str(path),
        "binary_sha256": _sha256(path),
        "elf": header,
        "protections": protections,
        "evidence": {
            "commands": commands,
            "program_headers": program,
            "dynamic": dynamic,
            "symbols": symbols,
            "disassembly": instructions,
        },
        "limitations": [
            "PIE does not prove that ASLR is enabled in the runtime environment.",
            "A stack-canary symbol or instruction does not prove that every function is protected.",
            "RELRO classification is based on the GNU_RELRO segment and immediate-binding flags.",
            "The inspection describes the binary, not the compiler flags that produced it.",
        ],
    }


def _rank(protection: str, status: str) -> int:
    order = {
        "relro": {"none": 0, "partial": 1, "full": 2},
        "pie": {"disabled": 0, "shared-object": 0, "unknown": 0, "enabled": 2},
        "nx": {"disabled": 0, "unknown": 0, "enabled": 2},
        "stack_canary": {"absent": 0, "present": 2},
    }
    return order.get(protection, {}).get(status, 0)


def compare_hardening(base: dict[str, Any], patched: dict[str, Any]) -> dict[str, Any]:
    """Compare two hardening reports and flag protection regressions."""
    changes = []
    warnings = []
    for protection in ("relro", "pie", "nx", "stack_canary"):
        before = base["protections"][protection]["status"]
        after = patched["protections"][protection]["status"]
        if before == after:
            continue
        change = {
            "protection": protection,
            "base": before,
            "patched": after,
            "direction": "regressed" if _rank(protection, after) < _rank(protection, before) else "improved",
        }
        changes.append(change)
        if change["direction"] == "regressed":
            warnings.append(
                f"{protection} protection regressed from {before!r} to {after!r} between the base and patched binaries."
            )
    return {
        "schema_version": "1.0",
        "analysis_type": "elf_hardening_comparison",
        "base_binary_sha256": base["binary_sha256"],
        "patched_binary_sha256": patched["binary_sha256"],
        "changes": changes,
        "warnings": warnings,
        "unexpected_changes": [change for change in changes if change["direction"] == "regressed"],
    }


def check_requirements(report: dict[str, Any], required: dict[str, str]) -> dict[str, Any]:
    """Check a hardening report against a target's declared requirements."""
    results = []
    for protection, expected in required.items():
        if protection not in report["protections"]:
            results.append({
                "protection": protection,
                "expected": expected,
                "observed": None,
                "compliant": False,
                "reason": "Unknown protection name.",
            })
            continue
        observed = report["protections"][protection]["status"]
        results.append({
            "protection": protection,
            "expected": expected,
            "observed": observed,
            "compliant": observed == expected,
            "reason": report["protections"][protection]["reason"],
        })
    return {
        "compliant": all(item["compliant"] for item in results),
        "results": results,
    }
