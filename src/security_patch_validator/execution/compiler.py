"""Enforce and audit sanitizer flags for declared C/C++ translation units.

This is a cooperative build check, not a sandbox for hostile build recipes.
The compiler entry points run as standalone scripts using only the stdlib.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path


SOURCE_SUFFIXES = {".c", ".C", ".cc", ".cp", ".cpp", ".cxx", ".c++", ".i", ".ii"}


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def compiler_main(settings_path: str, name: str) -> int:
    settings = json.loads(Path(settings_path).read_text())
    original = sys.argv[1:]
    # An opaque response file can hide flag overrides and source operands.
    # Reject it rather than claim coverage without having audited its contents.
    if any(arg.startswith("@") for arg in original):
        print("spv: compiler response files are not supported by the sanitizer audit; "
              "expand the arguments in the build recipe", file=sys.stderr)
        return 2
    if any(arg.startswith(("-fno-sanitize=", "-fsanitize-trap", "-fsanitize-ignorelist",
                           "-fsanitize-blacklist")) or arg == "-fsanitize-undefined-trap-on-error"
           for arg in original):
        print("spv: sanitizer disabling/trapping options are not allowed in an audited build",
              file=sys.stderr)
        return 2
    arguments = list(original)
    insertion = arguments.index("--") if "--" in arguments else len(arguments)
    arguments[insertion:insertion] = settings["flags"]
    sources = []
    if not set(original).intersection({"-E", "-M", "-MM", "-fsyntax-only"}):
        for arg in original:
            path = Path(arg)
            if not arg.startswith("-") and path.suffix in SOURCE_SUFFIXES and path.is_file():
                sources.append({"path": str(path.resolve()), "sha256": _digest(path)})
    command = [settings["compilers"][name], *arguments]
    result = subprocess.run(command)
    record = {"compiler": command[0], "argv": command, "cwd": os.getcwd(),
              "enforced_flags": settings["flags"], "sources": sources, "returncode": result.returncode}
    destination = Path(settings["records"]) / f"{uuid.uuid4().hex}.json"
    destination.write_text(json.dumps(record), encoding="utf-8")
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def prepare_compiler_audit(directory: Path, env: dict[str, str], flags: tuple[str, ...]) -> dict[str, str]:
    directory.mkdir()
    wrappers = directory / "bin"
    records = directory / "records"
    wrappers.mkdir()
    records.mkdir()
    compilers = {}
    for name in ("gcc", "g++", "cc", "c++", "clang", "clang++"):
        compiler = shutil.which(name, path=env["PATH"])
        if compiler:
            compilers[name] = str(Path(compiler).absolute())
    settings = directory / "settings.json"
    settings.write_text(json.dumps({"compilers": compilers, "flags": list(flags),
                                    "records": str(records)}), encoding="utf-8")
    mapping = {}
    for name, compiler in compilers.items():
        wrapper = wrappers / name
        wrapper.write_text(
            f"#!{sys.executable}\nimport runpy\n"
            f"entry = runpy.run_path({str(Path(__file__).resolve())!r})\n"
            f"raise SystemExit(entry['compiler_main']({str(settings)!r}, {name!r}))\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        mapping[compiler] = str(wrapper)
        mapping[str(Path(compiler).resolve())] = str(wrapper)
    env["PATH"] = str(wrappers) + os.pathsep + env["PATH"]
    if "gcc" in compilers:
        env["CC"] = str(wrappers / "gcc")
    if "g++" in compilers:
        env["CXX"] = str(wrappers / "g++")
    # Cached outputs must not replace an observed compilation in this build.
    env["CCACHE_DISABLE"] = "1"
    env["SCCACHE_DISABLE"] = "1"
    return mapping


def verify_compiler_audit(directory: Path, source: Path,
                          translation_units: tuple[str, ...] | None) -> dict:
    if translation_units is None:
        expected = sorted({path.resolve() for path in source.rglob("*")
                           if path.is_file() and path.suffix in SOURCE_SUFFIXES})
        scope = "discovered_source_files"
    else:
        expected = sorted({(source / name).resolve() for name in translation_units})
        scope = "declared_translation_units"
    records = [json.loads(path.read_text()) for path in sorted((directory / "records").glob("*.json"))]
    observed = {(item["path"], item["sha256"])
                for record in records if record["returncode"] == 0 for item in record["sources"]}
    units = []
    for path in expected:
        valid = path.is_relative_to(source) and path.is_file()
        fingerprint = _digest(path) if valid else None
        verified = valid and (str(path), fingerprint) in observed
        units.append({"source": str(path.relative_to(source)) if path.is_relative_to(source) else str(path),
                      "sha256": fingerprint, "verified": verified})
    return {"status": "verified" if units and all(unit["verified"] for unit in units) else "unverified",
            "scope": scope, "translation_units": units, "invocations": records,
            "limitations": ["Verifies observed compilation flags for the listed translation units; "
                            "does not prove instrumentation of every instruction, source-level "
                            "no_sanitize annotations, system libraries, or hostile build recipes."]}
