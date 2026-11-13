
import hashlib
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from datetime import datetime, timezone


SENSITIVE_KEYWORDS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key"
)


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def _capture_environment(overrides):
    effective = os.environ.copy()

    if overrides:
        effective.update(overrides)

    recorded = {}

    for key, value in sorted(effective.items()):
        if any(
            keyword in key.lower()
            for keyword in SENSITIVE_KEYWORDS
        ):
            recorded[key] = "<REDACTED>"
        else:
            recorded[key] = value

    return recorded


def create_bundle(
    binary_path,
    input_path,
    command,
    commit_hash,
    build_settings,
    environment,
    output_dir,
    replay_results=None
):
    binary = Path(binary_path).resolve()
    input_file = Path(input_path).resolve()
    output = Path(output_dir).resolve()

    if not binary.is_file():
        raise FileNotFoundError(f"Binary not found: {binary}")

    if not input_file.is_file():
        raise FileNotFoundError(f"Input not found: {input_file}")

    output.mkdir(parents=True, exist_ok=True)

    # Save the original input.
    saved_input = output / input_file.name

    if input_file != saved_input.resolve():
        shutil.copy2(input_file, saved_input)

    # Save a copy of the executable binary.
    binary_dir = output / "binary"
    binary_dir.mkdir(parents=True, exist_ok=True)

    saved_binary = binary_dir / binary.name

    if binary != saved_binary.resolve():
        shutil.copy2(binary, saved_binary)

    effective_environment = _capture_environment(environment)

    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "commit_hash": commit_hash,

        "binary_path": str(binary),
        "binary_file": str(saved_binary.relative_to(output)),
        "binary_sha256": calculate_sha256(saved_binary),

        "input_file": saved_input.name,
        "input_sha256": calculate_sha256(saved_input),

        "command": command,
        "working_directory": os.getcwd(),

        "build_settings": build_settings,
        "environment": effective_environment,

        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python_version": sys.version,

        "replay_results": replay_results
    }

    metadata_path = output / "metadata.json"

    with open(metadata_path, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4, ensure_ascii=False)

    return metadata_path
