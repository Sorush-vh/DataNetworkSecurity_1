import hashlib
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


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

    saved_input = output / input_file.name
    shutil.copy2(input_file, saved_input)

    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "commit_hash": commit_hash,
        "binary_path": str(binary),
        "binary_sha256": calculate_sha256(binary),
        "input_file": saved_input.name,
        "input_sha256": calculate_sha256(saved_input),
        "command": command,
        "build_settings": build_settings,
        "environment": environment,
        "replay_results": replay_results
    }

    metadata_path = output / "metadata.json"

    with open(metadata_path, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4, ensure_ascii=False)

    return metadata_path
