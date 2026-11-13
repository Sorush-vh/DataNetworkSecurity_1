
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


def generate_regression_test(
    minimized_input,
    test_name,
    error_type,
    output_dir
):
    source = Path(minimized_input).resolve()

    if not source.is_file():
        raise FileNotFoundError(f"Input not found: {source}")

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", test_name)

    if not safe_name:
        raise ValueError("Test name cannot be empty")

    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    test_file = output / f"{safe_name}.input"
    shutil.copy2(source, test_file)

    sha256 = hashlib.sha256(test_file.read_bytes()).hexdigest()

    manifest_path = output / "regression_tests.json"

    if manifest_path.exists():
        with open(manifest_path, encoding="utf-8") as file:
            manifest = json.load(file)
    else:
        manifest = {"tests": []}

    if any(test["name"] == safe_name for test in manifest["tests"]):
        raise ValueError(f"Test already exists: {safe_name}")

    manifest["tests"].append({
        "name": safe_name,
        "input_file": test_file.name,
        "sha256": sha256,
        "error_type": error_type,
        "expected_on_base": True,
        "expected_on_patched": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    with open(manifest_path, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4, ensure_ascii=False)

    return test_file
