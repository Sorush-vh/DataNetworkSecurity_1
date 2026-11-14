#!/usr/bin/env bash
# Run the complete four-scenario matrix for both targets in the isolated image.
#
# Usage:
#   ./pipeline/run_targets.sh [tlvparse|bzip2 ...]
#
# The script expects Docker. It mounts the repository read-write because the
# orchestrator writes artifacts and reports; the target sources are copied by
# the execution module and are not modified.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${SPV_IMAGE:-spv-targets}"
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(tlvparse bzip2)
fi

cd "$ROOT"
docker build --platform linux/amd64 -f docker/targets.Dockerfile -t "$IMAGE" .

for target in "${TARGETS[@]}"; do
    echo "=== ${target}: four-scenario matrix ==="
    docker run --rm --platform linux/amd64 \
        -v "$ROOT:/project" -w /project -e PYTHONPATH=src \
        "$IMAGE" \
        python3 -m security_patch_validator.cli targets run-all \
        --target "targets/${target}/target.json" \
        --artifacts-dir "artifacts/${target}" \
        --output "reports/${target}-matrix.json" --summary --pretty
done

echo "All requested scenarios matched their expected exit codes."
