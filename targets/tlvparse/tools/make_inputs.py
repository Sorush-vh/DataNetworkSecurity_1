#!/usr/bin/env python3
"""Generate deterministic TLV inputs for the second target."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def record(kind: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("TLV length is one byte")
    return bytes([kind, len(value)]) + value


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)

    valid_name = b"alice-0123456789"
    boundary_name = b"abcdefghijklmnopqrstuvwxyz01234"
    (inputs / "valid.tlv").write_bytes(
        record(1, valid_name) + record(2, struct.pack("<I", 0x12345678)) + record(3, b"")
    )
    (inputs / "boundary.tlv").write_bytes(
        record(1, boundary_name) + record(2, struct.pack("<I", 1)) + record(3, b"")
    )
    (inputs / "overflow-200.tlv").write_bytes(record(1, b"A" * 200) + record(3, b""))
    (inputs / "overflow-64.tlv").write_bytes(record(1, b"B" * 64) + record(3, b""))
    (inputs / "invalid-truncated.tlv").write_bytes(bytes([1, 10]) + b"short")
    (inputs / "invalid-type.tlv").write_bytes(bytes([9, 0]))
    print(f"wrote inputs to {inputs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
