"""
StegoForge Zero-Width Unicode Text Method Plugin.

Conceals bits in plain text by inserting invisible Zero-Width Unicode characters
(ZWSP, ZWNJ) delimited by a ZWJ start marker.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, ENVELOPE_HEADER_SIZE, MethodID
from stegoforge.core.exceptions import (
    CapacityExceededError,
    CorruptEnvelopeError,
    StegoForgeError,
)
from stegoforge.methods.base import MethodPlugin, register_method


class ZeroWidthMethod(MethodPlugin):
    """Zero Width — Invisible Unicode characters inserted between text glyphs."""

    name: ClassVar[str] = "Zero Width"
    method_id: ClassVar[MethodID] = MethodID.ZERO_WIDTH
    applicable_types: ClassVar[list[str]] = ["text/plain"]

    ZWSP = "\u200b"  # Bit 0
    ZWNJ = "\u200c"  # Bit 1
    ZWJ = "\u200d"   # Start marker

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        char_count = carrier.format_details.get("char_count", 0)
        usable_bytes = (char_count // 8) - ENVELOPE_HEADER_SIZE
        return max(0, usable_bytes)

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)
        try:
            with open(carrier_path, "r", encoding="utf-8", errors="replace") as fin:
                content = fin.read()

            bits: list[int] = []
            for byte in envelope:
                for i in range(8):
                    bits.append((byte >> (7 - i)) & 1)

            if len(bits) > len(content):
                raise CapacityExceededError(
                    len(envelope),
                    len(content) // 8 - ENVELOPE_HEADER_SIZE,
                    self.name,
                )

            # Insert ZWJ at start of hidden sequence, then interleaving ZWSP/ZWNJ
            res = [content[0], self.ZWJ] if len(content) > 0 else [self.ZWJ]
            for i, bit in enumerate(bits):
                res.append(self.ZWSP if bit == 0 else self.ZWNJ)
                if i + 1 < len(content):
                    res.append(content[i + 1])

            if len(bits) + 1 < len(content):
                res.append(content[len(bits) + 1 :])

            with open(out_path, "w", encoding="utf-8") as fout:
                fout.write("".join(res))
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during zero-width embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with open(stego_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            marker_idx = content.find(self.ZWJ)
            if marker_idx == -1:
                raise CorruptEnvelopeError("Zero-width start marker not found.")

            bits: list[int] = []
            for char in content[marker_idx + 1 :]:
                if char == self.ZWSP:
                    bits.append(0)
                elif char == self.ZWNJ:
                    bits.append(1)

            bytes_data = bytearray()
            for i in range(0, len(bits) - (len(bits) % 8), 8):
                byte = 0
                for j in range(8):
                    byte |= bits[i + j] << (7 - j)
                bytes_data.append(byte)

            return bytes(bytes_data)
        except CorruptEnvelopeError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during zero-width extract: {e}") from e


zero_width_instance = ZeroWidthMethod()
register_method(zero_width_instance)
