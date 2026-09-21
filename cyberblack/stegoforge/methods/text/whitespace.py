"""
StegoForge Text Whitespace Method Plugin.

Conceals bits in plain text as trailing space (0) or tab (1) characters per line.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, ENVELOPE_HEADER_SIZE, MethodID
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method


class WhitespaceMethod(MethodPlugin):
    """Whitespace — Plain text steganography via trailing whitespace patterns."""

    name: ClassVar[str] = "Whitespace"
    method_id: ClassVar[MethodID] = MethodID.WHITESPACE
    applicable_types: ClassVar[list[str]] = ["text/plain"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        line_count = carrier.format_details.get("line_count", 0)
        usable_bytes = (line_count // 8) - ENVELOPE_HEADER_SIZE
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
                lines = [line.rstrip("\r\n") for line in fin.readlines()]

            bits: list[int] = []
            for byte in envelope:
                for i in range(8):
                    bits.append((byte >> (7 - i)) & 1)

            if len(bits) > len(lines):
                raise CapacityExceededError(
                    len(envelope),
                    len(lines) // 8 - ENVELOPE_HEADER_SIZE,
                    self.name,
                )

            for i, bit in enumerate(bits):
                lines[i] += " " if bit == 0 else "\t"

            with open(out_path, "w", encoding="utf-8") as fout:
                for line in lines:
                    fout.write(line + "\n")
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during whitespace embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with open(stego_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            bits: list[int] = []
            for line in lines:
                line_stripped = line.rstrip("\r\n")
                if line_stripped.endswith("\t"):
                    bits.append(1)
                elif line_stripped.endswith(" "):
                    bits.append(0)
                else:
                    break

            bytes_data = bytearray()
            for i in range(0, len(bits) - (len(bits) % 8), 8):
                byte = 0
                for j in range(8):
                    byte |= bits[i + j] << (7 - j)
                bytes_data.append(byte)

            return bytes(bytes_data)
        except Exception as e:
            raise StegoForgeError(f"Error during whitespace extract: {e}") from e


whitespace_instance = WhitespaceMethod()
register_method(whitespace_instance)
