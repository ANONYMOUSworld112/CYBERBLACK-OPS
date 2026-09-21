"""
StegoForge EOF Append Method Plugin — Universal Fallback.

Appends delimiter + envelope bytes to the end of any file format.
Works with all carrier types ('*').
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, MethodID
from stegoforge.core.exceptions import CorruptEnvelopeError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method

DELIMITER = b"\x00SGF_EOF\x00"


class EofAppendMethod(MethodPlugin):
    """EOF Append — Universal fallback steganography method."""

    name: ClassVar[str] = "EOF Append"
    method_id: ClassVar[MethodID] = MethodID.EOF_APPEND
    applicable_types: ClassVar[list[str]] = ["*"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        """Effectively unbounded for EOF append."""
        return sys.maxsize - 1024

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)
        try:
            with open(carrier_path, "rb") as fin:
                data = fin.read()
            with open(out_path, "wb") as fout:
                fout.write(data)
                fout.write(DELIMITER)
                fout.write(envelope)
        except OSError as e:
            raise StegoForgeError(f"IOError during EOF embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with open(stego_path, "rb") as f:
                data = f.read()
            idx = data.rfind(DELIMITER)
            if idx == -1:
                raise CorruptEnvelopeError("EOF delimiter not found in stego file.")
            return data[idx + len(DELIMITER) :]
        except CorruptEnvelopeError:
            raise
        except OSError as e:
            raise StegoForgeError(f"IOError during EOF extract: {e}") from e


eof_append_instance = EofAppendMethod()
register_method(eof_append_instance)
