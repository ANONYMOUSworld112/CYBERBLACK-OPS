"""
StegoForge JPEG Embedding Method Plugin.

Conceals StegoForge envelope data inside JPEG containers using compliant
JPEG COM (Comment) / APP segments per ISO/IEC 10918-1 JPEG specification.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, MethodID
from stegoforge.core.exceptions import (
    CapacityExceededError,
    CorruptEnvelopeError,
    StegoForgeError,
)
from stegoforge.methods.base import MethodPlugin, register_method

JPEG_COM_MARKER = b"\xff\xfe"
MAX_JPEG_COM_SIZE = 65533  # 65535 - 2 bytes for length


class DctJpegMethod(MethodPlugin):
    """DCT JPEG — JPEG steganography via compliant marker segment concealment."""

    name: ClassVar[str] = "DCT JPEG"
    method_id: ClassVar[MethodID] = MethodID.DCT_JPEG
    applicable_types: ClassVar[list[str]] = ["image/jpeg"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        return 65530

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)

        if len(envelope) > MAX_JPEG_COM_SIZE:
            raise CapacityExceededError(len(envelope), MAX_JPEG_COM_SIZE, self.name)

        try:
            with open(carrier_path, "rb") as f:
                jpeg_bytes = f.read()

            if not jpeg_bytes.startswith(b"\xff\xd8"):
                raise StegoForgeError("Invalid JPEG file (missing SOI marker).")

            # Build COM segment: Marker (2B) + Length (2B big endian, includes length field) + Data
            seg_len = len(envelope) + 2
            com_segment = JPEG_COM_MARKER + struct.pack(">H", seg_len) + envelope

            # Insert right after SOI (Start of Image, offset 2)
            new_jpeg = jpeg_bytes[:2] + com_segment + jpeg_bytes[2:]

            with open(out_path, "wb") as f:
                f.write(new_jpeg)
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during JPEG embed: {e}") from e

    def extract(self, stego_path: Path | Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with open(stego_path, "rb") as f:
                data = f.read()

            if not data.startswith(b"\xff\xd8"):
                raise StegoForgeError("Invalid JPEG file (missing SOI marker).")

            # Scan for COM markers (0xFF 0xFE)
            idx = 2
            while idx < len(data) - 4:
                if data[idx : idx + 2] == JPEG_COM_MARKER:
                    seg_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
                    payload = data[idx + 4 : idx + 2 + seg_len]
                    if payload.startswith(b"SGF1"):
                        return payload
                    idx += 2 + seg_len
                elif data[idx] == 0xFF and data[idx + 1] not in (0x00, 0xD8, 0xD9):
                    # Other 2-byte marker
                    if idx + 4 <= len(data):
                        m_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
                        idx += 2 + m_len
                    else:
                        idx += 1
                else:
                    idx += 1

            raise CorruptEnvelopeError("No StegoForge payload found in JPEG markers.")
        except CorruptEnvelopeError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during JPEG extract: {e}") from e


dct_jpeg_instance = DctJpegMethod()
register_method(dct_jpeg_instance)
