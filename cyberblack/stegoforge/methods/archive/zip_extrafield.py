"""
StegoForge ZIP Extra Field Method Plugin.

Conceals StegoForge envelope data in the per-file Extra Field headers of
ZIP archives per PKWARE APPNOTE.TXT specification (Header ID 0x5347).
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, MethodID
from stegoforge.core.exceptions import (
    CapacityExceededError,
    CorruptEnvelopeError,
    StegoForgeError,
)
from stegoforge.methods.base import MethodPlugin, register_method

ZIP_EXTRA_HEADER_ID = b"SG"  # 0x5347
MAX_EXTRA_CHUNK = 65000


class ZipExtraFieldMethod(MethodPlugin):
    """ZIP Extra Field — Archive steganography via APPNOTE.TXT extra fields."""

    name: ClassVar[str] = "ZIP Extra Field"
    method_id: ClassVar[MethodID] = MethodID.ZIP_EXTRA_FIELD
    applicable_types: ClassVar[list[str]] = ["application/zip"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        return 1024 * 1024  # 1MB capacity

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)
        try:
            with zipfile.ZipFile(str(carrier_path), "r") as zin:
                infos = zin.infolist()
                if not infos:
                    raise CapacityExceededError(
                        len(envelope), 0, "ZIP contains no entries to attach data to."
                    )

                # Split envelope across entries if needed
                chunks = [
                    envelope[i : i + MAX_EXTRA_CHUNK]
                    for i in range(0, len(envelope), MAX_EXTRA_CHUNK)
                ]

                with zipfile.ZipFile(
                    str(out_path), "w", compression=zipfile.ZIP_DEFLATED
                ) as zout:
                    for i, item in enumerate(infos):
                        raw_content = zin.read(item.filename)
                        if i < len(chunks):
                            chunk = chunks[i]
                            # Extra field format: 2B ID + 2B Length (LE) + Data
                            extra_block = (
                                ZIP_EXTRA_HEADER_ID
                                + struct.pack("<H", len(chunk))
                                + chunk
                            )
                            item.extra = (item.extra or b"") + extra_block
                        zout.writestr(item, raw_content)
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during ZIP embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            extracted_data = bytearray()
            with zipfile.ZipFile(str(stego_path), "r") as zin:
                for item in zin.infolist():
                    extra = item.extra or b""
                    idx = 0
                    while idx + 4 <= len(extra):
                        h_id = extra[idx : idx + 2]
                        d_len = struct.unpack("<H", extra[idx + 2 : idx + 4])[0]
                        idx += 4
                        if h_id == ZIP_EXTRA_HEADER_ID:
                            extracted_data.extend(extra[idx : idx + d_len])
                        idx += d_len

            if not extracted_data:
                raise CorruptEnvelopeError("No StegoForge extra fields found in ZIP.")

            return bytes(extracted_data)
        except CorruptEnvelopeError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during ZIP extract: {e}") from e


zip_extrafield_instance = ZipExtraFieldMethod()
register_method(zip_extrafield_instance)
