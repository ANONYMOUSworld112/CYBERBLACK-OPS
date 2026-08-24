"""
StegoForge PDF Metadata Method Plugin.

Embeds base85-encoded StegoForge envelope data in PDF document metadata fields.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import ClassVar

from pypdf import PdfReader, PdfWriter

from stegoforge.core.contracts import CarrierProfile, MethodID
from stegoforge.core.exceptions import (
    CapacityExceededError,
    CorruptEnvelopeError,
    StegoForgeError,
)
from stegoforge.methods.base import MethodPlugin, register_method

MAX_PDF_METADATA_SIZE = 65536


class PdfMetadataMethod(MethodPlugin):
    """PDF Metadata — Document steganography via PDF metadata concealment."""

    name: ClassVar[str] = "PDF Metadata"
    method_id: ClassVar[MethodID] = MethodID.PDF_METADATA
    applicable_types: ClassVar[list[str]] = ["application/pdf"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        return MAX_PDF_METADATA_SIZE

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)

        if len(envelope) > MAX_PDF_METADATA_SIZE:
            raise CapacityExceededError(len(envelope), MAX_PDF_METADATA_SIZE, self.name)

        try:
            encoded_data = base64.b85encode(envelope).decode("utf-8")
            reader = PdfReader(str(carrier_path))
            writer = PdfWriter()

            for page in reader.pages:
                writer.add_page(page)

            metadata = reader.metadata or {}
            new_metadata = {k: v for k, v in metadata.items()}
            new_metadata["/StegoForge"] = encoded_data
            writer.add_metadata(new_metadata)

            with open(out_path, "wb") as fp:
                writer.write(fp)
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during PDF embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            reader = PdfReader(str(stego_path))
            metadata = reader.metadata

            if not metadata or "/StegoForge" not in metadata:
                raise CorruptEnvelopeError("StegoForge metadata not found in PDF.")

            encoded_data = metadata["/StegoForge"]
            return base64.b85decode(encoded_data)
        except CorruptEnvelopeError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during PDF extract: {e}") from e


pdf_metadata_instance = PdfMetadataMethod()
register_method(pdf_metadata_instance)
