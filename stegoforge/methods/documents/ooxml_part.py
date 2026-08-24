"""
StegoForge OOXML Custom Part Method Plugin.

Conceals StegoForge envelope data in a custom XML part inside DOCX/XLSX/PPTX
zip containers without corrupting the document structure.
"""

from __future__ import annotations

import base64
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

MAX_OOXML_SIZE = 10 * 1024 * 1024  # 10MB


class OoxmlPartMethod(MethodPlugin):
    """OOXML Part — Document steganography via custom XML parts in DOCX/XLSX/PPTX."""

    name: ClassVar[str] = "OOXML Part"
    method_id: ClassVar[MethodID] = MethodID.OOXML_PART
    applicable_types: ClassVar[list[str]] = [
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        return MAX_OOXML_SIZE

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)

        if len(envelope) > MAX_OOXML_SIZE:
            raise CapacityExceededError(len(envelope), MAX_OOXML_SIZE, self.name)

        try:
            encoded_data = base64.b85encode(envelope).decode("utf-8")
            custom_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>'
                f"<stegoforge><data>{encoded_data}</data></stegoforge>"
            ).encode("utf-8")

            with zipfile.ZipFile(str(carrier_path), "r") as zin:
                with zipfile.ZipFile(str(out_path), "w", zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        if item.filename != "customXml/stegoforge.xml":
                            zout.writestr(item, zin.read(item.filename))
                    # Inject custom part
                    zout.writestr("customXml/stegoforge.xml", custom_xml)
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during OOXML embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with zipfile.ZipFile(str(stego_path), "r") as zin:
                if "customXml/stegoforge.xml" not in zin.namelist():
                    raise CorruptEnvelopeError("StegoForge custom part not found in OOXML.")
                xml_content = zin.read("customXml/stegoforge.xml").decode("utf-8")

            start_tag = "<data>"
            end_tag = "</data>"
            s_idx = xml_content.find(start_tag)
            e_idx = xml_content.find(end_tag)
            if s_idx == -1 or e_idx == -1:
                raise CorruptEnvelopeError("Invalid StegoForge OOXML XML structure.")

            encoded_data = xml_content[s_idx + len(start_tag) : e_idx]
            return base64.b85decode(encoded_data)
        except CorruptEnvelopeError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during OOXML extract: {e}") from e


ooxml_part_instance = OoxmlPartMethod()
register_method(ooxml_part_instance)
