"""
StegoForge Multi-Payload Bundle Architecture.

Enables packaging single or multiple dynamic payloads (text, documents,
images, audio, video, archives, arbitrary binary files) into a deterministic,
versioned container prior to compression, encryption, and steganographic embedding.

Container layout:
    [MAGIC: 4B b"SFB1"]
    [MANIFEST_LEN: 4B uint32 LE]
    [MANIFEST_JSON: variable UTF-8 bytes]
    [CONCATENATED_PAYLOAD_BYTES: variable]

Manifest format:
    {
        "version": 1,
        "count": N,
        "items": [
            {
                "id": "001",
                "name": "report.pdf",
                "mime": "application/pdf",
                "size": 582934,
                "sha256": "..."
            }, ...
        ]
    }
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stegoforge.core.exceptions import StegoForgeError

BUNDLE_MAGIC = b"SFB1"
BUNDLE_HEADER_SIZE = 8  # 4B magic + 4B manifest length


@dataclass
class PayloadObject:
    """Universal Payload Object representing a single hidden asset."""

    name: str
    data: bytes
    mime_type: str = "application/octet-stream"
    size: int = 0
    sha256: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.size:
            self.size = len(self.data)
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.data).hexdigest()
        if not self.mime_type or self.mime_type == "application/octet-stream":
            guess, _ = mimetypes.guess_type(self.name)
            if guess:
                self.mime_type = guess


def create_payload_from_file(file_path: Path | str) -> PayloadObject:
    """Create a PayloadObject from a file path."""
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Payload file not found: {path}")
    data = path.read_bytes()
    mime, _ = mimetypes.guess_type(path.name)
    return PayloadObject(
        name=path.name,
        data=data,
        mime_type=mime or "application/octet-stream",
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def create_payload_from_text(text: str, name: str = "message.txt") -> PayloadObject:
    """Create a PayloadObject from a UTF-8 text string."""
    data = text.encode("utf-8")
    return PayloadObject(
        name=name,
        data=data,
        mime_type="text/plain; charset=utf-8",
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def create_payload_from_bytes(
    data: bytes, name: str = "payload.bin", mime: str = "application/octet-stream"
) -> PayloadObject:
    """Create a PayloadObject from raw bytes."""
    return PayloadObject(
        name=name,
        data=data,
        mime_type=mime,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def is_bundle(data: bytes) -> bool:
    """Check whether data starts with the StegoForge Bundle magic signature."""
    return data[:4] == BUNDLE_MAGIC if len(data) >= 4 else False


def pack_bundle(payloads: list[PayloadObject]) -> bytes:
    """
    Package one or more PayloadObjects into a deterministic container.

    Args:
        payloads: List of PayloadObject instances to package.

    Returns:
        Serialized binary container bytes.
    """
    if not payloads:
        raise ValueError("Cannot pack empty payload list")

    items_manifest = []
    payload_blobs = bytearray()

    for idx, p in enumerate(payloads, 1):
        items_manifest.append(
            {
                "id": f"{idx:03d}",
                "name": p.name,
                "mime": p.mime_type,
                "size": len(p.data),
                "sha256": p.sha256,
                "metadata": p.metadata,
            }
        )
        payload_blobs.extend(p.data)

    manifest_dict = {
        "version": 1,
        "count": len(payloads),
        "items": items_manifest,
    }

    manifest_bytes = json.dumps(manifest_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    manifest_len = len(manifest_bytes)

    header = struct.pack("<4sI", BUNDLE_MAGIC, manifest_len)
    return header + manifest_bytes + bytes(payload_blobs)


def unpack_bundle(data: bytes) -> list[PayloadObject]:
    """
    Unpack a deterministic bundle container into individual PayloadObjects,
    verifying SHA-256 hashes for all extracted items.

    Args:
        data: Raw bundle bytes.

    Returns:
        List of reconstructed PayloadObjects.

    Raises:
        StegoForgeError: If header is malformed, truncated, or hash verification fails.
    """
    if len(data) < BUNDLE_HEADER_SIZE:
        raise StegoForgeError("Data too short for bundle header")

    magic, manifest_len = struct.unpack("<4sI", data[:BUNDLE_HEADER_SIZE])
    if magic != BUNDLE_MAGIC:
        raise StegoForgeError(f"Invalid bundle magic: expected {BUNDLE_MAGIC!r}, got {magic!r}")

    manifest_end = BUNDLE_HEADER_SIZE + manifest_len
    if len(data) < manifest_end:
        raise StegoForgeError("Truncated bundle manifest")

    manifest_bytes = data[BUNDLE_HEADER_SIZE:manifest_end]
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        raise StegoForgeError(f"Malformed bundle manifest JSON: {exc}") from exc

    items = manifest.get("items", [])
    offset = manifest_end
    extracted: list[PayloadObject] = []

    for item in items:
        name = item.get("name", "unnamed.bin")
        mime = item.get("mime", "application/octet-stream")
        size = item.get("size", 0)
        expected_sha = item.get("sha256", "")
        meta = item.get("metadata", {})

        if offset + size > len(data):
            raise StegoForgeError(f"Truncated bundle payload for item '{name}'")

        item_data = data[offset : offset + size]
        offset += size

        actual_sha = hashlib.sha256(item_data).hexdigest()
        if expected_sha and actual_sha != expected_sha:
            raise StegoForgeError(
                f"Integrity failure for bundle item '{name}': expected {expected_sha[:12]}, got {actual_sha[:12]}"
            )

        extracted.append(
            PayloadObject(
                name=name,
                data=item_data,
                mime_type=mime,
                size=size,
                sha256=actual_sha,
                metadata=meta,
            )
        )

    return extracted
