"""
StegoForge Compression Layer.

Performs payload compression BEFORE encryption (to maximize compression efficiency
since encrypted data is high entropy and cannot be compressed effectively).

Supports DEFLATE (zlib), LZMA, BZIP2, and automatic algorithm selection.
"""

from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from enum import IntEnum, StrEnum

from stegoforge.core.exceptions import StegoForgeError

COMPRESSION_MAGIC = b"SFC0"
COMPRESSION_HEADER_SIZE = 9  # 4B magic + 1B alg + 4B uncompressed_len


class CompressionAlgoID(IntEnum):
    NONE = 0x00
    DEFLATE = 0x01
    BZIP2 = 0x02
    LZMA = 0x03


class CompressionMode(StrEnum):
    AUTO = "auto"
    NONE = "none"
    DEFLATE = "deflate"
    BZIP2 = "bzip2"
    LZMA = "lzma"


def compress_payload(data: bytes, mode: str | CompressionMode = CompressionMode.AUTO) -> tuple[bytes, str]:
    """
    Compress payload bytes and wrap with a self-describing compression header.

    Args:
        data: Raw uncompressed payload bytes.
        mode: Requested compression mode ('auto', 'deflate', 'lzma', 'bzip2', 'none').

    Returns:
        tuple of (wrapped_bytes, selected_algorithm_name)
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Payload data must be bytes")

    raw_len = len(data)
    mode_str = str(mode).lower()

    if raw_len == 0:
        header = struct.pack("<4sBI", COMPRESSION_MAGIC, CompressionAlgoID.NONE.value, 0)
        return header, "none"

    if mode_str == CompressionMode.NONE:
        header = struct.pack("<4sBI", COMPRESSION_MAGIC, CompressionAlgoID.NONE.value, raw_len)
        return header + bytes(data), "none"

    if mode_str == CompressionMode.DEFLATE:
        comp = zlib.compress(data, level=9)
        header = struct.pack("<4sBI", COMPRESSION_MAGIC, CompressionAlgoID.DEFLATE.value, raw_len)
        return header + comp, "deflate"

    if mode_str == CompressionMode.BZIP2:
        comp = bz2.compress(data, compresslevel=9)
        header = struct.pack("<4sBI", COMPRESSION_MAGIC, CompressionAlgoID.BZIP2.value, raw_len)
        return header + comp, "bzip2"

    if mode_str == CompressionMode.LZMA:
        comp = lzma.compress(data, preset=6)
        header = struct.pack("<4sBI", COMPRESSION_MAGIC, CompressionAlgoID.LZMA.value, raw_len)
        return header + comp, "lzma"

    # AUTO MODE: benchmark available algorithms and select best ratio
    candidates: list[tuple[bytes, CompressionAlgoID, str]] = []

    try:
        c_deflate = zlib.compress(data, level=9)
        candidates.append((c_deflate, CompressionAlgoID.DEFLATE, "deflate"))
    except Exception:
        pass

    try:
        c_lzma = lzma.compress(data, preset=6)
        candidates.append((c_lzma, CompressionAlgoID.LZMA, "lzma"))
    except Exception:
        pass

    try:
        c_bz2 = bz2.compress(data, compresslevel=9)
        candidates.append((c_bz2, CompressionAlgoID.BZIP2, "bzip2"))
    except Exception:
        pass

    if candidates:
        best_comp, best_id, best_name = min(candidates, key=lambda x: len(x[0]))
        # Only use compression if it yields at least 3% savings + header
        if len(best_comp) + COMPRESSION_HEADER_SIZE < raw_len * 0.97:
            header = struct.pack("<4sBI", COMPRESSION_MAGIC, best_id.value, raw_len)
            return header + best_comp, best_name

    # Fallback to NONE if compression does not save space
    header = struct.pack("<4sBI", COMPRESSION_MAGIC, CompressionAlgoID.NONE.value, raw_len)
    return header + bytes(data), "none"


def decompress_payload(data: bytes) -> tuple[bytes, str]:
    """
    Decompress payload bytes wrapped with a self-describing compression header.
    If the data does not contain the compression header (legacy/raw payload),
    it is returned as-is with mode 'none'.

    Args:
        data: Compressed or raw payload bytes.

    Returns:
        tuple of (uncompressed_bytes, algorithm_used)
    """
    if len(data) < COMPRESSION_HEADER_SIZE or data[:4] != COMPRESSION_MAGIC:
        # Not wrapped with compression header -> raw uncompressed data
        return data, "none"

    magic, alg_byte, uncompressed_len = struct.unpack("<4sBI", data[:COMPRESSION_HEADER_SIZE])
    payload = data[COMPRESSION_HEADER_SIZE:]

    try:
        alg_id = CompressionAlgoID(alg_byte)
    except ValueError:
        raise StegoForgeError(f"Unknown compression algorithm ID: 0x{alg_byte:02X}")

    if alg_id == CompressionAlgoID.NONE:
        if len(payload) != uncompressed_len:
            raise StegoForgeError(
                f"Uncompressed length mismatch: header says {uncompressed_len}, got {len(payload)}"
            )
        return payload, "none"

    if alg_id == CompressionAlgoID.DEFLATE:
        try:
            decomp = zlib.decompress(payload)
        except Exception as exc:
            raise StegoForgeError(f"DEFLATE decompression failed: {exc}") from exc
        return decomp, "deflate"

    if alg_id == CompressionAlgoID.BZIP2:
        try:
            decomp = bz2.decompress(payload)
        except Exception as exc:
            raise StegoForgeError(f"BZIP2 decompression failed: {exc}") from exc
        return decomp, "bzip2"

    if alg_id == CompressionAlgoID.LZMA:
        try:
            decomp = lzma.decompress(payload)
        except Exception as exc:
            raise StegoForgeError(f"LZMA decompression failed: {exc}") from exc
        return decomp, "lzma"

    raise StegoForgeError(f"Unsupported compression algorithm: {alg_id}")
