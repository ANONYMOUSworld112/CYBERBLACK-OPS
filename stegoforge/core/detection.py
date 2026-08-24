"""
StegoForge Input Detection Agent — magic-byte + extension sniffing.

Auto-detects input file type via magic bytes and cross-checks with file
extension (FR-1).  Mismatch = warn, don't block.

Returns a CarrierProfile with all the metadata downstream agents need.
"""

from __future__ import annotations

import mimetypes
import struct
from pathlib import Path
from typing import Any

from stegoforge.core.contracts import CarrierProfile
from stegoforge.core.exceptions import UnsupportedFormatError


# ---------------------------------------------------------------------------
# Magic byte signatures → MIME type mapping
# ---------------------------------------------------------------------------

# Ordered from most specific (longest prefix) to least specific.
_MAGIC_SIGNATURES: list[tuple[bytes, int, str]] = [
    # (magic_bytes, offset, mime_type)
    # Images
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"GIF89a", 0, "image/gif"),
    (b"GIF87a", 0, "image/gif"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"BM", 0, "image/bmp"),
    (b"RIFF", 0, "_riff"),  # WAV or AVI — needs sub-check
    # Documents
    (b"%PDF", 0, "application/pdf"),
    (b"PK\x03\x04", 0, "_zip"),  # ZIP or OOXML — needs sub-check
    # Plain text is detected as fallback
]

# Extension → MIME for cross-checking and fallback
_EXTENSION_MIME: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".wav": "audio/x-wav",
    ".wave": "audio/x-wav",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".text": "text/plain",
    ".md": "text/plain",
    ".csv": "text/plain",
    ".log": "text/plain",
    ".json": "text/plain",
    ".xml": "text/plain",
    ".html": "text/plain",
    ".htm": "text/plain",
}

# OOXML content type → MIME
_OOXML_CONTENT_TYPES: dict[str, str] = {
    "word/": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xl/": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt/": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def detect(file_path: Path) -> CarrierProfile:
    """
    Detect the type and characteristics of a carrier file.

    Uses magic bytes as primary detection, extension as cross-check.
    If they disagree, the CarrierProfile.extension_mismatch flag is set
    but the operation is not blocked (FR-1).

    Args:
        file_path: Path to the carrier file.

    Returns:
        CarrierProfile with detected type, size, and format details.

    Raises:
        UnsupportedFormatError: If the file doesn't exist or can't be read.
    """
    file_path = Path(file_path).resolve()

    if not file_path.exists():
        raise UnsupportedFormatError(
            mime_type="unknown",
            file_path=str(file_path),
        )

    if not file_path.is_file():
        raise UnsupportedFormatError(
            mime_type="directory",
            file_path=str(file_path),
        )

    size_bytes = file_path.stat().st_size
    if size_bytes == 0:
        raise UnsupportedFormatError(
            mime_type="empty",
            file_path=str(file_path),
        )

    extension = file_path.suffix.lower()

    # Read enough bytes for magic detection
    with open(file_path, "rb") as f:
        header = f.read(4096)

    # Detect MIME from magic bytes
    magic_mime = _detect_magic(header, file_path)

    # Detect MIME from extension
    ext_mime = _EXTENSION_MIME.get(extension)
    if ext_mime is None:
        # Try stdlib mimetypes as fallback
        guessed, _ = mimetypes.guess_type(str(file_path))
        ext_mime = guessed

    # Determine final MIME: magic takes precedence, extension is cross-check
    if magic_mime:
        mime_type = magic_mime
        extension_mismatch = ext_mime is not None and ext_mime != magic_mime
    elif ext_mime:
        mime_type = ext_mime
        extension_mismatch = False
    else:
        # Can't determine type — use generic (EOF-append will still work)
        mime_type = "application/octet-stream"
        extension_mismatch = False

    # Gather format-specific details
    format_details = _gather_format_details(mime_type, file_path, header)

    return CarrierProfile(
        file_path=file_path,
        mime_type=mime_type,
        extension=extension,
        size_bytes=size_bytes,
        format_details=format_details,
        extension_mismatch=extension_mismatch,
    )


def _detect_magic(header: bytes, file_path: Path) -> str | None:
    """Match header bytes against known magic signatures."""
    for magic, offset, mime in _MAGIC_SIGNATURES:
        if header[offset: offset + len(magic)] == magic:
            if mime == "_riff":
                return _classify_riff(header)
            if mime == "_zip":
                return _classify_zip(file_path)
            return mime

    # Check if it looks like text (heuristic: high ratio of printable/whitespace)
    if _looks_like_text(header):
        return "text/plain"

    return None


def _classify_riff(header: bytes) -> str | None:
    """Distinguish WAV from other RIFF formats (AVI, etc.)."""
    if len(header) >= 12:
        riff_type = header[8:12]
        if riff_type == b"WAVE":
            return "audio/x-wav"
        if riff_type == b"AVI ":
            return "video/x-msvideo"  # Deferred to v2
    return "application/octet-stream"


def _classify_zip(file_path: Path) -> str:
    """Distinguish plain ZIP from OOXML (DOCX/XLSX/PPTX)."""
    import zipfile

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
            # OOXML files contain [Content_Types].xml
            if "[Content_Types].xml" in names:
                for prefix, mime in _OOXML_CONTENT_TYPES.items():
                    if any(n.startswith(prefix) for n in names):
                        return mime
                # Generic OOXML — treat as docx
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            return "application/zip"
    except zipfile.BadZipFile:
        return "application/zip"


def _looks_like_text(header: bytes) -> bool:
    """Heuristic: is this likely a text file?"""
    if not header:
        return False

    # Check first 512 bytes for text-like content
    sample = header[:512]
    # Allow UTF-8 BOM
    if sample.startswith(b"\xef\xbb\xbf"):
        sample = sample[3:]

    if not sample:
        return False

    # Count printable + whitespace characters
    text_chars = sum(
        1 for b in sample
        if 32 <= b <= 126  # Printable ASCII
        or b in (9, 10, 13)  # Tab, LF, CR
    )

    return (text_chars / len(sample)) > 0.85


def _gather_format_details(
    mime_type: str, file_path: Path, header: bytes
) -> dict[str, Any]:
    """Collect format-specific metadata for capacity estimation."""
    details: dict[str, Any] = {}

    if mime_type in ("image/png", "image/bmp", "image/gif", "image/jpeg"):
        details.update(_image_details(file_path))
    elif mime_type == "audio/x-wav":
        details.update(_wav_details(file_path, header))
    elif mime_type == "text/plain":
        details.update(_text_details(file_path))

    return details


def _image_details(file_path: Path) -> dict[str, Any]:
    """Get image dimensions and channel count."""
    try:
        from PIL import Image

        with Image.open(file_path) as img:
            width, height = img.size
            mode = img.mode
            channels = len(img.getbands())
            return {
                "width": width,
                "height": height,
                "mode": mode,
                "channels": channels,
            }
    except Exception:
        return {}


def _wav_details(file_path: Path, header: bytes) -> dict[str, Any]:
    """Parse WAV header for sample rate, channels, bit depth, sample count."""
    try:
        import wave

        with wave.open(str(file_path), "rb") as wf:
            return {
                "channels": wf.getnchannels(),
                "sample_width": wf.getsampwidth(),
                "frame_rate": wf.getframerate(),
                "n_frames": wf.getnframes(),
            }
    except Exception:
        return {}


def _text_details(file_path: Path) -> dict[str, Any]:
    """Count lines in a text file for capacity estimation."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        char_count = sum(len(line) for line in lines)
        return {
            "line_count": len(lines),
            "char_count": char_count,
        }
    except Exception:
        return {}
