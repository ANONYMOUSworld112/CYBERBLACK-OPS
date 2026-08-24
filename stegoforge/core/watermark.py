"""
StegoForge Digital Watermarking & Asset Authentication Subsystem.

Provides deterministic cryptographic watermarking, owner signing with HMAC-SHA256,
tamper detection, and verification reports. Designed as a separate, distinct
layer from hidden payload storage.
"""

from __future__ import annotations

import hmac
import hashlib
import struct
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stegoforge.core.advisor import get_available_methods
from stegoforge.core.detection import detect
from stegoforge.core.exceptions import StegoForgeError
from stegoforge.methods.base import get_method

WATERMARK_MAGIC = b"SGWM"
WATERMARK_VERSION = 1
WATERMARK_HEADER_STRUCT = struct.Struct("<4sBHHH32s")
# magic(4s) version(B) owner_len(H) desc_len(H) time_len(H) hmac(32s) = 43 bytes


@dataclass
class WatermarkReport:
    """Detailed verification report for a digital watermark."""

    file_path: Path
    detected: bool
    signature_valid: bool
    owner: str = ""
    timestamp: str = ""
    description: str = ""
    tampered: bool = False
    details: str = ""


def create_watermark_envelope(
    owner: str, secret_key: str, description: str = ""
) -> bytes:
    """
    Construct a cryptographically signed watermark envelope.

    Args:
        owner: Owner or author identifier string.
        secret_key: Secret key or passphrase used to compute the HMAC signature.
        description: Optional asset or copyright description.

    Returns:
        Packed watermark binary payload.
    """
    if not owner:
        raise ValueError("Owner identifier must not be empty")
    if not secret_key:
        raise ValueError("Secret key must not be empty")

    iso_time = datetime.now(timezone.utc).isoformat()
    owner_b = owner.encode("utf-8")
    desc_b = description.encode("utf-8")
    time_b = iso_time.encode("utf-8")

    # Message payload to sign
    sign_data = owner_b + b"|" + time_b + b"|" + desc_b
    signature = hmac.new(secret_key.encode("utf-8"), sign_data, hashlib.sha256).digest()

    header = WATERMARK_HEADER_STRUCT.pack(
        WATERMARK_MAGIC,
        WATERMARK_VERSION,
        len(owner_b),
        len(desc_b),
        len(time_b),
        signature,
    )

    return header + owner_b + desc_b + time_b


def parse_and_verify_watermark(data: bytes, secret_key: str) -> WatermarkReport:
    """
    Parse a watermark envelope and verify its cryptographic HMAC signature.

    Args:
        data: Watermark bytes extracted from carrier.
        secret_key: Secret key for HMAC verification.

    Returns:
        WatermarkReport.
    """
    hdr_size = WATERMARK_HEADER_STRUCT.size
    if len(data) < hdr_size:
        return WatermarkReport(
            file_path=Path(""),
            detected=False,
            signature_valid=False,
            details="Data too short for watermark header",
        )

    magic, version, owner_len, desc_len, time_len, sig = WATERMARK_HEADER_STRUCT.unpack(
        data[:hdr_size]
    )

    if magic != WATERMARK_MAGIC:
        return WatermarkReport(
            file_path=Path(""),
            detected=False,
            signature_valid=False,
            details=f"Invalid watermark magic: {magic!r}",
        )

    offset = hdr_size
    owner_b = data[offset : offset + owner_len]
    offset += owner_len
    desc_b = data[offset : offset + desc_len]
    offset += desc_len
    time_b = data[offset : offset + time_len]

    owner = owner_b.decode("utf-8", errors="replace")
    desc = desc_b.decode("utf-8", errors="replace")
    timestamp = time_b.decode("utf-8", errors="replace")

    sign_data = owner_b + b"|" + time_b + b"|" + desc_b
    expected_sig = hmac.new(secret_key.encode("utf-8"), sign_data, hashlib.sha256).digest()

    if hmac.compare_digest(sig, expected_sig):
        return WatermarkReport(
            file_path=Path(""),
            detected=True,
            signature_valid=True,
            owner=owner,
            timestamp=timestamp,
            description=desc,
            tampered=False,
            details="Watermark signature verified successfully; ownership and integrity confirmed.",
        )
    else:
        return WatermarkReport(
            file_path=Path(""),
            detected=True,
            signature_valid=False,
            owner=owner,
            timestamp=timestamp,
            description=desc,
            tampered=True,
            details="Watermark detected but cryptographic signature verification failed (incorrect key or tampered asset).",
        )


def embed_watermark(
    carrier_path: Path | str,
    owner: str,
    secret_key: str,
    description: str = "",
    output_path: Path | str | None = None,
    method_name: str | None = None,
) -> tuple[Path, str]:
    """
    Embed an authenticated watermark into a carrier file.

    Args:
        carrier_path: Path to the clean carrier file.
        owner: Owner or author identifier.
        secret_key: Signing key.
        description: Description / metadata.
        output_path: Output stego file destination.
        method_name: Stego method name (or None for auto-selection).

    Returns:
        tuple of (output_path, method_used)
    """
    c_path = Path(carrier_path).resolve()
    if not c_path.is_file():
        raise FileNotFoundError(f"Carrier file not found: {c_path}")

    profile = detect(c_path)
    wm_payload = create_watermark_envelope(owner, secret_key, description)

    if method_name:
        method = get_method(method_name)
    else:
        available = get_available_methods(profile)
        if not available:
            raise StegoForgeError(f"No compatible embedding methods for {profile.mime_type}")
        # Prefer domain-specific over EOF append if capacity fits
        pref = [m for m in available if m.plugin_name != "eof-append" and m.capacity_bytes >= len(wm_payload)]
        method_opt = pref[0] if pref else available[0]
        method = get_method(method_opt.plugin_name)

    if method is None:
        raise StegoForgeError("Failed to resolve embedding method plugin")

    out = Path(output_path).resolve() if output_path else c_path.with_name(f"watermarked_{c_path.name}")
    method.embed(c_path, wm_payload, out)
    return out, method.name


def verify_watermark(
    stego_path: Path | str,
    secret_key: str,
    method_name: str | None = None,
) -> WatermarkReport:
    """
    Verify the digital watermark in a media file.

    Args:
        stego_path: Path to the watermarked file.
        secret_key: Secret key used to sign the watermark.
        method_name: Specific method or None to attempt all compatible methods.

    Returns:
        WatermarkReport.
    """
    s_path = Path(stego_path).resolve()
    if not s_path.is_file():
        raise FileNotFoundError(f"Stego file not found: {s_path}")

    profile = detect(s_path)
    methods_to_try = []

    if method_name:
        m = get_method(method_name)
        if m:
            methods_to_try.append(m)
    else:
        available = get_available_methods(profile)
        for opt in available:
            m = get_method(opt.plugin_name)
            if m:
                methods_to_try.append(m)

    for m in methods_to_try:
        try:
            raw = m.extract(s_path)
            if raw and WATERMARK_MAGIC in raw:
                # Find magic offset
                idx = raw.find(WATERMARK_MAGIC)
                report = parse_and_verify_watermark(raw[idx:], secret_key)
                report.file_path = s_path
                return report
        except Exception:
            continue

    return WatermarkReport(
        file_path=s_path,
        detected=False,
        signature_valid=False,
        details="No valid StegoForge watermark signature detected with the provided parameters.",
    )
