"""
StegoForge CLI Orchestrator Agent.

Sequences all internal agents for embed, extract, analyze, steganalysis,
watermarking, and laboratory research operations per Master Specification §3.4 and §3.5.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Ensure all ciphers and methods are registered
import stegoforge.ciphers  # noqa: F401
import stegoforge.methods  # noqa: F401
from stegoforge.ciphers.base import get_cipher, get_cipher_by_id
from stegoforge.core.advisor import get_available_methods
from stegoforge.core.audit import log_operation
from stegoforge.core.bundle import (
    PayloadObject,
    is_bundle,
    pack_bundle,
    unpack_bundle,
)
from stegoforge.core.compression import compress_payload, decompress_payload
from stegoforge.core.contracts import (
    CarrierProfile,
    OperationResult,
    OperationType,
    SecurityTier,
)
from stegoforge.core.detection import detect
from stegoforge.core.envelope import detect_envelope_in_bytes, pack, unpack
from stegoforge.core.exceptions import (
    AuthenticationError,
    CapacityExceededError,
    CipherLabRequiredError,
    CorruptEnvelopeError,
    StegoForgeError,
    UnsupportedFormatError,
)
from stegoforge.core.quality import analyze_image_quality
from stegoforge.core.steganalysis import SteganalysisReport, analyze_carrier_forensics
from stegoforge.core.validation import compute_integrity_tag, validate_and_decrypt
from stegoforge.core.watermark import (
    WatermarkReport,
    embed_watermark,
    verify_watermark,
)
from stegoforge.methods.base import get_all_methods, get_method, get_methods_for_mime


def embed_operation(
    carrier_path: Path | str,
    method_name: str,
    cipher_name: str,
    payload: bytes | list[PayloadObject],
    passphrase: str | None = None,
    output_path: Path | str | None = None,
    compression: str = "auto",
    verify: bool = True,
    no_log: bool = False,
    cipher_lab: bool = False,
) -> OperationResult:
    """
    Execute full embed pipeline with multi-payload bundling, pre-encryption compression,
    cryptographic envelope packaging, carrier embedding, quality analysis, and verification.
    """
    carrier_path = Path(carrier_path).resolve()
    if output_path is None:
        output_path = carrier_path.with_name(f"stego_{carrier_path.name}")
    else:
        output_path = Path(output_path).resolve()

    passphrase_str = passphrase or ""

    try:
        # 1. Detection Agent
        profile = detect(carrier_path)

        # 2. Look up method plugin
        method = get_method(method_name)
        if method is None:
            raise UnsupportedFormatError(
                mime_type=profile.mime_type,
                file_path=f"Method '{method_name}' not found",
            )

        # 3. Look up cipher plugin
        cipher = get_cipher(cipher_name)
        if cipher is None:
            raise StegoForgeError(f"Cipher '{cipher_name}' is not registered.")

        # 4. Gating for Cipher Lab educational ciphers (ADR-004)
        if (
            cipher.security_tier == SecurityTier.EDUCATIONAL_WEAK
            and not cipher_lab
        ):
            raise CipherLabRequiredError(cipher.name)

        # 5. Packaging layer: single bytes vs multi-payload bundle
        if isinstance(payload, list):
            raw_payload_bytes = pack_bundle(payload)
            payload_count = len(payload)
        else:
            raw_payload_bytes = bytes(payload)
            payload_count = 1

        # 6. Compression layer (happens BEFORE encryption)
        compressed_bytes, comp_used = compress_payload(raw_payload_bytes, mode=compression)

        # 7. Cipher Agent: encrypt compressed payload
        ciphertext, salt, nonce = cipher.encrypt(compressed_bytes, passphrase_str)

        # 8. Envelope Agent: pack binary envelope (§2.5)
        envelope_bytes = pack(
            method_id=method.method_id,
            cipher_id=cipher.cipher_id,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
        )

        # 9. Pre-flight capacity check (FR-5)
        capacity = method.capacity_bytes(profile)
        if len(envelope_bytes) > capacity:
            raise CapacityExceededError(
                payload_size=len(envelope_bytes),
                capacity=capacity,
                method_name=method.name,
            )

        # 10. Embedding Agent: conceal into carrier
        method.embed(carrier_path, envelope_bytes, output_path)

        # 11. Visual Quality Analysis (if image)
        quality_info = {}
        if profile.mime_type.startswith("image/"):
            try:
                quality_info = analyze_image_quality(carrier_path, output_path)
            except Exception:
                pass

        # 12. Compute integrity tag
        tag = compute_integrity_tag(raw_payload_bytes)

        # 13. Self-verify (PRD §1.6 step 10)
        if verify:
            extracted_raw = method.extract(output_path)
            extracted_env = unpack(extracted_raw)
            extracted_comp = validate_and_decrypt(extracted_env, passphrase_str)
            decompressed_raw, _ = decompress_payload(extracted_comp)
            if decompressed_raw != raw_payload_bytes:
                raise AuthenticationError(
                    "Self-verification failed: extracted payload does not match original."
                )

        # 14. Audit Agent: log operation (§2.7)
        log_operation(
            operation="embed",
            input_path=carrier_path,
            method_name=method.name,
            cipher_name=cipher.name,
            success=True,
            log_enabled=not no_log,
        )

        msg_parts = [f"Successfully embedded {len(raw_payload_bytes):,} bytes into {output_path.name}"]
        if comp_used != "none":
            msg_parts.append(f"Compression: {comp_used}")
        if quality_info and "psnr_db" in quality_info:
            msg_parts.append(f"PSNR: {quality_info['psnr_db']} dB, SSIM: {quality_info.get('ssim', 'N/A')}")

        return OperationResult(
            success=True,
            operation=OperationType.EMBED,
            method_name=method.name,
            cipher_name=cipher.name,
            integrity_tag=tag,
            output_path=output_path,
            payload_size=len(raw_payload_bytes),
            message=" | ".join(msg_parts),
        )

    except Exception as e:
        log_operation(
            operation="embed",
            input_path=carrier_path,
            method_name=method_name,
            cipher_name=cipher_name,
            success=False,
            error_message=str(e),
            log_enabled=not no_log,
        )
        raise


def extract_operation(
    stego_path: Path | str,
    passphrase: str | None = None,
    method_name: str | None = None,
    output_dir: Path | str | None = None,
    no_log: bool = False,
) -> tuple[bytes | list[PayloadObject], OperationResult]:
    """
    Execute full extract pipeline with method auto-detection, decryption,
    decompression, bundle unpacking, and integrity verification.
    """
    stego_path = Path(stego_path).resolve()
    passphrase_str = passphrase or ""

    try:
        # 1. Detection Agent
        profile = detect(stego_path)

        # 2. Determine method plugin
        chosen_method = None
        raw_envelope_bytes = None

        if method_name:
            chosen_method = get_method(method_name)
            if chosen_method is None:
                raise UnsupportedFormatError(
                    mime_type=profile.mime_type,
                    file_path=f"Method '{method_name}' not found",
                )
            raw_envelope_bytes = chosen_method.extract(stego_path)
        else:
            # Auto-detect method via envelope magic check
            candidates = get_methods_for_mime(profile.mime_type)
            all_m = list(get_all_methods().values())
            for m in all_m:
                if m not in candidates:
                    candidates.append(m)

            for cand in candidates:
                try:
                    data = cand.extract(stego_path)
                    if detect_envelope_in_bytes(data):
                        unpack(data)
                        chosen_method = cand
                        raw_envelope_bytes = data
                        break
                except Exception:
                    continue

            if chosen_method is None or raw_envelope_bytes is None:
                raise CorruptEnvelopeError(
                    "No valid StegoForge payload could be detected in this carrier."
                )

        # 3. Envelope Agent: unpack envelope
        envelope_data = unpack(raw_envelope_bytes)

        # 4. Cipher Agent + Integrity/Validation Agent: decrypt & verify AEAD tag
        decrypted_compressed = validate_and_decrypt(envelope_data, passphrase_str)

        # 5. Decompress
        raw_payload, comp_used = decompress_payload(decrypted_compressed)

        # 6. Check if payload is a multi-file bundle
        if is_bundle(raw_payload):
            unpacked_bundle = unpack_bundle(raw_payload)
            final_payload: bytes | list[PayloadObject] = unpacked_bundle
            if output_dir:
                out_d = Path(output_dir).resolve()
                out_d.mkdir(parents=True, exist_ok=True)
                for item in unpacked_bundle:
                    (out_d / item.name).write_bytes(item.data)
            payload_desc = f"bundle containing {len(unpacked_bundle)} files ({len(raw_payload):,} bytes)"
        else:
            final_payload = raw_payload
            payload_desc = f"{len(raw_payload):,} bytes"

        # 7. Compute integrity tag
        tag = compute_integrity_tag(raw_payload)
        cipher_plugin = get_cipher_by_id(envelope_data.cipher_id)
        cipher_name = cipher_plugin.name if cipher_plugin else "Unknown"

        # 8. Audit Agent
        log_operation(
            operation="extract",
            input_path=stego_path,
            method_name=chosen_method.name,
            cipher_name=cipher_name,
            success=True,
            log_enabled=not no_log,
        )

        result = OperationResult(
            success=True,
            operation=OperationType.EXTRACT,
            method_name=chosen_method.name,
            cipher_name=cipher_name,
            integrity_tag=tag,
            output_path=Path(output_dir) if output_dir else None,
            payload_size=len(raw_payload),
            message=f"Successfully extracted {payload_desc} (Integrity Tag: {tag})",
        )

        return final_payload, result

    except Exception as e:
        log_operation(
            operation="extract",
            input_path=stego_path,
            method_name=method_name or "auto-detect",
            cipher_name="N/A",
            success=False,
            error_message=str(e),
            log_enabled=not no_log,
        )
        raise


def analyze_operation(file_path: Path | str, no_log: bool = False) -> dict[str, Any]:
    """
    Analyze a file for steganographic capacity and StegoForge signatures (FR-8).
    """
    file_path = Path(file_path).resolve()
    profile = detect(file_path)
    methods = get_available_methods(profile)

    has_stegoforge_payload = False
    detected_method_name = ""

    for opt in methods:
        plugin = get_method(opt.plugin_name)
        if plugin:
            try:
                data = plugin.extract(file_path)
                if detect_envelope_in_bytes(data):
                    unpack(data)
                    has_stegoforge_payload = True
                    detected_method_name = opt.name
                    break
            except Exception:
                continue

    log_operation(
        operation="analyze",
        input_path=file_path,
        method_name="N/A",
        cipher_name="N/A",
        success=True,
        log_enabled=not no_log,
    )

    return {
        "file_path": str(file_path),
        "mime_type": profile.mime_type,
        "extension": profile.extension,
        "size_bytes": profile.size_bytes,
        "format_details": profile.format_details,
        "extension_mismatch": profile.extension_mismatch,
        "available_methods": methods,
        "has_stegoforge_payload": has_stegoforge_payload,
        "detected_method": detected_method_name,
    }


def steganalysis_operation(file_path: Path | str) -> SteganalysisReport:
    """Execute defensive forensic steganalysis scan on a carrier or stego file."""
    return analyze_carrier_forensics(file_path)


def watermark_embed_operation(
    carrier_path: Path | str,
    owner: str,
    secret_key: str,
    description: str = "",
    output_path: Path | str | None = None,
    method_name: str | None = None,
) -> tuple[Path, str]:
    """Embed digital watermark into media carrier."""
    return embed_watermark(
        carrier_path=carrier_path,
        owner=owner,
        secret_key=secret_key,
        description=description,
        output_path=output_path,
        method_name=method_name,
    )


def watermark_verify_operation(
    stego_path: Path | str,
    secret_key: str,
    method_name: str | None = None,
) -> WatermarkReport:
    """Verify digital watermark in media carrier."""
    return verify_watermark(
        stego_path=stego_path,
        secret_key=secret_key,
        method_name=method_name,
    )
