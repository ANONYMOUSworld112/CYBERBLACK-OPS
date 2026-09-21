"""
StegoForge Capacity Calculator & Explainable Algorithm Recommendation Engine.

Analyzes carrier format, channel dimensions, payload overhead, compression potential,
cryptographic envelope margins, and operator goals to produce explainable,
deterministic method recommendations before embedding operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from stegoforge.core.advisor import get_available_methods
from stegoforge.core.contracts import CarrierProfile
from stegoforge.core.envelope import envelope_overhead


@dataclass
class RecommendationResult:
    """Explainable algorithm recommendation and capacity evaluation."""

    carrier_name: str
    carrier_mime: str
    recommended_method: str
    recommended_cipher: str
    recommended_compression: str
    available_capacity_bytes: int
    required_capacity_bytes: int
    safety_margin_pct: float
    fits: bool
    expected_distortion: str
    robustness: str
    compatibility: str
    explanation: str
    alternative_methods: list[dict[str, Any]] = field(default_factory=list)


def evaluate_and_recommend(
    carrier: CarrierProfile,
    payload_size_bytes: int,
    security_goal: str = "high",
    optimization_goal: str = "fidelity",
) -> RecommendationResult:
    """
    Perform pre-flight capacity calculation and explainable algorithm recommendation.

    Args:
        carrier: Detected CarrierProfile.
        payload_size_bytes: Size of uncompressed payload in bytes.
        security_goal: 'high' (AEAD AES-256-GCM / Argon2id), 'stream' (ChaCha20), 'lab'.
        optimization_goal: 'fidelity' (minimal carrier distortion), 'capacity' (maximum space), 'robustness'.

    Returns:
        RecommendationResult.
    """
    available_methods = get_available_methods(carrier)
    if not available_methods:
        return RecommendationResult(
            carrier_name=carrier.file_path.name,
            carrier_mime=carrier.mime_type,
            recommended_method="none",
            recommended_cipher="none",
            recommended_compression="none",
            available_capacity_bytes=0,
            required_capacity_bytes=payload_size_bytes,
            safety_margin_pct=0.0,
            fits=False,
            expected_distortion="N/A",
            robustness="N/A",
            compatibility="None",
            explanation="No compatible steganographic plugins available for this carrier MIME type.",
        )

    # Estimate required capacity: payload + bundle manifest estimate (100B) + envelope header (38B) + tag (16B)
    overhead = envelope_overhead() + 16 + 120
    required_capacity = payload_size_bytes + overhead

    # Filter methods that fit
    fitting_methods = [m for m in available_methods if m.capacity_bytes >= required_capacity]

    # Decide cipher
    if security_goal == "stream":
        recommended_cipher = "chacha20-poly1305"
    elif security_goal == "lab":
        recommended_cipher = "xor"
    else:
        recommended_cipher = "aes-256-gcm"

    # Decide compression
    recommended_comp = "auto"

    alternatives = []
    for m in available_methods:
        m_margin = (
            round(((m.capacity_bytes - required_capacity) / m.capacity_bytes) * 100.0, 1)
            if m.capacity_bytes > 0
            else 0.0
        )
        alternatives.append(
            {
                "method_name": m.name,
                "plugin": m.plugin_name,
                "capacity_bytes": m.capacity_bytes,
                "fits": m.capacity_bytes >= required_capacity,
                "safety_margin_pct": m_margin,
                "notes": m.notes,
            }
        )

    if not fitting_methods:
        # Check if EOF append is available as fallback
        eof_opt = next((m for m in available_methods if m.plugin_name == "eof-append"), None)
        if eof_opt:
            return RecommendationResult(
                carrier_name=carrier.file_path.name,
                carrier_mime=carrier.mime_type,
                recommended_method=eof_opt.plugin_name,
                recommended_cipher=recommended_cipher,
                recommended_compression=recommended_comp,
                available_capacity_bytes=eof_opt.capacity_bytes,
                required_capacity_bytes=required_capacity,
                safety_margin_pct=99.9,
                fits=True,
                expected_distortion="NONE (Appended at EOF)",
                robustness="MEDIUM",
                compatibility="Universal",
                explanation=(
                    f"In-carrier capacity for structured methods is insufficient ({max(m.capacity_bytes for m in available_methods):,} B available). "
                    "Selected universal EOF-Append fallback to accommodate payload without truncating."
                ),
                alternative_methods=alternatives,
            )
        else:
            return RecommendationResult(
                carrier_name=carrier.file_path.name,
                carrier_mime=carrier.mime_type,
                recommended_method="none",
                recommended_cipher=recommended_cipher,
                recommended_compression=recommended_comp,
                available_capacity_bytes=max((m.capacity_bytes for m in available_methods), default=0),
                required_capacity_bytes=required_capacity,
                safety_margin_pct=0.0,
                fits=False,
                expected_distortion="N/A",
                robustness="N/A",
                compatibility="Insufficient Capacity",
                explanation=(
                    f"Payload size ({payload_size_bytes:,} B + {overhead} B overhead = {required_capacity:,} B) "
                    f"exceeds maximum carrier capacity ({max(m.capacity_bytes for m in available_methods):,} B)."
                ),
                alternative_methods=alternatives,
            )

    # Select best fitting method: prefer domain-specific over generic EOF-append for concealment
    domain_specific = [m for m in fitting_methods if m.plugin_name != "eof-append"]
    selected = domain_specific[0] if domain_specific else fitting_methods[0]

    margin = (
        round(((selected.capacity_bytes - required_capacity) / selected.capacity_bytes) * 100.0, 1)
        if selected.capacity_bytes < 10**12
        else 99.9
    )

    # Explain reasoning
    if carrier.mime_type in ("image/png", "image/bmp", "image/gif") and selected.plugin_name == "lsb-spatial":
        distortion = "VERY LOW / INVISIBLE"
        robustness = "HIGH (Lossless)"
        explanation = (
            f"Lossless raster format ({carrier.mime_type.split('/')[-1].upper()}) with {selected.capacity_bytes:,} B "
            f"available capacity. LSB Spatial offers optimal visual fidelity with a {margin}% safety margin."
        )
    elif carrier.mime_type == "image/jpeg" and selected.plugin_name == "dct-jpeg":
        distortion = "LOW TO MODERATE"
        robustness = "MEDIUM (JPEG Frequency Domain)"
        explanation = (
            "JPEG carrier selected. DCT coefficient modulation preserves JPEG compliance and survives standard viewing."
        )
    elif carrier.mime_type == "audio/x-wav":
        distortion = "AUDIBLY INAUDIBLE"
        robustness = "HIGH (PCM Waveform)"
        explanation = (
            f"Uncompressed PCM Audio detected. Sample LSB modulation provides {selected.capacity_bytes:,} B "
            f"capacity with zero human-audible distortion."
        )
    elif "pdf" in carrier.mime_type or "document" in carrier.mime_type:
        distortion = "NONE (Structural / Metadata)"
        robustness = "HIGH"
        explanation = "Document carrier selected. Metadata & structural embedding maintains 100% visual layout fidelity."
    else:
        distortion = "LOW"
        robustness = "MEDIUM"
        explanation = f"Selected '{selected.name}' with {margin}% safety margin."

    return RecommendationResult(
        carrier_name=carrier.file_path.name,
        carrier_mime=carrier.mime_type,
        recommended_method=selected.plugin_name,
        recommended_cipher=recommended_cipher,
        recommended_compression=recommended_comp,
        available_capacity_bytes=selected.capacity_bytes,
        required_capacity_bytes=required_capacity,
        safety_margin_pct=margin,
        fits=True,
        expected_distortion=distortion,
        robustness=robustness,
        compatibility=carrier.mime_type,
        explanation=explanation,
        alternative_methods=alternatives,
    )
