"""
StegoForge Defensive Steganalysis & Forensic Inspection Engine.

Provides deep statistical profiling, Shannon entropy variance analysis,
Chi-Square (PoV) tests on LSB distributions, file structure anomaly detection,
trailing EOF byte carving, signature scanning, and cybersecurity risk scoring.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from stegoforge.core.detection import detect


@dataclass
class SteganalysisReport:
    """Detailed defensive steganalysis assessment report."""

    file_path: Path
    file_size: int
    mime_type: str
    global_entropy: float
    block_entropy_mean: float
    block_entropy_std: float
    chi_square_p_value: float | None
    lsb_anomaly_score: float
    trailing_bytes: int
    signatures_found: list[str] = field(default_factory=list)
    suspicion_score: int = 0
    risk_level: str = "CLEAN"
    confidence_pct: float = 0.0
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def calculate_block_entropy(data: bytes, block_size: int = 1024) -> tuple[float, float]:
    """Calculate mean and standard deviation of entropy across sliding blocks."""
    if len(data) < block_size:
        h = calculate_shannon_entropy(data)
        return h, 0.0

    entropies = []
    for i in range(0, len(data) - block_size + 1, block_size):
        block = data[i : i + block_size]
        entropies.append(calculate_shannon_entropy(block))

    arr = np.array(entropies)
    return float(np.mean(arr)), float(np.std(arr))


def chi_square_lsb_test(values: np.ndarray) -> tuple[float, float]:
    """
    Perform Chi-Square test on Pairs of Values (PoVs) for LSB steganography detection.
    Compares observed frequencies of even value 2k and odd value 2k+1 against their expected average.
    Returns (chi2_statistic, p_value_estimate).
    """
    if len(values) == 0:
        return 0.0, 1.0

    flat = values.flatten().astype(np.uint8)
    counts = np.bincount(flat, minlength=256)

    chi2 = 0.0
    dof = 0

    for k in range(128):
        obs_even = counts[2 * k]
        obs_odd = counts[2 * k + 1]
        total = obs_even + obs_odd
        if total > 5:
            expected = total / 2.0
            chi2 += ((obs_even - expected) ** 2 + (obs_odd - expected) ** 2) / expected
            dof += 1

    if dof == 0:
        return 0.0, 1.0

    # Approximate p-value using chi2 / dof relation
    # High chi2 with small p-value in natural images indicates natural imbalance.
    # In randomized LSB embedding, even and odd counts equalize artificially (chi2 drops towards zero).
    normalized_stat = chi2 / max(1, dof)
    return float(chi2), float(normalized_stat)


def detect_trailing_eof_bytes(file_path: Path, mime_type: str) -> int:
    """Detect unreferenced bytes appended after known container EOF markers."""
    data = file_path.read_bytes()
    size = len(data)

    if mime_type == "image/jpeg":
        # Look for last 0xFF 0xD9 (EOI marker)
        pos = data.rfind(b"\xff\xd9")
        if pos != -1 and pos + 2 < size:
            return size - (pos + 2)

    elif mime_type == "image/png":
        # Look for IEND chunk (b"IEND\xae\x42\x60\x82")
        pos = data.rfind(b"IEND\xaeB`\x82")
        if pos != -1 and pos + 8 < size:
            return size - (pos + 8)

    elif mime_type == "application/pdf":
        pos = data.rfind(b"%%EOF")
        if pos != -1 and pos + 5 < size:
            return size - (pos + 5)

    elif mime_type == "application/zip":
        # End of Central Directory signature: b"PK\x05\x06"
        pos = data.rfind(b"PK\x05\x06")
        if pos != -1 and pos + 22 < size:
            comment_len = int.from_bytes(data[pos + 20 : pos + 22], "little")
            expected_end = pos + 22 + comment_len
            if expected_end < size:
                return size - expected_end

    return 0


def scan_known_stego_signatures(data: bytes) -> list[str]:
    """Scan data for known steganography and envelope signatures."""
    signatures = {
        b"SGF1": "StegoForge / Steganox v1 Encrypted Envelope",
        b"SFB1": "StegoForge Multi-Payload Bundle Container",
        b"SFC0": "StegoForge Compression Envelope",
        b"SGWM": "StegoForge Digital Watermark Signature",
        b"SFC1": "StegoForge Cipher Envelope (Argon2id + AES-GCM)",
        b"OPENSTEGO": "OpenStego Signature",
        b"stghide": "Steghide Signature Header",
    }
    found = []
    for sig, desc in signatures.items():
        if sig in data:
            found.append(desc)
    return found


def analyze_carrier_forensics(file_path: Path | str) -> SteganalysisReport:
    """
    Perform comprehensive defensive steganalysis on a file.

    Args:
        file_path: Path to the media or document file.

    Returns:
        SteganalysisReport with full metrics, findings, and suspicion score.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = path.read_bytes()
    file_size = len(data)

    try:
        profile = detect(path)
        mime = profile.mime_type
    except Exception:
        mime = "application/octet-stream"

    # 1. Global & Block Entropy
    global_entropy = calculate_shannon_entropy(data)
    mean_entropy, std_entropy = calculate_block_entropy(data)

    # 2. Known Signatures
    signatures = scan_known_stego_signatures(data)

    # 3. Trailing EOF Data
    trailing_bytes = detect_trailing_eof_bytes(path, mime)

    # 4. Image-specific LSB / Statistical tests
    chi_square_p = None
    lsb_anomaly_score = 0.0

    if mime.startswith("image/"):
        try:
            with Image.open(path) as img:
                arr = np.array(img.convert("RGB"), dtype=np.uint8)
                lsb_plane = arr & 1
                lsb_density = float(np.mean(lsb_plane))
                # LSB density in natural images is typically biased; purely random LSB is ~0.5
                lsb_anomaly_score = float(1.0 - abs(lsb_density - 0.5) * 2.0)
                chi2_val, norm_stat = chi_square_lsb_test(arr)
                chi_square_p = norm_stat
        except Exception:
            pass

    # 5. Risk Scoring & Finding Generation
    findings: list[str] = []
    recommendations: list[str] = []
    suspicion_points = 0

    if signatures:
        suspicion_points += 60
        findings.append(f"Known steganographic signatures detected: {', '.join(signatures)}")
        recommendations.append("Execute StegoForge extraction with operator passphrase or inspect envelope headers.")

    if trailing_bytes > 0:
        suspicion_points += 35
        findings.append(f"Unreferenced payload of {trailing_bytes:,} bytes detected appended beyond EOF marker.")
        recommendations.append("Perform file carving or EOF extraction to inspect unreferenced binary data.")

    if global_entropy > 7.92 and file_size > 4096:
        suspicion_points += 25
        findings.append(
            f"Extremely high global Shannon entropy ({global_entropy:.3f} bits/byte) indicative of encrypted/compressed payload."
        )

    if std_entropy > 1.2:
        suspicion_points += 15
        findings.append(
            f"High block entropy variance ({std_entropy:.3f}) indicating localized regions of dense encrypted data."
        )

    if lsb_anomaly_score > 0.95:
        suspicion_points += 20
        findings.append(
            f"LSB bit-plane distribution shows high artificial randomness (score {lsb_anomaly_score:.2f})."
        )

    # Cap score
    suspicion_score = min(100, suspicion_points)

    if suspicion_score >= 80:
        risk_level = "CRITICAL / CONFIRMED"
        confidence_pct = 95.0
    elif suspicion_score >= 50:
        risk_level = "HIGH"
        confidence_pct = 80.0
    elif suspicion_score >= 25:
        risk_level = "MEDIUM"
        confidence_pct = 65.0
    elif suspicion_score >= 10:
        risk_level = "LOW"
        confidence_pct = 50.0
    else:
        risk_level = "CLEAN / BENIGN"
        confidence_pct = 90.0
        findings.append("No overt steganographic signatures or statistical anomalies detected.")
        recommendations.append("Carrier appears benign under standard statistical and structural heuristics.")

    return SteganalysisReport(
        file_path=path,
        file_size=file_size,
        mime_type=mime,
        global_entropy=round(global_entropy, 3),
        block_entropy_mean=round(mean_entropy, 3),
        block_entropy_std=round(std_entropy, 3),
        chi_square_p_value=round(chi_square_p, 3) if chi_square_p is not None else None,
        lsb_anomaly_score=round(lsb_anomaly_score, 3),
        trailing_bytes=trailing_bytes,
        signatures_found=signatures,
        suspicion_score=suspicion_score,
        risk_level=risk_level,
        confidence_pct=confidence_pct,
        findings=findings,
        recommendations=recommendations,
    )
