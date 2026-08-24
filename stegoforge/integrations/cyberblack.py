"""
StegoForge Integration Bridge for CyberBlack-Ops.

Connects StegoForge steganography and defensive steganalysis platform
with the CyberBlack-Ops pentesting / CEH toolkit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stegoforge.methods.base import get_all_methods
from stegoforge.ciphers.base import get_all_ciphers


def generate_cyberblack_category_yaml() -> str:
    """Generate YAML specification for CyberBlack-Ops Category 11."""
    return """id: '11'
name: Steganography & Covert Ops
icon: 🎭
color: bright_magenta
description: Data hiding, cryptographic carrier encapsulation, digital watermarking, and defensive steganalysis
tools:
- name: StegoForge
  binary: stegoforge
  tagline: Universal Multimedia Steganography & Concealment Engine
  description: Modular steganography & AEAD encryption platform supporting lossless images (PNG, BMP, GIF), lossy JPEG (DCT), uncompressed WAV audio, PDF/OOXML documents, ZIP extra-fields, and EOF append with Argon2id + AES-256-GCM / ChaCha20 protection.
  risk: low
  install: pip install -e /path/to/stegoforge
  syntax: stegoforge [command] [options]
  flags:
  - flag: embed -i <carrier> -m <method> -c <cipher> --payload-file <file>
    description: Embed protected payload into carrier media
  - flag: extract -i <stego_file> -o <out_file>
    description: Extract and authenticate hidden payload
  - flag: analyze -i <carrier>
    description: Analyze carrier format and calculate live capacities
  - flag: recommend -c <carrier> -s <bytes>
    description: Explainable algorithm recommender & pre-flight capacity check
  examples:
  - description: Interactive TUI Wizard
    command: stegoforge
  - description: Embed file with AES-256-GCM + Argon2id
    command: stegoforge embed -i carrier.png -m lsb-spatial -c aes-256-gcm --payload-file secret.pdf -o stego.png
  - description: Extract payload from stego carrier
    command: stegoforge extract -i stego.png -o recovered.pdf
  tips:
  - Always check capacity before embedding to ensure payload fits without truncation.
  - Multi-payload bundling automatically packages files with SHA-256 integrity verification.
"""


def export_audit_to_cyberblack(
    stegoforge_audit_path: Path | str,
    cyberblack_log_path: Path | str,
) -> int:
    """
    Export StegoForge audit entries into CyberBlack run log format (~/.cyberblack/run_log.jsonl).
    Returns count of migrated log records.
    """
    s_path = Path(stegoforge_audit_path).resolve()
    c_path = Path(cyberblack_log_path).resolve()

    if not s_path.is_file():
        return 0

    c_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with open(s_path, "r", encoding="utf-8") as sf_in, open(c_path, "a", encoding="utf-8") as cb_out:
        for line in sf_in:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                cb_record = {
                    "timestamp": data.get("timestamp"),
                    "tool": f"stegoforge-{data.get('operation', 'unknown')}",
                    "command": f"stegoforge {data.get('operation')} (method={data.get('method_name')}, cipher={data.get('cipher_name')})",
                    "exit_code": 0 if data.get("success") else 1,
                    "target": data.get("input_hash", "local_carrier"),
                }
                cb_out.write(json.dumps(cb_record) + "\n")
                count += 1
            except Exception:
                continue

    return count
