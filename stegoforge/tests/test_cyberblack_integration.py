"""
Unit tests for StegoForge CyberBlack-Ops Integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from stegoforge.integrations.cyberblack import (
    export_audit_to_cyberblack,
    generate_cyberblack_category_yaml,
)


def test_generate_cyberblack_category_yaml():
    yaml_content = generate_cyberblack_category_yaml()
    assert "Steganography & Covert Ops" in yaml_content
    assert "StegoForge" in yaml_content
    assert "id: '11'" in yaml_content


def test_export_audit_to_cyberblack(tmp_path: Path):
    sf_log = tmp_path / "stegoforge_audit.jsonl"
    cb_log = tmp_path / "cyberblack_run_log.jsonl"

    sample_entry = {
        "timestamp": "2026-08-24T12:00:00Z",
        "operation": "embed",
        "input_hash": "a1b2c3d4e5f6",
        "method_name": "LSB Spatial",
        "cipher_name": "AES-256-GCM",
        "success": True,
        "error_message": "",
    }
    sf_log.write_text(json.dumps(sample_entry) + "\n", encoding="utf-8")

    migrated = export_audit_to_cyberblack(sf_log, cb_log)
    assert migrated == 1

    cb_lines = cb_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(cb_lines) == 1
    cb_data = json.loads(cb_lines[0])
    assert cb_data["tool"] == "stegoforge-embed"
    assert cb_data["exit_code"] == 0
