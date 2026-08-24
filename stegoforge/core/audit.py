"""
StegoForge Audit Agent — local-only, redacted operation logging.

Writes to ~/.stegoforge/audit.log (§2.7, FR-0.3, ADR-009).
Logs: timestamp, operation, input file hash, method, cipher, success/failure.
NEVER logs passphrase, key material, plaintext, or ciphertext.
Local-only, opt-out via --no-log, never transmitted.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from stegoforge.core.contracts import AuditEntry

# Default log location
_STEGOFORGE_DIR = Path.home() / ".stegoforge"
_AUDIT_LOG_PATH = _STEGOFORGE_DIR / "audit.log"

# Module logger for internal errors (not the audit log itself)
_logger = logging.getLogger(__name__)


def log_operation(
    operation: str,
    input_path: Path,
    method_name: str,
    cipher_name: str,
    success: bool,
    error_message: str = "",
    *,
    log_enabled: bool = True,
    log_path: Path | None = None,
) -> AuditEntry:
    """
    Record an operation to the local audit log.

    Args:
        operation: 'embed', 'extract', or 'analyze'.
        input_path: Path to the input file.
        method_name: Name of the steg method used.
        cipher_name: Name of the cipher used.
        success: Whether the operation succeeded.
        error_message: Error description if failed (never contains secrets).
        log_enabled: If False, creates the entry but doesn't write to disk.
        log_path: Override the default log file path.

    Returns:
        The AuditEntry that was (or would have been) logged.
    """
    # Compute file hash (of the file itself, not payload content)
    input_hash = _hash_file(input_path)

    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        operation=operation,
        input_hash=input_hash,
        method_name=method_name,
        cipher_name=cipher_name,
        success=success,
        error_message=error_message,
    )

    if log_enabled:
        _write_entry(entry, log_path or _AUDIT_LOG_PATH)

    return entry


def _hash_file(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file (streams, memory-efficient)."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return "unreadable"


def _write_entry(entry: AuditEntry, log_path: Path) -> None:
    """Append a JSON-line entry to the audit log file."""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write as JSON lines format (one JSON object per line)
        line = json.dumps(
            {
                "timestamp": entry.timestamp,
                "operation": entry.operation,
                "input_hash": entry.input_hash,
                "method": entry.method_name,
                "cipher": entry.cipher_name,
                "success": entry.success,
                "error": entry.error_message,
            },
            separators=(",", ":"),
        )

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    except (OSError, IOError) as e:
        # Logging failure should never crash the tool
        _logger.warning("Failed to write audit log: %s", e)
