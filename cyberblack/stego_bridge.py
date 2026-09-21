"""
CyberBlack-Ops StegoForge Integration Bridge.

Provides direct access to StegoForge steganography, digital watermarking,
and defensive steganalysis engines from within CyberBlack-Ops.
"""

from __future__ import annotations

import sys


def is_stegoforge_installed() -> bool:
    """Check if StegoForge is installed (always True as built-in)."""
    return True


def launch_stegoforge_wizard() -> None:
    """Launch the interactive StegoForge TUI wizard."""
    try:
        from .stegoforge.cli.wizard import main_wizard
        main_wizard()
    except Exception as exc:
        print(f"Error launching StegoForge wizard: {exc}", file=sys.stderr)

