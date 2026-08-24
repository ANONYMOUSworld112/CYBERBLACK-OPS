"""
CyberBlack-Ops StegoForge Integration Bridge.

Provides direct access to StegoForge steganography, digital watermarking,
and defensive steganalysis engines from within CyberBlack-Ops.
"""

from __future__ import annotations

import sys
import subprocess
import shutil
from pathlib import Path


def is_stegoforge_installed() -> bool:
    """Check if stegoforge is installed in the current environment or available in PATH."""
    if shutil.which("stegoforge") is not None:
        return True
    try:
        import stegoforge  # noqa: F401
        return True
    except ImportError:
        return False


def launch_stegoforge_wizard() -> None:
    """Launch the interactive StegoForge TUI wizard."""
    try:
        from stegoforge.cli.wizard import main_wizard
        main_wizard()
    except ImportError:
        if shutil.which("stegoforge"):
            subprocess.run(["stegoforge"])
        else:
            print("StegoForge is not installed. Install with: pip install -e /path/to/stegoforge", file=sys.stderr)
