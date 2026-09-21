"""
StegoForge compatibility shim.

StegoForge has been integrated into CyberBlack (cyberblack.stegoforge).
This shim redirects legacy imports for backward compatibility.
"""
from __future__ import annotations

from pathlib import Path
import cyberblack.stegoforge

# Delegate subpackage discovery to cyberblack/stegoforge
__path__ = [str(Path(cyberblack.stegoforge.__file__).parent)]
