"""
StegoForge Method Advisor Agent — filters methods by carrier type + live capacity.

Given a CarrierProfile, returns the filtered list of valid methods with
live capacity per method (FR-2, FR-5).  This is the core of the
"show only what's valid for this file" behavior the spec requires.
"""

from __future__ import annotations

from stegoforge.core.contracts import CarrierProfile, MethodOption
from stegoforge.methods.base import get_methods_for_mime


def get_available_methods(carrier: CarrierProfile) -> list[MethodOption]:
    """
    Return all valid steg methods for this carrier, with live capacity.

    Methods are filtered by MIME type compatibility and sorted by
    capacity (highest first).  Each entry includes the method's notes
    about robustness/tradeoffs.

    Args:
        carrier: Profile of the carrier file.

    Returns:
        List of MethodOption, sorted by capacity_bytes descending.
        Empty list if no methods support this carrier type.
    """
    matching_plugins = get_methods_for_mime(carrier.mime_type)

    options: list[MethodOption] = []
    for plugin in matching_plugins:
        try:
            capacity = plugin.capacity_bytes(carrier)
        except Exception:
            # If capacity calculation fails, skip this method
            # (e.g., corrupt carrier that can't be parsed by this plugin)
            continue

        if capacity <= 0:
            # Method technically supports this type but this specific
            # file has zero usable capacity — skip from the menu
            continue

        key = plugin.name.lower().replace(" ", "-").replace("_", "-")
        options.append(
            MethodOption(
                name=plugin.name,
                method_id=plugin.method_id,
                capacity_bytes=capacity,
                notes=_get_method_notes(plugin),
                plugin_name=key,
            )
        )

    # Sort by capacity descending — highest capacity first
    options.sort(key=lambda o: o.capacity_bytes, reverse=True)
    return options


def check_capacity(
    carrier: CarrierProfile,
    method_name: str,
    envelope_size: int,
) -> tuple[bool, int, int]:
    """
    Pre-flight capacity check: can this envelope fit in this carrier?

    Args:
        carrier: Carrier profile.
        method_name: Registry key of the chosen method.
        envelope_size: Total envelope size in bytes.

    Returns:
        Tuple of (fits, capacity_bytes, shortfall_bytes).
        fits=True and shortfall=0 if it fits.
    """
    from stegoforge.methods.base import get_method

    plugin = get_method(method_name)
    if plugin is None:
        return (False, 0, envelope_size)

    try:
        capacity = plugin.capacity_bytes(carrier)
    except Exception:
        return (False, 0, envelope_size)

    if envelope_size <= capacity:
        return (True, capacity, 0)
    else:
        return (False, capacity, envelope_size - capacity)


def _get_method_notes(plugin: object) -> str:
    """Generate operator-facing notes about a method's characteristics."""
    from stegoforge.methods.base import MethodPlugin

    if not isinstance(plugin, MethodPlugin):
        return ""

    # Notes based on method name/type — helps operator understand
    # the robustness/capacity/compatibility tradeoff (ADR-006)
    notes_map: dict[str, str] = {
        "eof-append": (
            "Universal fallback. Works with any file type. "
            "Very high capacity but very low robustness — "
            "any process that truncates or re-saves the file will strip the payload."
        ),
        "lsb-spatial": (
            "Modifies least significant bits of pixel channels. "
            "High capacity for lossless images. "
            "Destroyed by re-encoding, resizing, or format conversion."
        ),
        "dct-jpeg": (
            "Modifies mid-frequency DCT coefficients. "
            "Survives same-quality JPEG re-save. "
            "More complex, moderate capacity."
        ),
        "lsb-sample": (
            "Modifies least significant bits of audio samples. "
            "High capacity for uncompressed audio. "
            "Destroyed by re-encoding or format conversion."
        ),
        "echo-hide": (
            "Encodes data as subtle echo patterns. "
            "Lower capacity but more robust to resampling than LSB."
        ),
        "phase-coding": (
            "Modifies phase components of audio segments. "
            "Lowest capacity among audio methods but highest robustness."
        ),
        "whitespace": (
            "Encodes bits as trailing space/tab patterns per line. "
            "Very low capacity. Destroyed by reformatting or trimming."
        ),
        "zero-width": (
            "Inserts invisible zero-width Unicode characters. "
            "Low capacity. May be stripped by some applications on copy/paste."
        ),
        "pdf-metadata": (
            "Embeds data in PDF metadata fields. "
            "Low capacity but survives normal viewing."
        ),
        "ooxml-part": (
            "Injects a custom XML part inside the OOXML zip container. "
            "Medium-high capacity. Survives normal document editing."
        ),
        "zip-extra-field": (
            "Uses the per-file extra field in ZIP directory entries. "
            "Medium capacity. Survives normal zip operations."
        ),
    }

    key = plugin.name.lower().replace(" ", "-").replace("_", "-")
    return notes_map.get(key, "")
