"""
StegoForge Method Plugin Interface — the extensibility surface for steg methods.

Every carrier format handler implements this ABC.  Plugins self-register
via the registry functions here, and the Method Advisor Agent discovers
them at startup.  Adding a new format = one MethodPlugin subclass,
zero changes to core/ (§4.3, FR-10).

Spec reference: §4.3 Plugin Architecture (Strategy Pattern)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, MethodID


class MethodPlugin(ABC):
    """
    Abstract base for all steganographic embedding/extraction methods.

    Subclasses MUST define:
        name: Human-readable name shown in the interactive menu.
        method_id: Unique MethodID enum value stored in the envelope.
        applicable_types: List of MIME types this method can handle.
            Use '*' as a wildcard for universal methods (e.g. EOF-append).

    Subclasses MUST implement:
        capacity_bytes(): Pre-flight capacity calculation.
        embed(): Conceal envelope bytes into the carrier.
        extract(): Recover envelope bytes from a stego file.
    """

    name: ClassVar[str]
    method_id: ClassVar[MethodID]
    applicable_types: ClassVar[list[str]]

    @abstractmethod
    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        """
        Calculate the maximum payload capacity in bytes for the given carrier.

        This is called BEFORE the operator provides a payload, so it must
        be fast (no heavy I/O beyond what's needed to read dimensions/headers).

        The returned value should account for envelope overhead — i.e.,
        it's the max *ciphertext* size that can be concealed, not the
        raw carrier modification budget.

        Args:
            carrier: Profile of the carrier file.

        Returns:
            Maximum embeddable payload size in bytes.
        """
        ...

    @abstractmethod
    def embed(
        self,
        carrier_path: Path,
        envelope: bytes,
        out_path: Path,
    ) -> None:
        """
        Conceal envelope bytes into the carrier, writing the result to out_path.

        The envelope is an opaque byte blob (already encrypted + wrapped).
        This method MUST NOT interpret or modify envelope contents — it only
        needs to hide them inside the carrier format.

        Args:
            carrier_path: Path to the original carrier file.
            envelope: Raw envelope bytes to conceal.
            out_path: Path where the stego output file should be written.

        Raises:
            CapacityExceededError: If envelope is larger than capacity.
            StegoForgeError: On any format-specific I/O or processing error.
        """
        ...

    @abstractmethod
    def extract(self, stego_path: Path) -> bytes:
        """
        Recover envelope bytes from a stego file.

        Args:
            stego_path: Path to the stego file.

        Returns:
            Raw envelope bytes (to be parsed by the Envelope Agent).

        Raises:
            CorruptEnvelopeError: If no valid envelope can be found.
            StegoForgeError: On any format-specific I/O or processing error.
        """
        ...


# ---------------------------------------------------------------------------
# Plugin Registry
# ---------------------------------------------------------------------------

_METHOD_REGISTRY: dict[str, MethodPlugin] = {}


def register_method(plugin: MethodPlugin) -> None:
    """Register a method plugin instance in the global registry."""
    key = plugin.name.lower().replace(" ", "-").replace("_", "-")
    _METHOD_REGISTRY[key] = plugin


def get_method(name: str) -> MethodPlugin | None:
    """Look up a registered method by its registry key."""
    return _METHOD_REGISTRY.get(name.lower().replace(" ", "-").replace("_", "-"))


def get_all_methods() -> dict[str, MethodPlugin]:
    """Return a copy of the full method registry."""
    return dict(_METHOD_REGISTRY)


def get_methods_for_mime(mime_type: str) -> list[MethodPlugin]:
    """
    Return all registered methods that can handle the given MIME type.

    Methods with '*' in their applicable_types match everything (e.g. EOF-append).
    """
    results: list[MethodPlugin] = []
    for plugin in _METHOD_REGISTRY.values():
        if "*" in plugin.applicable_types or mime_type in plugin.applicable_types:
            results.append(plugin)
    return results


def get_method_by_id(method_id: MethodID) -> MethodPlugin | None:
    """Look up a registered method by its MethodID enum value."""
    for plugin in _METHOD_REGISTRY.values():
        if plugin.method_id == method_id:
            return plugin
    return None
