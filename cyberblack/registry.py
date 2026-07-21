from __future__ import annotations

import functools
import shutil
from pathlib import Path

import yaml

from .models import RegistryLoadError, ToolCategory


class ToolRegistry:
    def __init__(self, categories: tuple[ToolCategory, ...]) -> None:
        self._categories = categories
        self._by_id = {c.id: c for c in categories}

    @property
    def categories(self) -> tuple[ToolCategory, ...]:
        return self._categories

    def category_by_id(self, category_id: str) -> ToolCategory | None:
        return self._by_id.get(category_id)

    def all_tools(self):
        for c in self._categories:
            yield from c.tools

    def __len__(self) -> int:
        return len(self._categories)


def _default_data_dir() -> Path:
    return Path(__file__).parent / "data" / "categories"


def load_registry(data_dir: Path | None = None) -> ToolRegistry:
    directory = data_dir or _default_data_dir()
    if not directory.is_dir():
        raise RegistryLoadError(f"Data directory not found: {directory}")

    categories: list[ToolCategory] = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RegistryLoadError(f"Invalid YAML in {path.name}: {exc}") from exc
        if not isinstance(raw, dict):
            raise RegistryLoadError(f"{path.name} did not parse to a mapping")
        categories.append(ToolCategory.from_mapping(raw))

    if not categories:
        raise RegistryLoadError(f"No category files found in {directory}")

    categories.sort(key=lambda c: int(c.id) if c.id.isdigit() else 999)
    return ToolRegistry(tuple(categories))


@functools.lru_cache(maxsize=None)
def _cached_is_installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def is_installed(binary: str) -> bool:
    return _cached_is_installed(binary)


def refresh_status_cache() -> None:
    _cached_is_installed.cache_clear()
