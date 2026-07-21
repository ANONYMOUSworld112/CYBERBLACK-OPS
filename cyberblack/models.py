from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class RegistryLoadError(Exception):
    pass


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def color(self) -> str:
        return {
            RiskLevel.LOW: "bright_green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red",
        }[self]


@dataclass(slots=True, frozen=True)
class FlagDoc:
    flag: str
    description: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "FlagDoc":
        return cls(flag=str(data["flag"]), description=str(data["description"]))


@dataclass(slots=True, frozen=True)
class UsageExample:
    description: str
    command: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "UsageExample":
        return cls(description=str(data["description"]), command=str(data["command"]))


@dataclass(slots=True, frozen=True)
class Tool:
    name: str
    binary: str
    tagline: str
    description: str
    install: str
    risk: RiskLevel
    syntax: str
    flags: tuple[FlagDoc, ...]
    examples: tuple[UsageExample, ...]
    tips: tuple[str, ...]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "Tool":
        try:
            return cls(
                name=data["name"],
                binary=data["binary"],
                tagline=data["tagline"],
                description=data["description"],
                install=data["install"],
                risk=RiskLevel(data["risk"]),
                syntax=data["syntax"],
                flags=tuple(FlagDoc.from_mapping(f) for f in data["flags"]),
                examples=tuple(UsageExample.from_mapping(e) for e in data["examples"]),
                tips=tuple(data["tips"]),
            )
        except KeyError as exc:
            name = data.get("name", "<unnamed>")
            raise RegistryLoadError(f"Tool {name!r} is missing field {exc}") from exc
        except ValueError as exc:
            name = data.get("name", "<unnamed>")
            raise RegistryLoadError(f"Tool {name!r} has an invalid value: {exc}") from exc


@dataclass(slots=True, frozen=True)
class ToolCategory:
    id: str
    name: str
    icon: str
    color: str
    description: str
    tools: tuple[Tool, ...]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ToolCategory":
        try:
            return cls(
                id=str(data["id"]),
                name=data["name"],
                icon=data["icon"],
                color=data["color"],
                description=data["description"],
                tools=tuple(Tool.from_mapping(t) for t in data["tools"]),
            )
        except KeyError as exc:
            name = data.get("name", "<unnamed>")
            raise RegistryLoadError(f"Category {name!r} is missing field {exc}") from exc
