import pytest
from cyberblack.models import FlagDoc, RegistryLoadError, RiskLevel, Tool, ToolCategory, UsageExample


class TestRiskLevel:
    def test_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_colors(self):
        assert RiskLevel.LOW.color == "bright_green"
        assert RiskLevel.MEDIUM.color == "yellow"
        assert RiskLevel.HIGH.color == "red"
        assert RiskLevel.CRITICAL.color == "bold red"

    def test_from_value(self):
        assert RiskLevel("low") is RiskLevel.LOW

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            RiskLevel("invalid")


class TestTool:
    def test_from_mapping(self):
        t = Tool.from_mapping({
            "name": "Nmap", "binary": "nmap", "tagline": "Mapper",
            "description": "Port scanner", "install": "apt install",
            "risk": "medium", "syntax": "nmap {target}",
            "flags": [{"flag": "-sS", "description": "SYN"}],
            "examples": [{"description": "Quick", "command": "nmap 1.2.3.4"}],
            "tips": ["tip1"],
        })
        assert t.name == "Nmap"
        assert t.risk is RiskLevel.MEDIUM
        assert len(t.flags) == 1

    def test_missing_field(self):
        with pytest.raises(RegistryLoadError):
            Tool.from_mapping({"name": "X", "binary": "x", "tagline": "x",
                "description": "x", "install": "x", "risk": "low",
                "flags": [], "examples": [], "tips": []})

    def test_frozen(self):
        t = Tool(name="A", binary="a", tagline="a", description="a", install="a",
                 risk=RiskLevel.LOW, syntax="a", flags=(), examples=(), tips=())
        with pytest.raises(AttributeError):
            t.name = "B"


class TestCategory:
    def test_from_mapping(self):
        c = ToolCategory.from_mapping({
            "id": "1", "name": "Net", "icon": "N", "color": "cyan",
            "description": "desc",
            "tools": [{"name": "X", "binary": "x", "tagline": "x", "description": "x",
                       "install": "x", "risk": "low", "syntax": "x",
                       "flags": [], "examples": [], "tips": []}],
        })
        assert c.name == "Net"
        assert len(c.tools) == 1
