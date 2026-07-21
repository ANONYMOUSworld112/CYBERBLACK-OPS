import tempfile, pytest, yaml
from pathlib import Path
from cyberblack.registry import ToolRegistry, load_registry, is_installed, refresh_status_cache, _cached_is_installed


@pytest.fixture
def data_dir():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        cat = d / "categories"
        cat.mkdir()
        with open(cat / "01-test.yaml", "w") as f:
            yaml.dump({
                "id": "1", "name": "Scan", "icon": "N", "color": "cyan",
                "description": "desc",
                "tools": [{"name": "Nmap", "binary": "nmap", "tagline": "t",
                           "description": "d", "install": "i", "risk": "medium",
                           "syntax": "s", "flags": [], "examples": [], "tips": []}],
            }, f)
        yield cat


class TestRegistry:
    def test_empty(self):
        r = ToolRegistry(tuple())
        assert len(r) == 0

    def test_load(self, data_dir):
        r = load_registry(data_dir)
        assert len(r) == 1
        assert r.category_by_id("1").name == "Scan"

    def test_all_tools(self, data_dir):
        r = load_registry(data_dir)
        assert len(list(r.all_tools())) == 1

    def test_missing_dir(self):
        with pytest.raises(Exception):
            load_registry(Path("/nonexistent"))

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "categories"
            d.mkdir()
            with pytest.raises(Exception):
                load_registry(d)

    def test_bad_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "categories"
            d.mkdir()
            (d / "bad.yaml").write_text("{bad: *yaml")
            with pytest.raises(Exception):
                load_registry(d)


class TestIsInstalled:
    def test_known(self):
        refresh_status_cache()
        assert isinstance(is_installed("python"), bool)

    def test_unknown(self):
        refresh_status_cache()
        assert is_installed("nonexistent-xyzzy") is False

    def test_cache_clear(self):
        refresh_status_cache()
        _cached_is_installed.cache_clear()
        assert _cached_is_installed.cache_info().currsize == 0
