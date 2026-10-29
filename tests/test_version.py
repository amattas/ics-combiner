import tomllib
from importlib import metadata
from pathlib import Path

import pytest

from src import _version

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


@pytest.mark.parametrize("installed_version", [None, "9.9.9"])
def test_get_version_prefers_metadata_then_pyproject(monkeypatch, installed_version):
    declared = tomllib.loads(PYPROJECT.read_text())["project"]["version"]

    def fake_version(name):
        assert name == "ics-combiner"
        if installed_version is None:
            raise metadata.PackageNotFoundError(name)
        return installed_version

    monkeypatch.setattr(_version.metadata, "version", fake_version)
    assert _version.get_version() == (installed_version or declared)
