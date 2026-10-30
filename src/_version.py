"""Single source of truth for the version: ``[project] version`` in pyproject.toml.

Reads installed package metadata when the distribution is installed; otherwise
falls back to parsing pyproject.toml at the repo (or image) root.
"""

import tomllib
from importlib import metadata
from pathlib import Path

DIST_NAME = "ics-combiner"


def get_version() -> str:
    try:
        return metadata.version(DIST_NAME)
    except metadata.PackageNotFoundError:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        with pyproject.open("rb") as f:
            return str(tomllib.load(f)["project"]["version"])


__version__ = get_version()
