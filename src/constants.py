from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # pyright: ignore[reportMissingImports]


def _load_version() -> str:
    """Load the package version"""
    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    try:
        with pyproject_path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError:
        data = {}
    project = data.get("project", {})
    if isinstance(project, dict) and project.get("version"):
        return str(project["version"])

    try:
        return version("tenable-sc-scan-analysis")
    except PackageNotFoundError:
        return "0+unknown"


VERSION = _load_version()


INCLUDE = "Include"
EXCLUDE = "Exclude"

STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"
STATUS_GAP = "GAP"
