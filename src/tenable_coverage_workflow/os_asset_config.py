from typing import Any, Callable

from ..io.parsing import parse_string_mapping
from .models import OsAssetClassification

ScalarGetter = Callable[[str, str | None, Any], Any]

DEFAULT_OS_ASSET_CLASSIFICATIONS = (
    OsAssetClassification(name="Windows", os_contains="Windows"),
    OsAssetClassification(name="Linux", os_contains="Linux"),
)


def build_os_asset_classifications_from_settings(
    scalar_getter: ScalarGetter,
) -> tuple[OsAssetClassification, ...]:
    """Load OS asset groups from a name-to-OS-contains mapping.

    An omitted setting creates the standard Windows and Linux assets. Set an
    empty mapping to disable OS asset proposals, or add more mappings for other
    classifications.
    """
    raw = scalar_getter("os_asset_classifications", "OS_ASSET_CLASSIFICATIONS", None)
    if raw is None:
        return DEFAULT_OS_ASSET_CLASSIFICATIONS

    mapping = parse_string_mapping(raw)
    classifications = tuple(
        OsAssetClassification(name=name, os_contains=os_contains)
        for name, os_contains in mapping.items()
        if name.strip() and os_contains.strip()
    )
    if len(classifications) != len(mapping):
        raise ValueError(
            "os_asset_classifications requires non-empty classification names "
            "and OS values"
        )
    return classifications
