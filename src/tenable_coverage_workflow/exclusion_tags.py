"""Helper for ranges with exclude tags"""

from collections.abc import Iterable

EXCLUDE_TAG = "exclude"


def find_exclusion_tag(tags: Iterable[object]) -> str | None:
    """Look for exclude tag in subnet-as-code definitions"""

    for tag in tags:
        normalized = str(tag).strip()
        if normalized.casefold() == EXCLUDE_TAG:
            return normalized
    return None
