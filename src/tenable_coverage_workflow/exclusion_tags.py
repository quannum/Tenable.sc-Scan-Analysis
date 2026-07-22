"""Helper for ranges with exclude tags."""

from collections.abc import Iterable

EXCLUDE_TAG = "exclude"


def find_exclusion_tag(tags: Iterable[object]) -> str | None:
    """Return the sac source tag that marks a target range as excluded."""

    for tag in tags:
        normalized = str(tag).strip()
        if normalized.casefold() == EXCLUDE_TAG:
            return normalized
    return None
