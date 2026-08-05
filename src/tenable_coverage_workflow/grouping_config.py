from typing import Any

from ..io.parsing import parse_string_mapping
from .models import VLAN_ASSESSMENT_BUCKETS, GroupingConfig


def build_grouping_config(
    mode_value: Any,
    prefix_value: Any,
    tag_map_value: Any,
) -> GroupingConfig:
    """Build grouping config"""
    mode = str(mode_value or "default").strip() or "default"
    if mode not in {"default", "vlan_tag"}:
        raise ValueError("grouping_mode must be 'default' or 'vlan_tag'.")

    prefix = str(prefix_value or "vlan-").strip() or "vlan-"
    tag_map = {
        str(key).strip(): str(value).strip().upper()
        for key, value in parse_string_mapping(tag_map_value).items()
        if str(key).strip() and str(value).strip()
    }
    invalid_buckets = sorted(set(tag_map.values()) - VLAN_ASSESSMENT_BUCKETS)
    if mode == "vlan_tag" and invalid_buckets:
        allowed = ", ".join(sorted(VLAN_ASSESSMENT_BUCKETS))
        invalid = ", ".join(invalid_buckets)
        raise ValueError(
            "grouping_tag_map values must be scan buckets: "
            f"{allowed}. Invalid: {invalid}."
        )

    return GroupingConfig(
        mode=mode,
        vlan_tag_prefix=prefix,
        tag_map=tag_map,
    )
