from typing import Any

from ..io.parsing import parse_string_mapping
from .models import GroupingConfig


def build_grouping_config(
    mode_value: Any,
    prefix_value: Any,
    tag_map_value: Any,
) -> GroupingConfig:
    """Build grouping config by vlan_tag"""
    mode = str(mode_value or "default").strip() or "default"
    if mode not in {"default", "vlan_tag"}:
        raise ValueError("grouping_mode must be 'default' or 'vlan_tag'.")

    prefix = str(prefix_value or "vlan-").strip() or "vlan-"
    return GroupingConfig(
        mode=mode,
        vlan_tag_prefix=prefix,
        tag_map=parse_string_mapping(tag_map_value),
    )
