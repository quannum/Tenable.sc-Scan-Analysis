import re
from dataclasses import replace

from ..exclusion_tags import find_exclusion_tag
from ..models import CoverageTarget, GroupingConfig

_NON_WORD_PATTERN = re.compile(r"[^A-Za-z0-9]+")
_UNDERSCORE_PATTERN = re.compile(r"_+")
_ROLE_ALIAS_MAP = {
    "server": "SERVER",
    "servers": "SERVER",
    "mgmt": "NETWORK",
    "management": "NETWORK",
    "network": "NETWORK",
    "workstation": "END_USER",
    "workstations": "END_USER",
    "enduser": "END_USER",
    "end_user": "END_USER",
    "end-user": "END_USER",
    "user": "END_USER",
    "users": "END_USER",
    "wireless": "WIRELESS",
    "wifi": "WIRELESS",
    "wi_fi": "WIRELESS",
    "wi-fi": "WIRELESS",
    "av": "AV",
    "media": "AV",
}


def normalize_name_part(value: str | None, fallback: str = "Unknown") -> str:
    """Normalize name part"""
    text = str(value or "").strip()
    cleaned = _NON_WORD_PATTERN.sub("_", text)
    cleaned = _UNDERSCORE_PATTERN.sub("_", cleaned).strip("_")
    return cleaned or fallback


def _normalize_optional_name_part(value: str | None) -> str | None:
    """Normalize optional name part"""
    normalized = normalize_name_part(value, fallback="")
    return normalized or None


def classify_vlan_role(vlan_name: str | None) -> str:
    """Classify vlan role"""
    normalized = normalize_name_part(vlan_name, fallback="Standard").lower()
    raw = str(vlan_name or "").strip().lower()

    if "server" in raw or "server" in normalized:
        return "SERVER"
    if (
        "end user" in raw
        or "workstation" in raw
        or raw == "user"
        or "_end_user_" in f"_{normalized}_"
        or "workstation" in normalized
        or normalized == "user"
        or normalized.endswith("_user")
    ):
        return "END_USER"
    if (
        "network" in raw
        or "management" in raw
        or "mgmt" in raw
        or "network" in normalized
        or "management" in normalized
        or "mgmt" in normalized
    ):
        return "NETWORK"
    if "media" in raw or raw == "av" or "media" in normalized or normalized == "av":
        return "AV"
    if (
        "wireless" in raw
        or "wifi" in raw
        or "wi-fi" in raw
        or "wireless" in normalized
        or "wifi" in normalized
        or "wi_fi" in normalized
    ):
        return "WIRELESS"
    return "STANDARD"


def _normalize_role_from_value(value: str | None) -> str:
    """Normalize role from value"""
    normalized = normalize_name_part(value, fallback="STANDARD").upper()
    return _ROLE_ALIAS_MAP.get(normalized.lower(), normalized)


def _role_name_segment(role: str) -> str:
    """Return the readable name segment for a role"""
    known = {
        "SERVER": "Server",
        "END_USER": "End_User",
        "NETWORK": "Network",
        "WIRELESS": "Wireless",
        "AV": "AV",
        "STANDARD": "Standard",
    }
    if role in known:
        return known[role]
    return normalize_name_part(role.title(), fallback="Standard")


def _policy_name_for_role(role: str) -> str:
    """Return proposed policy name for each role"""
    if role == "SERVER":
        return "Credentialed Server Assessment"
    if role == "END_USER":
        return "Credentialed Workstation Assessment"
    if role == "NETWORK":
        return "Network Infrastructure Assessment"
    if role == "AV":
        return "AV / Media Device Assessment"
    if role == "WIRELESS":
        return "Wireless Assessment"
    return f"{_role_name_segment(role).replace('_', ' ')} Assessment"


def _extract_vlan_grouping_tag(
    target: CoverageTarget,
    grouping_config: GroupingConfig,
) -> str | None:
    """Get vlan tag"""
    if target.target_type != "VLAN" or grouping_config.mode != "vlan_tag":
        return None

    prefix = str(grouping_config.vlan_tag_prefix or "").strip().lower()
    if not prefix:
        return None

    for tag in target.tags:
        normalized_tag = str(tag).strip()
        if normalized_tag.lower().startswith(prefix):
            return normalized_tag
    return None


def _classify_vlan_role_from_grouping_tag(
    grouping_tag: str,
    grouping_config: GroupingConfig,
) -> str:
    """Classify vlan role from grouping tag"""
    normalized_tag = str(grouping_tag).strip().lower()
    tag_map = {
        str(key).strip().lower(): _normalize_role_from_value(str(value).strip())
        for key, value in grouping_config.tag_map.items()
        if str(key).strip() and str(value).strip()
    }
    if normalized_tag in tag_map:
        return tag_map[normalized_tag]

    prefix = str(grouping_config.vlan_tag_prefix or "").strip().lower()
    suffix = normalized_tag[len(prefix) :].strip(" -_") if prefix else normalized_tag
    if not suffix:
        return "STANDARD"
    return _normalize_role_from_value(suffix)


def resolve_target_role(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    """Resolve target role"""
    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _extract_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        return _classify_vlan_role_from_grouping_tag(grouping_tag, grouping_config)
    return classify_vlan_role(target.vlan_name)


def build_required_asset_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    """Build required asset name"""
    if target.target_type == "PUBLIC":
        return f"{target.site_code}_Public"
    if target.target_type == "PRIVATE_SUPERNET":
        return f"{target.site_code}_Private_Discovery"

    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _extract_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        role = _classify_vlan_role_from_grouping_tag(grouping_tag, grouping_config)
        return f"{target.site_code}_{_role_name_segment(role)}_VLAN_Group"

    vlan_name = normalize_name_part(target.vlan_name, fallback="VLAN")
    vlan_tag = normalize_name_part(str(target.vlan_tag), fallback="NO_TAG")
    return f"{target.site_code}_{vlan_name}_VLAN_{vlan_tag}"


def _scan_scope_segments(target: CoverageTarget) -> list[str]:
    """Build scan scope in region > site_code > location > global priority."""
    region = _normalize_optional_name_part(target.region)
    site_code = _normalize_optional_name_part(target.site_code)
    location = _normalize_optional_name_part(target.location)

    segments = [segment for segment in (region, site_code or location) if segment]
    return segments or ["Global"]


def _grouped_scan_scope_segments(target: CoverageTarget) -> list[str]:
    """Build grouped VLAN scan scope in site_code > location > global priority."""
    site_code = _normalize_optional_name_part(target.site_code)
    location = _normalize_optional_name_part(target.location)
    return [site_code or location or "Global"]


def _scan_description_segment(target: CoverageTarget, fallback: str) -> str:
    """Return description segment for a scan name"""
    return normalize_name_part(target.description, fallback=fallback)


def _compose_scan_name(
    target: CoverageTarget,
    description_fallback: str,
    purpose: str,
) -> str:
    """Build scan name from its standard parts"""
    return "_".join(
        [
            *_scan_scope_segments(target),
            _scan_description_segment(target, description_fallback),
            purpose,
        ]
    )


def build_required_scan_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    """Build required scan name"""
    if target.target_type == "PUBLIC":
        return _compose_scan_name(
            target,
            description_fallback="Public",
            purpose="Assessment",
        )
    if target.target_type == "PRIVATE_SUPERNET":
        return _compose_scan_name(
            target,
            description_fallback="Private",
            purpose="Discovery",
        )

    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _extract_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        role = _classify_vlan_role_from_grouping_tag(grouping_tag, grouping_config)
        return "_".join(
            [
                *_grouped_scan_scope_segments(target),
                _role_name_segment(role),
                "Assessment",
            ]
        )

    role = resolve_target_role(target, grouping_config)
    return _compose_scan_name(
        target,
        description_fallback=_role_name_segment(role),
        purpose="Assessment",
    )


def build_required_policy_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    """Build required policy name"""
    if target.target_type == "PUBLIC":
        return "Public Facing Assessment"
    if target.target_type == "PRIVATE_SUPERNET":
        return "Discovery"

    role = resolve_target_role(target, grouping_config)
    return _policy_name_for_role(role)


def apply_naming_rules(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> CoverageTarget:
    """Apply naming rules"""
    grouping_config = grouping_config or GroupingConfig()
    if find_exclusion_tag(target.tags):
        return target
    return replace(
        target,
        required_asset_name=(
            target.required_asset_name
            or build_required_asset_name(target, grouping_config)
        ),
        required_scan_name=(
            target.required_scan_name
            or build_required_scan_name(target, grouping_config)
        ),
        required_policy_name=(
            target.required_policy_name
            or build_required_policy_name(target, grouping_config)
        ),
    )


def apply_naming_rules_to_targets(
    targets: list[CoverageTarget],
    grouping_config: GroupingConfig | None = None,
) -> list[CoverageTarget]:
    """Apply naming rules to targets"""
    return [apply_naming_rules(target, grouping_config) for target in targets]
