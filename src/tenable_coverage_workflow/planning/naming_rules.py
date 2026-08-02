import re
from dataclasses import replace

from ..exclusion_tags import find_exclusion_tag
from ..models import CoverageTarget, GroupingConfig

# naming rules to keep proposals, coverage checks, and apply operations using
# the same names

_NON_WORD_PATTERN = re.compile(r"[^A-Za-z0-9]+")
_UNDERSCORE_PATTERN = re.compile(r"_+")
_SPACE_PATTERN = re.compile(r"\s+")
_NAME_PREFIX = "ABC Corp"
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
    text = str(value or "").strip()
    cleaned = _NON_WORD_PATTERN.sub("_", text)
    cleaned = _UNDERSCORE_PATTERN.sub("_", cleaned).strip("_")
    return cleaned or fallback


# clean up and standardize display names, site codes, and vlan roles/tags
# used in scan / asset / policy name builders below
def _display_name_part(value: str | None, fallback: str = "Unknown") -> str:
    text = str(value or "").strip()
    cleaned = _NON_WORD_PATTERN.sub(" ", text)
    cleaned = _SPACE_PATTERN.sub(" ", cleaned).strip()
    return cleaned or fallback


def _site_code_prefix(site_code: str | None) -> str:
    """Return an uppercase site code for generated names"""
    return _display_name_part(site_code, fallback="Global").upper()


def _scan_site_name(target: CoverageTarget) -> str:
    """Return site name segment used in scan names"""
    if str(target.site_code or "").strip():
        return _site_code_prefix(target.site_code)
    return _display_name_part(target.location, fallback="Global")


def classify_vlan_role(vlan_name: str | None) -> str:
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
    normalized = normalize_name_part(value, fallback="STANDARD").upper()
    return _ROLE_ALIAS_MAP.get(normalized.lower(), normalized)


def _role_name_segment(role: str) -> str:
    known = {
        "SERVER": "Server",
        "END_USER": "Workstation",
        "NETWORK": "Network",
        "WIRELESS": "Wireless",
        "AV": "AV",
        "STANDARD": "Standard",
    }
    if role in known:
        return known[role]
    return _display_name_part(role.title(), fallback="Standard")


def _policy_name_for_role(role: str) -> str:
    """Return proposed policy name for each role"""
    if role == "NETWORK":
        return "Network Infrastructure Assessment"
    if role == "AV":
        return "AV / Media Device Assessment"
    return "Basic Assessment Policy"


def find_vlan_grouping_tag(
    target_type: str,
    tags: list[str],
    grouping_config: GroupingConfig,
) -> str | None:
    if target_type != "VLAN" or grouping_config.mode != "vlan_tag":
        return None

    prefix = str(grouping_config.vlan_tag_prefix or "").strip().lower()
    if not prefix:
        return None

    for tag in tags:
        normalized_tag = str(tag).strip()
        if normalized_tag.lower().startswith(prefix):
            return normalized_tag
    return None


def _extract_vlan_grouping_tag(
    target: CoverageTarget,
    grouping_config: GroupingConfig,
) -> str | None:
    return find_vlan_grouping_tag(target.target_type, target.tags, grouping_config)


def _classify_vlan_role_from_grouping_tag(
    grouping_tag: str,
    grouping_config: GroupingConfig,
) -> str:
    normalized_tag = str(grouping_tag).strip().lower()
    tag_map = {
        str(key).strip().lower(): _normalize_role_from_value(str(value).strip())
        for key, value in grouping_config.tag_map.items()
        if str(key).strip() and str(value).strip()
    }
    if normalized_tag in tag_map:
        # if using config file, tag map in config wins over
        # default vlan tags
        return tag_map[normalized_tag]

    prefix = str(grouping_config.vlan_tag_prefix or "").strip().lower()
    matched_prefix = prefix if prefix and normalized_tag.startswith(prefix) else ""
    suffix = (
        normalized_tag[len(matched_prefix) :].strip(" -_")
        if matched_prefix
        else normalized_tag
    )
    # this might need to be modified
    # confirm with it if this is how vlans should be grouped
    if suffix in {"server", "servers", "storage", "other", "environment"}:
        return "SERVER"
    if suffix in {"workstation", "workstations", "wireless", "wifi", "wi-fi"}:
        return "END_USER"
    if not suffix:
        return "STANDARD"
    return _normalize_role_from_value(suffix)


def _grouping_tag_name_segment(
    grouping_tag: str,
    grouping_config: GroupingConfig,
) -> str:
    """Return the readable group name from a VLAN tag"""
    normalized_tag = str(grouping_tag).strip().lower()
    prefix = str(grouping_config.vlan_tag_prefix or "").strip().lower()
    matched_prefix = prefix if prefix and normalized_tag.startswith(prefix) else ""
    suffix = normalized_tag[len(matched_prefix) :] if matched_prefix else normalized_tag
    return _display_name_part(suffix, fallback="VLAN").title()


def resolve_target_role(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _extract_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        return _classify_vlan_role_from_grouping_tag(grouping_tag, grouping_config)
    return classify_vlan_role(target.vlan_name)


def build_required_asset_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    site_code = _site_code_prefix(target.site_code)
    if target.target_type == "PUBLIC":
        return f"{_NAME_PREFIX} {site_code} Public"
    if target.target_type == "PRIVATE_SUPERNET":
        return f"{_NAME_PREFIX} {site_code} Private Discovery"

    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _extract_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        # Asset groups stay separate by tag even when their scans share a role
        group_name = _grouping_tag_name_segment(grouping_tag, grouping_config)
        return f"{_NAME_PREFIX} {site_code} VLAN {group_name}"

    vlan_name = _display_name_part(target.vlan_name, fallback="VLAN")
    vlan_tag = _display_name_part(str(target.vlan_tag), fallback="No Tag")
    return f"{_NAME_PREFIX} {site_code} VLAN {vlan_name} {vlan_tag}"


def build_required_scan_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    site_identifier = _scan_site_name(target)
    if target.target_type == "PUBLIC":
        return f"{_NAME_PREFIX} Assessment {site_identifier} Public"
    if target.target_type == "PRIVATE_SUPERNET":
        return f"{_NAME_PREFIX} Discovery {site_identifier} Private"

    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _extract_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        role = _classify_vlan_role_from_grouping_tag(grouping_tag, grouping_config)
        return f"{_NAME_PREFIX} Assessment {site_identifier} {_role_name_segment(role)}"

    role = resolve_target_role(target, grouping_config)
    return f"{_NAME_PREFIX} Assessment {site_identifier} {_role_name_segment(role)}"


def build_required_policy_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
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
    return [apply_naming_rules(target, grouping_config) for target in targets]
