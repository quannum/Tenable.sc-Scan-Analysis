import re
from dataclasses import replace

from ..exclusion_tags import find_exclusion_tag
from ..models import VLAN_ASSESSMENT_BUCKETS, CoverageTarget, GroupingConfig

# naming rules to keep proposals, coverage checks, and apply operations using
# the same names

_NON_WORD_PATTERN = re.compile(r"[^A-Za-z0-9]+")
_UNDERSCORE_PATTERN = re.compile(r"_+")
_SPACE_PATTERN = re.compile(r"\s+")
_NAME_PREFIX = "ABC Corp"
ASSESSMENT_MAPPING_UNMAPPED = "UNMAPPED"
_DEFAULT_VLAN_TAG_BUCKETS = {
    "vlan-server": "SERVER",
    "vlan-servers": "SERVER",
    "vlan-storage": "SERVER",
    "vlan-other": "SERVER",
    "vlan-environment": "SERVER",
    "vlan-workstation": "WORKSTATION",
    "vlan-workstations": "WORKSTATION",
    "vlan-wireless": "WORKSTATION",
    "vlan-wifi": "WORKSTATION",
    "vlan-wi-fi": "WORKSTATION",
    "vlan-mgmt": "NETWORK",
    "vlan-management": "NETWORK",
    "vlan-network": "NETWORK",
    "vlan-av": "NETWORK",
    "vlan-media": "NETWORK",
}


def normalize_name_part(value: str | None, fallback: str = "Unknown") -> str:
    text = str(value or "").strip()
    cleaned = _NON_WORD_PATTERN.sub("_", text)
    cleaned = _UNDERSCORE_PATTERN.sub("_", cleaned).strip("_")
    return cleaned or fallback

# old function for normalizing names

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


def _role_name_segment(role: str) -> str:
    known = {
        "SERVER": "Server",
        "WORKSTATION": "Workstation",
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


def _get_vlan_grouping_tag(
    target: CoverageTarget,
    grouping_config: GroupingConfig,
) -> str | None:
    return find_vlan_grouping_tag(target.target_type, target.tags, grouping_config)


def _assessment_bucket_for_grouping_tag(
    grouping_tag: str,
    grouping_config: GroupingConfig,
) -> str | None:
    """Return the direct scan bucket assigned to a VLAN grouping tag."""
    normalized_tag = str(grouping_tag).strip().lower()
    configured_bucket = grouping_config.tag_map.get(normalized_tag)
    if configured_bucket is not None:
        return (
            configured_bucket if configured_bucket in VLAN_ASSESSMENT_BUCKETS else None
        )
    return _DEFAULT_VLAN_TAG_BUCKETS.get(normalized_tag)


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
    grouping_tag = _get_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        bucket = _assessment_bucket_for_grouping_tag(grouping_tag, grouping_config)
        if bucket:
            return bucket
        # In VLAN-tag mode, a meaningful tag is itself an explicit grouping.
        # Keep it out of the generic Standard bucket even when it has no
        # configured assessment-bucket alias.
        return normalize_name_part(
            _grouping_tag_name_segment(grouping_tag, grouping_config),
            fallback="VLAN",
        ).upper()
    return classify_vlan_role(target.vlan_name)


def has_explicit_assessment_mapping(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> bool:
    """Return whether a VLAN role has a defined scan and policy mapping."""
    if target.target_type != "VLAN":
        return True

    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _get_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        return True
    return classify_vlan_role(target.vlan_name) != "STANDARD"


def vlan_role_name(
    target: CoverageTarget,
    grouping_config: GroupingConfig | None = None,
) -> str:
    """Return the readable role supplied by the VLAN name or grouping tag."""
    grouping_config = grouping_config or GroupingConfig()
    grouping_tag = _get_vlan_grouping_tag(target, grouping_config)
    if grouping_tag:
        return _grouping_tag_name_segment(grouping_tag, grouping_config)
    return _display_name_part(target.vlan_name, fallback="VLAN")


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
    grouping_tag = _get_vlan_grouping_tag(target, grouping_config)
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

    if not has_explicit_assessment_mapping(target, grouping_config):
        classification = dict(target.scan_classification)
        classification.update(
            {
                "vlan_role": vlan_role_name(target, grouping_config),
                "assessment_mapping": ASSESSMENT_MAPPING_UNMAPPED,
                "review_required": True,
            }
        )
        return replace(
            target,
            required_asset_name=(
                target.required_asset_name
                or build_required_asset_name(target, grouping_config)
            ),
            scan_classification=classification,
        )

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
