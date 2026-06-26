import re
from dataclasses import replace

from ..models import CoverageTarget

_NON_WORD_PATTERN = re.compile(r"[^A-Za-z0-9]+")
_UNDERSCORE_PATTERN = re.compile(r"_+")


def normalize_name_part(value: str | None, fallback: str = "Unknown") -> str:
    text = str(value or "").strip()
    cleaned = _NON_WORD_PATTERN.sub("_", text)
    cleaned = _UNDERSCORE_PATTERN.sub("_", cleaned).strip("_")
    return cleaned or fallback


def normalize_region_name(region: str | None) -> str:
    return normalize_name_part(region, fallback="Global")


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
    return "STANDARD"


def build_required_asset_name(target: CoverageTarget) -> str:
    if target.target_type == "PUBLIC":
        return f"{target.site_code}_Public"
    if target.target_type == "PRIVATE_SUPERNET":
        return f"{target.site_code}_Private_Discovery"

    vlan_name = normalize_name_part(target.vlan_name, fallback="VLAN")
    vlan_tag = normalize_name_part(str(target.vlan_tag), fallback="NO_TAG")
    return f"{target.site_code}_{vlan_name}_VLAN_{vlan_tag}"


def build_required_scan_name(target: CoverageTarget) -> str:
    if target.target_type == "PUBLIC":
        return "Public_External_Assessment"
    if target.target_type == "PRIVATE_SUPERNET":
        return f"{normalize_region_name(target.region)}_Discovery"

    region_name = normalize_region_name(target.region)
    role = classify_vlan_role(target.vlan_name)
    if role == "SERVER":
        return f"{region_name}_Server_Assessment"
    if role == "END_USER":
        return f"{region_name}_End_User_Assessment"
    if role == "NETWORK":
        return f"{region_name}_Network_Assessment"
    if role == "AV":
        return f"{region_name}_AV_Assessment"
    return f"{region_name}_Standard_Assessment"


def build_required_policy_name(target: CoverageTarget) -> str:
    if target.target_type == "PUBLIC":
        return "Public Facing Assessment"
    if target.target_type == "PRIVATE_SUPERNET":
        return "Discovery"

    role = classify_vlan_role(target.vlan_name)
    if role == "SERVER":
        return "Credentialed Server Assessment"
    if role == "END_USER":
        return "Credentialed Workstation Assessment"
    if role == "NETWORK":
        return "Network Infrastructure Assessment"
    if role == "AV":
        return "AV / Media Device Assessment"
    return "Standard Assessment"


def apply_naming_rules(target: CoverageTarget) -> CoverageTarget:
    return replace(
        target,
        required_asset_name=build_required_asset_name(target),
        required_scan_name=build_required_scan_name(target),
        required_policy_name=build_required_policy_name(target),
    )


def apply_naming_rules_to_targets(
    targets: list[CoverageTarget],
) -> list[CoverageTarget]:
    return [apply_naming_rules(target) for target in targets]
