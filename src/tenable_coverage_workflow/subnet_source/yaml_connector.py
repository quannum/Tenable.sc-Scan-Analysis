import ipaddress
from pathlib import Path
from typing import Any

import yaml

from ..models import (
    CoverageTarget,
    NetworkRange,
    PrivateNetworkRange,
    SiteNetworkDefinition,
    ValidationIssue,
    VlanRange,
    YamlConnectorResult,
)


def load_yaml_subnet_repo(
    repo_path: str | Path, audit_logger=None
) -> YamlConnectorResult:
    root = Path(repo_path)
    result = YamlConnectorResult()

    yaml_files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    seen_paths = set()

    for path in yaml_files:
        normalized_path = path.resolve()
        if normalized_path in seen_paths:
            continue
        seen_paths.add(normalized_path)
        result.files_processed += 1

        file_loaded = _load_yaml_file(root, path)
        result.validation_issues.extend(file_loaded["issues"])

        if file_loaded["site_definition"] is not None:
            result.site_definitions.append(file_loaded["site_definition"])

        if file_loaded["coverage_targets"]:
            result.coverage_targets.extend(file_loaded["coverage_targets"])
            if audit_logger:
                audit_logger.emit(
                    "yaml_file_loaded",
                    source_file=file_loaded["source_file"],
                    site_code=file_loaded["site_code"],
                    target_count=len(file_loaded["coverage_targets"]),
                    validation_errors=[
                        issue.message for issue in file_loaded["issues"]
                    ],
                )
                for target in file_loaded["coverage_targets"]:
                    audit_logger.emit(
                        "coverage_target_created",
                        source_file=target.source_file,
                        site_code=target.site_code,
                        target_type=target.target_type,
                        cidr=target.cidr,
                        vlan_name=target.vlan_name,
                        vlan_tag=target.vlan_tag,
                    )
            continue

        result.files_failed += 1
        if audit_logger:
            audit_logger.emit(
                "yaml_file_failed",
                source_file=file_loaded["source_file"],
                site_code=file_loaded["site_code"],
                errors=[issue.message for issue in file_loaded["issues"]],
            )

    return result


def _load_yaml_file(repo_root: Path, path: Path) -> dict[str, Any]:
    source_file = path.relative_to(repo_root).as_posix()
    issues: list[ValidationIssue] = []

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return {
            "source_file": source_file,
            "site_code": None,
            "site_definition": None,
            "coverage_targets": [],
            "issues": [ValidationIssue(source_file=source_file, message=str(exc))],
        }

    if not isinstance(raw, dict):
        return {
            "source_file": source_file,
            "site_code": None,
            "site_definition": None,
            "coverage_targets": [],
            "issues": [
                ValidationIssue(
                    source_file=source_file,
                    message="YAML root must be a mapping/object.",
                )
            ],
        }

    site_code = _as_text(raw.get("site_code")) or path.stem.upper()
    site_name = _as_text(raw.get("name")) or site_code
    description = _as_optional_text(raw.get("description"))
    location = _as_optional_text(raw.get("location"))
    region = _as_optional_text(raw.get("region"))

    public_ranges: list[NetworkRange] = []
    private_ranges: list[PrivateNetworkRange] = []

    public_block = raw.get("public_network_definition")
    if public_block is not None:
        public_range = _parse_network_range(
            source_file=source_file,
            site_code=site_code,
            field_name="public_network_definition",
            block=public_block,
            issues=issues,
        )
        if public_range is not None:
            public_ranges.append(public_range)

    private_block = raw.get("private_network_definition")
    if private_block is not None:
        private_range = _parse_private_network_range(
            source_file=source_file,
            site_code=site_code,
            block=private_block,
            issues=issues,
        )
        if private_range is not None:
            private_ranges.append(private_range)

    if not public_ranges and not private_ranges:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                message=(
                    "No valid public_network_definition or "
                    "private_network_definition entries were found."
                ),
            )
        )
        return {
            "source_file": source_file,
            "site_code": site_code,
            "site_definition": None,
            "coverage_targets": [],
            "issues": issues,
        }

    site_definition = SiteNetworkDefinition(
        source_file=source_file,
        site_name=site_name,
        site_code=site_code,
        description=description,
        location=location,
        region=region,
        public_ranges=public_ranges,
        private_ranges=private_ranges,
    )
    coverage_targets = flatten_site_definition(site_definition)

    return {
        "source_file": source_file,
        "site_code": site_code,
        "site_definition": site_definition,
        "coverage_targets": coverage_targets,
        "issues": issues,
    }


def flatten_site_definition(
    site_definition: SiteNetworkDefinition,
) -> list[CoverageTarget]:
    targets: list[CoverageTarget] = []

    for public_range in site_definition.public_ranges:
        targets.append(
            CoverageTarget(
                target_type="PUBLIC",
                cidr=public_range.cidr,
                site_code=site_definition.site_code,
                site_name=site_definition.site_name,
                location=site_definition.location,
                region=site_definition.region,
                description=public_range.description or site_definition.description,
                source_file=site_definition.source_file,
            )
        )

    for private_range in site_definition.private_ranges:
        targets.append(
            CoverageTarget(
                target_type="PRIVATE_SUPERNET",
                cidr=private_range.cidr,
                site_code=site_definition.site_code,
                site_name=site_definition.site_name,
                location=site_definition.location,
                region=site_definition.region,
                description=private_range.description or site_definition.description,
                source_file=site_definition.source_file,
            )
        )
        for vlan in private_range.vlans:
            targets.append(
                CoverageTarget(
                    target_type="VLAN",
                    cidr=vlan.cidr,
                    site_code=site_definition.site_code,
                    site_name=site_definition.site_name,
                    location=site_definition.location,
                    region=site_definition.region,
                    description=vlan.description or site_definition.description,
                    vlan_name=vlan.name,
                    vlan_tag=vlan.vlan_tag,
                    source_file=site_definition.source_file,
                )
            )

    return targets


def _parse_private_network_range(
    source_file: str,
    site_code: str,
    block: Any,
    issues: list[ValidationIssue],
) -> PrivateNetworkRange | None:
    parsed = _parse_network_range(
        source_file=source_file,
        site_code=site_code,
        field_name="private_network_definition",
        block=block,
        issues=issues,
    )
    if parsed is None:
        return None

    if not isinstance(block, dict):
        return None

    vlans: list[VlanRange] = []
    raw_vlans = block.get("vlans", [])
    if raw_vlans is None:
        raw_vlans = []

    if not isinstance(raw_vlans, list):
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name="private_network_definition.vlans",
                message="private_network_definition.vlans must be a list.",
            )
        )
        raw_vlans = []

    parent_network = ipaddress.ip_network(parsed.cidr, strict=False)

    for index, vlan_block in enumerate(raw_vlans):
        vlan = _parse_vlan_range(
            source_file=source_file,
            site_code=site_code,
            field_name=f"private_network_definition.vlans[{index}]",
            block=vlan_block,
            issues=issues,
        )
        if vlan is None:
            continue

        vlan_network = ipaddress.ip_network(vlan.cidr, strict=False)
        if not vlan_network.subnet_of(parent_network):
            issues.append(
                ValidationIssue(
                    source_file=source_file,
                    site_code=site_code,
                    field_name=f"private_network_definition.vlans[{index}]",
                    message=(
                        f"VLAN CIDR {vlan.cidr} is outside parent private range "
                        f"{parsed.cidr}."
                    ),
                )
            )
            continue

        vlans.append(vlan)

    return PrivateNetworkRange(
        name=parsed.name,
        description=parsed.description,
        cidr=parsed.cidr,
        network=parsed.network,
        prefix_length=parsed.prefix_length,
        subnetmask=parsed.subnetmask,
        vlans=vlans,
    )


def _parse_network_range(
    source_file: str,
    site_code: str,
    field_name: str,
    block: Any,
    issues: list[ValidationIssue],
) -> NetworkRange | None:
    if not isinstance(block, dict):
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"{field_name} must be a mapping/object.",
            )
        )
        return None

    network_value = block.get("network")
    cidr_value = block.get("cidr")
    if network_value in (None, "") or cidr_value in (None, ""):
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"{field_name} must include both network and cidr fields.",
            )
        )
        return None

    normalized = _normalize_cidr(
        source_file=source_file,
        site_code=site_code,
        field_name=field_name,
        network_value=network_value,
        cidr_value=cidr_value,
        issues=issues,
    )
    if normalized is None:
        return None

    return NetworkRange(
        name=_as_optional_text(block.get("name")),
        description=_as_optional_text(block.get("description")),
        cidr=normalized["cidr"],
        network=normalized["network"],
        prefix_length=normalized["prefix_length"],
        subnetmask=_as_optional_text(block.get("subnetmask"))
        or normalized["subnetmask"],
    )


def _parse_vlan_range(
    source_file: str,
    site_code: str,
    field_name: str,
    block: Any,
    issues: list[ValidationIssue],
) -> VlanRange | None:
    parsed = _parse_network_range(
        source_file=source_file,
        site_code=site_code,
        field_name=field_name,
        block=block,
        issues=issues,
    )
    if parsed is None:
        return None

    if not isinstance(block, dict):
        return None

    vlan_name = _as_text(block.get("name"))
    if not vlan_name:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"{field_name} must include a VLAN name.",
            )
        )
        return None

    return VlanRange(
        name=vlan_name,
        vlan_tag=block.get("vlan_tag"),
        description=parsed.description,
        cidr=parsed.cidr,
        network=parsed.network,
        prefix_length=parsed.prefix_length,
        subnetmask=parsed.subnetmask,
    )


def _normalize_cidr(
    source_file: str,
    site_code: str,
    field_name: str,
    network_value: Any,
    cidr_value: Any,
    issues: list[ValidationIssue],
) -> dict[str, Any] | None:
    try:
        network = ipaddress.ip_network(
            f"{str(network_value).strip()}/{str(cidr_value).strip()}",
            strict=False,
        )
    except ValueError as exc:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"Invalid CIDR '{network_value}/{cidr_value}': {exc}",
            )
        )
        return None

    return {
        "cidr": f"{network.network_address}/{network.prefixlen}",
        "network": str(network.network_address),
        "prefix_length": int(network.prefixlen),
        "subnetmask": str(network.netmask),
    }


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_optional_text(value: Any) -> str | None:
    text = _as_text(value)
    return text or None
