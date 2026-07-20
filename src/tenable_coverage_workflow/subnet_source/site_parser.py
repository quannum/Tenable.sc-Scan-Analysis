import ipaddress
from typing import Any

from ..models import (
    NetworkRange,
    PrivateNetworkRange,
    SiteNetworkDefinition,
    ValidationIssue,
    VlanRange,
)


def extract_site_objects(payload: Any) -> list[Any] | None:
    """Extract site objects"""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return None

    site_definition = payload.get("site_definition")
    if isinstance(site_definition, list):
        return site_definition
    if isinstance(site_definition, dict):
        return [site_definition]

    for key in ("sites", "locations", "data", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested_site_definition = value.get("site_definition")
            if isinstance(nested_site_definition, list):
                return nested_site_definition
            if isinstance(nested_site_definition, dict):
                return [nested_site_definition]
            for nested_key in ("sites", "locations", "items", "data"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    return nested
    return [payload]


def parse_site_object(
    raw: Any, source_file: str
) -> tuple[SiteNetworkDefinition | None, list[ValidationIssue]]:
    """Parse site object"""
    issues: list[ValidationIssue] = []
    if not isinstance(raw, dict):
        return None, [ValidationIssue(source_file, "Site entry must be an object.")]

    site_code = _text(raw.get("site_code") or raw.get("code"))
    if not site_code:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                message="site_code is required.",
                field_name="site_code",
            )
        )
        return None, issues

    site_name = _text(raw.get("site_name") or raw.get("name")) or site_code

    public_ranges: list[NetworkRange] = []
    for index, value in enumerate(
        _as_list(
            raw.get(
                "public_ranges",
                raw.get("public_networks", raw.get("public_network_definition")),
            )
        )
    ):
        public_ranges.extend(
            _parse_public_ranges(
                value,
                source_file=source_file,
                site_code=site_code,
                field_name=f"public_ranges[{index}]",
                issues=issues,
            )
        )

    private_ranges: list[PrivateNetworkRange] = []
    for index, value in enumerate(
        _as_list(
            raw.get(
                "private_ranges",
                raw.get("private_networks", raw.get("private_network_definition")),
            )
        )
    ):
        private_ranges.extend(
            _parse_private_ranges(
                value,
                source_file=source_file,
                site_code=site_code,
                field_name=f"private_ranges[{index}]",
                issues=issues,
            )
        )

    if not public_ranges and not private_ranges:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                message="Site contains no valid network ranges.",
            )
        )
        return None, issues

    tags = _coerce_tags(
        raw.get("tags"),
        source_file=source_file,
        site_code=site_code,
        field_name="tags",
        issues=issues,
    )
    classification = raw.get("scan_classification", raw.get("scan_metadata", {}))
    if not isinstance(classification, dict):
        classification = {"value": classification}

    return (
        SiteNetworkDefinition(
            source_file=source_file,
            site_name=site_name,
            site_code=site_code,
            description=_optional(raw.get("description")),
            location=_optional(raw.get("location")),
            region=_optional(raw.get("region")),
            timezone=_optional(raw.get("timezone")),
            site_type=_optional(raw.get("site_type")),
            utc_offset=_optional(raw.get("utc_offset")),
            tags=tags,
            environment=_optional(raw.get("environment")),
            business_function=_optional(
                raw.get("business_function") or raw.get("function")
            ),
            scan_classification=classification,
            public_ranges=public_ranges,
            private_ranges=private_ranges,
            source_metadata=_source_metadata(
                raw,
                {
                    "site_code",
                    "code",
                    "site_name",
                    "name",
                    "description",
                    "location",
                    "region",
                    "timezone",
                    "site_type",
                    "utc_offset",
                    "tags",
                    "environment",
                    "business_function",
                    "function",
                    "scan_classification",
                    "scan_metadata",
                    "public_ranges",
                    "public_networks",
                    "public_network_definition",
                    "private_ranges",
                    "private_networks",
                    "private_network_definition",
                },
            ),
        ),
        issues,
    )


def _parse_public_ranges(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[NetworkRange]:
    """Parse public ranges"""
    if isinstance(value, dict) and isinstance(value.get("subnets"), list):
        ranges: list[NetworkRange] = []
        for index, subnet in enumerate(value["subnets"]):
            ranges.extend(
                _parse_network_blocks(
                    subnet,
                    source_file=source_file,
                    site_code=site_code,
                    field_name=f"{field_name}.subnets[{index}]",
                    issues=issues,
                    default_name_keys=("display_name", "vlan_name", "name"),
                    default_description_keys=("description", "display_name"),
                )
            )
        if ranges:
            return ranges

    if isinstance(value, dict) and value.get("supernet") is not None:
        return _parse_network_blocks(
            value.get("supernet"),
            source_file=source_file,
            site_code=site_code,
            field_name=f"{field_name}.supernet",
            issues=issues,
        )
    return _parse_network_blocks(
        value,
        source_file=source_file,
        site_code=site_code,
        field_name=field_name,
        issues=issues,
    )


def _parse_private_ranges(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[PrivateNetworkRange]:
    """Parse private ranges"""
    outer_tags: list[str] = []
    outer_metadata: dict[str, object] = {}
    if isinstance(value, dict) and value.get("supernet") is not None:
        parent_input = value.get("supernet")
        raw_vlans = value.get("vlans", value.get("subnets", []))
        outer_tags = _coerce_tags(
            value.get("tags"),
            source_file=source_file,
            site_code=site_code,
            field_name=f"{field_name}.tags",
            issues=issues,
        )
        outer_metadata = _source_metadata(
            value,
            {"supernet", "vlans", "subnets", "tags"},
        )
    else:
        parent_input = value
        raw_vlans = value.get("vlans", []) if isinstance(value, dict) else []

    if raw_vlans is None:
        raw_vlans = []
    if not isinstance(raw_vlans, list):
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=f"{field_name}.vlans",
                message=f"{field_name}.vlans must be a list.",
            )
        )
        raw_vlans = []

    parent_ranges = _parse_network_blocks(
        parent_input,
        source_file=source_file,
        site_code=site_code,
        field_name=(
            f"{field_name}.supernet"
            if isinstance(value, dict) and value.get("supernet") is not None
            else field_name
        ),
        issues=issues,
    )

    private_ranges: list[PrivateNetworkRange] = []
    for parent in parent_ranges:
        parent_network = ipaddress.ip_network(parent.cidr, strict=False)
        vlans: list[VlanRange] = []
        for index, raw_vlan in enumerate(raw_vlans):
            vlan_field = f"{field_name}.vlans[{index}]"
            for vlan in _parse_vlan_blocks(
                raw_vlan,
                source_file=source_file,
                site_code=site_code,
                field_name=vlan_field,
                issues=issues,
            ):
                vlan_network = ipaddress.ip_network(vlan.cidr, strict=False)
                if isinstance(parent_network, ipaddress.IPv4Network) and isinstance(
                    vlan_network, ipaddress.IPv4Network
                ):
                    vlan_is_child = vlan_network.subnet_of(parent_network)
                elif isinstance(parent_network, ipaddress.IPv6Network) and isinstance(
                    vlan_network, ipaddress.IPv6Network
                ):
                    vlan_is_child = vlan_network.subnet_of(parent_network)
                else:
                    vlan_is_child = False
                if not vlan_is_child:
                    issues.append(
                        ValidationIssue(
                            source_file=source_file,
                            site_code=site_code,
                            field_name=vlan_field,
                            message=(
                                f"VLAN CIDR {vlan.cidr} is outside parent private "
                                f"range {parent.cidr}."
                            ),
                        )
                    )
                    continue
                vlans.append(vlan)

        private_ranges.append(
            PrivateNetworkRange(
                name=parent.name,
                description=parent.description,
                cidr=parent.cidr,
                network=parent.network,
                prefix_length=parent.prefix_length,
                subnetmask=parent.subnetmask,
                tags=_merge_tags(parent.tags, outer_tags),
                source_metadata={**outer_metadata, **parent.source_metadata},
                vlans=vlans,
            )
        )
    return private_ranges


def _parse_vlan_blocks(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[VlanRange]:
    """Parse vlan blocks"""
    name = ""
    vlan_tag = None
    routing = None
    gateway = None
    dhcp_start = None
    dhcp_end = None
    ip_addresses: list[dict[str, object]] = []
    tags: list[str] = []
    metadata: dict[str, object] = {}

    if isinstance(value, dict):
        name = _text(
            value.get("name") or value.get("vlan_name") or value.get("display_name")
        )
        vlan_tag = value.get("vlan_id", value.get("vlan_tag", value.get("vlan")))
        routing = _optional(value.get("routing"))
        gateway = _optional(value.get("gateway"))
        dhcp_start = _optional(value.get("dhcp-start") or value.get("dhcp_start"))
        dhcp_end = _optional(value.get("dhcp-end") or value.get("dhcp_end"))
        tags = _coerce_tags(
            value.get("tags"),
            source_file=source_file,
            site_code=site_code,
            field_name=f"{field_name}.tags",
            issues=issues,
        )
        ip_addresses = _coerce_ip_addresses(
            value.get("ip_addresses"),
            source_file=source_file,
            site_code=site_code,
            field_name=f"{field_name}.ip_addresses",
            issues=issues,
        )
        metadata = _source_metadata(
            value,
            {
                "name",
                "vlan_name",
                "display_name",
                "vlan",
                "vlan_id",
                "vlan_tag",
                "description",
                "network",
                "cidr",
                "cidr_value",
                "range",
                "scope",
                "subnet_mask",
                "subnetmask",
                "routing",
                "gateway",
                "dhcp-start",
                "dhcp_start",
                "dhcp-end",
                "dhcp_end",
                "tags",
                "ip_addresses",
            },
        )

    parsed_ranges = _parse_network_blocks(
        value,
        source_file=source_file,
        site_code=site_code,
        field_name=field_name,
        issues=issues,
        default_name_keys=("name", "vlan_name", "display_name"),
        default_description_keys=("description", "display_name"),
    )
    if not name:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"{field_name} must include a VLAN name.",
            )
        )
        return []

    vlans: list[VlanRange] = []
    for parsed in parsed_ranges:
        vlans.append(
            VlanRange(
                name=name,
                vlan_tag=vlan_tag,
                description=parsed.description,
                cidr=parsed.cidr,
                network=parsed.network,
                prefix_length=parsed.prefix_length,
                subnetmask=parsed.subnetmask,
                tags=tags,
                routing=routing,
                gateway=gateway,
                dhcp_start=dhcp_start,
                dhcp_end=dhcp_end,
                ip_addresses=ip_addresses,
                source_metadata=metadata,
            )
        )
    return vlans


def _parse_network_blocks(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
    default_name_keys: tuple[str, ...] = ("name",),
    default_description_keys: tuple[str, ...] = ("description",),
) -> list[NetworkRange]:
    """Parse network blocks"""
    block = value if isinstance(value, dict) else {}
    scope = _extract_scope(block, value)
    scope_label = _scope_label(block)
    if not scope:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"{field_name} must contain a CIDR or IP range.",
            )
        )
        return []

    try:
        networks = _parse_scope(scope)
    except ValueError as exc:
        if "IPv6 is not supported" in str(exc):
            issues.append(
                ValidationIssue(
                    source_file=source_file,
                    site_code=site_code,
                    field_name=field_name,
                    message=(
                        f"IPv6 scope '{scope}' is not supported by Tenable "
                        "scope analysis."
                    ),
                )
            )
            return []
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=(
                    f"Invalid CIDR '{scope}': {exc}"
                    if scope_label == "CIDR"
                    else f"Invalid network scope '{scope}': {exc}"
                ),
            )
        )
        return []

    tags = _coerce_tags(
        block.get("tags"),
        source_file=source_file,
        site_code=site_code,
        field_name=f"{field_name}.tags",
        issues=issues,
    )
    name = _first_text(block, default_name_keys)
    description = _first_text(block, default_description_keys)

    metadata = _source_metadata(
        block,
        {
            "name",
            "vlan_name",
            "display_name",
            "description",
            "network",
            "cidr",
            "cidr_value",
            "range",
            "scope",
            "ip",
            "address",
            "subnet_mask",
            "subnetmask",
            "tags",
            "supernet",
            "subnets",
        },
    )

    return [
        NetworkRange(
            name=name or None,
            description=description or None,
            cidr=str(network),
            network=str(network.network_address),
            prefix_length=network.prefixlen,
            subnetmask=str(network.netmask),
            tags=list(tags),
            source_metadata=dict(metadata),
        )
        for network in networks
    ]


def _extract_scope(block: dict[str, Any], value: Any) -> str | None:
    """Extract scope"""
    if isinstance(value, str):
        return value.strip()

    direct_cidr = _text(block.get("cidr"))
    if direct_cidr and "/" in direct_cidr and not block.get("network"):
        return direct_cidr

    network = _text(block.get("network"))
    cidr = _text(block.get("cidr"))
    if network and cidr:
        return f"{network}/{cidr.lstrip('/')}"

    subnetmask = _text(block.get("subnet_mask") or block.get("subnetmask"))
    if network and subnetmask:
        return f"{network}/{subnetmask}"

    for key in ("cidr_value", "range", "scope", "ip", "address"):
        text = _text(block.get(key))
        if text:
            return text
    return None


def _scope_label(block: dict[str, Any]) -> str:
    """Describe label"""
    has_network = bool(_text(block.get("network")))
    has_prefix = bool(_text(block.get("cidr")))
    has_mask = bool(_text(block.get("subnet_mask") or block.get("subnetmask")))
    return "CIDR" if has_network and (has_prefix or has_mask) else "network scope"


def _parse_scope(scope: str) -> list[ipaddress.IPv4Network]:
    """Parse scope"""
    text = str(scope).strip()
    if "-" in text:
        start_text, end_text = text.split("-", 1)
        start = ipaddress.ip_address(start_text.strip())
        end = ipaddress.ip_address(end_text.strip())
        if start.version != 4 or end.version != 4:
            raise ValueError("IPv6 is not supported")
        return list(ipaddress.summarize_address_range(start, end))

    network = ipaddress.ip_network(text, strict=False)
    if network.version != 4:
        raise ValueError("IPv6 is not supported")
    return [network]


def _coerce_ip_addresses(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[dict[str, object]]:
    """Turn IP address input into a list of address records"""
    if value is None:
        return []
    if not isinstance(value, list):
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                field_name=field_name,
                message=f"{field_name} must be a list.",
            )
        )
        return []

    records: list[dict[str, object]] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            issues.append(
                ValidationIssue(
                    source_file=source_file,
                    site_code=site_code,
                    field_name=f"{field_name}[{index}]",
                    message=f"{field_name}[{index}] must be an object.",
                )
            )
            continue
        record = {str(key): entry[key] for key in entry}
        record_tags = record.get("tags")
        if record_tags is not None:
            record["tags"] = _coerce_tags(
                record_tags,
                source_file=source_file,
                site_code=site_code,
                field_name=f"{field_name}[{index}].tags",
                issues=issues,
            )
        records.append(record)
    return records


def _coerce_tags(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[str]:
    """Turn tag input into a list of tag names"""
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    issues.append(
        ValidationIssue(
            source_file=source_file,
            site_code=site_code,
            field_name=field_name,
            message=f"{field_name} must be a list or comma-separated string.",
        )
    )
    return []


def _merge_tags(*values: list[str]) -> list[str]:
    """Merge tags"""
    result: list[str] = []
    for tags in values:
        for tag in tags:
            normalized = str(tag).strip()
            if normalized and normalized not in result:
                result.append(normalized)
    return result


def _source_metadata(value: Any, consumed_keys: set[str]) -> dict[str, object]:
    """Keep source fields that the parser did not use"""
    if not isinstance(value, dict):
        return {}
    return {
        str(key): raw_value
        for key, raw_value in value.items()
        if str(key) not in consumed_keys
    }


def _as_list(value: Any) -> list[Any]:
    """Convert to list"""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first_text(block: dict[str, Any], keys: tuple[str, ...]) -> str:
    """Return the first non-empty text value for these keys"""
    for key in keys:
        text = _text(block.get(key))
        if text:
            return text
    return ""


def _text(value: Any) -> str:
    """Convert a value to trimmed text"""
    return "" if value is None else str(value).strip()


def _optional(value: Any) -> str | None:
    """Get an optional the requested value"""
    text = _text(value)
    return text or None
