import ipaddress
from typing import Any

from ..models import (
    IpAddress,
    PrivateNetworkRange,
    PublicNetworkRange,
    SiteNetworkDefinition,
    ValidationIssue,
    VlanRange,
)

# subnet-as-code returns one stable payload shape. Keep the source boundary
# strict so schema changes are found during validation instead of guessed at.


def extract_site_objects(payload: Any) -> list[dict[str, Any]] | None:
    """Return the site_definition records from a subnet-as-code payload"""
    if not isinstance(payload, dict):
        return None

    site_definition = payload.get("site_definition")
    if isinstance(site_definition, dict):
        return [site_definition]
    if isinstance(site_definition, list) and all(
        isinstance(item, dict) for item in site_definition
    ):
        return site_definition
    return None


def parse_site_object(
    raw: dict[str, Any], source_file: str
) -> tuple[SiteNetworkDefinition | None, list[ValidationIssue]]:
    """Parse one subnet-as-code site_definition record"""
    issues: list[ValidationIssue] = []
    site_code = _required_text(raw, "site_code", source_file, None, issues)
    site_name = _required_text(raw, "site_name", source_file, site_code, issues)
    if not site_code or not site_name:
        return None, issues

    public_ranges = _parse_public_ranges(
        raw.get("public_ranges", []), source_file, site_code, issues
    )
    private_ranges = _parse_private_ranges(
        raw.get("private_ranges", []), source_file, site_code, issues
    )
    if not public_ranges and not private_ranges:
        issues.append(
            ValidationIssue(
                source_file=source_file,
                site_code=site_code,
                message="Site contains no valid public or private ranges.",
            )
        )
        return None, issues

    return (
        SiteNetworkDefinition(
            source_file=source_file,
            site_code=site_code,
            site_name=site_name,
            site_type=_optional_text(raw.get("site_type")),
            email_domain=_optional_text(raw.get("email_domain")),
            everyone_at=_optional_text(raw.get("everyone_at")),
            vcenter_endpoint=_optional_text(raw.get("vcenter_endpoint")),
            content_library=_optional_text(raw.get("content_library")),
            timezone=_optional_text(raw.get("timezone")),
            utc_offset=_optional_text(raw.get("utc_offset")),
            grid_code=_optional_text(raw.get("grid_code")),
            public_ranges=public_ranges,
            private_ranges=private_ranges,
        ),
        issues,
    )


def _parse_public_ranges(
    value: Any,
    source_file: str,
    site_code: str,
    issues: list[ValidationIssue],
) -> list[PublicNetworkRange]:
    """Parse the public_ranges records for one site"""
    ranges: list[PublicNetworkRange] = []
    for index, raw_range in enumerate(
        _required_list(value, "public_ranges", source_file, site_code, issues)
    ):
        field_name = f"public_ranges[{index}]"
        if not isinstance(raw_range, dict):
            _issue(issues, source_file, site_code, field_name, "must be an object.")
            continue
        cidr = _parse_network(
            raw_range.get("supernet"),
            source_file,
            site_code,
            f"{field_name}.supernet",
            issues,
        )
        subnets = _parse_subnets(
            raw_range.get("subnets"), source_file, site_code, field_name, issues
        )
        if not cidr or not subnets:
            continue
        subnets = _contained_subnets(
            cidr, subnets, source_file, site_code, field_name, issues
        )
        if subnets:
            ranges.append(
                PublicNetworkRange(
                    cidr=cidr,
                    tags=_parse_tags(
                        raw_range.get("tags"),
                        source_file,
                        site_code,
                        f"{field_name}.tags",
                        issues,
                    ),
                    subnets=subnets,
                )
            )
    return ranges


def _parse_private_ranges(
    value: Any,
    source_file: str,
    site_code: str,
    issues: list[ValidationIssue],
) -> list[PrivateNetworkRange]:
    """Parse the private_ranges records for one site"""
    ranges: list[PrivateNetworkRange] = []
    for index, raw_range in enumerate(
        _required_list(value, "private_ranges", source_file, site_code, issues)
    ):
        field_name = f"private_ranges[{index}]"
        if not isinstance(raw_range, dict):
            _issue(issues, source_file, site_code, field_name, "must be an object.")
            continue
        cidr = _parse_network(
            raw_range.get("supernet"),
            source_file,
            site_code,
            f"{field_name}.supernet",
            issues,
        )
        vlans = _parse_subnets(
            raw_range.get("subnets"), source_file, site_code, field_name, issues
        )
        if not cidr:
            continue
        ranges.append(
            PrivateNetworkRange(
                cidr=cidr,
                tags=_parse_tags(
                    raw_range.get("tags"),
                    source_file,
                    site_code,
                    f"{field_name}.tags",
                    issues,
                ),
                dhcp_options=_parse_dhcp_options(
                    raw_range.get("dhcp-options"),
                    source_file,
                    site_code,
                    f"{field_name}.dhcp-options",
                    issues,
                ),
                vlans=_contained_subnets(
                    cidr, vlans, source_file, site_code, field_name, issues
                ),
            )
        )
    return ranges


def _parse_subnets(
    value: Any,
    source_file: str,
    site_code: str,
    parent_field: str,
    issues: list[ValidationIssue],
) -> list[VlanRange]:
    """Parse the subnets list used for public and private VLAN records"""
    subnets: list[VlanRange] = []
    field_name = f"{parent_field}.subnets"
    for index, raw_subnet in enumerate(
        _required_list(value, field_name, source_file, site_code, issues)
    ):
        item_field = f"{field_name}[{index}]"
        if not isinstance(raw_subnet, dict):
            _issue(issues, source_file, site_code, item_field, "must be an object.")
            continue
        vlan_name = _required_text(
            raw_subnet, "vlan_name", source_file, site_code, issues, item_field
        )
        cidr = _parse_network(raw_subnet, source_file, site_code, item_field, issues)
        vlan = _parse_vlan_number(
            raw_subnet.get("vlan"),
            source_file,
            site_code,
            f"{item_field}.vlan",
            issues,
        )
        if not vlan_name or not cidr:
            continue
        _validate_subnet_mask(
            raw_subnet.get("subnet_mask"),
            cidr,
            source_file,
            site_code,
            f"{item_field}.subnet_mask",
            issues,
        )
        subnets.append(
            VlanRange(
                vlan_name=vlan_name,
                display_name=_optional_text(raw_subnet.get("display_name")),
                vlan=vlan,
                cidr=cidr,
                gateway=_optional_text(raw_subnet.get("gateway")),
                routing=_optional_text(raw_subnet.get("routing")),
                dhcp_start=_optional_text(raw_subnet.get("dhcp-start")),
                dhcp_end=_optional_text(raw_subnet.get("dhcp-end")),
                tags=_parse_tags(
                    raw_subnet.get("tags"),
                    source_file,
                    site_code,
                    f"{item_field}.tags",
                    issues,
                ),
                ip_addresses=_parse_ip_addresses(
                    raw_subnet.get("ip_addresses"),
                    source_file,
                    site_code,
                    f"{item_field}.ip_addresses",
                    issues,
                ),
            )
        )
    return subnets


def _parse_network(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> str | None:
    """Build a canonical IPv4 CIDR from network and cidr fields"""
    if not isinstance(value, dict):
        _issue(issues, source_file, site_code, field_name, "must be an object.")
        return None
    network = _required_text(
        value, "network", source_file, site_code, issues, field_name
    )
    prefix = _required_text(
        value, "cidr", source_file, site_code, issues, field_name
    )
    if not network or not prefix:
        return None
    try:
        parsed = ipaddress.ip_network(
            f"{network}/{prefix.lstrip('/')}".strip(), strict=False
        )
    except ValueError as exc:
        _issue(
            issues,
            source_file,
            site_code,
            field_name,
            f"has an invalid CIDR: {exc}",
        )
        return None
    if parsed.version != 4:
        _issue(
            issues,
            source_file,
            site_code,
            field_name,
            "uses IPv6, which is unsupported.",
        )
        return None
    return str(parsed)


def _parse_vlan_number(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> int | None:
    """Read an optional numeric VLAN identifier"""
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        _issue(issues, source_file, site_code, field_name, "must be a number.")
        return None


def _parse_ip_addresses(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[IpAddress]:
    """Parse IP address records attached to one VLAN"""
    if value is None:
        return []
    records: list[IpAddress] = []
    for index, raw_address in enumerate(
        _required_list(value, field_name, source_file, site_code, issues)
    ):
        item_field = f"{field_name}[{index}]"
        if not isinstance(raw_address, dict):
            _issue(issues, source_file, site_code, item_field, "must be an object.")
            continue
        address = _required_text(
            raw_address, "ip", source_file, site_code, issues, item_field
        )
        if not address:
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            _issue(
                issues,
                source_file,
                site_code,
                item_field,
                f"has an invalid IP: {exc}",
            )
            continue
        if parsed.version != 4:
            _issue(
                issues,
                source_file,
                site_code,
                item_field,
                "uses IPv6, which is unsupported.",
            )
            continue
        records.append(
            IpAddress(
                ip=str(parsed),
                name=_optional_text(raw_address.get("name")),
                tags=_parse_tags(
                    raw_address.get("tags"),
                    source_file,
                    site_code,
                    f"{item_field}.tags",
                    issues,
                ),
            )
        )
    return records


def _contained_subnets(
    parent_cidr: str,
    subnets: list[VlanRange],
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[VlanRange]:
    """Keep only VLANs contained by their public or private supernet"""
    parent = ipaddress.ip_network(parent_cidr)
    contained: list[VlanRange] = []
    for subnet in subnets:
        if ipaddress.ip_network(subnet.cidr).subnet_of(parent):
            contained.append(subnet)
            continue
        _issue(
            issues,
            source_file,
            site_code,
            field_name,
            f"VLAN CIDR {subnet.cidr} is outside parent range {parent_cidr}.",
        )
    return contained


def _validate_subnet_mask(
    value: Any,
    cidr: str,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> None:
    """Report a subnet mask that disagrees with the supplied CIDR"""
    subnet_mask = _optional_text(value)
    if subnet_mask and subnet_mask != str(ipaddress.ip_network(cidr).netmask):
        _issue(
            issues,
            source_file,
            site_code,
            field_name,
            f"does not match CIDR {cidr}.",
        )


def _parse_dhcp_options(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> dict[str, object]:
    """Copy the optional dhcp-options mapping from a private range"""
    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(key): raw_value for key, raw_value in value.items()}
    _issue(issues, source_file, site_code, field_name, "must be an object.")
    return {}


def _parse_tags(
    value: Any,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> list[str]:
    """Read tags from their one supported list format"""
    if value is None:
        return []
    if not isinstance(value, list):
        _issue(issues, source_file, site_code, field_name, "must be a list.")
        return []
    return [str(tag).strip() for tag in value if str(tag).strip()]


def _required_list(
    value: Any,
    field_name: str,
    source_file: str,
    site_code: str,
    issues: list[ValidationIssue],
) -> list[Any]:
    """Return a source list or record a validation issue"""
    if isinstance(value, list):
        return value
    _issue(issues, source_file, site_code, field_name, "must be a list.")
    return []


def _required_text(
    value: dict[str, Any],
    key: str,
    source_file: str,
    site_code: str | None,
    issues: list[ValidationIssue],
    parent_field: str = "",
) -> str | None:
    """Return a required text field or record a validation issue"""
    text = _optional_text(value.get(key))
    if text:
        return text
    field_name = f"{parent_field}.{key}" if parent_field else key
    _issue(issues, source_file, site_code, field_name, "is required.")
    return None


def _optional_text(value: Any) -> str | None:
    """Convert an optional scalar source value to text"""
    text = "" if value is None else str(value).strip()
    return text or None


def _issue(
    issues: list[ValidationIssue],
    source_file: str,
    site_code: str | None,
    field_name: str,
    message: str,
) -> None:
    """Add one source validation issue"""
    issues.append(
        ValidationIssue(
            source_file=source_file,
            site_code=site_code,
            field_name=field_name,
            message=f"{field_name} {message}",
        )
    )
