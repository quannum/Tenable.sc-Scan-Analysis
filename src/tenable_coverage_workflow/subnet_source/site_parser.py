import ipaddress
from dataclasses import asdict, is_dataclass
from typing import Any

from ...core.scope_utils import parse_scope_item, scope_contains
from ..models import (
    IpAddress,
    PrivateNetworkRange,
    PublicNetworkRange,
    SiteNetworkDefinition,
    ValidationIssue,
    VlanRange,
)

# getting site_definitions expect same format for all sites
# subnet-as-code network definitions should all be same format
# or this will be upset and throw up errors


def get_site_objects(payload: Any) -> list[dict[str, Any]] | None:
    """Return the site_definition records from a subnet-as-code payload"""
    payload = _as_mapping(payload)
    if isinstance(payload, list):
        return _site_records(payload)
    if not isinstance(payload, dict):
        return None

    for key in (
        "site_definition",
        "site_definitions",
        "sites",
        "locations",
        "data",
        "items",
    ):
        site_definition = _as_mapping(payload.get(key))
        if isinstance(site_definition, dict):
            return [site_definition]
        if isinstance(site_definition, list):
            sites = _site_records(site_definition)
            if sites is not None:
                return sites
    return None


def parse_site_object(
    raw: dict[str, Any], source_file: str
) -> tuple[SiteNetworkDefinition | None, list[ValidationIssue]]:
    """Parse one subnet-as-code site_definition"""
    raw = _as_mapping(raw)
    issues: list[ValidationIssue] = []
    if not isinstance(raw, dict):
        issues.append(
            ValidationIssue(
                source_file=source_file,
                message="Site definition must be an object.",
            )
        )
        return None, issues
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
        raw_range = _as_mapping(raw_range)
        field_name = f"public_ranges[{index}]"
        if not isinstance(raw_range, dict):
            cidr = _parse_network(raw_range, source_file, site_code, field_name, issues)
            if cidr:
                ranges.append(
                    PublicNetworkRange(
                        cidr=cidr,
                        subnets=[_synthetic_subnet(cidr, "Public Range")],
                    )
                )
            continue
        cidr = _parse_network(
            raw_range.get("supernet", raw_range),
            source_file,
            site_code,
            f"{field_name}.supernet",
            issues,
        )
        subnets = (
            _parse_subnets(
                _subnet_records(raw_range), source_file, site_code, field_name, issues
            )
            if _has_subnet_records(raw_range)
            else []
        )
        if not cidr:
            continue
        if subnets:
            subnets = _contained_subnets(
                cidr, subnets, source_file, site_code, field_name, issues
            )
        else:
            subnets = [_synthetic_subnet(cidr, _optional_text(raw_range.get("name")))]
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
        raw_range = _as_mapping(raw_range)
        field_name = f"private_ranges[{index}]"
        if not isinstance(raw_range, dict):
            cidr = _parse_network(raw_range, source_file, site_code, field_name, issues)
            if cidr:
                ranges.append(PrivateNetworkRange(cidr=cidr))
            continue
        cidr = _parse_network(
            raw_range.get("supernet", raw_range),
            source_file,
            site_code,
            f"{field_name}.supernet",
            issues,
        )
        vlans = (
            _parse_subnets(
                _subnet_records(raw_range), source_file, site_code, field_name, issues
            )
            if _has_subnet_records(raw_range)
            else []
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
        raw_subnet = _as_mapping(raw_subnet)
        item_field = f"{field_name}[{index}]"
        if not isinstance(raw_subnet, dict):
            cidr = _parse_network(
                raw_subnet, source_file, site_code, item_field, issues
            )
            if cidr:
                subnets.append(_synthetic_subnet(cidr, None))
            continue
        vlan_name = _required_text_any(
            raw_subnet,
            ("vlan_name", "name"),
            source_file,
            site_code,
            issues,
            item_field,
        )
        cidr = _parse_network(raw_subnet, source_file, site_code, item_field, issues)
        vlan = _parse_vlan_number(
            _first_value(raw_subnet, "vlan", "vlan_id", "vlan_tag"),
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
                display_name=(
                    _optional_text(raw_subnet.get("display_name"))
                    or _optional_text(raw_subnet.get("name"))
                ),
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
    """Build a IPv4 cidr from network and cidr fields"""
    value = _as_mapping(value)
    if isinstance(value, str):
        return _parse_scope_text(value, source_file, site_code, field_name, issues)
    if not isinstance(value, dict):
        _issue(issues, source_file, site_code, field_name, "must be an object.")
        return None
    if "network" not in value and "cidr" in value:
        cidr = _required_text(value, "cidr", source_file, site_code, issues, field_name)
        if not cidr:
            return None
        return _parse_scope_text(cidr, source_file, site_code, field_name, issues)
    network = _required_text(
        value, "network", source_file, site_code, issues, field_name
    )
    prefix = _required_text(value, "cidr", source_file, site_code, issues, field_name)
    if not network or not prefix:
        return None
    return _parse_scope_text(
        f"{network}/{prefix.lstrip('/')}", source_file, site_code, field_name, issues
    )


def _parse_scope_text(
    value: str,
    source_file: str,
    site_code: str,
    field_name: str,
    issues: list[ValidationIssue],
) -> str | None:
    """Parse a direct CIDR, range, or IP address into scope text"""
    try:
        parsed_type, parsed_value = parse_scope_item(value)
    except ValueError as exc:
        if "IPv6 is not supported" in str(exc):
            _issue(
                issues,
                source_file,
                site_code,
                field_name,
                "uses IPv6, which is unsupported.",
            )
            return None
        _issue(
            issues,
            source_file,
            site_code,
            field_name,
            f"has an invalid CIDR: {exc}",
        )
        return None
    if parsed_type == "cidr":
        return str(parsed_value)
    start_ip, end_ip = parsed_value
    return f"{start_ip}-{end_ip}"


def _synthetic_subnet(cidr: str, display_name: str | None) -> VlanRange:
    """Create a subnet record for direct range formats without nested VLAN data"""
    return VlanRange(
        vlan_name=display_name or "network-range",
        display_name=display_name,
        vlan=None,
        cidr=cidr,
    )


def _has_subnet_records(value: dict[str, Any]) -> bool:
    """Check for either supported subnet list key"""
    return "subnets" in value or "vlans" in value


def _subnet_records(value: dict[str, Any]) -> Any:
    """Return the supported subnet list value from a range object"""
    return value.get("subnets") if "subnets" in value else value.get("vlans")


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
        raw_address = _as_mapping(raw_address)
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
    """check VLANs are contained by their public or private supernet"""
    parent = parse_scope_item(parent_cidr)
    contained: list[VlanRange] = []
    for subnet in subnets:
        if scope_contains(parent, parse_scope_item(subnet.cidr)):
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
    """Report a subnet mask that doesn't match with the supplied CIDR"""
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
    """Copy the optional dhcp-options from a private range"""
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
    value = _as_mapping(value)
    if isinstance(value, (list, tuple)):
        return list(value)
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
    value = _as_mapping(value)
    if not isinstance(value, dict):
        field_name = f"{parent_field}.{key}" if parent_field else key
        _issue(issues, source_file, site_code, field_name, "is required.")
        return None
    text = _optional_text(value.get(key))
    if text:
        return text
    field_name = f"{parent_field}.{key}" if parent_field else key
    _issue(issues, source_file, site_code, field_name, "is required.")
    return None


def _required_text_any(
    value: dict[str, Any],
    keys: tuple[str, ...],
    source_file: str,
    site_code: str | None,
    issues: list[ValidationIssue],
    parent_field: str = "",
) -> str | None:
    """Return the first populated text field from a set of aliases"""
    for key in keys:
        text = _optional_text(value.get(key))
        if text:
            return text
    field_name = f"{parent_field}.{keys[0]}" if parent_field else keys[0]
    _issue(issues, source_file, site_code, field_name, "is required.")
    return None


def _first_value(value: dict[str, Any], *keys: str) -> Any:
    """Return the first present and non-empty value from a dict"""
    for key in keys:
        if key in value and value[key] not in (None, ""):
            return value[key]
    return None


def _optional_text(value: Any) -> str | None:
    """Convert an optional source value to text"""
    text = "" if value is None else str(value).strip()
    return text or None


def _site_records(value: list[Any]) -> list[dict[str, Any]] | None:
    """Convert a list of site-like records into dicts"""
    records = [_as_mapping(item) for item in value]
    if all(isinstance(item, dict) for item in records):
        return records
    return None


def _as_mapping(value: Any) -> Any:
    """Convert dataclass or object records from source connectors into dicts"""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, (dict, list, str)) or value is None:
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump()
    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        return dict_method()
    if hasattr(value, "__dict__"):
        return {
            key: item for key, item in vars(value).items() if not key.startswith("_")
        }
    return value


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
