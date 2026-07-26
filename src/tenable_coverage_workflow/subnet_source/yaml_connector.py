from ..exclusion_tags import find_exclusion_tag
from ..models import (
    CoverageTarget,
    SiteNetworkDefinition,
)


def flatten_site_definition(
    site_definition: SiteNetworkDefinition,
) -> list[CoverageTarget]:
    """Turn one site definition into coverage targets"""
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
                timezone=site_definition.timezone,
                tags=_merged_tags(site_definition.tags, public_range.tags),
                environment=site_definition.environment,
                business_function=site_definition.business_function,
                scan_classification=dict(site_definition.scan_classification),
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
                timezone=site_definition.timezone,
                tags=_merged_tags(site_definition.tags, private_range.tags),
                environment=site_definition.environment,
                business_function=site_definition.business_function,
                scan_classification=dict(site_definition.scan_classification),
            )
        )
        for vlan in private_range.vlans:
            vlan_tags = _merged_tags(
                site_definition.tags,
                private_range.tags,
                vlan.tags,
            )
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
                    timezone=site_definition.timezone,
                    tags=vlan_tags,
                    environment=site_definition.environment,
                    business_function=site_definition.business_function,
                    scan_classification=dict(site_definition.scan_classification),
                )
            )
            for ip_address in vlan.ip_addresses:
                ip_address_tags = _tags_from_ip_address(ip_address)
                if not find_exclusion_tag(ip_address_tags):
                    continue
                ip_tags = _merged_tags(vlan_tags, ip_address_tags)
                ip_scope = _ip_address_scope(ip_address)
                if not ip_scope:
                    continue
                targets.append(
                    CoverageTarget(
                        target_type="IP_ADDRESS",
                        cidr=ip_scope,
                        site_code=site_definition.site_code,
                        site_name=site_definition.site_name,
                        location=site_definition.location,
                        region=site_definition.region,
                        description=_ip_address_description(ip_address)
                        or vlan.description
                        or site_definition.description,
                        vlan_name=vlan.name,
                        vlan_tag=vlan.vlan_tag,
                        source_file=site_definition.source_file,
                        timezone=site_definition.timezone,
                        tags=ip_tags,
                        environment=site_definition.environment,
                        business_function=site_definition.business_function,
                        scan_classification=dict(site_definition.scan_classification),
                    )
                )

    return targets


def _merged_tags(*values: list[str]) -> list[str]:
    """Combine tag lists without duplicate values"""
    result: list[str] = []
    for tags in values:
        for tag in tags:
            normalized = str(tag).strip()
            if normalized and normalized not in result:
                result.append(normalized)
    return result


def _tags_from_ip_address(value: dict[str, object]) -> list[str]:
    """Read tags from an individual IP address record"""
    tags = value.get("tags")
    if not isinstance(tags, list):
        return []
    return [str(tag).strip() for tag in tags if str(tag).strip()]


def _ip_address_scope(value: dict[str, object]) -> str | None:
    """Return an individual IP address as a /32 scope"""
    address = str(value.get("ip") or value.get("address") or "").strip()
    return f"{address}/32" if address else None


def _ip_address_description(value: dict[str, object]) -> str | None:
    """Read the name or description for an IP address"""
    name = str(value.get("name") or value.get("description") or "").strip()
    return name or None
