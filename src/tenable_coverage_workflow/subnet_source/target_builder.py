from ..exclusion_tags import find_exclusion_tag
from ..models import CoverageTarget, SiteNetworkDefinition, VlanRange


def build_coverage_targets(
    site_definition: SiteNetworkDefinition,
) -> list[CoverageTarget]:
    """Turn one site definition into coverage targets"""
    targets: list[CoverageTarget] = []

    for public_range in site_definition.public_ranges:
        for subnet in public_range.subnets:
            subnet_tags = _merged_tags(public_range.tags, subnet.tags)
            targets.append(
                CoverageTarget(
                    target_type="PUBLIC",
                    cidr=subnet.cidr,
                    site_code=site_definition.site_code,
                    site_name=site_definition.site_name,
                    location=None,
                    region=None,
                    description=subnet.display_name,
                    source_file=site_definition.source_file,
                    timezone=site_definition.timezone,
                    tags=subnet_tags,
                )
            )
            _append_excluded_ip_targets(targets, site_definition, subnet, subnet_tags)

    for private_range in site_definition.private_ranges:
        targets.append(
            CoverageTarget(
                target_type="PRIVATE_SUPERNET",
                cidr=private_range.cidr,
                site_code=site_definition.site_code,
                site_name=site_definition.site_name,
                location=None,
                region=None,
                description=None,
                source_file=site_definition.source_file,
                timezone=site_definition.timezone,
                tags=list(private_range.tags),
            )
        )
        for vlan in private_range.vlans:
            vlan_tags = _merged_tags(private_range.tags, vlan.tags)
            targets.append(
                CoverageTarget(
                    target_type="VLAN",
                    cidr=vlan.cidr,
                    site_code=site_definition.site_code,
                    site_name=site_definition.site_name,
                    location=None,
                    region=None,
                    description=vlan.display_name,
                    vlan_name=vlan.vlan_name,
                    vlan_tag=vlan.vlan,
                    source_file=site_definition.source_file,
                    timezone=site_definition.timezone,
                    tags=vlan_tags,
                )
            )
            _append_excluded_ip_targets(targets, site_definition, vlan, vlan_tags)

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


def _append_excluded_ip_targets(
    targets: list[CoverageTarget],
    site_definition: SiteNetworkDefinition,
    subnet: VlanRange,
    subnet_tags: list[str],
) -> None:
    """Add IPs with exclude tag"""
    for ip_address in subnet.ip_addresses:
        if not find_exclusion_tag(ip_address.tags):
            continue
        targets.append(
            CoverageTarget(
                target_type="IP_ADDRESS",
                cidr=f"{ip_address.ip}/32",
                site_code=site_definition.site_code,
                site_name=site_definition.site_name,
                location=None,
                region=None,
                description=ip_address.name or subnet.display_name,
                vlan_name=subnet.vlan_name,
                vlan_tag=subnet.vlan,
                source_file=site_definition.source_file,
                timezone=site_definition.timezone,
                tags=_merged_tags(subnet_tags, ip_address.tags),
            )
        )
