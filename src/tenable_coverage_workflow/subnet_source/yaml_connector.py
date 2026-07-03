from ..models import (
    CoverageTarget,
    SiteNetworkDefinition,
)


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
                    tags=_merged_tags(
                        site_definition.tags,
                        private_range.tags,
                        vlan.tags,
                    ),
                    environment=site_definition.environment,
                    business_function=site_definition.business_function,
                    scan_classification=dict(site_definition.scan_classification),
                )
            )

    return targets


def _merged_tags(*values: list[str]) -> list[str]:
    result: list[str] = []
    for tags in values:
        for tag in tags:
            normalized = str(tag).strip()
            if normalized and normalized not in result:
                result.append(normalized)
    return result
