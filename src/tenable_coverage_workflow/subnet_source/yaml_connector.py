from pathlib import Path
from typing import Any

import yaml

from ..models import (
    CoverageTarget,
    SiteNetworkDefinition,
    ValidationIssue,
    YamlConnectorResult,
)
from .site_parser import extract_site_objects, parse_site_object
from .validation import add_relationship_issues


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
        result.site_definitions.extend(file_loaded["site_definitions"])
        result.coverage_targets.extend(file_loaded["coverage_targets"])

        if file_loaded["site_definitions"]:
            if audit_logger:
                for definition in file_loaded["site_definitions"]:
                    site_targets = [
                        target
                        for target in file_loaded["coverage_targets"]
                        if target.site_code == definition.site_code
                    ]
                    audit_logger.emit(
                        "yaml_file_loaded",
                        source_file=definition.source_file,
                        site_code=definition.site_code,
                        target_count=len(site_targets),
                        validation_errors=[
                            issue.message
                            for issue in file_loaded["issues"]
                            if issue.site_code == definition.site_code
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
                site_code=None,
                errors=[issue.message for issue in file_loaded["issues"]],
            )

    return add_relationship_issues(result)


def _load_yaml_file(repo_root: Path, path: Path) -> dict[str, Any]:
    source_file = path.relative_to(repo_root).as_posix()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return {
            "source_file": source_file,
            "site_definitions": [],
            "coverage_targets": [],
            "issues": [ValidationIssue(source_file=source_file, message=str(exc))],
        }

    sites = extract_site_objects(raw)
    if sites is None:
        return {
            "source_file": source_file,
            "site_definitions": [],
            "coverage_targets": [],
            "issues": [
                ValidationIssue(
                    source_file=source_file,
                    message=(
                        "YAML root must be a site object, a list of sites, or an "
                        "object containing a 'site_definition', 'sites', "
                        "'locations', or 'data' list."
                    ),
                )
            ],
        }

    site_definitions: list[SiteNetworkDefinition] = []
    coverage_targets: list[CoverageTarget] = []
    issues: list[ValidationIssue] = []
    for index, raw_site in enumerate(sites):
        item_source = f"{source_file}#sites[{index}]"
        definition, site_issues = parse_site_object(raw_site, item_source)
        issues.extend(site_issues)
        if definition is None:
            continue
        site_definitions.append(definition)
        coverage_targets.extend(flatten_site_definition(definition))

    return {
        "source_file": source_file,
        "site_definitions": site_definitions,
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
