from typing import Any

from ..models import SourceLoadResult, ValidationIssue
from .site_parser import extract_site_objects, parse_site_object
from .validation import add_relationship_issues
from .yaml_connector import flatten_site_definition


def load_json_payload(
    payload: Any, source_file: str = "json-payload", audit_logger=None
) -> SourceLoadResult:
    result = SourceLoadResult(files_processed=1)
    sites = extract_site_objects(payload)
    if sites is None:
        result.files_failed = 1
        result.validation_issues.append(
            ValidationIssue(
                source_file=source_file,
                message=(
                    "JSON root must be a site object, a list of sites, or an "
                    "object containing a 'site_definition', 'sites', "
                    "'locations', or 'data' list."
                ),
            )
        )
        return result

    for index, raw_site in enumerate(sites):
        item_source = f"{source_file}#sites[{index}]"
        definition, issues = parse_site_object(raw_site, item_source)
        result.validation_issues.extend(issues)
        if definition is None:
            result.files_failed += 1
            continue
        result.site_definitions.append(definition)
        targets = flatten_site_definition(definition)
        result.coverage_targets.extend(targets)
        if audit_logger:
            audit_logger.emit(
                "authoritative_site_loaded",
                source_file=item_source,
                site_code=definition.site_code,
                target_count=len(targets),
            )
    return add_relationship_issues(result)
