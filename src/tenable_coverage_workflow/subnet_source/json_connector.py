from typing import Any

from ..models import SourceLoadResult, ValidationIssue
from .site_parser import get_site_objects, parse_site_object
from .target_builder import build_coverage_targets
from .validation import add_relationship_issues


def load_json_payload(
    payload: Any, source_file: str = "json-payload", audit_logger=None
) -> SourceLoadResult:
    result = SourceLoadResult(files_processed=1)
    sites = get_site_objects(payload)
    if sites is None:
        result.files_failed = 1
        result.validation_issues.append(
            ValidationIssue(
                source_file=source_file,
                message=(
                    "Authoritative data must be an object containing a "
                    "'site_definition' object or list."
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
        targets = build_coverage_targets(definition)
        result.coverage_targets.extend(targets)
        if audit_logger:
            audit_logger.emit(
                "authoritative_site_loaded",
                source_file=item_source,
                site_code=definition.site_code,
                target_count=len(targets),
            )
    return add_relationship_issues(result)
