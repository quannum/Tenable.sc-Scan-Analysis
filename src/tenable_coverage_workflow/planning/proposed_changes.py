from typing import Any

from ..models import CoverageValidationResult, ProposedChange


def adapt_coverage_result(row: Any) -> CoverageValidationResult:
    if isinstance(row, CoverageValidationResult):
        return row

    getter = _build_getter(row)
    covering_scans = getter("covering_scans", [])
    if isinstance(covering_scans, set):
        covering_scans = sorted(covering_scans)
    elif isinstance(covering_scans, tuple):
        covering_scans = list(covering_scans)

    return CoverageValidationResult(
        status=str(getter("status", getter("current_status", "UNKNOWN")) or "UNKNOWN"),
        target_type=str(getter("target_type", "")),
        cidr=str(getter("cidr", getter("scope_item", ""))),
        site_code=str(getter("site_code", "")),
        site_name=getter("site_name"),
        region=getter("region", getter("environment")),
        location=getter("location"),
        description=getter("description"),
        vlan_name=getter("vlan_name"),
        vlan_tag=getter("vlan_tag"),
        covering_scans=[str(item) for item in covering_scans if str(item).strip()],
        reason=str(getter("reason", "")),
        source_file=getter("source_file"),
        required_asset_name=getter("required_asset_name"),
        required_scan_name=getter("required_scan_name", getter("required_scan")),
        required_policy_name=getter("required_policy_name"),
        required_scan_covered=str(getter("required_scan_covered", "")),
        expected_size=int(getter("expected_size", 0) or 0),
        covered_count=int(getter("covered_count", 0) or 0),
        gap_count=int(getter("gap_count", 0) or 0),
        exclusion_ip_total=int(getter("exclusion_ip_total", 0) or 0),
        coverage_pct=float(getter("coverage_pct", 0.0) or 0.0),
        required_asset_present=str(getter("required_asset_present", "")),
        required_scan_present=str(getter("required_scan_present", "")),
        configured_repository=getter("configured_repository"),
        configured_policy=getter("configured_policy"),
        required_policy_configured=str(getter("required_policy_configured", "")),
        timezone=getter("timezone"),
        tags=list(getter("tags", []) or []),
        environment=getter("environment"),
        business_function=getter("business_function"),
        scan_classification=dict(getter("scan_classification", {}) or {}),
    )


def generate_proposed_changes(
    coverage_results: list[Any],
    run_id: str,
) -> list[ProposedChange]:
    changes: list[ProposedChange] = []

    for row in coverage_results:
        result = adapt_coverage_result(row)
        proposed_action = determine_proposed_action(result)
        issue = build_issue(result, proposed_action)
        changes.append(
            ProposedChange(
                run_id=run_id,
                site_code=result.site_code,
                site_name=result.site_name,
                target_type=result.target_type,
                cidr=result.cidr,
                vlan_name=result.vlan_name,
                vlan_tag=result.vlan_tag,
                current_status=result.status,
                issue=issue,
                proposed_action=proposed_action,
                proposed_asset_name=result.required_asset_name,
                proposed_scan_name=result.required_scan_name,
                proposed_policy_name=result.required_policy_name,
                approval_status="PENDING",
                reviewer=None,
                decision_notes=None,
                source_file=result.source_file,
            )
        )

    return changes


def determine_proposed_action(result: CoverageValidationResult) -> str:
    if result.required_asset_present == "No" or result.required_scan_present == "No":
        return _create_or_update_action(result.target_type)

    if result.required_policy_configured == "No":
        return "UPDATE_SCAN_POLICY_AND_TARGET"

    if (
        result.required_scan_name
        and result.required_scan_covered == "No"
        and result.covering_scans
    ):
        return "REVIEW_WRONG_SCAN"

    if result.status == "OK":
        return "NO_ACTION"
    if result.status == "EXCLUDED":
        return "REVIEW_EXCLUSION"
    if result.status == "PARTIAL":
        return "REVIEW_PARTIAL_COVERAGE"
    if result.status == "GAP":
        return _create_or_update_action(result.target_type)

    return "REVIEW_COVERAGE"


def _create_or_update_action(target_type: str) -> str:
    if target_type == "PUBLIC":
        return "CREATE_OR_UPDATE_PUBLIC_ASSET_AND_SCAN"
    if target_type == "PRIVATE_SUPERNET":
        return "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN"
    if target_type == "VLAN":
        return "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN"
    return "REVIEW_COVERAGE"


def build_issue(result: CoverageValidationResult, proposed_action: str) -> str:
    if proposed_action == "REVIEW_WRONG_SCAN":
        covering_scans = ", ".join(sorted(result.covering_scans)) or "none"
        return (
            f"Required scan '{result.required_scan_name}' is not among covering "
            f"scans: {covering_scans}"
        )

    if result.reason:
        return result.reason

    if result.status == "OK":
        return "Coverage target is fully covered."
    if result.status == "EXCLUDED":
        return "Coverage is impacted by exclusions."
    if result.status == "PARTIAL":
        return "Coverage target is only partially covered."
    if result.status == "GAP":
        return "Coverage target is not covered by any scan scope."
    return "Coverage target requires review."


def _build_getter(row: Any):
    if isinstance(row, dict):
        return lambda name, default=None: row.get(name, default)
    return lambda name, default=None: getattr(row, name, default)
