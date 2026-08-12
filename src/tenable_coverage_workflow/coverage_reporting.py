import csv
import ipaddress
from collections import Counter, defaultdict
from dataclasses import asdict
from io import StringIO
from pathlib import Path
from typing import Any

from ..core.scope_utils import (
    merge_intervals,
    parse_scope_item,
    scope_to_interval,
    subtract_intervals,
)
from .audit.audit_logger import atomic_write_json, atomic_write_text
from .models import CoverageTarget, CoverageValidationResult, ValidationIssue

# Reports are derived from coverage results. They do not make or apply
# changes in Tenable

DETAIL_COLUMNS = [
    "status",
    "target_type",
    "cidr",
    "site_code",
    "site_name",
    "region",
    "location",
    "timezone",
    "tags",
    "excluded_by_tag",
    "exclusion_tag",
    "environment",
    "business_function",
    "scan_classification",
    "vlan_name",
    "vlan_tag",
    "expected_size",
    "covered_count",
    "gap_count",
    "coverage_pct",
    "covering_scans",
    "required_asset_name",
    "required_asset_present",
    "required_scan_name",
    "required_scan_present",
    "required_policy_name",
    "configured_policy",
    "required_policy_configured",
    "configured_repository",
    "reason",
    "source_file",
]


def write_coverage_reports(
    run_dir: str | Path,
    coverage_results: list[CoverageValidationResult],
    targets: list[CoverageTarget],
    actual_scopes,
    validation_issues: list[ValidationIssue],
) -> dict[str, Any]:
    output_dir = Path(run_dir)
    details = [asdict(result) for result in coverage_results]
    # extra targets are scan targets outside authoritative scope
    extras = detect_extra_scan_targets(actual_scopes, targets)
    proposed_exclusions = build_proposed_exclusions(extras)
    summary = build_coverage_summary(coverage_results, extras)

    details_json = atomic_write_json(
        output_dir / "coverage_results.json",
        {"schema_version": 1, "results": details},
    )
    details_csv = _write_details_csv(output_dir / "coverage_results.csv", details)
    summary_json = atomic_write_json(output_dir / "coverage_summary.json", summary)
    summary_md = _write_summary_markdown(output_dir / "coverage_summary.md", summary)
    extras_json = atomic_write_json(
        output_dir / "extra_scan_targets.json",
        {"schema_version": 1, "findings": extras},
    )
    exclusions_json = atomic_write_json(
        output_dir / "proposed_exclusions.json",
        {"schema_version": 1, "proposed_exclusions": proposed_exclusions},
    )
    exclusions_csv = _write_dict_csv(
        output_dir / "proposed_exclusions.csv",
        proposed_exclusions,
        [
            "scan_name",
            "configured_scope",
            "proposed_exclusion",
            "proposed_action",
            "approval_status",
        ],
    )
    issues_json = atomic_write_json(
        output_dir / "definition_validation_issues.json",
        {
            "schema_version": 1,
            "issues": [asdict(issue) for issue in validation_issues],
        },
    )
    return {
        "coverage_results_json": str(details_json),
        "coverage_results_csv": str(details_csv),
        "coverage_summary_json": str(summary_json),
        "coverage_summary_markdown": str(summary_md),
        "extra_scan_targets_json": str(extras_json),
        "proposed_exclusions_json": str(exclusions_json),
        "proposed_exclusions_csv": str(exclusions_csv),
        "definition_validation_issues_json": str(issues_json),
        "extra_scan_target_count": len(extras),
    }


def build_proposed_exclusions(extras: list[dict[str, Any]]) -> list[dict[str, Any]]:
    proposals = []
    for finding in extras:
        for cidr in finding["extra_cidrs"]:
            proposals.append(
                {
                    "scan_name": finding["scan_name"],
                    "configured_scope": finding["configured_scope"],
                    "proposed_exclusion": cidr,
                    "proposed_action": ("REVIEW_ADD_EXCLUSION_OR_REMOVE_STALE_TARGET"),
                    "approval_status": "PENDING",
                }
            )
    return proposals


def build_coverage_summary(
    results: list[CoverageValidationResult], extras: list[dict[str, Any]]
) -> dict[str, Any]:
    totals = _aggregate(results)
    dimensions = {
        "region": _group_summary(results, lambda item: item.region),
        "site": _group_summary(results, lambda item: item.site_code),
        "vlan": _group_summary(
            results,
            lambda item: f"{item.site_code}/{item.vlan_name or item.target_type}",
        ),
        "scan_type": _group_summary(results, lambda item: item.required_scan_name),
        "repository": _group_summary(results, lambda item: item.configured_repository),
        "policy": _group_summary(
            results,
            lambda item: item.required_policy_name,
        ),
    }
    return {
        "schema_version": 1,
        "totals": totals,
        "dimensions": dimensions,
        "tag_exclusions": [
            {
                "site_code": result.site_code,
                "target_type": result.target_type,
                "cidr": result.cidr,
                "vlan_name": result.vlan_name,
                "vlan_tag": result.vlan_tag,
                "exclusion_tag": result.exclusion_tag,
                "source_file": result.source_file,
            }
            for result in results
            if result.excluded_by_tag
        ],
        "tag_excluded_count": sum(result.excluded_by_tag for result in results),
        "missing_asset_groups": sorted(
            {
                result.required_asset_name
                for result in results
                if (
                    not result.excluded_by_tag
                    and result.required_asset_present == "No"
                    and result.required_asset_name
                )
            }
        ),
        "missing_scans": sorted(
            {
                result.required_scan_name
                for result in results
                if (
                    not result.excluded_by_tag
                    and result.required_scan_present == "No"
                    and result.required_scan_name
                )
            }
        ),
        "policy_mismatches": [
            {
                "site_code": result.site_code,
                "scan": result.required_scan_name,
                "expected_policy": result.required_policy_name,
                "configured_policy": result.configured_policy,
            }
            for result in results
            if result.required_policy_configured == "No"
        ],
        "extra_scan_target_count": len(extras),
    }


def _group_summary(results, key_fn) -> list[dict[str, Any]]:
    """Build coverage totals for each group"""
    grouped = defaultdict(list)
    for result in results:
        grouped[str(key_fn(result) or "UNASSIGNED")].append(result)
    return [
        {"name": name, **_aggregate(items)} for name, items in sorted(grouped.items())
    ]


def _aggregate(results: list[CoverageValidationResult]) -> dict[str, Any]:
    """Build overall coverage totals"""
    statuses = Counter(result.status for result in results)
    expected = sum(result.expected_size for result in results)
    covered = sum(result.covered_count for result in results)
    gap = sum(result.gap_count for result in results)
    return {
        "target_count": len(results),
        "expected_ip_count": expected,
        "covered_ip_count": covered,
        "gap_ip_count": gap,
        "coverage_pct": round((covered / expected) * 100, 2) if expected else 0.0,
        "status_counts": dict(sorted(statuses.items())),
    }


def detect_extra_scan_targets(actual_scopes, targets) -> list[dict[str, Any]]:
    """Detect extra scan targets

    "Extra" scan targets are scan targets not found in network definitions
    """
    expected_intervals = [
        scope_to_interval(parse_scope_item(target.cidr)) for target in targets
    ]
    findings = []
    for actual in actual_scopes:
        actual_start, actual_end = scope_to_interval(actual.parsed)
        overlaps = []
        for expected_start, expected_end in expected_intervals:
            start = max(actual_start, expected_start)
            end = min(actual_end, expected_end)
            if start <= end:
                overlaps.append((start, end))
        # subtract the expected overlaps to find only the unowned scan scope
        extras = subtract_intervals(
            [(actual_start, actual_end)], merge_intervals(overlaps)
        )
        if not extras:
            continue
        extra_cidrs: list[str] = []
        for start, end in extras:
            extra_cidrs.extend(
                str(network)
                for network in ipaddress.summarize_address_range(
                    ipaddress.ip_address(start), ipaddress.ip_address(end)
                )
            )
        configured_size = actual_end - actual_start + 1
        extra_size = sum(end - start + 1 for start, end in extras)
        findings.append(
            {
                "scan_name": actual.scan_name,
                "configured_scope": actual.scope_item,
                "classification": (
                    "EXTRA" if extra_size == configured_size else "PARTIAL_EXTRA"
                ),
                "extra_ip_count": extra_size,
                "extra_cidrs": extra_cidrs,
            }
        )
    return findings


def _write_details_csv(path: Path, details: list[dict[str, Any]]) -> Path:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=DETAIL_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in details:
        csv_row = dict(row)
        csv_row["covering_scans"] = ", ".join(row.get("covering_scans", []))
        csv_row["tags"] = ", ".join(row.get("tags", []))
        csv_row["scan_classification"] = str(row.get("scan_classification", {}))
        writer.writerow(csv_row)
    return atomic_write_text(path, buffer.getvalue())


def _write_dict_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> Path:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return atomic_write_text(path, buffer.getvalue())


def write_final_audit_report(
    path: str | Path,
    summary: dict[str, Any],
    validation_issues: list[ValidationIssue],
    coverage_results: list[CoverageValidationResult],
) -> Path:
    severity_counts = Counter(issue.severity for issue in validation_issues)
    lines = [
        "# Tenable.sc Scan Analysis - Final Audit Report",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Started: `{summary['started_at']}`",
        f"- Completed: `{summary['completed_at']}`",
        f"- Authoritative source: `{summary['authoritative_source_type']}`",
        f"- Dry run: `{summary['dry_run']}`",
        "",
        "## Definition Validation",
        "",
        f"- Files/records processed: {summary['authoritative_units_processed']}",
        f"- Failed records: {summary['authoritative_units_failed']}",
        f"- Errors: {severity_counts.get('ERROR', 0)}",
        f"- Warnings: {severity_counts.get('WARNING', 0)}",
        "",
        "## Coverage",
        "",
        f"- Targets checked: {len(coverage_results)}",
        f"- Matched/OK: {summary['ok_count']}",
        f"- Missing/GAP: {summary['gap_count']}",
        f"- Partial: {summary['partial_count']}",
        f"- Exclusion impacted: {summary['excluded_count']}",
        f"- Tag-excluded scope: {summary.get('tag_excluded_count', 0)}",
        f"- Missing asset groups: {summary['missing_asset_group_count']}",
        f"- Missing required scans: {summary['missing_required_scan_count']}",
        f"- Policy mismatches: {summary['scan_policy_mismatch_count']}",
        f"- Extra/stale targets: {summary['extra_scan_target_count']}",
        "",
        "## Proposed Changes",
        "",
        f"- Proposed rows: {summary['proposed_changes_count']}",
        "- Approval state: PENDING (no mutation performed by this run)",
        "",
    ]
    tag_exclusions = [result for result in coverage_results if result.excluded_by_tag]
    if tag_exclusions:
        lines.extend(("## Tag-Excluded Scope", ""))
        for result in tag_exclusions:
            lines.append(
                "- "
                f"{result.site_code} / {result.target_type} `{result.cidr}`: tagged "
                f"`{result.exclusion_tag}`"
            )
        lines.append("")
    lines.extend(("## Artifacts", ""))
    artifact_keys = (
        "coverage_results_json",
        "coverage_results_csv",
        "coverage_summary_json",
        "coverage_summary_markdown",
        "extra_scan_targets_json",
        "proposed_exclusions_json",
        "proposed_exclusions_csv",
        "definition_validation_issues_json",
        "csv_audit",
        "markdown_audit",
        "audit_log",
    )
    for key in artifact_keys:
        if summary.get(key):
            lines.append(f"- {key}: `{summary[key]}`")
    return atomic_write_text(Path(path), "\n".join(lines).rstrip() + "\n")


def _write_summary_markdown(path: Path, summary: dict[str, Any]) -> Path:
    totals = summary["totals"]
    lines = [
        "# Coverage Summary",
        "",
        f"- Targets: {totals['target_count']}",
        f"- Expected IPs: {totals['expected_ip_count']}",
        f"- Covered IPs: {totals['covered_ip_count']}",
        f"- Gap IPs: {totals['gap_ip_count']}",
        f"- Coverage: {totals['coverage_pct']}%",
        f"- Extra/stale scan target findings: {summary['extra_scan_target_count']}",
        f"- Tag-excluded targets: {summary['tag_excluded_count']}",
        "",
    ]
    for dimension, groups in summary["dimensions"].items():
        lines.extend((f"## By {dimension.replace('_', ' ').title()}", ""))
        lines.append("| Name | Targets | Coverage | Gaps |")
        lines.append("|---|---:|---:|---:|")
        for group in groups:
            lines.append(
                f"| {group['name']} | {group['target_count']} | "
                f"{group['coverage_pct']}% | {group['gap_ip_count']} |"
            )
        lines.append("")
    lines.extend(("## Missing Asset Groups", ""))
    lines.extend(f"- {name}" for name in summary["missing_asset_groups"])
    if not summary["missing_asset_groups"]:
        lines.append("- None")
    lines.extend(("", "## Missing Scans", ""))
    lines.extend(f"- {name}" for name in summary["missing_scans"])
    if not summary["missing_scans"]:
        lines.append("- None")
    lines.extend(("", "## Policy Mismatches", ""))
    if summary["policy_mismatches"]:
        for mismatch in summary["policy_mismatches"]:
            lines.append(
                "- "
                f"{mismatch['site_code']} / {mismatch['scan']}: expected "
                f"{mismatch['expected_policy'] or 'N/A'}, configured "
                f"{mismatch['configured_policy'] or 'N/A'}"
            )
    else:
        lines.append("- None")
    lines.extend(("", "## Tag-Excluded Scope", ""))
    if summary["tag_exclusions"]:
        for exclusion in summary["tag_exclusions"]:
            vlan = exclusion["vlan_name"] or exclusion["vlan_tag"]
            vlan_suffix = f" / VLAN {vlan}" if vlan else ""
            lines.append(
                "- "
                f"{exclusion['site_code']} / {exclusion['target_type']} "
                f"`{exclusion['cidr']}`{vlan_suffix}: tagged "
                f"`{exclusion['exclusion_tag']}`"
            )
    else:
        lines.append("- None")
    lines.extend(("", "## Extra/Stale Scan Targets", ""))
    lines.append(f"- Findings: {summary['extra_scan_target_count']}")
    return atomic_write_text(path, "\n".join(lines).rstrip() + "\n")
