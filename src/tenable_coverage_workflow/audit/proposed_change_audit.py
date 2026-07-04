import csv
from collections import defaultdict
from io import StringIO
from pathlib import Path

from ..models import ProposedChange
from .audit_logger import atomic_write_text

CSV_COLUMNS = [
    "Run ID",
    "Site Code",
    "Site Name",
    "Target Type",
    "CIDR",
    "VLAN Name",
    "VLAN Tag",
    "Current Status",
    "Issue",
    "Proposed Action",
    "Proposed Asset Name",
    "Proposed Scan Name",
    "Proposed Policy Name",
    "Approval Status",
    "Reviewer",
    "Decision Notes",
    "Source YAML File",
]


def write_proposed_change_audits(
    run_id: str,
    run_dir: str | Path,
    proposed_changes: list[ProposedChange],
    audit_logger=None,
) -> tuple[Path, Path]:
    run_directory = Path(run_dir)
    csv_path = _write_csv(run_id, run_directory, proposed_changes)
    md_path = _write_markdown(run_id, run_directory, proposed_changes)

    if audit_logger:
        audit_logger.emit(
            "proposed_change_audit_written",
            csv_path=csv_path,
            markdown_path=md_path,
            proposed_change_count=len(proposed_changes),
        )

    return csv_path, md_path


def _write_csv(
    run_id: str,
    run_dir: Path,
    proposed_changes: list[ProposedChange],
) -> Path:
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)

    for change in proposed_changes:
        writer.writerow(
            [
                run_id,
                change.site_code,
                change.site_name or "",
                change.target_type,
                change.cidr,
                change.vlan_name or "",
                "" if change.vlan_tag is None else change.vlan_tag,
                change.current_status,
                change.issue,
                change.proposed_action,
                change.proposed_asset_name or "",
                change.proposed_scan_name or "",
                change.proposed_policy_name or "",
                change.approval_status,
                change.reviewer or "",
                change.decision_notes or "",
                change.source_file or "",
            ]
        )

    return atomic_write_text(run_dir / "proposed_changes.csv", buffer.getvalue())


def _write_markdown(
    run_id: str,
    run_dir: Path,
    proposed_changes: list[ProposedChange],
) -> Path:
    groups: dict[tuple[str, str | None], list[ProposedChange]] = defaultdict(list)
    for change in proposed_changes:
        groups[(change.site_code, change.site_name)].append(change)

    lines = ["# Proposed Changes Audit", "", f"Run ID: `{run_id}`", ""]

    for site_code, site_name in sorted(groups):
        heading = site_code if not site_name else f"{site_code} - {site_name}"
        lines.append(f"## {heading}")
        lines.append("")

        for change in sorted(
            groups[(site_code, site_name)],
            key=lambda item: (
                item.target_type,
                item.cidr,
                item.vlan_name or "",
                str(item.vlan_tag or ""),
            ),
        ):
            lines.append(f"### {change.target_type}: `{change.cidr}`")
            lines.append(f"- Current Status: {change.current_status}")
            lines.append(f"- Issue: {change.issue}")
            lines.append(f"- Proposed Action: {change.proposed_action}")
            lines.append(f"- Proposed Asset: {change.proposed_asset_name or 'N/A'}")
            lines.append(f"- Proposed Scan: {change.proposed_scan_name or 'N/A'}")
            lines.append(f"- Proposed Policy: {change.proposed_policy_name or 'N/A'}")
            lines.append(f"- Approval Status: {change.approval_status}")
            lines.append(f"- Source YAML File: {change.source_file or 'N/A'}")
            if change.vlan_name or change.vlan_tag is not None:
                vlan_label = change.vlan_name or "N/A"
                vlan_tag = change.vlan_tag if change.vlan_tag is not None else "N/A"
                lines.append(f"- VLAN: {vlan_label} / {vlan_tag}")
            lines.append("")

    return atomic_write_text(
        run_dir / "proposed_changes.md",
        "\n".join(lines).rstrip() + "\n",
    )
