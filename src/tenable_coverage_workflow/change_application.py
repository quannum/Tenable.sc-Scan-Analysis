import csv
import hashlib
import ipaddress
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from ..core.scope_utils import split_scope_items
from .audit.audit_logger import atomic_write_text

# This module applies only reviewed plan rows and verifies each Tenable change
# before reporting it as successful.

SUPPORTED_ACTIONS = {
    "CREATE_OR_UPDATE_PUBLIC_ASSET_AND_SCAN",
    "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN",
    "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN",
    "UPDATE_SCAN_POLICY_AND_TARGET",
}
MANAGED_DESCRIPTION = "Managed by Tenable.sc Scan Analysis"
RECENT_HOST_DAYS = 30
AGENT_DETECTED_ASSET_NAME = "Tenable.sc Scan Analysis - Nessus Agent Detected"
AGENT_DETECTED_DESCRIPTION = (
    MANAGED_DESCRIPTION
    + "\n\nHosts with a Nessus Agent detection result from plugins "
    "100574, 110230, or 110231."
)
DYNAMIC_TARGET_DESCRIPTION = (
    "Target criteria: approved CIDR ranges, last seen within 30 days, "
    "and no Nessus Agent detected."
)


@dataclass(frozen=True)
class ApprovedChange:
    run_id: str
    site_code: str
    cidr: str
    target_type: str
    proposed_action: str
    asset_name: str
    scan_name: str
    policy_name: str
    reviewer: str
    decision_notes: str
    vlan_name: str = ""
    vlan_tag: str = ""
    grouping_tag: str = ""


@dataclass(frozen=True)
class ApprovedPlan:
    path: str
    sha256: str
    run_id: str
    total_rows: int
    approved_changes: list[ApprovedChange]


@dataclass(frozen=True)
class ApplyOperation:
    site_code: str
    cidr: str
    action: str
    status: str
    asset_status: str
    scan_status: str
    asset_id: int | None
    scan_id: int | None
    message: str


class ChangeDataAccess(Protocol):
    config: Any

    def get_asset_lists(self) -> list[dict[str, Any]]: ...

    def get_scans(self) -> list[dict[str, Any]]: ...

    def get_policies(self) -> list[dict[str, Any]]: ...

    def get_asset(self, asset_id: int) -> dict[str, Any]: ...

    def get_scan_details(self, scan_id: int) -> dict[str, Any]: ...

    def create_static_asset(
        self, name: str, ips: list[str], description: str
    ) -> dict[str, Any]: ...

    def update_static_asset(
        self, asset_id: int, ips: list[str], description: str | None = None
    ) -> dict[str, Any]: ...

    def create_dynamic_asset(
        self, name: str, rules: dict[str, Any], description: str
    ) -> dict[str, Any]: ...

    def update_dynamic_asset(
        self,
        asset_id: int,
        rules: dict[str, Any],
        description: str | None = None,
    ) -> dict[str, Any]: ...

    def create_combination_asset(
        self,
        name: str,
        included_asset_id: int,
        excluded_asset_id: int,
        description: str,
    ) -> dict[str, Any]: ...

    def update_combination_asset(
        self,
        asset_id: int,
        included_asset_id: int,
        excluded_asset_id: int,
        description: str | None = None,
    ) -> dict[str, Any]: ...

    def create_scan(
        self, name: str, repository_id: int, asset_ids: list[int], policy_id: int
    ) -> dict[str, Any]: ...

    def update_scan_configuration(
        self, scan_id: int, asset_ids: list[int], repository_id: int, policy_id: int
    ) -> dict[str, Any]: ...


def load_approved_plan(path_value: str | Path) -> ApprovedPlan:
    path = Path(path_value)
    raw_bytes = path.read_bytes()
    fingerprint = hashlib.sha256(raw_bytes).hexdigest()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "Run ID",
            "Site Code",
            "CIDR",
            "Proposed Action",
            "Proposed Asset Name",
            "Proposed Scan Name",
            "Proposed Policy Name",
            "Approval Status",
            "Reviewer",
            "Decision Notes",
        }
        missing = sorted(required.difference(reader.fieldnames or []))
        if missing:
            raise ValueError(
                "Approved plan is missing required column(s): " + ", ".join(missing)
            )

        approved: list[ApprovedChange] = []
        run_ids: set[str] = set()
        identities: set[tuple[str, str, str]] = set()
        total_rows = 0
        for row_number, row in enumerate(reader, start=2):
            total_rows += 1
            approval = _text(row.get("Approval Status")).upper()
            if approval not in {"PENDING", "APPROVED", "REJECTED", "SKIPPED"}:
                raise ValueError(
                    f"Row {row_number} has invalid Approval Status '{approval}'."
                )
            if approval != "APPROVED":
                continue
            reviewer = _text(row.get("Reviewer"))
            if not reviewer:
                raise ValueError(f"Row {row_number} is APPROVED but has no Reviewer.")
            run_id = _required_text(row, "Run ID", row_number)
            change = ApprovedChange(
                run_id=run_id,
                site_code=_required_text(row, "Site Code", row_number),
                cidr=_required_text(row, "CIDR", row_number),
                target_type=_text(row.get("Target Type")).upper(),
                proposed_action=_required_text(
                    row, "Proposed Action", row_number
                ).upper(),
                asset_name=_required_text(row, "Proposed Asset Name", row_number),
                scan_name=_required_text(row, "Proposed Scan Name", row_number),
                policy_name=_required_text(row, "Proposed Policy Name", row_number),
                reviewer=reviewer,
                decision_notes=_text(row.get("Decision Notes")),
                vlan_name=_text(row.get("VLAN Name")),
                vlan_tag=_text(row.get("VLAN Tag")),
                grouping_tag=_text(row.get("VLAN Grouping Tag")),
            )
            try:
                canonical_cidr = str(ipaddress.ip_network(change.cidr, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"Row {row_number} has invalid CIDR '{change.cidr}': {exc}"
                ) from exc
            change = ApprovedChange(**{**asdict(change), "cidr": canonical_cidr})
            identity = (change.asset_name, change.scan_name, change.cidr)
            if identity in identities:
                raise ValueError(
                    f"Row {row_number} duplicates an approved asset/scan/CIDR change."
                )
            identities.add(identity)
            run_ids.add(run_id)
            approved.append(change)

    if not approved:
        raise ValueError("Plan contains no APPROVED changes.")
    if len(run_ids) != 1:
        raise ValueError("All APPROVED rows must have the same Run ID.")
    return ApprovedPlan(
        path=str(path),
        sha256=fingerprint,
        run_id=next(iter(run_ids)),
        total_rows=total_rows,
        approved_changes=approved,
    )


class ChangeApplier:
    def __init__(self, data_access: ChangeDataAccess, repository_id: int) -> None:
        if data_access.config.mode != "live":
            raise ValueError("apply-changes requires --mode live")
        if int(repository_id) <= 0:
            raise ValueError("repository_id must be a positive integer")
        self.data_access = data_access
        self.repository_id = int(repository_id)
        self.assets = self._unique_name_index(
            data_access.get_asset_lists(), "asset group"
        )
        self.scans = self._unique_name_index(data_access.get_scans(), "scan")
        self.policies = self._unique_name_index(data_access.get_policies(), "policy")
        self.asset_scopes: dict[str, set[str]] = {}
        self.agent_asset: dict[str, Any] | None = None

    def preflight(self, plan: ApprovedPlan) -> None:
        """Check requirements before applying changes"""
        errors = []
        # check every named policy before creating or updating anything
        for change in plan.approved_changes:
            if change.proposed_action not in SUPPORTED_ACTIONS:
                continue
            if change.policy_name not in self.policies:
                errors.append(
                    f"{change.site_code}: policy '{change.policy_name}' was not found"
                )
        if errors:
            raise ValueError("Apply preflight failed: " + "; ".join(errors))

    def apply(self, plan: ApprovedPlan) -> dict[str, Any]:
        self.preflight(plan)
        started_at = datetime.now(timezone.utc)
        operations = []
        actionable_changes = [
            change
            for change in plan.approved_changes
            if change.proposed_action in SUPPORTED_ACTIONS
        ]
        self.asset_scopes = _build_asset_scopes(actionable_changes)
        asset_descriptions = _build_asset_descriptions(actionable_changes)
        if actionable_changes:
            self.agent_asset = self._confirm_agent_asset()
        for change in plan.approved_changes:
            if change.proposed_action not in SUPPORTED_ACTIONS:
                # keep manual review before applying or updating antyhign
                operations.append(
                    ApplyOperation(
                        site_code=change.site_code,
                        cidr=change.cidr,
                        action=change.proposed_action,
                        status="SKIPPED",
                        asset_status="SKIPPED",
                        scan_status="SKIPPED",
                        asset_id=None,
                        scan_id=None,
                        message=(
                            "Action requires manual review and is not auto-applied."
                        ),
                    )
                )
                continue
            try:
                operations.append(
                    self._apply_change(
                        change,
                        asset_descriptions.get(change.asset_name, MANAGED_DESCRIPTION),
                    )
                )
            except Exception as exc:
                operations.append(
                    ApplyOperation(
                        site_code=change.site_code,
                        cidr=change.cidr,
                        action=change.proposed_action,
                        status="FAILED",
                        asset_status="UNKNOWN",
                        scan_status="UNKNOWN",
                        asset_id=None,
                        scan_id=None,
                        message=str(exc),
                    )
                )

        completed_at = datetime.now(timezone.utc)
        counts = Counter(operation.status for operation in operations)
        return {
            "schema_version": 1,
            "run_id": plan.run_id,
            "plan_file": plan.path,
            "plan_sha256": plan.sha256,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "repository_id": self.repository_id,
            "approved_change_count": len(plan.approved_changes),
            "status_counts": dict(sorted(counts.items())),
            "operations": [asdict(operation) for operation in operations],
        }

    def _apply_change(
        self,
        change: ApprovedChange,
        asset_description: str,
    ) -> ApplyOperation:
        asset, asset_status = self._confirm_asset(change, asset_description)
        asset_id = _resource_id(asset, "asset group", change.asset_name)
        scan, scan_status = self._confirm_scan(change, asset_id)
        scan_id = _resource_id(scan, "scan", change.scan_name)
        status = (
            "UNCHANGED"
            if asset_status == "UNCHANGED" and scan_status == "UNCHANGED"
            else "APPLIED"
        )
        return ApplyOperation(
            site_code=change.site_code,
            cidr=change.cidr,
            action=change.proposed_action,
            status=status,
            asset_status=asset_status,
            scan_status=scan_status,
            asset_id=asset_id,
            scan_id=scan_id,
            message="Post-change verification passed.",
        )

    def _confirm_asset(
        self,
        change: ApprovedChange,
        asset_description: str,
    ) -> tuple[dict[str, Any], str]:
        """confirm recent non-agent target asset is available"""
        if self.agent_asset is None:
            raise RuntimeError("Nessus Agent detection asset was not initialized")

        candidate_name = _candidate_asset_name(change.asset_name)
        candidate_scopes = self.asset_scopes[change.asset_name]
        candidate, candidate_status = self._confirm_recent_candidate_asset(
            candidate_name,
            candidate_scopes,
            change.asset_name,
        )
        candidate_id = _resource_id(candidate, "candidate asset group", candidate_name)
        agent_id = _resource_id(
            self.agent_asset,
            "Nessus Agent detection asset group",
            AGENT_DETECTED_ASSET_NAME,
        )
        existing = self.assets.get(change.asset_name)
        description = _merge_asset_description(
            _text(existing.get("description")) if existing else "",
            _dynamic_target_description(asset_description),
        )
        if existing is None:
            created = self.data_access.create_combination_asset(
                change.asset_name,
                candidate_id,
                agent_id,
                description,
            )
            asset_id = _resource_id(created, "asset group", change.asset_name)
            self._verify_target_asset(asset_id, candidate_id, agent_id)
            self.assets[change.asset_name] = created
            return created, _combined_asset_status(candidate_status, "CREATED")

        asset_id = _resource_id(existing, "asset group", change.asset_name)
        details = self.data_access.get_asset(asset_id) or existing
        if _combination_matches(details, candidate_id, agent_id) and (
            description == _text(details.get("description"))
        ):
            return details, candidate_status
        updated = self.data_access.update_combination_asset(
            asset_id,
            candidate_id,
            agent_id,
            description,
        )
        self._verify_target_asset(asset_id, candidate_id, agent_id)
        merged = updated if isinstance(updated, dict) and updated else details
        self.assets[change.asset_name] = merged
        return merged, "UPDATED"

    def _confirm_agent_asset(self) -> dict[str, Any]:
        """confirm shared dynamic asset detects hosts with Nessus Agents"""
        rules = _agent_detection_rules()
        existing = self.assets.get(AGENT_DETECTED_ASSET_NAME)
        if existing is None:
            created = self.data_access.create_dynamic_asset(
                AGENT_DETECTED_ASSET_NAME,
                rules,
                AGENT_DETECTED_DESCRIPTION,
            )
            self.assets[AGENT_DETECTED_ASSET_NAME] = created
            return created

        asset_id = _resource_id(
            existing, "Nessus Agent detection asset group", AGENT_DETECTED_ASSET_NAME
        )
        details = self.data_access.get_asset(asset_id) or existing
        if _asset_type(details) != "dynamic":
            raise RuntimeError(
                f"Asset group '{AGENT_DETECTED_ASSET_NAME}' must be dynamic."
            )
        if _dynamic_rules_match(details, rules) and (
            _text(details.get("description")) == AGENT_DETECTED_DESCRIPTION
        ):
            return details
        updated = self.data_access.update_dynamic_asset(
            asset_id,
            rules,
            AGENT_DETECTED_DESCRIPTION,
        )
        merged = updated if isinstance(updated, dict) and updated else details
        self.assets[AGENT_DETECTED_ASSET_NAME] = merged
        return merged

    def _confirm_recent_candidate_asset(
        self,
        candidate_name: str,
        scopes: set[str],
        target_name: str,
    ) -> tuple[dict[str, Any], str]:
        """confirm dynamic CIDR and source asset is available"""
        rules = _recent_scope_rules(scopes)
        description = _candidate_description(target_name)
        existing = self.assets.get(candidate_name)
        if existing is None:
            created = self.data_access.create_dynamic_asset(
                candidate_name,
                rules,
                description,
            )
            self.assets[candidate_name] = created
            return created, "CREATED"

        asset_id = _resource_id(existing, "candidate asset group", candidate_name)
        details = self.data_access.get_asset(asset_id) or existing
        if _asset_type(details) != "dynamic":
            raise RuntimeError(f"Asset group '{candidate_name}' must be dynamic.")
        if _dynamic_rules_match(details, rules) and (
            _text(details.get("description")) == description
        ):
            return details, "UNCHANGED"
        updated = self.data_access.update_dynamic_asset(asset_id, rules, description)
        merged = updated if isinstance(updated, dict) and updated else details
        self.assets[candidate_name] = merged
        return merged, "UPDATED"

    def _confirm_scan(
        self, change: ApprovedChange, asset_id: int
    ) -> tuple[dict[str, Any], str]:
        """Confirm scan created or updated"""
        existing = self.scans.get(change.scan_name)
        # Policy names are resolved here so each Tenable instance uses its own ID.
        policy_id = _resource_id(
            self.policies[change.policy_name], "policy", change.policy_name
        )
        if existing is None:
            created = self.data_access.create_scan(
                change.scan_name,
                self.repository_id,
                [asset_id],
                policy_id,
            )
            scan_id = _resource_id(created, "scan", change.scan_name)
            self.scans[change.scan_name] = created
            self._verify_scan(scan_id, asset_id, policy_id)
            return created, "CREATED"

        scan_id = _resource_id(existing, "scan", change.scan_name)
        details = self.data_access.get_scan_details(scan_id) or existing
        current_asset_ids = get_scan_asset_ids(details)
        current_repository_id = get_nested_id(details, "repository", "repositoryID")
        current_policy_id = get_nested_id(details, "policy", "policyID")
        if (
            asset_id in current_asset_ids
            and current_repository_id == self.repository_id
            and current_policy_id == policy_id
        ):
            return details, "UNCHANGED"
        # add this asset without dropping assets already assigned to the scan
        updated_ids = sorted(current_asset_ids | {asset_id})
        updated = self.data_access.update_scan_configuration(
            scan_id,
            updated_ids,
            self.repository_id,
            policy_id,
        )
        self._verify_scan(scan_id, asset_id, policy_id)
        merged = updated if isinstance(updated, dict) and updated else details
        self.scans[change.scan_name] = merged
        return merged, "UPDATED"

    def _verify_target_asset(
        self,
        asset_id: int,
        expected_candidate_id: int,
        expected_agent_id: int,
    ) -> None:
        """Check that a target excludes hosts with the Nessus Agent installed"""
        details = self.data_access.get_asset(asset_id)
        if not _combination_matches(
            details, expected_candidate_id, expected_agent_id
        ):
            raise RuntimeError(
                f"Asset {asset_id} verification failed: expected dynamic target "
                "definition is not present"
            )

    def _verify_scan(
        self,
        scan_id: int,
        expected_asset_id: int,
        expected_policy_id: int | None = None,
    ) -> None:
        """Check that a scan has the expected settings"""
        details = self.data_access.get_scan_details(scan_id)
        if expected_asset_id not in get_scan_asset_ids(details):
            raise RuntimeError(
                f"Scan {scan_id} verification failed: asset {expected_asset_id} "
                "not attached"
            )
        if get_nested_id(details, "repository", "repositoryID") != (
            self.repository_id
        ):
            raise RuntimeError(
                f"Scan {scan_id} verification failed: repository mismatch"
            )
        if (
            expected_policy_id is not None
            and get_nested_id(details, "policy", "policyID") != expected_policy_id
        ):
            raise RuntimeError(f"Scan {scan_id} verification failed: policy mismatch")

    @staticmethod
    def _unique_name_index(
        records: list[dict[str, Any]], resource_type: str
    ) -> dict[str, dict[str, Any]]:
        """Index resources by name and get rid of duplicate names"""
        result = {}
        for record in records:
            name = _text(record.get("name"))
            if not name:
                continue
            if name in result:
                raise ValueError(
                    f"Ambiguous {resource_type} name '{name}'; exact names "
                    "must be unique"
                )
            result[name] = record
        return result


def get_asset_scopes(asset: dict[str, Any]) -> set[str]:
    values = []
    type_fields = asset.get("typeFields", {})
    if isinstance(type_fields, dict):
        values.append(type_fields.get("definedIPs"))
    values.extend((asset.get("ips"), asset.get("ipList")))
    scopes = set()
    for value in values:
        raw_items = value if isinstance(value, list) else split_scope_items(value or "")
        for item in raw_items:
            try:
                scopes.add(str(ipaddress.ip_network(str(item).strip(), strict=False)))
            except ValueError:
                scopes.add(str(item).strip())
    return {scope for scope in scopes if scope}


def _build_asset_scopes(changes: list[ApprovedChange]) -> dict[str, set[str]]:
    """Group the CIDRs that form each proposed target"""
    scopes: dict[str, set[str]] = {}
    for change in changes:
        scopes.setdefault(change.asset_name, set()).add(change.cidr)
    return scopes


def _candidate_asset_name(target_name: str) -> str:
    """Name the managed source asset behind a proposed scan target"""
    return f"{target_name} - Recent Hosts"


def _candidate_description(target_name: str) -> str:
    """Describe a dynamic candidate asset"""
    return (
        f"{MANAGED_DESCRIPTION}\n\n"
        f"Candidate hosts for '{target_name}': approved CIDR ranges and last seen "
        f"within {RECENT_HOST_DAYS} days."
    )


def _dynamic_target_description(asset_description: str) -> str:
    """Describe the final dynamically evaluated scan target"""
    return _merge_asset_description(asset_description, DYNAMIC_TARGET_DESCRIPTION)


def _recent_scope_rules(scopes: set[str]) -> dict[str, Any]:
    """Build the dynamic rules for approved CIDRs seen recently"""
    return {
        "operator": "all",
        "children": [
            {
                "type": "group",
                "operator": "any",
                "children": [
                    {
                        "type": "clause",
                        "filterName": "ip",
                        "operator": "eq",
                        "value": scope,
                    }
                    for scope in sorted(scopes)
                ],
            },
            {
                "type": "clause",
                "filterName": "lastseen",
                "operator": "lt",
                "value": str(RECENT_HOST_DAYS),
            },
        ],
    }


def _agent_detection_rules() -> dict[str, Any]:
    """Build dynamic rules for Nessus Agent detection plugins"""
    return {
        "operator": "any",
        "children": [
            {
                "type": "clause",
                "filterName": "pluginid",
                "operator": "eq",
                "value": {"id": plugin_id},
            }
            for plugin_id in (100574, 110230, 110231)
        ],
    }


def _asset_type(asset: dict[str, Any]) -> str:
    """Read an asset-list type consistently"""
    return _text(asset.get("type")).lower()


def _dynamic_rules_match(asset: dict[str, Any], expected_rules: dict[str, Any]) -> bool:
    """Check an asset has the expected dynamic rules"""
    type_fields = asset.get("typeFields")
    if not isinstance(type_fields, dict):
        return False
    return type_fields.get("rules") == expected_rules


def _combination_matches(
    asset: dict[str, Any], included_asset_id: int, excluded_asset_id: int
) -> bool:
    """Check an asset is the expected difference combination"""
    if _asset_type(asset) != "combination":
        return False
    type_fields = asset.get("typeFields")
    if not isinstance(type_fields, dict):
        return False
    combination = type_fields.get("combinations")
    if not isinstance(combination, dict):
        return False
    return (
        combination.get("operator") == "difference"
        and _nested_id(combination.get("operand1")) == included_asset_id
        and _nested_id(combination.get("operand2")) == excluded_asset_id
    )


def _nested_id(value: Any) -> int | None:
    """Read an ID from a nested Tenable.sc record"""
    if not isinstance(value, dict):
        return None
    try:
        return int(value.get("id"))
    except (TypeError, ValueError):
        return None


def _combined_asset_status(*statuses: str) -> str:
    """Reduce supporting asset changes to one operation status"""
    if "CREATED" in statuses:
        return "CREATED"
    if "UPDATED" in statuses:
        return "UPDATED"
    return "UNCHANGED"


def get_scan_asset_ids(scan: dict[str, Any]) -> set[int]:
    values = scan.get("assets", scan.get("assetLists", []))
    if not isinstance(values, list):
        return set()
    result = set()
    for value in values:
        raw_id = value.get("id") if isinstance(value, dict) else value
        if raw_id in (None, ""):
            continue
        try:
            result.add(int(cast(Any, raw_id)))
        except (TypeError, ValueError):
            continue
    return result


def get_nested_id(
    record: dict[str, Any], nested_key: str, scalar_key: str
) -> int | None:
    value = record.get(nested_key)
    raw_id = value.get("id") if isinstance(value, dict) else record.get(scalar_key)
    if raw_id in (None, ""):
        return None
    try:
        return int(cast(Any, raw_id))
    except (TypeError, ValueError):
        return None


def _resource_id(record: dict[str, Any], resource_type: str, name: str) -> int:
    try:
        return int(record["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            f"{resource_type.title()} '{name}' response has no numeric id"
        ) from exc


def _required_text(row: dict[str, Any], column: str, row_number: int) -> str:
    value = _text(row.get(column))
    if not value:
        raise ValueError(f"Row {row_number} has no {column}.")
    return value


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _build_asset_descriptions(changes: list[ApprovedChange]) -> dict[str, str]:
    """Build descriptions for proposed asset groups"""
    scope_lines: dict[str, set[str]] = {}
    for change in changes:
        line = _asset_description_line(change)
        if not line:
            continue
        scope_lines.setdefault(change.asset_name, set()).add(line)

    return {
        asset_name: MANAGED_DESCRIPTION + "\n\n" + "\n".join(sorted(lines))
        for asset_name, lines in scope_lines.items()
    }


def _asset_description_line(change: ApprovedChange) -> str | None:
    if change.vlan_name:
        grouping_label = change.grouping_tag or f"VLAN {change.vlan_tag or 'N/A'}"
        return f"{change.vlan_name} {change.cidr} {grouping_label}"
    if change.target_type == "PUBLIC":
        return f"Public Range {change.cidr}"
    if change.target_type == "PRIVATE_SUPERNET":
        return f"Private Supernet {change.cidr}"
    return None


def _merge_asset_description(existing: str, planned: str) -> str:
    """Add planned VLAN lines without removing existing description text"""
    if not existing or existing == planned:
        return planned
    if planned == MANAGED_DESCRIPTION:
        return existing

    missing_lines = [line for line in planned.splitlines() if line not in existing]
    if not missing_lines:
        return existing
    return existing.rstrip() + "\n" + "\n".join(missing_lines)


def write_apply_markdown(result: dict[str, Any], path_value: str | Path) -> Path:
    lines = [
        "# Tenable.sc Apply Audit",
        "",
        f"- Run ID: `{result['run_id']}`",
        f"- Plan SHA-256: `{result['plan_sha256']}`",
        f"- Repository ID: `{result['repository_id']}`",
        f"- Started: `{result['started_at']}`",
        f"- Completed: `{result['completed_at']}`",
        "",
        "## Status Summary",
        "",
    ]
    for status, count in sorted(result["status_counts"].items()):
        lines.append(f"- {status}: {count}")
    lines.extend(("", "## Operations", ""))
    for operation in result["operations"]:
        lines.extend(
            (
                f"### {operation['site_code']} - `{operation['cidr']}`",
                "",
                f"- Action: {operation['action']}",
                f"- Status: {operation['status']}",
                f"- Asset: {operation['asset_status']} "
                f"(ID: {operation['asset_id'] or 'N/A'})",
                f"- Scan: {operation['scan_status']} "
                f"(ID: {operation['scan_id'] or 'N/A'})",
                f"- Result: {operation['message']}",
                "",
            )
        )
    return atomic_write_text(Path(path_value), "\n".join(lines).rstrip() + "\n")
