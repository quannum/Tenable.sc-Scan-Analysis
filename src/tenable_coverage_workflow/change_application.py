import csv
import hashlib
import ipaddress
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from ..core.scope_utils import split_scope_items
from .audit.audit_logger import atomic_write_text

# This module applies only reviewed plan rows and verifies each Tenable change
# before reporting it as successful

SUPPORTED_ACTIONS = {
    "CREATE_OR_UPDATE_PUBLIC_ASSET_AND_SCAN",
    "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN",
    "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN",
    "UPDATE_SCAN_POLICY_AND_TARGET",
}


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
    desired_asset_type: str = ""


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


class _ApplyChangeFailure(RuntimeError):
    """Carry known resource state when a change applies only partially."""

    def __init__(
        self,
        message: str,
        asset_status: str,
        scan_status: str,
        asset_id: int | None,
        scan_id: int | None,
    ) -> None:
        super().__init__(message)
        self.asset_status = asset_status
        self.scan_status = scan_status
        self.asset_id = asset_id
        self.scan_id = scan_id


@dataclass(frozen=True)
class AssetDefinition:
    name: str
    asset_type: str
    cidrs: tuple[str, ...]
    description: str
    label: str | None = None


@dataclass(frozen=True)
class ScanDefinition:
    name: str
    description: str | None


class ChangeDataAccess(Protocol):
    config: Any

    def get_asset_lists(self) -> list[dict[str, Any]]: ...

    def get_scans(self) -> list[dict[str, Any]]: ...

    def get_policies(self) -> list[dict[str, Any]]: ...

    def get_asset(self, asset_id: int) -> dict[str, Any]: ...

    def get_scan_details(self, scan_id: int) -> dict[str, Any]: ...

    def create_static_asset(
        self,
        name: str,
        ips: list[str],
        description: str,
        label: str | None = None,
    ) -> dict[str, Any]: ...

    def update_static_asset(
        self,
        asset_id: int,
        ips: list[str],
        description: str | None = None,
        label: str | None = None,
    ) -> dict[str, Any]: ...

    def create_dynamic_asset(
        self,
        name: str,
        rules: dict[str, Any],
        description: str,
        label: str | None = None,
    ) -> dict[str, Any]: ...

    def update_dynamic_asset(
        self,
        asset_id: int,
        rules: dict[str, Any],
        description: str | None = None,
        label: str | None = None,
    ) -> dict[str, Any]: ...

    def create_scan(
        self,
        name: str,
        repository_id: int,
        asset_ids: list[int],
        policy_id: int,
        description: str | None = None,
    ) -> dict[str, Any]: ...

    def update_scan_configuration(
        self,
        scan_id: int,
        asset_ids: list[int],
        repository_id: int,
        policy_id: int,
        description: str | None = None,
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
                    f"Row {row_number} has invalid Approval Status '{approval}'"
                )
            if approval != "APPROVED":
                continue
            reviewer = _text(row.get("Reviewer"))
            if not reviewer:
                raise ValueError(f"Row {row_number} is APPROVED but has no Reviewer")
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
                desired_asset_type=_text(row.get("Desired Asset Type")).lower(),
            )
            try:
                canonical_cidr = str(ipaddress.ip_network(change.cidr, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"Row {row_number} has invalid CIDR '{change.cidr}': {exc}"
                ) from exc
            change = ApprovedChange(**{**asdict(change), "cidr": canonical_cidr})
            expected_asset_type = _asset_type_for_target(change.target_type)
            desired_asset_type = change.desired_asset_type or expected_asset_type
            if desired_asset_type != expected_asset_type:
                raise ValueError(
                    f"Row {row_number} has Desired Asset Type "
                    f"'{desired_asset_type}', but {change.target_type} requires "
                    f"'{expected_asset_type}'"
                )
            change = ApprovedChange(
                **{**asdict(change), "desired_asset_type": desired_asset_type}
            )
            identity = (change.asset_name, change.scan_name, change.cidr)
            if identity in identities:
                raise ValueError(
                    f"Row {row_number} duplicates an approved asset/scan/CIDR change"
                )
            identities.add(identity)
            run_ids.add(run_id)
            approved.append(change)

    if not approved:
        raise ValueError("Plan contains no APPROVED changes")
    if len(run_ids) != 1:
        raise ValueError("All APPROVED rows must have the same Run ID")
    return ApprovedPlan(
        path=str(path),
        sha256=fingerprint,
        run_id=next(iter(run_ids)),
        total_rows=total_rows,
        approved_changes=approved,
    )


class ChangeApplier:
    def __init__(
        self,
        data_access: ChangeDataAccess,
        repository_id: int,
        asset_label: str | None = None,
    ) -> None:
        if data_access.config.mode != "live":
            raise ValueError("apply-changes requires --mode live")
        if int(repository_id) <= 0:
            raise ValueError("repository_id must be a positive integer")
        self.data_access = data_access
        self.repository_id = int(repository_id)
        self.asset_label = _optional_text(asset_label)
        self.assets = self._unique_name_index(
            _apply_resource_list(
                data_access, "get_usable_asset_lists", "get_asset_lists"
            ),
            "asset group",
        )
        self.scans = self._unique_name_index(
            _apply_resource_list(data_access, "get_usable_scans", "get_scans"),
            "scan",
        )
        self.policies = self._unique_name_index(
            _apply_resource_list(data_access, "get_usable_policies", "get_policies"),
            "policy",
        )

    def preflight(
        self,
        plan: ApprovedPlan,
        asset_definitions: dict[str, AssetDefinition] | None = None,
    ) -> None:
        """Check requirements before applying changes"""
        errors: list[str] = []
        # Check every named policy before creating or updating anything
        for change in plan.approved_changes:
            if change.proposed_action not in SUPPORTED_ACTIONS:
                continue
            if change.policy_name not in self.policies:
                errors.append(
                    f"{change.site_code}: policy '{change.policy_name}' was not found"
                )
        asset_definitions = asset_definitions or _build_asset_definitions(
            plan.approved_changes, self.asset_label
        )
        for definition in asset_definitions.values():
            existing = self.assets.get(definition.name)
            if existing is None:
                continue
            asset_id = _resource_id(existing, "asset group", definition.name)
            details = self.data_access.get_asset(asset_id) or existing
            current_type = _asset_type(details)
            if current_type and current_type != definition.asset_type:
                errors.append(
                    f"Asset '{definition.name}' is {current_type}, but the plan "
                    f"requires {definition.asset_type}. Manual change is required"
                )
        if errors:
            raise ValueError("Apply preflight failed: " + "; ".join(errors))

    def apply(self, plan: ApprovedPlan) -> dict[str, Any]:
        asset_definitions = _build_asset_definitions(
            plan.approved_changes, self.asset_label
        )
        scan_definitions = _build_scan_definitions(plan.approved_changes)
        self.preflight(plan, asset_definitions)
        started_at = datetime.now(timezone.utc)
        operations = []
        for change in plan.approved_changes:
            if change.proposed_action not in SUPPORTED_ACTIONS:
                # Keep manual review rows visible without applying them
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
                            "Action requires manual review and is not auto-applied"
                        ),
                    )
                )
                continue
            try:
                operations.append(
                    self._apply_change(
                        change,
                        asset_definitions[change.asset_name],
                        scan_definitions[change.scan_name],
                    )
                )
            except Exception as exc:
                failure = (
                    exc
                    if isinstance(exc, _ApplyChangeFailure)
                    else _ApplyChangeFailure(
                        str(exc),
                        asset_status="UNKNOWN",
                        scan_status="UNKNOWN",
                        asset_id=None,
                        scan_id=None,
                    )
                )
                operations.append(
                    ApplyOperation(
                        site_code=change.site_code,
                        cidr=change.cidr,
                        action=change.proposed_action,
                        status="FAILED",
                        asset_status=failure.asset_status,
                        scan_status=failure.scan_status,
                        asset_id=failure.asset_id,
                        scan_id=failure.scan_id,
                        message=str(failure),
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
            "asset_label": self.asset_label,
            "approved_change_count": len(plan.approved_changes),
            "status_counts": dict(sorted(counts.items())),
            "operations": [asdict(operation) for operation in operations],
        }

    def _apply_change(
        self,
        change: ApprovedChange,
        asset_definition: AssetDefinition,
        scan_definition: ScanDefinition,
    ) -> ApplyOperation:
        asset_status = "UNKNOWN"
        scan_status = "UNKNOWN"
        asset_id: int | None = None
        scan_id: int | None = None
        try:
            asset, asset_status = self._confirm_asset(asset_definition)
            asset_id = _resource_id(asset, "asset group", change.asset_name)
            self._verify_asset(asset_id, asset_definition)

            scan, scan_status = self._confirm_scan(change, asset_id, scan_definition)
            scan_id = _resource_id(scan, "scan", change.scan_name)
            policy_id = _resource_id(
                self.policies[change.policy_name], "policy", change.policy_name
            )
            self._verify_scan(scan_id, asset_id, policy_id, scan_definition.description)
        except Exception as exc:
            raise _ApplyChangeFailure(
                str(exc), asset_status, scan_status, asset_id, scan_id
            ) from exc

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
            message="Post-change verification passed",
        )

    def _confirm_asset(self, definition: AssetDefinition) -> tuple[dict[str, Any], str]:
        """Checks if asset already exists and is correctly scoped

        If doesn't exist, creates an asset

        If exists and matches criteria, do nothing

        If exists and criteria is different, updates criteria
        """
        existing = self.assets.get(definition.name)
        if existing is None:
            if definition.asset_type == "static":
                created = self.data_access.create_static_asset(
                    definition.name,
                    list(definition.cidrs),
                    definition.description,
                    definition.label,
                )
            else:
                created = self.data_access.create_dynamic_asset(
                    definition.name,
                    build_dynamic_asset_rules(definition.cidrs),
                    definition.description,
                    definition.label,
                )
            asset_id = _resource_id(created, "asset group", definition.name)
            self.assets[definition.name] = created
            return created, "CREATED"

        asset_id = _resource_id(existing, "asset group", definition.name)
        details = self.data_access.get_asset(asset_id) or existing
        current_type = _asset_type(details)
        if current_type and current_type != definition.asset_type:
            raise RuntimeError(
                f"Asset '{definition.name}' is {current_type}, but requires "
                f"{definition.asset_type}. Manual change is required"
            )

        if definition.asset_type == "static":
            current_scopes = get_asset_scopes(details)
            desired_scopes = tuple(sorted(current_scopes | set(definition.cidrs)))
            if (
                desired_scopes == tuple(sorted(current_scopes))
                and _text(details.get("description")) == definition.description
                and _asset_has_label(details, definition.label)
            ):
                return details, "UNCHANGED"
            updated = self.data_access.update_static_asset(
                asset_id,
                list(desired_scopes),
                definition.description,
                _merged_asset_label(details, definition.label),
            )
        else:
            desired_rules = build_dynamic_asset_rules(definition.cidrs)
            if (
                _dynamic_rules_match(details, desired_rules)
                and _text(details.get("description")) == definition.description
                and _asset_has_label(details, definition.label)
            ):
                return details, "UNCHANGED"
            if _has_unmanaged_dynamic_rules(get_dynamic_asset_rules(details)):
                raise RuntimeError(
                    f"Asset '{definition.name}' contains non-managed dynamic rules; "
                    "manual change is required"
                )
            updated = self.data_access.update_dynamic_asset(
                asset_id,
                desired_rules,
                definition.description,
                _merged_asset_label(details, definition.label),
            )

        merged = updated if isinstance(updated, dict) and updated else details
        self.assets[definition.name] = merged
        return merged, "UPDATED"

    def _confirm_scan(
        self,
        change: ApprovedChange,
        asset_id: int,
        definition: ScanDefinition,
    ) -> tuple[dict[str, Any], str]:
        """Confirm scan created or updated"""
        existing = self.scans.get(change.scan_name)
        # policy names are resolved by name so each Tenable instance uses its own ID
        policy_id = _resource_id(
            self.policies[change.policy_name], "policy", change.policy_name
        )
        if existing is None:
            created = self.data_access.create_scan(
                change.scan_name,
                self.repository_id,
                [asset_id],
                policy_id,
                description=definition.description,
            )
            scan_id = _resource_id(created, "scan", change.scan_name)
            self.scans[change.scan_name] = created
            return created, "CREATED"

        scan_id = _resource_id(existing, "scan", change.scan_name)
        details = self.data_access.get_scan_details(scan_id) or existing
        current_asset_ids = get_scan_asset_ids(details)
        current_repository_id = get_nested_id(details, "repository", "repositoryID")
        current_policy_id = get_nested_id(details, "policy", "policyID")
        description_matches = (
            definition.description is None
            or _text(details.get("description")) == definition.description
        )
        if (
            asset_id in current_asset_ids
            and current_repository_id == self.repository_id
            and current_policy_id == policy_id
            and description_matches
        ):
            return details, "UNCHANGED"
        # add this asset without dropping assets already assigned to the scan
        updated_ids = sorted(current_asset_ids | {asset_id})
        updated = self.data_access.update_scan_configuration(
            scan_id,
            updated_ids,
            self.repository_id,
            policy_id,
            description=definition.description,
        )
        merged = updated if isinstance(updated, dict) and updated else details
        self.scans[change.scan_name] = merged
        return merged, "UPDATED"

    def _verify_asset(self, asset_id: int, definition: AssetDefinition) -> None:
        """Check that an asset group matches its desired static or dynamic state"""
        details = self.data_access.get_asset(asset_id) or {}
        message = self._asset_verification_message(asset_id, details, definition)
        if message:
            raise RuntimeError(message)

    @staticmethod
    def _asset_verification_message(
        asset_id: int, details: dict[str, Any], definition: AssetDefinition
    ) -> str:
        """Return an asset verification failure message, or an empty string"""
        if _asset_type(details) != definition.asset_type:
            return (
                f"Asset {asset_id} verification failed: expected "
                f"{definition.asset_type} type"
            )
        if definition.asset_type == "static":
            missing = set(definition.cidrs).difference(get_asset_scopes(details))
            if missing:
                return (
                    f"Asset {asset_id} verification failed: missing "
                    f"{', '.join(sorted(missing))}"
                )
        else:
            expected_rules = build_dynamic_asset_rules(definition.cidrs)
            if not _dynamic_rules_match(details, expected_rules):
                expected_signature = _normalize_dynamic_rule(expected_rules)
                actual_signature = _normalize_dynamic_rule(
                    get_dynamic_asset_rules(details)
                )
                return (
                    f"Asset {asset_id} verification failed: dynamic rules do not "
                    f"match (expected {expected_signature!r}; "
                    f"received {actual_signature!r})"
                )
        if _text(details.get("description")) != definition.description:
            return f"Asset {asset_id} verification failed: description does not match"
        if not _asset_has_label(details, definition.label):
            return f"Asset {asset_id} verification failed: label does not match"
        return ""

    def _verify_scan(
        self,
        scan_id: int,
        expected_asset_id: int,
        expected_policy_id: int | None = None,
        expected_description: str | None = None,
    ) -> None:
        """Check that a scan has the expected settings"""
        details = self.data_access.get_scan_details(scan_id)
        if expected_asset_id not in get_scan_asset_ids(details):
            raise RuntimeError(
                f"Scan {scan_id} verification failed: asset {expected_asset_id} "
                "not attached"
            )
        if get_nested_id(details, "repository", "repositoryID") != (self.repository_id):
            raise RuntimeError(
                f"Scan {scan_id} verification failed: repository mismatch"
            )
        if (
            expected_policy_id is not None
            and get_nested_id(details, "policy", "policyID") != expected_policy_id
        ):
            raise RuntimeError(f"Scan {scan_id} verification failed: policy mismatch")
        if (
            expected_description is not None
            and _text(details.get("description")) != expected_description
        ):
            raise RuntimeError(
                f"Scan {scan_id} verification failed: description mismatch"
            )

    @staticmethod
    def _unique_name_index(
        records: list[dict[str, Any]], resource_type: str
    ) -> dict[str, dict[str, Any]]:
        """Index resources by name and reject duplicates"""
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


def get_asset_labels(asset: dict[str, Any]) -> tuple[str, ...]:
    """Read the API's comma-separated asset-label field."""
    value = asset.get("tags")
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = _text(value).split(",")
    return tuple(sorted({_text(item) for item in values if _text(item)}))


def _asset_has_label(asset: dict[str, Any], label: str | None) -> bool:
    return label is None or label in get_asset_labels(asset)


def _merged_asset_label(asset: dict[str, Any], label: str | None) -> str | None:
    if label is None:
        return None
    return ",".join((*get_asset_labels(asset), label)) if not _asset_has_label(
        asset, label
    ) else ",".join(get_asset_labels(asset))


def build_dynamic_asset_rules(cidrs: tuple[str, ...]) -> dict[str, Any]:
    """Build the exported Tenable.sc rule shape for a VLAN asset group"""
    return {
        "operator": "all",
        "children": [
            {
                "operator": "any",
                "children": [
                    {
                        "filterName": "ip",
                        "operator": "eq",
                        "value": cidr,
                        "type": "clause",
                    }
                    for cidr in cidrs
                ],
                "type": "group",
            },
            {
                "filterName": "lastseen",
                "operator": "lt",
                "value": "30",
                "type": "clause",
            },
        ],
        "type": "group",
    }


def get_dynamic_asset_rules(asset: dict[str, Any]) -> dict[str, Any] | None:
    """Read dynamic rules across Security Center detail response shapes"""
    return _dynamic_rules_from_response(asset)


def _json_object(value: Any) -> dict[str, Any] | None:
    """Return an object directly or when Security Center serializes it as JSON"""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _dynamic_rules_match(response: Any, expected_rules: dict[str, Any]) -> bool:
    """Compare requested and stored dynamic rules by their semantic content"""
    return _normalize_dynamic_rule(
        _dynamic_rules_from_response(response)
    ) == _normalize_dynamic_rule(expected_rules)


def _dynamic_rules_from_response(response: Any) -> dict[str, Any] | None:
    """Extract rules whether Security Center returns them at root or typeFields."""
    record = _json_object(response)
    if record is None:
        return None
    return _dynamic_rules_from_type_fields(record.get("typeFields")) or (
        _dynamic_rules_from_type_fields(record)
    )


def _dynamic_rules_from_type_fields(type_fields: Any) -> dict[str, Any] | None:
    """Extract dynamic rules from a Security Center typeFields object"""
    record = _json_object(type_fields)
    if record is None:
        return None
    for key in ("rules", "dynamicRules"):
        rules = _json_object(record.get(key))
        if rules is not None:
            return rules
    return None


def _has_unmanaged_dynamic_rules(rules: dict[str, Any] | None) -> bool:
    """Identify dynamic clauses that an application update cannot safely replace."""
    if not isinstance(rules, dict):
        return False
    children = rules.get("children")
    if _text(rules.get("operator")).lower() != "all" or not isinstance(
        children, (list, tuple)
    ):
        return True
    return any(not _is_managed_dynamic_child(child) for child in children)


def _is_managed_dynamic_child(rule: Any) -> bool:
    """Return whether a root rule is generated and safely owned by this workflow."""
    if not isinstance(rule, dict):
        return False
    if _dynamic_filter_name(rule) == "lastseen":
        return True
    children = rule.get("children")
    if not isinstance(children, (list, tuple)):
        return False
    return bool(children) and all(
        _dynamic_filter_name(child) == "ip" for child in children
    )


def _dynamic_filter_name(rule: dict[str, Any]) -> str:
    return _text(rule.get("filtername", rule.get("filterName"))).lower()


def _normalize_dynamic_rule(rule: Any) -> tuple[Any, ...] | None:
    """Create an order-independent representation of a dynamic rule tree"""
    if not isinstance(rule, dict):
        return None
    children = rule.get("children")
    if isinstance(children, (list, tuple)):
        return (
            "group",
            _text(rule.get("type")).lower() or "group",
            _text(rule.get("operator")).lower(),
            tuple(
                sorted(
                    (_normalize_dynamic_rule(child) for child in children),
                    key=repr,
                )
            ),
        )
    filter_name = _dynamic_filter_name(rule)
    return (
        "clause",
        _text(rule.get("type")).lower() or "clause",
        _text(rule.get("operator")).lower(),
        filter_name,
        _normalize_dynamic_rule_value(filter_name, rule.get("value")),
    )


def _normalize_dynamic_rule_value(filter_name: str, value: Any) -> Any:
    """Normalize IP rule values while preserving all non-IP values exactly"""
    if filter_name != "ip":
        return value
    normalized = _text(value)
    if "-" in normalized:
        start_text, end_text = (part.strip() for part in normalized.split("-", 1))
        try:
            start = ipaddress.ip_address(start_text)
            end = ipaddress.ip_address(end_text)
        except ValueError:
            return normalized
        if start.version == end.version and int(start) <= int(end):
            return ("ip-range", start.version, int(start), int(end))
        return normalized
    try:
        network = ipaddress.ip_network(normalized, strict=False)
        return (
            "ip-range",
            network.version,
            int(network.network_address),
            int(network.broadcast_address),
        )
    except ValueError:
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return normalized
        return ("ip-range", address.version, int(address), int(address))


def _asset_type(asset: dict[str, Any]) -> str:
    value = _text(asset.get("type")).lower()
    if value:
        return value
    type_fields = asset.get("typeFields")
    if isinstance(type_fields, dict) and type_fields.get("definedIPs") is not None:
        return "static"
    return ""


def _asset_type_for_target(target_type: str) -> str:
    return "dynamic" if target_type == "VLAN" else "static"


def _build_asset_definitions(
    changes: list[ApprovedChange], asset_label: str | None = None
) -> dict[str, AssetDefinition]:
    grouped: dict[str, list[ApprovedChange]] = {}
    for change in changes:
        if change.proposed_action not in SUPPORTED_ACTIONS:
            continue
        grouped.setdefault(change.asset_name, []).append(change)

    definitions: dict[str, AssetDefinition] = {}
    for name, members in grouped.items():
        asset_types = {change.desired_asset_type for change in members}
        if len(asset_types) != 1:
            raise ValueError(f"Asset '{name}' has conflicting asset types")
        definitions[name] = AssetDefinition(
            name=name,
            asset_type=next(iter(asset_types)),
            cidrs=tuple(sorted({change.cidr for change in members})),
            description=_build_asset_description(members),
            label=_optional_text(asset_label),
        )
    return definitions


def _build_asset_description(changes: list[ApprovedChange]) -> str:
    first = changes[0]
    if first.desired_asset_type == "dynamic":
        role = _grouping_role_label(first.grouping_tag)
        lines = [
            f"Dynamic VLAN asset for {first.site_code} {role} networks",
            "",
            "VLANs:",
        ]
        lines.extend(
            _vlan_description_line(change) for change in _sorted_vlans(changes)
        )
        lines.extend(
            (
                "",
                f"Source grouping tag: {first.grouping_tag or 'N/A'}",
                "Membership criteria: IP address within the listed VLAN ranges "
                "AND Last Seen < 30 days",
                "Source of truth: subnet-as-code",
            )
        )
        return "\n".join(lines)

    scope_kind = "public range" if first.target_type == "PUBLIC" else "private supernet"
    lines = [
        f"Static authoritative {scope_kind} for {first.site_code}",
        "",
        "Ranges:",
    ]
    lines.extend(
        f"- {change.cidr}" for change in sorted(changes, key=lambda item: item.cidr)
    )
    lines.extend(("", "Source of truth: subnet-as-code"))
    return "\n".join(lines)


def _build_scan_definitions(changes: list[ApprovedChange]) -> dict[str, ScanDefinition]:
    grouped: dict[str, list[ApprovedChange]] = {}
    for change in changes:
        if change.proposed_action in SUPPORTED_ACTIONS:
            grouped.setdefault(change.scan_name, []).append(change)

    definitions: dict[str, ScanDefinition] = {}
    for name, members in grouped.items():
        vlan_members = [
            change for change in members if change.desired_asset_type == "dynamic"
        ]
        definitions[name] = ScanDefinition(
            name=name,
            description=(
                _build_scan_description(vlan_members) if vlan_members else None
            ),
        )
    return definitions


def _build_scan_description(changes: list[ApprovedChange]) -> str:
    first = changes[0]
    asset_names = sorted({change.asset_name for change in changes})
    grouping_tags = sorted(
        {change.grouping_tag for change in changes if change.grouping_tag}
    )
    if len(grouping_tags) == 1:
        heading = (
            f"Assessment scan for {first.site_code} "
            f"{_grouping_role_label(grouping_tags[0])} VLANs"
        )
    else:
        heading = f"Assessment scan for {first.site_code} VLAN groups"
    lines = [
        heading,
        "",
        "Target assets:",
        *(f"- {name}" for name in asset_names),
    ]
    if len(grouping_tags) > 1:
        lines.extend(
            (
                "",
                "Source grouping tags:",
                *(f"- {tag}" for tag in grouping_tags),
            )
        )
    lines.extend(
        (
            "",
            "Included VLANs:",
            *(_vlan_description_line(change) for change in _sorted_vlans(changes)),
            "",
            "Asset membership is dynamically limited to hosts seen within the last "
            "30 days",
            "Source of truth: subnet-as-code",
        )
    )
    return "\n".join(lines)


def _sorted_vlans(changes: list[ApprovedChange]) -> list[ApprovedChange]:
    def sort_key(change: ApprovedChange) -> tuple[int, int, str, str]:
        try:
            return (0, int(change.vlan_tag), change.cidr, change.vlan_name)
        except ValueError:
            return (1, 0, change.cidr, change.vlan_name)

    return sorted(changes, key=sort_key)


def _vlan_description_line(change: ApprovedChange) -> str:
    parts = []
    if change.vlan_tag:
        parts.append(f"VLAN {change.vlan_tag}")
    if change.vlan_name:
        parts.append(change.vlan_name)
    parts.append(change.cidr)
    return "- " + " - ".join(parts)


def _grouping_role_label(grouping_tag: str) -> str:
    value = grouping_tag.strip()
    if value.lower().startswith("vlan-"):
        value = value[5:]
    label = " ".join(part.capitalize() for part in value.replace("_", "-").split("-"))
    return label or "VLAN"


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
    """Read a resource ID or throw an error"""
    try:
        return int(record["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            f"{resource_type.title()} '{name}' response has no numeric id"
        ) from exc


def _required_text(row: dict[str, Any], column: str, row_number: int) -> str:
    """Read a required text value from a CSV row"""
    value = _text(row.get(column))
    if not value:
        raise ValueError(f"Row {row_number} has no {column}")
    return value


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _optional_text(value: Any) -> str | None:
    text = _text(value)
    return text or None


def _apply_resource_list(
    data_access: ChangeDataAccess,
    usable_method_name: str,
    fallback_method_name: str,
) -> list[dict[str, Any]]:
    """Only look at 'usable' lists of assets / scans / policies

    when detecting duplicate names"""
    usable_method = getattr(cast(Any, data_access), usable_method_name, None)
    if callable(usable_method):
        return cast(list[dict[str, Any]], usable_method())
    fallback_method = getattr(data_access, fallback_method_name)
    return cast(list[dict[str, Any]], fallback_method())


def write_apply_markdown(result: dict[str, Any], path_value: str | Path) -> Path:
    lines = [
        "# Tenable.sc Apply Audit",
        "",
        f"- Run ID: `{result['run_id']}`",
        f"- Plan SHA-256: `{result['plan_sha256']}`",
        f"- Repository ID: `{result['repository_id']}`",
        f"- Asset label: `{result.get('asset_label') or 'None'}`",
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
