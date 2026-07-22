import csv
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..io.data_access import DataAccess

SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "access_key",
    "accesskey",
    "private_key",
    "apikey",
    "api_key",
)


def collect_tenable_inventory(data_access: DataAccess) -> dict[str, Any]:
    """Collect a best-effort, secret-safe Tenable.sc configuration snapshot."""
    inventory: dict[str, Any] = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "mode": data_access.config.mode,
        "resources": {},
        "collection_errors": {},
    }
    collectors: dict[str, Callable[[], list[dict[str, Any]]]] = {
        "repositories": data_access.get_repositories,
        "asset_groups": data_access.get_asset_lists,
        "scans": data_access.get_scans,
        "policies": data_access.get_policies,
        "credentials": data_access.get_credentials,
        "observed_hosts": data_access.get_observed_hosts,
    }
    for name, collector in collectors.items():
        try:
            records = collector()
            if name == "scans":
                records = _expand_details(records, data_access.get_scan_details)
            elif name == "asset_groups":
                records = _expand_details(records, data_access.get_asset)
            inventory["resources"][name] = redact_sensitive(records)
        except Exception as exc:
            inventory["resources"][name] = []
            inventory["collection_errors"][name] = str(exc)

    inventory["resource_counts"] = {
        name: len(records) for name, records in inventory["resources"].items()
    }
    return inventory


def _expand_details(
    records: list[dict[str, Any]],
    details_getter: Callable[[Any], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Expand details"""
    expanded = []
    for record in records:
        record_id = record.get("id")
        if record_id in (None, ""):
            expanded.append(record)
            continue
        try:
            details = details_getter(record_id)
        except Exception as exc:
            merged = dict(record)
            merged["_detail_error"] = str(exc)
            expanded.append(merged)
            continue
        expanded.append(details if isinstance(details, dict) and details else record)
    return expanded


def redact_sensitive(value: Any) -> Any:
    """Redact sensitive"""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def write_inventory_snapshot(snapshot: dict[str, Any], output_file: str | Path) -> Path:
    """Write inventory snapshot"""
    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            prefix="tenable-inventory-",
            dir=path.parent,
            delete=False,
        ) as handle:
            temp_name = handle.name
            json.dump(snapshot, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.remove(temp_name)
    return path


def write_inventory_reports(
    snapshot: dict[str, Any], output_file: str | Path
) -> dict[str, Path]:
    """Write readable inventory CSV reports"""
    snapshot_path = Path(output_file)
    report_dir = snapshot_path.with_name(f"{snapshot_path.stem}_reports")
    resources = snapshot.get("resources", {})
    if not isinstance(resources, dict):
        resources = {}

    repositories = _resource_name_index(resources.get("repositories", []))
    policies = _resource_name_index(resources.get("policies", []))
    asset_groups = _resource_name_index(resources.get("asset_groups", []))
    reports = {
        "summary": _write_csv(
            report_dir / "collection_summary.csv",
            ("Resource", "Record Count", "Collection Error"),
            _summary_rows(snapshot, resources),
        ),
        "scans": _write_csv(
            report_dir / "scans.csv",
            (
                "Scan ID",
                "Scan Name",
                "Description",
                "Status",
                "Schedule",
                "Repository ID",
                "Repository",
                "Policy ID",
                "Policy",
                "Asset Group IDs",
                "Asset Groups",
                "Direct Targets",
                "Additional Details",
            ),
            _scan_rows(
                resources.get("scans", []), repositories, policies, asset_groups
            ),
        ),
        "repositories": _write_resource_csv(
            report_dir / "repositories.csv", resources.get("repositories", [])
        ),
        "policies": _write_resource_csv(
            report_dir / "policies.csv", resources.get("policies", [])
        ),
        "asset_groups": _write_asset_group_csv(
            report_dir / "asset_groups.csv", resources.get("asset_groups", [])
        ),
        "credentials": _write_resource_csv(
            report_dir / "credentials.csv", resources.get("credentials", [])
        ),
        "observed_hosts": _write_resource_csv(
            report_dir / "observed_hosts.csv", resources.get("observed_hosts", [])
        ),
    }
    return reports


def _write_resource_csv(path: Path, records: Any) -> Path:
    """Write a general resource CSV"""
    return _write_csv(
        path,
        ("ID", "Name", "Description", "Additional Details"),
        (
            (
                _record_field(record, "id", "uuid"),
                _record_field(record, "name"),
                _record_field(record, "description"),
                _additional_details(record, {"id", "uuid", "name", "description"}),
            )
            for record in _records(records)
        ),
    )


def _write_asset_group_csv(path: Path, records: Any) -> Path:
    """Write an asset group CSV"""
    return _write_csv(
        path,
        (
            "Asset Group ID",
            "Asset Group Name",
            "Type",
            "Description",
            "Targets",
            "Additional Details",
        ),
        (
            (
                _record_field(record, "id"),
                _record_field(record, "name"),
                _record_field(record, "type"),
                _record_field(record, "description"),
                _asset_targets(record),
                _additional_details(
                    record,
                    {
                        "id",
                        "name",
                        "type",
                        "description",
                        "ipList",
                        "ips",
                        "typeFields",
                    },
                ),
            )
            for record in _records(records)
        ),
    )


def _write_csv(path: Path, fieldnames: tuple[str, ...], rows: Any) -> Path:
    """Write one CSV report"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(fieldnames)
        writer.writerows(rows)
    return path


def _summary_rows(snapshot: dict[str, Any], resources: dict[str, Any]):
    """Build collection summary rows"""
    counts = snapshot.get("resource_counts", {})
    errors = snapshot.get("collection_errors", {})
    for name in (
        "repositories",
        "asset_groups",
        "scans",
        "policies",
        "credentials",
        "observed_hosts",
    ):
        count = counts.get(name, len(_records(resources.get(name, []))))
        yield (name.replace("_", " ").title(), count, errors.get(name, ""))


def _scan_rows(
    records: Any,
    repositories: dict[str, str],
    policies: dict[str, str],
    asset_groups: dict[str, str],
):
    """Build readable scan rows"""
    for record in _records(records):
        repository_id, repository_name = _resource_reference(
            _record_field(record, "repository", "repo", "repositoryID"), repositories
        )
        policy_id, policy_name = _resource_reference(
            _record_field(record, "policy", "policyID"), policies
        )
        asset_ids, asset_names = _asset_references(record, asset_groups)
        yield (
            _record_field(record, "id"),
            _record_field(record, "name"),
            _record_field(record, "description"),
            _record_field(record, "status", "enabled"),
            _format_value(_record_field(record, "schedule")),
            repository_id,
            repository_name,
            policy_id,
            policy_name,
            "; ".join(asset_ids),
            "; ".join(asset_names),
            _asset_targets(record),
            _additional_details(
                record,
                {
                    "id", "name", "description", "status", "enabled", "schedule",
                    "repository", "repo", "repositoryID", "policy", "policyID",
                    "assets", "assetLists", "ipList", "ips", "typeFields",
                },
            ),
        )


def _resource_name_index(records: Any) -> dict[str, str]:
    """Index resource names by ID"""
    return {
        str(resource_id): str(name)
        for record in _records(records)
        if (resource_id := _record_field(record, "id", "uuid")) not in (None, "")
        and (name := _record_field(record, "name")) not in (None, "")
    }


def _asset_references(
    record: dict[str, Any], names: dict[str, str]
) -> tuple[list[str], list[str]]:
    """Resolve scan asset group references"""
    value = _record_field(record, "assets", "assetLists")
    values = (
        value if isinstance(value, list) else ([] if value in (None, "") else [value])
    )
    ids: list[str] = []
    resolved_names: list[str] = []
    for value in values:
        resource_id, resource_name = _resource_reference(value, names)
        if resource_id:
            ids.append(resource_id)
        if resource_name:
            resolved_names.append(resource_name)
    return ids, resolved_names


def _resource_reference(value: Any, names: dict[str, str]) -> tuple[str, str]:
    """Resolve one resource reference"""
    if isinstance(value, dict):
        resource_id = _record_field(value, "id", "repositoryID", "policyID")
        name = _record_field(value, "name")
    else:
        resource_id = value
        name = None
    resource_id_text = "" if resource_id in (None, "") else str(resource_id)
    name_text = "" if name in (None, "") else str(name)
    return resource_id_text, name_text or names.get(resource_id_text, "")


def _asset_targets(record: dict[str, Any]) -> str:
    """Get direct targets from a record"""
    targets = _record_field(record, "ipList", "ips")
    if targets not in (None, ""):
        return _format_value(targets)
    type_fields = record.get("typeFields")
    if isinstance(type_fields, dict):
        return _format_value(_record_field(type_fields, "ipList", "ips"))
    return ""


def _record_field(record: dict[str, Any], *names: str) -> Any:
    """Get a record field including nested scan info"""
    info = record.get("info")
    for source in (record, info if isinstance(info, dict) else {}):
        for name in names:
            if name in source and source[name] not in (None, ""):
                return source[name]
    return None


def _additional_details(record: dict[str, Any], excluded: set[str]) -> str:
    """Format fields not shown in their own column"""
    details = {key: value for key, value in record.items() if key not in excluded}
    return _format_value(details) if details else ""


def _format_value(value: Any) -> str:
    """Format a value for CSV output"""
    if value in (None, ""):
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _records(value: Any) -> list[dict[str, Any]]:
    """Return usable inventory records"""
    if not isinstance(value, list):
        return []
    return [record for record in value if isinstance(record, dict)]
