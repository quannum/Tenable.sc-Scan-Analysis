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
