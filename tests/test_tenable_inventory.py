import csv
import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.tenable_coverage_workflow.tenable_inventory import (
    collect_tenable_inventory,
    redact_sensitive,
    write_inventory_reports,
    write_inventory_snapshot,
)


@dataclass(frozen=True)
class FakeInventoryConfig:
    mode: str = "live"


class FakeDataAccess:
    config = FakeInventoryConfig()

    def get_repositories(self) -> list[dict[str, Any]]:
        return [{"id": 1, "name": "Main"}]

    def get_asset_lists(self) -> list[dict[str, Any]]:
        return [{"id": 2, "name": "Servers"}]

    def get_asset(self, asset_id: Any) -> dict[str, Any]:
        return {"id": asset_id, "name": "Servers", "password": "do-not-write"}

    def get_scans(self) -> list[dict[str, Any]]:
        return [{"id": 3, "name": "Assessment"}]

    def get_scan_details(self, scan_id: Any) -> dict[str, Any]:
        return {
            "id": scan_id,
            "name": "Assessment",
            "schedule": {"type": "ical"},
            "ipList": "10.0.0.0/24",
        }

    def get_policies(self) -> list[dict[str, Any]]:
        return [{"id": 4, "name": "Policy"}]

    def get_credentials(self) -> list[dict[str, Any]]:
        return [{"id": 5, "name": "Credential", "secretKey": "nope"}]

    def get_observed_hosts(self) -> list[dict[str, Any]]:
        raise PermissionError("host query denied")


class TenableInventoryTests(unittest.TestCase):
    def test_collection_expands_details_redacts_and_records_partial_errors(self):
        snapshot = collect_tenable_inventory(FakeDataAccess())

        self.assertEqual(snapshot["resource_counts"]["scans"], 1)
        self.assertEqual(snapshot["resources"]["scans"][0]["schedule"]["type"], "ical")
        self.assertEqual(
            snapshot["resources"]["asset_groups"][0]["password"], "[REDACTED]"
        )
        self.assertEqual(
            snapshot["resources"]["credentials"][0]["secretKey"], "[REDACTED]"
        )
        self.assertIn("observed_hosts", snapshot["collection_errors"])

    def test_redaction_is_recursive(self):
        self.assertEqual(
            redact_sensitive({"nested": [{"api-token": "secret"}]}),
            {"nested": [{"api-token": "[REDACTED]"}]},
        )

    def test_snapshot_write_is_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            write_inventory_snapshot({"schema_version": 1}, path)
            self.assertEqual(json.loads(path.read_text()), {"schema_version": 1})

    def test_reports_include_resolved_scan_configuration(self):
        snapshot = {
            "resource_counts": {"scans": 1},
            "collection_errors": {},
            "resources": {
                "repositories": [{"id": 1, "name": "Main Repository"}],
                "asset_groups": [
                    {"id": 2, "name": "Server VLANs", "ips": "10.0.0.0/24"}
                ],
                "scans": [
                    {
                        "id": 3,
                        "name": "Server Assessment",
                        "description": "Weekly server scan",
                        "schedule": {"enabled": True},
                        "repository": {"id": 1},
                        "policy": {"id": 4},
                        "assets": [{"id": 2}],
                        "ipList": "10.0.0.10",
                    }
                ],
                "policies": [{"id": 4, "name": "Basic Assessment Policy"}],
                "credentials": [],
                "observed_hosts": [],
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            reports = write_inventory_reports(
                snapshot, Path(directory) / "inventory.json"
            )
            with reports["scans"].open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.reader(handle))

        self.assertEqual(rows[0][0:3], ["Scan ID", "Scan Name", "Description"])
        self.assertEqual(rows[1][0:3], ["3", "Server Assessment", "Weekly server scan"])
        self.assertEqual(rows[1][6], "Main Repository")
        self.assertEqual(rows[1][8], "Basic Assessment Policy")
        self.assertEqual(rows[1][10], "Server VLANs")


if __name__ == "__main__":
    unittest.main()
