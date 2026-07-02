import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.tenable_coverage_workflow.tenable_inventory import (
    collect_tenable_inventory,
    redact_sensitive,
    write_inventory_snapshot,
)


class FakeDataAccess:
    config = SimpleNamespace(mode="live")

    def get_repositories(self):
        return [{"id": 1, "name": "Main"}]

    def get_asset_lists(self):
        return [{"id": 2, "name": "Servers"}]

    def get_asset(self, asset_id):
        return {"id": asset_id, "name": "Servers", "password": "do-not-write"}

    def get_scans(self):
        return [{"id": 3, "name": "Assessment"}]

    def get_scan_details(self, scan_id):
        return {
            "id": scan_id,
            "name": "Assessment",
            "schedule": {"type": "ical"},
            "ipList": "10.0.0.0/24",
        }

    def get_policies(self):
        return [{"id": 4, "name": "Policy"}]

    def get_credentials(self):
        return [{"id": 5, "name": "Credential", "secretKey": "nope"}]

    def get_observed_hosts(self):
        raise PermissionError("host query denied")


class TenableInventoryTests(unittest.TestCase):
    def test_collection_expands_details_redacts_and_records_partial_errors(self):
        snapshot = collect_tenable_inventory(FakeDataAccess())

        self.assertEqual(snapshot["resource_counts"]["scans"], 1)
        self.assertEqual(
            snapshot["resources"]["scans"][0]["schedule"]["type"], "ical"
        )
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


if __name__ == "__main__":
    unittest.main()
