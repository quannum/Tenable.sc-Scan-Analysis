import csv
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.tenable_coverage_workflow.change_application import (
    ChangeApplier,
    load_approved_plan,
)

COLUMNS = [
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
]


def write_plan(path: Path, rows: list[dict[str, str]]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def approved_row(**overrides):
    row = {
        "Run ID": "run-001",
        "Site Code": "NYC01",
        "CIDR": "10.1.16.0/24",
        "Proposed Action": "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN",
        "Proposed Asset Name": "NYC01_Servers_VLAN_120",
        "Proposed Scan Name": "US_East_Server_Assessment",
        "Proposed Policy Name": "Credentialed Server Assessment",
        "Approval Status": "APPROVED",
        "Reviewer": "security-reviewer",
        "Decision Notes": "Approved in change ticket CHG001",
    }
    row.update(overrides)
    return row


class FakeDataAccess:
    config = SimpleNamespace(mode="live")

    def __init__(self):
        self.assets = {}
        self.scans = {}
        self.policies = {
            30: {"id": 30, "name": "Credentialed Server Assessment"}
        }
        self.calls = []
        self.next_asset_id = 10
        self.next_scan_id = 20

    def get_asset_lists(self):
        return [
            {"id": item["id"], "name": item["name"]}
            for item in self.assets.values()
        ]

    def get_scans(self):
        return [
            {"id": item["id"], "name": item["name"]}
            for item in self.scans.values()
        ]

    def get_policies(self):
        return list(self.policies.values())

    def get_asset(self, asset_id):
        return self.assets.get(int(asset_id), {})

    def get_scan_details(self, scan_id):
        return self.scans.get(int(scan_id), {})

    def create_static_asset(self, name, ips, description):
        self.calls.append(("create_asset", name, tuple(ips)))
        asset_id = self.next_asset_id
        self.next_asset_id += 1
        record = {
            "id": asset_id,
            "name": name,
            "type": "static",
            "description": description,
            "typeFields": {"definedIPs": ",".join(ips)},
        }
        self.assets[asset_id] = record
        return record

    def update_static_asset(self, asset_id, ips, description=None):
        self.calls.append(("update_asset", asset_id, tuple(ips)))
        self.assets[asset_id]["typeFields"]["definedIPs"] = ",".join(ips)
        return self.assets[asset_id]

    def create_scan(self, name, repository_id, asset_ids, policy_id):
        self.calls.append(
            ("create_scan", name, repository_id, tuple(asset_ids), policy_id)
        )
        scan_id = self.next_scan_id
        self.next_scan_id += 1
        record = {
            "id": scan_id,
            "name": name,
            "repository": {"id": repository_id},
            "policy": {"id": policy_id},
            "assets": [{"id": item} for item in asset_ids],
        }
        self.scans[scan_id] = record
        return record

    def update_scan_configuration(
        self, scan_id, asset_ids, repository_id, policy_id
    ):
        self.calls.append(
            ("update_scan", scan_id, tuple(asset_ids), repository_id, policy_id)
        )
        self.scans[scan_id]["assets"] = [{"id": item} for item in asset_ids]
        self.scans[scan_id]["repository"] = {"id": repository_id}
        self.scans[scan_id]["policy"] = {"id": policy_id}
        return self.scans[scan_id]


class ChangeApplicationTests(unittest.TestCase):
    def test_approved_plan_requires_reviewer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_plan(
                Path(directory) / "plan.csv",
                [approved_row(**{"Reviewer": ""})],
            )
            with self.assertRaisesRegex(ValueError, "no Reviewer"):
                load_approved_plan(path)

    def test_create_then_repeat_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()

            first = ChangeApplier(data_access, repository_id=7).apply(plan)
            calls_after_first = list(data_access.calls)
            second = ChangeApplier(data_access, repository_id=7).apply(plan)

            self.assertEqual(first["status_counts"], {"APPLIED": 1})
            self.assertEqual(second["status_counts"], {"UNCHANGED": 1})
            self.assertEqual(data_access.calls, calls_after_first)
            self.assertEqual(len(data_access.assets), 1)
            self.assertEqual(len(data_access.scans), 1)

    def test_existing_asset_and_scan_are_extended_without_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()
            data_access.assets[8] = {
                "id": 8,
                "name": "NYC01_Servers_VLAN_120",
                "typeFields": {"definedIPs": "10.1.15.0/24"},
            }
            data_access.scans[9] = {
                "id": 9,
                "name": "US_East_Server_Assessment",
                "assets": [{"id": 99}],
            }

            result = ChangeApplier(data_access, repository_id=7).apply(plan)

            operation = result["operations"][0]
            self.assertEqual(operation["asset_status"], "UPDATED")
            self.assertEqual(operation["scan_status"], "UPDATED")
            self.assertEqual(
                data_access.assets[8]["typeFields"]["definedIPs"],
                "10.1.15.0/24,10.1.16.0/24",
            )
            self.assertEqual(
                data_access.scans[9]["assets"], [{"id": 8}, {"id": 99}]
            )

    def test_missing_policy_fails_preflight_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()
            data_access.policies.clear()

            with self.assertRaisesRegex(ValueError, "Apply preflight failed"):
                ChangeApplier(data_access, repository_id=7).apply(plan)
            self.assertEqual(data_access.calls, [])


if __name__ == "__main__":
    unittest.main()
