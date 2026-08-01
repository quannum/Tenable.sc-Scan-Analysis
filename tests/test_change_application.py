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
    "Target Type",
    "VLAN Name",
    "VLAN Tag",
    "VLAN Grouping Tag",
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
        "Target Type": "VLAN",
        "VLAN Name": "vl16-it-services-static",
        "VLAN Tag": "16",
        "VLAN Grouping Tag": "vlan-server",
        "Proposed Action": "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN",
        "Proposed Asset Name": "NYC01 Servers VLAN 120",
        "Proposed Scan Name": "US East NYC01 Server Assessment",
        "Proposed Policy Name": "Basic Assessment Policy",
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
        self.policies = {30: {"id": 30, "name": "Basic Assessment Policy"}}
        self.calls = []
        self.next_asset_id = 10
        self.next_scan_id = 20

    def get_asset_lists(self):
        return [
            {"id": item["id"], "name": item["name"]} for item in self.assets.values()
        ]

    def get_scans(self):
        return [
            {"id": item["id"], "name": item["name"]} for item in self.scans.values()
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
        if description is not None:
            self.assets[asset_id]["description"] = description
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

    def update_scan_configuration(self, scan_id, asset_ids, repository_id, policy_id):
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

    def test_created_scan_policy_is_verified(self):
        class WrongPolicyDataAccess(FakeDataAccess):
            def create_scan(self, name, repository_id, asset_ids, policy_id):
                scan = super().create_scan(name, repository_id, asset_ids, policy_id)
                scan["policy"] = {"id": 999}
                return scan

        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            result = ChangeApplier(
                WrongPolicyDataAccess(),
                repository_id=7,
            ).apply(plan)

            operation = result["operations"][0]
            self.assertEqual(operation["status"], "FAILED")
            self.assertIn("policy mismatch", operation["message"])

    def test_existing_asset_and_scan_are_extended_without_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()
            data_access.assets[8] = {
                "id": 8,
                "name": "NYC01 Servers VLAN 120",
                "typeFields": {"definedIPs": "10.1.15.0/24"},
            }
            data_access.scans[9] = {
                "id": 9,
                "name": "US East NYC01 Server Assessment",
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
            self.assertEqual(data_access.scans[9]["assets"], [{"id": 8}, {"id": 99}])
            self.assertEqual(
                data_access.assets[8]["description"],
                "Created with Tenable.sc Scan Analysis\n\n"
                "vl16-it-services-static 10.1.16.0/24 vlan-server",
            )

    def test_grouped_vlan_asset_description_lists_each_vlan(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(
                    Path(directory) / "plan.csv",
                    [
                        approved_row(
                            **{
                                "Proposed Asset Name": "NYC01 Workstation VLAN Group",
                                "Proposed Scan Name": "NYC01 Workstation Assessment",
                                "Proposed Policy Name": "Basic Assessment Policy",
                                "VLAN Grouping Tag": "vlan-workstation",
                            }
                        ),
                        approved_row(
                            **{
                                "CIDR": "10.1.17.0/24",
                                "Proposed Asset Name": "NYC01 Workstation VLAN Group",
                                "Proposed Scan Name": "NYC01 Workstation Assessment",
                                "Proposed Policy Name": "Basic Assessment Policy",
                                "VLAN Name": "vl17-it-services-sandbox",
                                "VLAN Grouping Tag": "vlan-workstation",
                            }
                        ),
                    ],
                )
            )
            data_access = FakeDataAccess()

            ChangeApplier(data_access, repository_id=7).apply(plan)

            asset = next(iter(data_access.assets.values()))
            self.assertEqual(
                asset["description"],
                "Created with Tenable.sc Scan Analysis\n\n"
                "vl16-it-services-static 10.1.16.0/24 vlan-workstation\n"
                "vl17-it-services-sandbox 10.1.17.0/24 vlan-workstation",
            )

    def test_public_and_private_assets_include_scope_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(
                    Path(directory) / "plan.csv",
                    [
                        approved_row(
                            **{
                                "CIDR": "203.0.113.0/24",
                                "Target Type": "PUBLIC",
                                "Proposed Action": (
                                    "CREATE_OR_UPDATE_PUBLIC_ASSET_AND_SCAN"
                                ),
                                "Proposed Asset Name": "NYC01 Public",
                                "Proposed Scan Name": "NYC01 Public Assessment",
                                "Proposed Policy Name": "Public Facing Assessment",
                                "VLAN Name": "",
                                "VLAN Tag": "",
                                "VLAN Grouping Tag": "",
                            }
                        ),
                        approved_row(
                            **{
                                "CIDR": "10.1.0.0/16",
                                "Target Type": "PRIVATE_SUPERNET",
                                "Proposed Action": (
                                    "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN"
                                ),
                                "Proposed Asset Name": "NYC01 Private Discovery",
                                "Proposed Scan Name": "NYC01 Private Discovery",
                                "Proposed Policy Name": "Discovery",
                                "VLAN Name": "",
                                "VLAN Tag": "",
                                "VLAN Grouping Tag": "",
                            }
                        ),
                    ],
                )
            )
            data_access = FakeDataAccess()
            data_access.policies[31] = {
                "id": 31,
                "name": "Public Facing Assessment",
            }
            data_access.policies[32] = {"id": 32, "name": "Discovery"}

            ChangeApplier(data_access, repository_id=7).apply(plan)

            descriptions = {
                asset["name"]: asset["description"]
                for asset in data_access.assets.values()
            }
            self.assertEqual(
                descriptions["NYC01 Public"],
                "Created with Tenable.sc Scan Analysis\n\nPublic Range 203.0.113.0/24",
            )
            self.assertEqual(
                descriptions["NYC01 Private Discovery"],
                "Created with Tenable.sc Scan Analysis\n\nPrivate Supernet 10.1.0.0/16",
            )

    def test_separate_vlan_assets_attach_to_the_same_workstation_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(
                    Path(directory) / "plan.csv",
                    [
                        approved_row(
                            **{
                                "Proposed Asset Name": "NYC01 Workstation VLAN Group",
                                "Proposed Scan Name": "NYC01 Workstation Assessment",
                                "Proposed Policy Name": "Basic Assessment Policy",
                                "VLAN Grouping Tag": "vlan-workstation",
                            }
                        ),
                        approved_row(
                            **{
                                "CIDR": "10.1.17.0/24",
                                "Proposed Asset Name": "NYC01 Wireless VLAN Group",
                                "Proposed Scan Name": "NYC01 Workstation Assessment",
                                "Proposed Policy Name": "Basic Assessment Policy",
                                "VLAN Name": "vl17-it-services-sandbox",
                                "VLAN Grouping Tag": "vlan-wireless",
                            }
                        ),
                    ],
                )
            )
            data_access = FakeDataAccess()

            ChangeApplier(data_access, repository_id=7).apply(plan)

            self.assertEqual(len(data_access.assets), 2)
            self.assertEqual(len(data_access.scans), 1)
            scan = next(iter(data_access.scans.values()))
            self.assertEqual(scan["name"], "NYC01 Workstation Assessment")
            self.assertEqual(scan["assets"], [{"id": 10}, {"id": 11}])

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
