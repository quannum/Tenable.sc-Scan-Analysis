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

    def create_dynamic_asset(self, name, rules, description):
        self.calls.append(("create_dynamic_asset", name, rules))
        asset_id = self.next_asset_id
        self.next_asset_id += 1
        record = {
            "id": asset_id,
            "name": name,
            "type": "dynamic",
            "description": description,
            "typeFields": {"rules": rules},
        }
        self.assets[asset_id] = record
        return record

    def update_dynamic_asset(self, asset_id, rules, description=None):
        self.calls.append(("update_dynamic_asset", asset_id, rules))
        self.assets[asset_id]["type"] = "dynamic"
        self.assets[asset_id]["typeFields"] = {"rules": rules}
        if description is not None:
            self.assets[asset_id]["description"] = description
        return self.assets[asset_id]

    def create_combination_asset(
        self, name, included_asset_id, excluded_asset_id, description
    ):
        self.calls.append(
            ("create_combination_asset", name, included_asset_id, excluded_asset_id)
        )
        asset_id = self.next_asset_id
        self.next_asset_id += 1
        record = {
            "id": asset_id,
            "name": name,
            "type": "combination",
            "description": description,
            "typeFields": {
                "combinations": {
                    "operator": "difference",
                    "operand1": {"id": included_asset_id},
                    "operand2": {"id": excluded_asset_id},
                }
            },
        }
        self.assets[asset_id] = record
        return record

    def update_combination_asset(
        self, asset_id, included_asset_id, excluded_asset_id, description=None
    ):
        self.calls.append(
            ("update_combination_asset", asset_id, included_asset_id, excluded_asset_id)
        )
        self.assets[asset_id]["type"] = "combination"
        self.assets[asset_id]["typeFields"] = {
            "combinations": {
                "operator": "difference",
                "operand1": {"id": included_asset_id},
                "operand2": {"id": excluded_asset_id},
            }
        }
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
            self.assertEqual(len(data_access.assets), 3)
            self.assertEqual(len(data_access.scans), 1)

    def test_proposed_target_is_recent_cidr_hosts_minus_agent_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()

            ChangeApplier(data_access, repository_id=7).apply(plan)

            agent_asset = next(
                asset
                for asset in data_access.assets.values()
                if asset["name"] == "Tenable.sc Scan Analysis - Nessus Agent Detected"
            )
            self.assertEqual(
                [
                    child["value"]["id"]
                    for child in agent_asset["typeFields"]["rules"]["children"]
                ],
                [100574, 110230, 110231],
            )
            candidate = next(
                asset
                for asset in data_access.assets.values()
                if asset["name"] == "NYC01 Servers VLAN 120 - Recent Hosts"
            )
            rules = candidate["typeFields"]["rules"]
            self.assertEqual(
                rules["children"][0]["children"][0]["value"],
                "10.1.16.0/24",
            )
            self.assertEqual(rules["children"][1]["filterName"], "lastseen")
            self.assertEqual(rules["children"][1]["operator"], "lt")
            self.assertEqual(rules["children"][1]["value"], "30")
            target = next(
                asset
                for asset in data_access.assets.values()
                if asset["name"] == "NYC01 Servers VLAN 120"
            )
            combination = target["typeFields"]["combinations"]
            self.assertEqual(combination["operator"], "difference")
            self.assertEqual(combination["operand1"], {"id": candidate["id"]})
            self.assertEqual(combination["operand2"], {"id": agent_asset["id"]})

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
                "type": "static",
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
            self.assertEqual(data_access.assets[8]["type"], "combination")
            candidate = next(
                asset
                for asset in data_access.assets.values()
                if asset["name"] == "NYC01 Servers VLAN 120 - Recent Hosts"
            )
            self.assertEqual(
                data_access.assets[8]["typeFields"]["combinations"]["operand1"],
                {"id": candidate["id"]},
            )
            self.assertEqual(data_access.scans[9]["assets"], [{"id": 8}, {"id": 99}])
            self.assertEqual(
                data_access.assets[8]["description"],
                "Managed by Tenable.sc Scan Analysis\n\n"
                "vl16-it-services-static 10.1.16.0/24 vlan-server\n"
                "Target criteria: approved CIDR ranges, last seen within 30 days, "
                "and no Nessus Agent detected.",
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

            asset = next(
                item
                for item in data_access.assets.values()
                if item["name"] == "NYC01 Workstation VLAN Group"
            )
            self.assertEqual(
                asset["description"],
                "Managed by Tenable.sc Scan Analysis\n\n"
                "vl16-it-services-static 10.1.16.0/24 vlan-workstation\n"
                "vl17-it-services-sandbox 10.1.17.0/24 vlan-workstation\n"
                "Target criteria: approved CIDR ranges, last seen within 30 days, "
                "and no Nessus Agent detected.",
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
                "Managed by Tenable.sc Scan Analysis\n\n"
                "Public Range 203.0.113.0/24\n"
                "Target criteria: approved CIDR ranges, last seen within 30 days, "
                "and no Nessus Agent detected.",
            )
            self.assertEqual(
                descriptions["NYC01 Private Discovery"],
                "Managed by Tenable.sc Scan Analysis\n\n"
                "Private Supernet 10.1.0.0/16\n"
                "Target criteria: approved CIDR ranges, last seen within 30 days, "
                "and no Nessus Agent detected.",
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

            self.assertEqual(len(data_access.assets), 5)
            self.assertEqual(len(data_access.scans), 1)
            scan = next(iter(data_access.scans.values()))
            self.assertEqual(scan["name"], "NYC01 Workstation Assessment")
            target_ids = [
                next(
                    asset["id"]
                    for asset in data_access.assets.values()
                    if asset["name"] == name
                )
                for name in (
                    "NYC01 Workstation VLAN Group",
                    "NYC01 Wireless VLAN Group",
                )
            ]
            self.assertEqual(scan["assets"], [{"id": item} for item in target_ids])

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
