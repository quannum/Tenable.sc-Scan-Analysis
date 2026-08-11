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
        self.assets[asset_id]["typeFields"]["rules"] = rules
        if description is not None:
            self.assets[asset_id]["description"] = description
        return self.assets[asset_id]

    def create_scan(self, name, repository_id, asset_ids, policy_id, description=None):
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
        if description is not None:
            record["description"] = description
        self.scans[scan_id] = record
        return record

    def update_scan_configuration(
        self, scan_id, asset_ids, repository_id, policy_id, description=None
    ):
        self.calls.append(
            ("update_scan", scan_id, tuple(asset_ids), repository_id, policy_id)
        )
        self.scans[scan_id]["assets"] = [{"id": item} for item in asset_ids]
        self.scans[scan_id]["repository"] = {"id": repository_id}
        self.scans[scan_id]["policy"] = {"id": policy_id}
        if description is not None:
            self.scans[scan_id]["description"] = description
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
            def create_scan(
                self, name, repository_id, asset_ids, policy_id, description=None
            ):
                scan = super().create_scan(
                    name, repository_id, asset_ids, policy_id, description
                )
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

    def test_existing_static_asset_and_scan_are_extended_without_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(
                    Path(directory) / "plan.csv",
                    [
                        approved_row(
                            **{
                                "CIDR": "10.1.0.0/16",
                                "Target Type": "PRIVATE_SUPERNET",
                                "Proposed Action": (
                                    "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN"
                                ),
                                "Proposed Asset Name": "NYC01 Private Discovery",
                                "Proposed Scan Name": "NYC01 Discovery",
                                "Proposed Policy Name": "Discovery",
                                "VLAN Name": "",
                                "VLAN Tag": "",
                                "VLAN Grouping Tag": "",
                            }
                        )
                    ],
                )
            )
            data_access = FakeDataAccess()
            data_access.policies[31] = {"id": 31, "name": "Discovery"}
            data_access.assets[8] = {
                "id": 8,
                "name": "NYC01 Private Discovery",
                "type": "static",
                "typeFields": {"definedIPs": "10.1.15.0/24"},
            }
            data_access.scans[9] = {
                "id": 9,
                "name": "NYC01 Discovery",
                "assets": [{"id": 99}],
            }

            result = ChangeApplier(data_access, repository_id=7).apply(plan)

            operation = result["operations"][0]
            self.assertEqual(operation["asset_status"], "UPDATED")
            self.assertEqual(operation["scan_status"], "UPDATED")
            self.assertEqual(
                data_access.assets[8]["typeFields"]["definedIPs"],
                "10.1.0.0/16,10.1.15.0/24",
            )
            self.assertEqual(data_access.scans[9]["assets"], [{"id": 8}, {"id": 99}])
            self.assertEqual(
                data_access.assets[8]["description"],
                "Static authoritative private supernet for NYC01.\n\n"
                "Ranges:\n- 10.1.0.0/16\n\nSource of truth: subnet-as-code.",
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
            self.assertEqual(asset["type"], "dynamic")
            self.assertEqual(
                asset["typeFields"]["rules"],
                {
                    "operator": "all",
                    "children": [
                        {
                            "operator": "any",
                            "children": [
                                {
                                    "filtername": "ip",
                                    "operator": "eq",
                                    "value": "10.1.16.0/24",
                                    "type": "clause",
                                },
                                {
                                    "filtername": "ip",
                                    "operator": "eq",
                                    "value": "10.1.17.0/24",
                                    "type": "clause",
                                },
                            ],
                            "type": "group",
                        },
                        {
                            "filtername": "lastseen",
                            "operator": "lt",
                            "value": "30",
                            "type": "clause",
                        },
                    ],
                    "type": "group",
                },
            )
            self.assertEqual(
                asset["description"],
                "Dynamic VLAN asset for NYC01 Workstation networks.\n\n"
                "VLANs:\n"
                "- VLAN 16 - vl16-it-services-static - 10.1.16.0/24\n"
                "- VLAN 16 - vl17-it-services-sandbox - 10.1.17.0/24\n\n"
                "Source grouping tag: vlan-workstation\n"
                "Membership criteria: IP address within the listed VLAN ranges "
                "AND Last Seen < 30 days.\n"
                "Source of truth: subnet-as-code.",
            )
            scan = next(iter(data_access.scans.values()))
            self.assertEqual(scan["assets"], [{"id": asset["id"]}])
            self.assertIn("Target assets:", scan["description"])
            self.assertIn("last 30 days", scan["description"])

    def test_one_vlan_creates_one_dynamic_asset_with_lastseen_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()

            ChangeApplier(data_access, repository_id=7).apply(plan)

            asset = next(iter(data_access.assets.values()))
            self.assertEqual(asset["type"], "dynamic")
            rules = asset["typeFields"]["rules"]
            self.assertEqual(rules["operator"], "all")
            self.assertEqual(rules["children"][0]["operator"], "any")
            self.assertEqual(
                rules["children"][0]["children"][0]["value"], "10.1.16.0/24"
            )
            self.assertEqual(
                rules["children"][1],
                {
                    "filtername": "lastseen",
                    "operator": "lt",
                    "value": "30",
                    "type": "clause",
                },
            )
            self.assertTrue(
                all("Recent Hosts" not in str(call) for call in data_access.calls)
            )
            self.assertTrue(
                all(
                    "combination" not in str(call).lower() for call in data_access.calls
                )
            )

    def test_changed_vlan_membership_updates_dynamic_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial = load_approved_plan(
                write_plan(root / "initial.csv", [approved_row()])
            )
            changed = load_approved_plan(
                write_plan(
                    root / "changed.csv",
                    [
                        approved_row(),
                        approved_row(
                            **{
                                "CIDR": "10.1.17.0/24",
                                "VLAN Name": "vl17-it-services-sandbox",
                            }
                        ),
                    ],
                )
            )
            data_access = FakeDataAccess()

            ChangeApplier(data_access, repository_id=7).apply(initial)
            result = ChangeApplier(data_access, repository_id=7).apply(changed)

            self.assertEqual(result["operations"][0]["asset_status"], "UPDATED")
            asset = next(iter(data_access.assets.values()))
            cidrs = {
                child["value"]
                for child in asset["typeFields"]["rules"]["children"][0]["children"]
            }
            self.assertEqual(cidrs, {"10.1.16.0/24", "10.1.17.0/24"})
            self.assertIn("vl17-it-services-sandbox", asset["description"])

    def test_dynamic_asset_description_is_deterministic_for_input_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_change = approved_row(
                **{
                    "Proposed Asset Name": "NYC01 Workstation VLAN Group",
                    "Proposed Scan Name": "NYC01 Workstation Assessment",
                    "VLAN Grouping Tag": "vlan-workstation",
                }
            )
            second_change = approved_row(
                **{
                    "CIDR": "10.1.17.0/24",
                    "VLAN Name": "vl17-it-services-sandbox",
                    "VLAN Tag": "17",
                    "Proposed Asset Name": "NYC01 Workstation VLAN Group",
                    "Proposed Scan Name": "NYC01 Workstation Assessment",
                    "VLAN Grouping Tag": "vlan-workstation",
                }
            )
            forward = load_approved_plan(
                write_plan(root / "forward.csv", [first_change, second_change])
            )
            reverse = load_approved_plan(
                write_plan(root / "reverse.csv", [second_change, first_change])
            )
            forward_access = FakeDataAccess()
            reverse_access = FakeDataAccess()

            ChangeApplier(forward_access, repository_id=7).apply(forward)
            ChangeApplier(reverse_access, repository_id=7).apply(reverse)

            forward_description = next(iter(forward_access.assets.values()))[
                "description"
            ]
            reverse_description = next(iter(reverse_access.assets.values()))[
                "description"
            ]
            self.assertEqual(forward_description, reverse_description)

    def test_dynamic_asset_type_conflict_requires_manual_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(Path(directory) / "plan.csv", [approved_row()])
            )
            data_access = FakeDataAccess()
            data_access.assets[8] = {
                "id": 8,
                "name": "NYC01 Servers VLAN 120",
                "type": "static",
                "typeFields": {"definedIPs": "10.1.16.0/24"},
            }

            with self.assertRaisesRegex(ValueError, "Manual change is required"):
                ChangeApplier(data_access, repository_id=7).apply(plan)
            self.assertEqual(data_access.calls, [])

    def test_private_supernet_with_18_prefix_remains_static(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = load_approved_plan(
                write_plan(
                    Path(directory) / "plan.csv",
                    [
                        approved_row(
                            **{
                                "CIDR": "10.214.0.0/18",
                                "Target Type": "PRIVATE_SUPERNET",
                                "Proposed Action": (
                                    "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN"
                                ),
                                "Proposed Asset Name": "NYC01 Private Discovery",
                                "Proposed Scan Name": "NYC01 Discovery",
                                "Proposed Policy Name": "Discovery",
                                "VLAN Name": "",
                                "VLAN Tag": "",
                                "VLAN Grouping Tag": "",
                            }
                        )
                    ],
                )
            )
            data_access = FakeDataAccess()
            data_access.policies[31] = {"id": 31, "name": "Discovery"}

            ChangeApplier(data_access, repository_id=7).apply(plan)

            asset = next(iter(data_access.assets.values()))
            self.assertEqual(asset["type"], "static")
            self.assertEqual(asset["typeFields"]["definedIPs"], "10.214.0.0/18")
            self.assertNotIn("lastseen", str(asset))

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
                "Static authoritative public range for NYC01.\n\n"
                "Ranges:\n- 203.0.113.0/24\n\nSource of truth: subnet-as-code.",
            )
            self.assertEqual(
                descriptions["NYC01 Private Discovery"],
                "Static authoritative private supernet for NYC01.\n\n"
                "Ranges:\n- 10.1.0.0/16\n\nSource of truth: subnet-as-code.",
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
