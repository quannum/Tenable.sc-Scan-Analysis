import csv
import json
import shutil
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.tenable_coverage_workflow.models import (
    CoverageTarget,
    CoverageValidationResult,
)
from src.tenable_coverage_workflow.planning.naming_rules import apply_naming_rules
from src.tenable_coverage_workflow.planning.proposed_changes import (
    generate_proposed_changes,
)
from src.tenable_coverage_workflow.run_detect_and_plan import (
    main as detect_and_plan_main,
)
from src.tenable_coverage_workflow.subnet_source.yaml_connector import (
    load_yaml_subnet_repo,
)


class YamlConnectorTests(unittest.TestCase):
    def test_yaml_connector_loads_nested_repo_and_collects_validation_errors(self):
        fixture_repo = Path("tests") / "fixtures" / "subnet_repo"

        result = load_yaml_subnet_repo(fixture_repo)

        self.assertEqual(result.files_processed, 6)
        self.assertEqual(result.files_failed, 2)
        self.assertEqual(
            {site.site_code for site in result.site_definitions},
            {"ATL01", "CHI01", "LON01", "NYC01"},
        )
        self.assertEqual(len(result.coverage_targets), 10)

        nyc_vlan = next(
            target
            for target in result.coverage_targets
            if target.site_code == "NYC01" and target.vlan_name == "End User"
        )
        self.assertEqual(nyc_vlan.target_type, "VLAN")
        self.assertEqual(nyc_vlan.vlan_tag, 130)
        self.assertEqual(nyc_vlan.cidr, "10.1.32.0/22")

        lon_vlan = next(
            target
            for target in result.coverage_targets
            if target.site_code == "LON01" and target.vlan_name == "Media / AV"
        )
        self.assertIsNone(lon_vlan.vlan_tag)

        issue_messages = [issue.message for issue in result.validation_issues]
        self.assertTrue(
            any("outside parent private range" in message for message in issue_messages)
        )
        self.assertTrue(any("Invalid CIDR" in message for message in issue_messages))


class PlanningTests(unittest.TestCase):
    def test_naming_rules_assign_required_names(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.16.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Server VLAN",
            vlan_name="Servers",
            vlan_tag=120,
            source_file="sites/us-east/nyc01.yaml",
        )

        named_target = apply_naming_rules(target)

        self.assertEqual(named_target.required_asset_name, "NYC01_Servers_VLAN_120")
        self.assertEqual(named_target.required_scan_name, "US_East_Server_Assessment")
        self.assertEqual(
            named_target.required_policy_name,
            "Credentialed Server Assessment",
        )

    def test_proposed_changes_map_wrong_scan_gap_and_excluded_statuses(self):
        results = [
            CoverageValidationResult(
                status="OK",
                target_type="VLAN",
                cidr="10.1.32.0/22",
                site_code="NYC01",
                site_name="New York Office",
                region="US East",
                location="New York, NY",
                description="End User VLAN",
                vlan_name="End User",
                vlan_tag=130,
                covering_scans=["US_East_Standard_Assessment"],
                reason="Fully contained by scan scope",
                source_file="sites/us-east/nyc01.yaml",
                required_asset_name="NYC01_End_User_VLAN_130",
                required_scan_name="US_East_End_User_Assessment",
                required_policy_name="Credentialed Workstation Assessment",
                required_scan_covered="No",
            ),
            CoverageValidationResult(
                status="GAP",
                target_type="PUBLIC",
                cidr="203.0.113.0/26",
                site_code="NYC01",
                site_name="New York Office",
                region="US East",
                location="New York, NY",
                description="Public range",
                vlan_name=None,
                vlan_tag=None,
                covering_scans=[],
                reason="No scan scope intersects expected range",
                source_file="sites/us-east/nyc01.yaml",
                required_asset_name="NYC01_Public",
                required_scan_name="Public_External_Assessment",
                required_policy_name="Public Facing Assessment",
            ),
            CoverageValidationResult(
                status="EXCLUDED",
                target_type="VLAN",
                cidr="10.1.48.0/24",
                site_code="NYC01",
                site_name="New York Office",
                region="US East",
                location="New York, NY",
                description="Network VLAN",
                vlan_name="Network Management",
                vlan_tag=140,
                covering_scans=["US_East_Network_Assessment"],
                reason="Excluded 128 IPs",
                source_file="sites/us-east/nyc01.yaml",
                required_asset_name="NYC01_Network_Management_VLAN_140",
                required_scan_name="US_East_Network_Assessment",
                required_policy_name="Network Infrastructure Assessment",
            ),
        ]

        changes = generate_proposed_changes(results, run_id="run-001")

        self.assertEqual(changes[0].proposed_action, "REVIEW_WRONG_SCAN")
        self.assertEqual(
            changes[1].proposed_action,
            "CREATE_OR_UPDATE_PUBLIC_ASSET_AND_SCAN",
        )
        self.assertEqual(changes[2].proposed_action, "REVIEW_EXCLUSION")
        self.assertTrue("Required scan" in changes[0].issue)


class DetectAndPlanCliTests(unittest.TestCase):
    def test_detect_and_plan_cli_writes_audits_and_continues_past_bad_yaml(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "detect_and_plan_case"
        fixture_repo = Path("tests") / "fixtures" / "subnet_repo"

        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            subnet_repo = temp_path / "subnet_repo"
            shutil.copytree(fixture_repo, subnet_repo)

            scan_dir = temp_path / "scans"
            asset_dir = temp_path / "assets"
            output_dir = temp_path / "output"
            scan_dir.mkdir()
            asset_dir.mkdir()

            scan_payloads = [
                {
                    "id": 1,
                    "name": "US_East_Discovery",
                    "ipList": "10.1.0.0/16,10.3.0.0/16",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
                {
                    "id": 2,
                    "name": "US_East_Server_Assessment",
                    "ipList": "10.1.16.0/24",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
                {
                    "id": 3,
                    "name": "US_East_Standard_Assessment",
                    "ipList": "10.1.32.0/22",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
            ]

            for payload in scan_payloads:
                (scan_dir / f"{payload['id']}_scan.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )

            stdout = StringIO()
            with patch("sys.stdout", new=stdout):
                exit_code = detect_and_plan_main(
                    [
                        "--subnet-repo-path",
                        str(subnet_repo),
                        "--output-dir",
                        str(output_dir),
                        "--run-id",
                        "run-nyc",
                        "--mode",
                        "offline",
                        "--scan-json-dir",
                        str(scan_dir),
                        "--asset-json-dir",
                        str(asset_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            run_dir = output_dir / "runs" / "run-nyc"
            audit_path = run_dir / "audit.jsonl"
            csv_path = run_dir / "proposed_changes.csv"
            md_path = run_dir / "proposed_changes.md"

            self.assertTrue(audit_path.exists())
            self.assertTrue(csv_path.exists())
            self.assertTrue(md_path.exists())

            audit_events = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            event_types = {event["event_type"] for event in audit_events}
            self.assertIn("run_started", event_types)
            self.assertIn("yaml_file_failed", event_types)
            self.assertIn("coverage_target_created", event_types)
            self.assertIn("proposed_change_audit_written", event_types)
            self.assertIn("run_completed", event_types)

            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            public_row = next(
                row
                for row in rows
                if row["Site Code"] == "NYC01" and row["Target Type"] == "PUBLIC"
            )
            self.assertEqual(public_row["Current Status"], "GAP")
            self.assertEqual(
                public_row["Proposed Action"],
                "CREATE_OR_UPDATE_PUBLIC_ASSET_AND_SCAN",
            )
            self.assertEqual(
                public_row["Proposed Scan Name"], "Public_External_Assessment"
            )

            private_row = next(
                row
                for row in rows
                if row["Site Code"] == "NYC01"
                and row["Target Type"] == "PRIVATE_SUPERNET"
            )
            self.assertEqual(private_row["Current Status"], "OK")
            self.assertEqual(
                private_row["Proposed Action"],
                "CREATE_OR_UPDATE_DISCOVERY_ASSET_AND_SCAN",
            )

            end_user_vlan_row = next(
                row
                for row in rows
                if row["Site Code"] == "NYC01" and row["VLAN Name"] == "End User"
            )
            self.assertEqual(end_user_vlan_row["Current Status"], "OK")
            self.assertEqual(
                end_user_vlan_row["Proposed Action"],
                "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN",
            )
            self.assertEqual(end_user_vlan_row["VLAN Tag"], "130")
            self.assertEqual(
                end_user_vlan_row["Proposed Scan Name"],
                "US_East_End_User_Assessment",
            )

            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("## NYC01 - New York Office", markdown)
            self.assertIn("### PUBLIC: `203.0.113.0/26`", markdown)

            coverage_summary = json.loads(
                (run_dir / "coverage_summary.json").read_text(encoding="utf-8")
            )
            self.assertIn("region", coverage_summary["dimensions"])
            self.assertIn(
                "NYC01_Private_Discovery",
                coverage_summary["missing_asset_groups"],
            )
            self.assertTrue((run_dir / "coverage_results.csv").is_file())
            self.assertTrue((run_dir / "extra_scan_targets.json").is_file())
            self.assertTrue((run_dir / "proposed_exclusions.csv").is_file())
            self.assertIn(
                "Final Audit Report",
                (run_dir / "final_audit_report.md").read_text(encoding="utf-8"),
            )

            summary = stdout.getvalue()
            self.assertIn("YAML files processed: 6", summary)
            self.assertIn("YAML files failed: 2", summary)
            self.assertIn(f"Output directory: {run_dir}", summary)
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)


if __name__ == "__main__":
    unittest.main()
