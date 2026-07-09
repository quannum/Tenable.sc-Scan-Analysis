import tempfile
import unittest
from pathlib import Path

from src.core.scope_utils import parse_scope_item
from src.core.tenable_scope_analysis import ScopeRecord
from src.tenable_coverage_workflow.coverage_reporting import (
    build_coverage_summary,
    build_proposed_exclusions,
    detect_extra_scan_targets,
    write_coverage_reports,
)
from src.tenable_coverage_workflow.models import (
    CoverageTarget,
    CoverageValidationResult,
)


class CoverageReportingTests(unittest.TestCase):
    def test_partial_extra_scope_is_reported_as_cidr_fragments(self):
        actual = [
            ScopeRecord(
                parsed=parse_scope_item("10.0.0.0/24"),
                scan_name="Broad Scan",
                scope_item="10.0.0.0/24",
            )
        ]
        targets = [
            CoverageTarget(
                target_type="VLAN",
                cidr="10.0.0.0/25",
                site_code="LAB01",
                site_name="Lab",
                location=None,
                region="Test",
                description=None,
            )
        ]

        findings = detect_extra_scan_targets(actual, targets)

        self.assertEqual(findings[0]["classification"], "PARTIAL_EXTRA")
        self.assertEqual(findings[0]["extra_ip_count"], 128)
        self.assertEqual(findings[0]["extra_cidrs"], ["10.0.0.128/25"])
        proposals = build_proposed_exclusions(findings)
        self.assertEqual(proposals[0]["proposed_exclusion"], "10.0.0.128/25")
        self.assertEqual(proposals[0]["approval_status"], "PENDING")

    def test_summary_groups_and_lists_missing_configuration(self):
        result = CoverageValidationResult(
            status="GAP",
            target_type="VLAN",
            cidr="10.0.0.0/24",
            site_code="LAB01",
            site_name="Lab",
            region="Test",
            location=None,
            description=None,
            vlan_name="Servers",
            vlan_tag=10,
            covering_scans=[],
            reason="gap",
            source_file="lab.json",
            required_asset_name="LAB01_Servers_VLAN_10",
            required_scan_name="Test_Server_Assessment",
            required_policy_name="Credentialed Server Assessment",
            expected_size=256,
            gap_count=256,
            required_asset_present="No",
            required_scan_present="No",
        )

        summary = build_coverage_summary([result], [])

        self.assertEqual(summary["totals"]["gap_ip_count"], 256)
        self.assertEqual(summary["missing_asset_groups"], ["LAB01_Servers_VLAN_10"])
        self.assertEqual(summary["dimensions"]["region"][0]["name"], "Test")

    def test_summary_markdown_lists_policy_mismatches_and_extra_count(self):
        result = CoverageValidationResult(
            status="OK",
            target_type="VLAN",
            cidr="10.0.0.0/24",
            site_code="LAB01",
            site_name="Lab",
            region="Test",
            location=None,
            description=None,
            vlan_name="Servers",
            vlan_tag=10,
            covering_scans=["Test_Server_Assessment"],
            reason="ok",
            source_file="subnet_as_code.get_sites#sites[0]",
            required_asset_name="LAB01_Servers_VLAN_10",
            required_scan_name="Test_Server_Assessment",
            required_policy_name="Credentialed Server Assessment",
            required_policy_configured="No",
            configured_policy="Basic Network Scan",
            expected_size=256,
            covered_count=256,
        )
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.0.0.0/24",
            site_code="LAB01",
            site_name="Lab",
            location=None,
            region="Test",
            description=None,
        )

        with tempfile.TemporaryDirectory() as directory:
            paths = write_coverage_reports(
                Path(directory),
                coverage_results=[result],
                targets=[target],
                actual_scopes=[],
                validation_issues=[],
            )

            markdown = Path(paths["coverage_summary_markdown"]).read_text(
                encoding="utf-8"
            )

        self.assertIn("## Policy Mismatches", markdown)
        self.assertIn("Basic Network Scan", markdown)
        self.assertIn("## Extra/Stale Scan Targets", markdown)


if __name__ == "__main__":
    unittest.main()
