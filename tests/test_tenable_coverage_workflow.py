import csv
import json
import os
import shutil
import tempfile
import unittest
from collections import defaultdict
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from src.constants import INCLUDE
from src.core.tenable_scope_analysis import build_scope_sheets, build_scope_tables
from src.tenable_coverage_workflow.grouping_config import build_grouping_config
from src.tenable_coverage_workflow.models import (
    CoverageTarget,
    CoverageValidationResult,
    GroupingConfig,
)
from src.tenable_coverage_workflow.planning.naming_rules import (
    apply_naming_rules,
    build_required_policy_name,
    build_required_scan_name,
)
from src.tenable_coverage_workflow.planning.proposed_changes import (
    generate_proposed_changes,
)
from src.tenable_coverage_workflow.run_detect_and_plan import (
    DetectAndPlanConfig,
    build_argument_parser,
    build_configuration_index,
    build_detect_and_plan_config,
    run_detect_and_plan,
    validate_coverage_targets,
)
from src.tenable_coverage_workflow.run_detect_and_plan import (
    main as detect_and_plan_main,
)
from src.tenable_coverage_workflow.subnet_source import AuthoritativeSourceConfig


class PlanningTests(unittest.TestCase):
    def test_naming_rules_assign_required_names(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.16.0/24",
            site_code="nyc01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Server VLAN",
            vlan_name="Servers",
            vlan_tag=120,
            source_file="sites/us-east/nyc01.yaml",
        )

        named_target = apply_naming_rules(target)

        self.assertEqual(
            named_target.required_asset_name,
            "ABC Corp NYC01 VLAN Servers 120",
        )
        self.assertEqual(
            named_target.required_scan_name,
            "ABC Corp Assessment NYC01 Server",
        )
        self.assertEqual(
            named_target.required_policy_name,
            "Basic Assessment Policy",
        )

    def test_unmapped_default_vlan_keeps_asset_but_requires_assessment_review(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.150.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Security Cameras",
            vlan_name="Security Cameras",
            vlan_tag=150,
        )

        named_target = apply_naming_rules(target)

        self.assertEqual(
            named_target.required_asset_name,
            "ABC Corp NYC01 VLAN Security Cameras 150",
        )
        self.assertIsNone(named_target.required_scan_name)
        self.assertIsNone(named_target.required_policy_name)
        self.assertEqual(
            named_target.scan_classification,
            {
                "vlan_role": "Security Cameras",
                "assessment_mapping": "UNMAPPED",
                "review_required": True,
            },
        )

    def test_unmapped_vlan_tag_keeps_source_role_and_asset_name(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.151.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Printers",
            vlan_name="Printers",
            vlan_tag=151,
            tags=["vlan-printers"],
        )

        named_target = apply_naming_rules(target, GroupingConfig(mode="vlan_tag"))

        self.assertEqual(
            named_target.required_asset_name,
            "ABC Corp NYC01 VLAN Printers",
        )
        self.assertIsNone(named_target.required_scan_name)
        self.assertIsNone(named_target.required_policy_name)
        self.assertEqual(named_target.scan_classification["vlan_role"], "Printers")
        self.assertEqual(
            named_target.scan_classification["assessment_mapping"], "UNMAPPED"
        )

    def test_explicit_tag_map_assigns_a_scan_bucket(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.152.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Printers",
            vlan_name="Printers",
            vlan_tag=152,
            tags=["vlan-printers"],
        )

        named_target = apply_naming_rules(
            target,
            GroupingConfig(
                mode="vlan_tag",
                tag_map={" VLAN-Printers ": "network"},
            ),
        )

        self.assertEqual(
            named_target.required_scan_name,
            "ABC Corp Assessment NYC01 Network",
        )
        self.assertEqual(
            named_target.required_policy_name,
            "Network Infrastructure Assessment",
        )
        self.assertEqual(named_target.scan_classification, {})

    def test_public_scan_name_uses_only_the_site_code(self):
        target = CoverageTarget(
            target_type="PUBLIC",
            cidr="139.138.231.0/24",
            site_code="nyc",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Direct Internet Access",
        )

        named_target = apply_naming_rules(target)

        self.assertEqual(named_target.required_asset_name, "ABC Corp NYC Public")
        self.assertEqual(
            named_target.required_scan_name,
            "ABC Corp Assessment NYC Public",
        )

    def test_exclude_tag_skips_naming_coverage_plans_and_missing_resources(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.99.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Restricted VLAN",
            vlan_name="Restricted",
            vlan_tag=999,
            tags=["Exclude"],
            source_file="sites/us-east/nyc01.yaml",
        )

        named_target = apply_naming_rules(target)
        results = validate_coverage_targets(
            [named_target],
            actual_scopes=[],
            actual_by_scan=defaultdict(list),
            excluded_by_scan=defaultdict(list),
        )

        self.assertIsNone(named_target.required_asset_name)
        self.assertIsNone(named_target.required_scan_name)
        self.assertEqual(results[0].status, "EXCLUDED")
        self.assertTrue(results[0].excluded_by_tag)
        self.assertEqual(results[0].exclusion_tag, "Exclude")
        self.assertEqual(results[0].gap_count, 0)
        self.assertEqual(generate_proposed_changes(results, run_id="run-001"), [])

    def test_unmapped_vlan_stays_in_coverage_and_asset_review(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.153.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Security Cameras",
            vlan_name="Security Cameras",
            vlan_tag=153,
        )
        named_target = apply_naming_rules(target)

        results = validate_coverage_targets(
            [named_target],
            actual_scopes=[],
            actual_by_scan=defaultdict(list),
            excluded_by_scan=defaultdict(list),
        )
        changes = generate_proposed_changes(results, run_id="run-001")

        self.assertEqual(results[0].status, "GAP")
        self.assertEqual(results[0].required_asset_present, "No")
        self.assertEqual(results[0].required_scan_present, "")
        self.assertEqual(results[0].required_policy_configured, "")
        self.assertEqual(
            results[0].scan_classification["vlan_role"], "Security Cameras"
        )
        self.assertEqual(changes[0].proposed_action, "REVIEW_ASSESSMENT_MAPPING")
        self.assertEqual(
            changes[0].proposed_asset_name,
            "ABC Corp NYC01 VLAN Security Cameras 153",
        )
        self.assertIsNone(changes[0].proposed_scan_name)
        self.assertIsNone(changes[0].proposed_policy_name)
        self.assertIn("No explicit assessment mapping", changes[0].issue)

    def test_vlan_tag_grouping_can_override_vlan_name_grouping(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.32.0/22",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Corp Wireless",
            vlan_name="Corp WiFi",
            vlan_tag=220,
            tags=["production", "vlan-workstation", "wireless"],
            source_file="sites/us-east/nyc01.yaml",
        )

        named_target = apply_naming_rules(
            target,
            GroupingConfig(mode="vlan_tag", vlan_tag_prefix="vlan-"),
        )

        self.assertEqual(
            named_target.required_asset_name,
            "ABC Corp NYC01 VLAN Workstation",
        )
        self.assertEqual(
            named_target.required_scan_name,
            "ABC Corp Assessment NYC01 Workstation",
        )
        self.assertEqual(
            named_target.required_policy_name,
            "Basic Assessment Policy",
        )

    def test_first_vlan_prefixed_tag_wins(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.48.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Shared VLAN",
            vlan_name="Shared",
            vlan_tag=140,
            tags=["vlan-wireless", "vlan-server"],
            source_file="sites/us-east/nyc01.yaml",
        )

        named_target = apply_naming_rules(
            target,
            GroupingConfig(mode="vlan_tag", vlan_tag_prefix="vlan-"),
        )

        self.assertEqual(
            named_target.required_asset_name,
            "ABC Corp NYC01 VLAN Wireless",
        )
        self.assertEqual(
            named_target.required_scan_name,
            "ABC Corp Assessment NYC01 Workstation",
        )
        self.assertEqual(
            named_target.required_policy_name,
            "Basic Assessment Policy",
        )

    def test_workstation_and_wireless_tags_share_grouped_names(self):
        workstation = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.48.0/24",
            site_code="nyc01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Workstation VLAN",
            vlan_name="Workstations",
            vlan_tag=141,
            tags=["vlan-workstation"],
            source_file="sites/us-east/nyc01.yaml",
        )
        wireless = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.49.0/24",
            site_code="nyc01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Wireless VLAN",
            vlan_name="Wireless",
            vlan_tag=142,
            tags=["vlan-wireless"],
            source_file="sites/us-east/nyc01.yaml",
        )
        config = GroupingConfig(mode="vlan_tag")

        workstation_named = apply_naming_rules(workstation, config)
        wireless_named = apply_naming_rules(wireless, config)

        self.assertEqual(
            workstation_named.required_asset_name,
            "ABC Corp NYC01 VLAN Workstation",
        )
        self.assertEqual(
            wireless_named.required_asset_name,
            "ABC Corp NYC01 VLAN Wireless",
        )
        self.assertNotEqual(
            workstation_named.required_asset_name,
            wireless_named.required_asset_name,
        )
        self.assertEqual(
            workstation_named.required_scan_name,
            "ABC Corp Assessment NYC01 Workstation",
        )
        self.assertEqual(
            workstation_named.required_scan_name,
            wireless_named.required_scan_name,
        )
        self.assertEqual(
            workstation_named.required_policy_name,
            wireless_named.required_policy_name,
        )
        self.assertEqual(
            workstation_named.required_policy_name,
            "Basic Assessment Policy",
        )

    def test_server_role_tags_share_server_scan(self):
        config = GroupingConfig(mode="vlan_tag")
        targets = (
            ("Storage", "10.1.50.0/24"),
            ("Other", "10.1.51.0/24"),
            ("Environment", "10.1.52.0/24"),
        )
        for group_name, cidr in targets:
            with self.subTest(group_name=group_name):
                target = CoverageTarget(
                    target_type="VLAN",
                    cidr=cidr,
                    site_code="NYC01",
                    site_name="New York Office",
                    location="New York, NY",
                    region="US East",
                    description=f"{group_name} VLAN",
                    vlan_name=group_name,
                    vlan_tag=150,
                    tags=[f"vlan-{group_name.lower()}"],
                )

                named_target = apply_naming_rules(target, config)

                self.assertEqual(
                    named_target.required_asset_name,
                    f"ABC Corp NYC01 VLAN {group_name}",
                )
                self.assertEqual(
                    named_target.required_scan_name,
                    "ABC Corp Assessment NYC01 Server",
                )
                self.assertEqual(
                    named_target.required_policy_name,
                    "Basic Assessment Policy",
                )

    def test_vlan_tag_mode_routes_av_into_the_network_bucket(self):
        targets = {
            "environment": CoverageTarget(
                target_type="VLAN",
                cidr="10.1.50.0/24",
                site_code="NYC01",
                site_name="New York Office",
                location="New York, NY",
                region="US East",
                description="Environment VLAN",
                vlan_name="Environment",
                vlan_tag=150,
                tags=["vlan-environment"],
            ),
            "network": CoverageTarget(
                target_type="VLAN",
                cidr="10.1.51.0/24",
                site_code="NYC01",
                site_name="New York Office",
                location="New York, NY",
                region="US East",
                description="Network VLAN",
                vlan_name="Network",
                vlan_tag=151,
                tags=["vlan-network"],
            ),
            "av": CoverageTarget(
                target_type="VLAN",
                cidr="10.1.52.0/24",
                site_code="NYC01",
                site_name="New York Office",
                location="New York, NY",
                region="US East",
                description="AV VLAN",
                vlan_name="AV",
                vlan_tag=152,
                tags=["vlan-av"],
            ),
        }
        config = GroupingConfig(mode="vlan_tag")

        self.assertEqual(
            build_required_policy_name(targets["environment"], config),
            "Basic Assessment Policy",
        )
        self.assertEqual(
            build_required_policy_name(targets["network"], config),
            "Network Infrastructure Assessment",
        )
        self.assertEqual(
            build_required_policy_name(targets["av"], config),
            "Network Infrastructure Assessment",
        )
        self.assertEqual(
            build_required_scan_name(targets["av"], config),
            "ABC Corp Assessment NYC01 Network",
        )

    def test_grouping_tag_map_can_override_the_scan_bucket(self):
        target = CoverageTarget(
            target_type="VLAN",
            cidr="10.1.64.0/24",
            site_code="NYC01",
            site_name="New York Office",
            location="New York, NY",
            region="US East",
            description="Wireless VLAN",
            vlan_name="Corp Wireless",
            vlan_tag=250,
            tags=["vlan-wireless"],
            source_file="sites/us-east/nyc01.yaml",
        )

        named_target = apply_naming_rules(
            target,
            GroupingConfig(
                mode="vlan_tag",
                vlan_tag_prefix="vlan-",
                tag_map={"vlan-wireless": "NETWORK"},
            ),
        )

        self.assertEqual(
            named_target.required_asset_name,
            "ABC Corp NYC01 VLAN Wireless",
        )
        self.assertEqual(
            named_target.required_scan_name,
            "ABC Corp Assessment NYC01 Network",
        )

    def test_grouping_config_rejects_role_aliases(self):
        with self.assertRaisesRegex(ValueError, "scan buckets"):
            build_grouping_config(
                mode_value="vlan_tag",
                prefix_value="vlan-",
                tag_map_value={"vlan-workstation": "END_USER"},
            )

    def test_scan_name_scope_falls_back_to_location_then_global(self):
        location_only_target = CoverageTarget(
            target_type="VLAN",
            cidr="10.2.16.0/24",
            site_code="",
            site_name="Remote Office",
            location="Raleigh, NC",
            region=None,
            description=None,
            vlan_name="Servers",
            vlan_tag=120,
            source_file="sites/remote.yaml",
        )
        global_target = CoverageTarget(
            target_type="VLAN",
            cidr="10.3.16.0/24",
            site_code="",
            site_name="Unmapped Office",
            location=None,
            region=None,
            description=None,
            vlan_name="Servers",
            vlan_tag=120,
            source_file="sites/unmapped.yaml",
        )
        grouped_location_target = CoverageTarget(
            target_type="VLAN",
            cidr="10.4.16.0/24",
            site_code="",
            site_name="Remote Office",
            location="Raleigh, NC",
            region="US East",
            description="Wireless VLAN",
            vlan_name="Corp Wireless",
            vlan_tag=220,
            tags=["vlan-workstation"],
            source_file="sites/remote.yaml",
        )

        self.assertEqual(
            build_required_scan_name(location_only_target),
            "ABC Corp Assessment Raleigh NC Server",
        )
        self.assertEqual(
            build_required_scan_name(global_target),
            "ABC Corp Assessment Global Server",
        )
        self.assertEqual(
            build_required_scan_name(
                grouped_location_target,
                GroupingConfig(mode="vlan_tag"),
            ),
            "ABC Corp Assessment Raleigh NC Workstation",
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
                required_scan_name="US_East_NYC01_End_User_VLAN_Assessment",
                required_policy_name="Credentialed Workstation Assessment",
                required_scan_covered="No",
            ),
            CoverageValidationResult(
                status="GAP",
                target_type="PUBLIC",
                cidr="139.138.231.0/26",
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
                required_scan_name="US_East_NYC01_Public_range_Assessment",
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
                required_scan_name="US_East_NYC01_Network_VLAN_Assessment",
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
    @staticmethod
    def _subnet_module():
        class Module:
            @staticmethod
            def get_sites(**kwargs):
                return [
                    {
                        "site_code": "NYC01",
                        "site_name": "New York Office",
                        "public_ranges": [
                            {
                                "supernet": {"network": "139.138.231.0", "cidr": "/26"},
                                "subnets": [
                                    {
                                        "vlan_name": "vl300-internet",
                                        "display_name": "Internet",
                                        "vlan": 300,
                                        "network": "139.138.231.0",
                                        "cidr": "/26",
                                        "subnet_mask": "255.255.255.192",
                                        "tags": [],
                                        "ip_addresses": None,
                                    }
                                ],
                            }
                        ],
                        "private_ranges": [
                            {
                                "supernet": {"network": "10.1.0.0", "cidr": "/16"},
                                "subnets": [
                                    {
                                        "vlan_name": "vl130-end-user",
                                        "display_name": "End User",
                                        "vlan": 130,
                                        "network": "10.1.32.0",
                                        "cidr": "/22",
                                        "subnet_mask": "255.255.252.0",
                                        "tags": [],
                                        "ip_addresses": None,
                                    },
                                    {
                                        "vlan_name": "vl153-security-cameras",
                                        "display_name": "Security Cameras",
                                        "vlan": 153,
                                        "network": "10.1.153.0",
                                        "cidr": "/24",
                                        "subnet_mask": "255.255.255.0",
                                        "tags": [],
                                        "ip_addresses": None,
                                    },
                                ],
                            }
                        ],
                    },
                    {
                        "site_code": "BAD01",
                        "site_name": "Broken Site",
                        "public_ranges": [
                            {
                                "supernet": {"network": "not-a-network", "cidr": "/24"},
                                "subnets": [
                                    {
                                        "vlan_name": "vl1-invalid",
                                        "display_name": "Invalid",
                                        "vlan": 1,
                                        "network": "192.0.2.0",
                                        "cidr": "/24",
                                        "subnet_mask": "255.255.255.0",
                                        "tags": [],
                                        "ip_addresses": None,
                                    }
                                ],
                            }
                        ],
                    },
                ]

        return Module

    def test_detect_and_plan_config_requires_offline_json_dirs(self):
        parser = build_argument_parser()
        args = parser.parse_args(
            [
                "--mode",
                "offline",
            ]
        )

        with self.assertRaisesRegex(ValueError, "Offline mode requires"):
            build_detect_and_plan_config(args)

    def test_detect_and_plan_config_prefers_tcw_transport_environment(self):
        parser = build_argument_parser()
        args = parser.parse_args(
            [
                "--mode",
                "live",
            ]
        )
        env = {
            "TCW_SC_URL": "https://tcw.tenable.local",
            "SC_URL": "https://legacy.tenable.local",
            "TCW_SC_ACCESS_KEY": "tcw-access",
            "SC_ACCESS_KEY": "legacy-access",
            "TCW_SC_SECRET_KEY": "tcw-secret",
            "SC_SECRET_KEY": "legacy-secret",
            "TCW_SC_TIMEOUT_SECONDS": "45",
            "SC_TIMEOUT_SECONDS": "60",
            "TCW_SC_RETRIES": "4",
            "TCW_SC_BACKOFF_SECONDS": "2.0",
            "TCW_SC_SSL_VERIFY": "false",
        }

        with patch.dict(os.environ, env, clear=True):
            config = build_detect_and_plan_config(args)

        self.assertEqual(config.sc_url, "https://tcw.tenable.local")
        self.assertEqual(config.sc_access_key, "tcw-access")
        self.assertEqual(config.sc_secret_key, "tcw-secret")
        self.assertEqual(config.sc_timeout_seconds, 45)
        self.assertEqual(config.sc_retries, 4)
        self.assertEqual(config.sc_backoff_seconds, 2.0)
        self.assertFalse(config.sc_ssl_verify)

    def test_detect_and_plan_rejects_no_dry_run(self):
        parser = build_argument_parser()
        args = parser.parse_args(
            [
                "--no-dry-run",
            ]
        )

        with self.assertRaisesRegex(ValueError, "does not support --no-dry-run"):
            build_detect_and_plan_config(args)

    def test_detect_and_plan_help_hides_no_dry_run(self):
        parser = build_argument_parser()
        help_text = parser.format_help()

        self.assertIn("--dry-run", help_text)
        self.assertNotIn("--no-dry-run", help_text)

    def test_run_detect_and_plan_rejects_programmatic_non_dry_run(self):
        config = DetectAndPlanConfig(
            source_config=AuthoritativeSourceConfig(),
            output_dir=Path("output"),
            run_id="run-001",
            dry_run=False,
            mode="offline",
            scan_json_dir="scans",
            asset_json_dir="assets",
            sc_access_key=None,
            sc_secret_key=None,
            sc_url=None,
            include_keywords=[],
            exclude_keywords=[],
            match_all_include=False,
            case_sensitive=False,
            filter_disabled_mode="ALL",
        )

        with self.assertRaisesRegex(ValueError, "dry_run=false"):
            run_detect_and_plan(config)

    def test_detect_and_plan_cli_writes_audits_for_bad_subnet_records(self):
        temp_path = Path(tempfile.mkdtemp(prefix="tenable-detect-plan-"))

        try:
            scan_dir = temp_path / "scans"
            asset_dir = temp_path / "assets"
            output_dir = temp_path / "output"
            scan_dir.mkdir()
            asset_dir.mkdir()

            scan_payloads = [
                {
                    "id": 1,
                    "name": "ABC Corp Discovery NYC01 Private",
                    "ipList": "10.1.0.0/16,10.3.0.0/16",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
                {
                    "id": 2,
                    "name": "ABC Corp Assessment NYC01 Server",
                    "ipList": "10.1.16.0/24",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
                {
                    "id": 3,
                    "name": "ABC Corp Assessment NYC01 Workstation",
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
            with (
                patch("sys.stdout", new=stdout),
                patch(
                    "src.tenable_coverage_workflow.subnet_source.source_loader."
                    "importlib.import_module",
                    return_value=self._subnet_module(),
                ),
            ):
                exit_code = detect_and_plan_main(
                    [
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
            self.assertIn("authoritative_site_loaded", event_types)
            unmapped_events = [
                event
                for event in audit_events
                if event["event_type"] == "assessment_mapping_missing"
            ]
            self.assertEqual(len(unmapped_events), 1)
            self.assertEqual(unmapped_events[0]["site_code"], "NYC01")
            self.assertEqual(unmapped_events[0]["cidr"], "10.1.153.0/24")
            self.assertIn("proposed_change_audit_written", event_types)
            self.assertIn("run_completed", event_types)

            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                self.assertIn("Source Reference", reader.fieldnames or [])
                self.assertNotIn("Source YAML File", reader.fieldnames or [])
                rows = list(reader)

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
                public_row["Proposed Scan Name"], "ABC Corp Assessment NYC01 Public"
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
                if row["Site Code"] == "NYC01" and row["VLAN Name"] == "vl130-end-user"
            )
            self.assertEqual(end_user_vlan_row["Current Status"], "OK")
            self.assertEqual(
                end_user_vlan_row["Proposed Action"],
                "CREATE_OR_UPDATE_VLAN_ASSET_AND_ATTACH_TO_SCAN",
            )
            self.assertEqual(end_user_vlan_row["VLAN Tag"], "130")
            self.assertEqual(
                end_user_vlan_row["Proposed Scan Name"],
                "ABC Corp Assessment NYC01 Workstation",
            )

            unmapped_vlan_row = next(
                row
                for row in rows
                if row["Site Code"] == "NYC01"
                and row["VLAN Name"] == "vl153-security-cameras"
            )
            self.assertEqual(
                unmapped_vlan_row["Proposed Action"],
                "REVIEW_ASSESSMENT_MAPPING",
            )
            self.assertEqual(
                unmapped_vlan_row["Proposed Asset Name"],
                "ABC Corp NYC01 VLAN vl153 security cameras 153",
            )
            self.assertEqual(unmapped_vlan_row["Proposed Scan Name"], "")
            self.assertEqual(unmapped_vlan_row["Proposed Policy Name"], "")
            self.assertIn("No explicit assessment mapping", unmapped_vlan_row["Issue"])

            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("## NYC01 - New York Office", markdown)
            self.assertIn("### PUBLIC: `139.138.231.0/26`", markdown)
            self.assertIn("Source Reference", markdown)

            coverage_summary = json.loads(
                (run_dir / "coverage_summary.json").read_text(encoding="utf-8")
            )
            coverage_results = json.loads(
                (run_dir / "coverage_results.json").read_text(encoding="utf-8")
            )["results"]
            unmapped_coverage_result = next(
                result
                for result in coverage_results
                if result["cidr"] == "10.1.153.0/24"
            )
            self.assertEqual(
                unmapped_coverage_result["scan_classification"],
                {
                    "vlan_role": "vl153 security cameras",
                    "assessment_mapping": "UNMAPPED",
                    "review_required": True,
                },
            )
            self.assertIsNone(unmapped_coverage_result["required_scan_name"])
            self.assertIsNone(unmapped_coverage_result["required_policy_name"])
            self.assertIn("region", coverage_summary["dimensions"])
            self.assertIn(
                "ABC Corp NYC01 Private Discovery",
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
            self.assertIn("Authoritative units processed: 1", summary)
            self.assertIn("Authoritative units failed: 1", summary)
            self.assertIn(f"Output directory: {run_dir}", summary)
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)


class ScanNameCompatibilityTests(unittest.TestCase):
    @staticmethod
    def _config():
        return SimpleNamespace(
            include_keywords=[],
            exclude_keywords=[],
            match_all_include=False,
            case_sensitive=False,
            filter_disabled_mode="ALL",
        )

    def test_build_scope_sheets_accepts_info_name_only_scan_records(self):
        class FakeDataAccess:
            @staticmethod
            def get_scans():
                return [{"id": 1, "info": {"name": "Production Weekly"}}]

            @staticmethod
            def get_scan_details(scan_id):
                self.assertEqual(scan_id, 1)
                return {
                    "id": 1,
                    "info": {"name": "Production Weekly"},
                    "ipList": "10.1.0.0/24",
                    "assets": [],
                }

        normalized_ws = build_scope_tables()
        build_scope_sheets(
            normalized_ws,
            FakeDataAccess(),
            self._config(),
        )

        rows = list(normalized_ws.iter_rows(min_row=2, values_only=True))
        self.assertEqual(
            rows,
            [("Production Weekly", "SCAN_IPLIST", INCLUDE, "10.1.0.0/24")],
        )

    def test_build_configuration_index_prefers_info_name(self):
        class FakeDataAccess:
            @staticmethod
            def get_asset_lists() -> list[dict[str, Any]]:
                return []

            @staticmethod
            def get_scans() -> list[dict[str, Any]]:
                return [{"id": 7, "name": "fallback", "info": {"name": "Canonical"}}]

            @staticmethod
            def get_scan_details(scan_id: Any) -> dict[str, Any]:
                self.assertEqual(scan_id, 7)
                return {"id": 7, "info": {"name": "Canonical"}, "assets": []}

        index = build_configuration_index(FakeDataAccess())

        self.assertIn("Canonical", index["scans_by_name"])
        self.assertNotIn("fallback", index["scans_by_name"])


if __name__ == "__main__":
    unittest.main()
