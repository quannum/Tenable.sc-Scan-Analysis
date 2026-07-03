import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from openpyxl import Workbook

from src.tenable_coverage_workflow.models import SourceLoadResult
from src.tenable_coverage_workflow.subnet_source import (
    AuthoritativeSourceConfig,
    load_authoritative_source,
    load_json_api,
    load_json_payload,
    load_yaml_subnet_repo,
)
from src.tenable_coverage_workflow.subnet_source.xlsx_connector import (
    load_xlsx_definitions,
)


class JsonAuthoritativeSourceTests(unittest.TestCase):
    def test_json_api_retries_and_sends_bearer_token(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return json.dumps(
                    {"site_code": "API01", "private_ranges": ["10.9.0.0/24"]}
                ).encode()

        calls = []

        def opener(request, timeout):
            calls.append((request, timeout))
            if len(calls) == 1:
                raise URLError("temporary")
            return Response()

        with patch(
            "src.tenable_coverage_workflow.subnet_source.json_connector.time.sleep"
        ) as sleep:
            result = load_json_api(
                "https://network-api.example/sites",
                token="api-token",
                timeout_seconds=8,
                opener=opener,
            )

        self.assertEqual(result.site_definitions[0].site_code, "API01")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[-1][1], 8)
        self.assertEqual(
            calls[-1][0].get_header("Authorization"), "Bearer api-token"
        )
        sleep.assert_called_once()

    def test_subnet_as_code_module_invokes_method_with_readme_query_params(self):
        calls = []

        class Module:
            @staticmethod
            def get_sites_properties(**kwargs):
                calls.append(kwargs)
                return {
                    "site_definition": [
                        {
                            "site_code": "API01",
                            "site_name": "Module Site",
                            "private_ranges": ["10.9.0.0/24"],
                        }
                    ]
                }

        with patch(
            "src.tenable_coverage_workflow.subnet_source.source_loader."
            "importlib.import_module",
            return_value=Module,
        ):
            source_type, result = load_authoritative_source(
                AuthoritativeSourceConfig(
                    subnet_as_code_method="get_sites_properties",
                    subnet_as_code_reference_id="ref-001",
                    subnet_as_code_sites=["NYC", "LON"],
                    subnet_as_code_tags=["production"],
                    subnet_as_code_name="New York",
                    subnet_as_code_network_type="private",
                    subnet_as_code_routing_type="core",
                    subnet_as_code_desired_properties=[
                        "site_code",
                        "private_ranges",
                    ],
                )
            )

        self.assertEqual(source_type, "subnet_as_code")
        self.assertEqual(result.site_definitions[0].site_code, "API01")
        self.assertEqual(
            calls[0],
            {
                "referenceId": "ref-001",
                "sites": ["NYC", "LON"],
                "tags": ["production"],
                "name": "New York",
                "networkType": "private",
                "routingType": "core",
                "desiredProperties": ["site_code", "private_ranges"],
            },
        )

    def test_subnet_as_code_get_ipaddress_example_is_normalized(self):
        class Module:
            @staticmethod
            def get_ipaddress(**kwargs):
                self.assertEqual(
                    kwargs,
                    {"sites": ["NYC", "LON"], "tags": ["production"]},
                )
                return [
                    {
                        "name": "lonw-camdev1",
                        "ip": "192.41.32.55",
                        "tags": ["production"],
                        "site_code": "lon",
                    },
                    {
                        "name": "nycw-jsmith",
                        "ip": "192.1.57.130",
                        "tags": ["production"],
                        "site_code": "nyc",
                    },
                    {
                        "name": "smith-test",
                        "ip": "187.1.1.1",
                        "tags": ["production"],
                        "site_code": "nyc",
                    },
                ]

        with patch(
            "src.tenable_coverage_workflow.subnet_source.source_loader."
            "importlib.import_module",
            return_value=Module,
        ):
            source_type, result = load_authoritative_source(
                AuthoritativeSourceConfig(
                    subnet_as_code_method="get_ipaddress",
                    subnet_as_code_sites=["NYC", "LON"],
                    subnet_as_code_tags=["production"],
                )
        )

        self.assertEqual(source_type, "subnet_as_code")
        self.assertEqual(
            {site.site_code for site in result.site_definitions},
            {"LON", "NYC"},
        )
        targets = {
            (target.site_code, target.target_type, target.cidr): target
            for target in result.coverage_targets
        }
        self.assertIn(("LON", "PUBLIC", "192.41.32.55/32"), targets)
        self.assertIn(("NYC", "PUBLIC", "192.1.57.130/32"), targets)
        self.assertIn(("NYC", "PUBLIC", "187.1.1.1/32"), targets)
        self.assertEqual(
            targets[("LON", "PUBLIC", "192.41.32.55/32")].tags,
            ["production"],
        )

    def test_subnet_as_code_has_priority_over_raw_api_url(self):
        expected = SourceLoadResult(files_processed=1)
        with (
            patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "_load_subnet_as_code",
                return_value=expected,
            ) as module_loader,
            patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "load_json_api"
            ) as api_loader,
        ):
            source_type, result = load_authoritative_source(
                AuthoritativeSourceConfig(
                    subnet_as_code_method="get_sites",
                    api_url="https://unused.example/api",
                )
            )

        self.assertEqual(source_type, "subnet_as_code")
        self.assertIs(result, expected)
        module_loader.assert_called_once()
        api_loader.assert_not_called()

    def test_subnet_as_code_method_specific_filters_require_explicit_method(self):
        with self.assertRaisesRegex(
            ValueError, "subnet_as_code_method is required"
        ):
            load_authoritative_source(
                AuthoritativeSourceConfig(
                    subnet_as_code_desired_properties=["site_code"]
                )
            )

    def test_normalized_json_preserves_metadata_and_flattens_ranges(self):
        payload = {
            "sites": [
                {
                    "site_code": "NYC01",
                    "site_name": "New York",
                    "region": "US East",
                    "timezone": "America/New_York",
                    "tags": ["office", "tier-1"],
                    "environment": "production",
                    "business_function": "corporate",
                    "scan_classification": {"server": "credentialed"},
                    "public_ranges": ["203.0.113.0-203.0.113.7"],
                    "private_ranges": [
                        {
                            "cidr": "10.10.0.0/16",
                            "name": "NYC private",
                            "vlans": [
                                {
                                    "name": "Servers",
                                    "vlan_id": 120,
                                    "cidr": "10.10.16.0/24",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        result = load_json_payload(payload)

        self.assertEqual(result.files_failed, 0)
        self.assertEqual(len(result.site_definitions), 1)
        site = result.site_definitions[0]
        self.assertEqual(site.timezone, "America/New_York")
        self.assertEqual(site.tags, ["office", "tier-1"])
        self.assertEqual(site.scan_classification["server"], "credentialed")
        targets = {
            (target.target_type, target.cidr) for target in result.coverage_targets
        }
        self.assertIn(("PUBLIC", "203.0.113.0/29"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "10.10.0.0/16"), targets)
        self.assertIn(("VLAN", "10.10.16.0/24"), targets)

    def test_subnet_as_code_site_definition_json_is_normalized(self):
        payload = {
            "site_definition": [
                {
                    "site_code": "ABCNYC",
                    "site_name": "Company New York",
                    "site_type": "Studio",
                    "email_domain": "@Company.com",
                    "timezone": "EST",
                    "utc_offset": -5,
                    "grid_code": "nyc",
                    "public_ranges": [
                        {
                            "supernet": {
                                "network": "187.127.231.0",
                                "cidr": "/27",
                            },
                            "subnets": [
                                {
                                    "vlan_name": "vl300-InternetDIA",
                                    "display_name": "Direct Internet Access",
                                    "vlan": 300,
                                    "network": "187.127.231.0",
                                    "subnet_mask": "255.255.255.224",
                                    "cidr": "/27",
                                    "gateway": "187.127.231.1",
                                    "routing": "edge",
                                    "tags": ["internet"],
                                }
                            ],
                        }
                    ],
                    "private_ranges": [
                        {
                            "supernet": {
                                "network": "192.168.0.0",
                                "cidr": "/16",
                            },
                            "dhcp-options": {
                                "domain-name": "Company.example.corp",
                            },
                            "subnets": [
                                {
                                    "vlan_name": "vl16-it-services-static",
                                    "display_name": "It Services Static",
                                    "vlan": 16,
                                    "network": "192.168.16.0",
                                    "subnet_mask": "255.255.255.0",
                                    "cidr": "/24",
                                    "gateway": "192.168.16.1",
                                    "routing": "core",
                                    "dhcp-start": "192.168.16.130",
                                    "dhcp-end": "192.168.16.150",
                                    "tags": ["dhcp-dmc", "vlan-server"],
                                    "ip_addresses": [
                                        {
                                            "ip": "192.168.16.200",
                                            "name": "example-host",
                                            "tags": ["production"],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        result = load_json_payload(payload)

        self.assertEqual(result.files_failed, 0)
        site = result.site_definitions[0]
        self.assertEqual(site.site_type, "Studio")
        self.assertEqual(site.utc_offset, "-5")
        self.assertEqual(site.source_metadata["email_domain"], "@Company.com")
        self.assertEqual(site.source_metadata["grid_code"], "nyc")
        self.assertEqual(site.public_ranges[0].cidr, "187.127.231.0/27")
        self.assertEqual(site.public_ranges[0].name, "Direct Internet Access")
        self.assertEqual(site.private_ranges[0].cidr, "192.168.0.0/16")
        self.assertEqual(
            site.private_ranges[0].source_metadata["dhcp-options"]["domain-name"],
            "Company.example.corp",
        )

        vlan = site.private_ranges[0].vlans[0]
        self.assertEqual(vlan.name, "vl16-it-services-static")
        self.assertEqual(vlan.vlan_tag, 16)
        self.assertEqual(vlan.routing, "core")
        self.assertEqual(vlan.gateway, "192.168.16.1")
        self.assertEqual(vlan.dhcp_start, "192.168.16.130")
        self.assertEqual(vlan.dhcp_end, "192.168.16.150")
        self.assertEqual(vlan.ip_addresses[0]["ip"], "192.168.16.200")

        targets = {
            (target.target_type, target.cidr): target
            for target in result.coverage_targets
        }
        self.assertIn(("PUBLIC", "187.127.231.0/27"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "192.168.0.0/16"), targets)
        self.assertIn(("VLAN", "192.168.16.0/24"), targets)
        self.assertEqual(targets[("PUBLIC", "187.127.231.0/27")].tags, ["internet"])
        self.assertEqual(
            targets[("VLAN", "192.168.16.0/24")].tags,
            ["dhcp-dmc", "vlan-server"],
        )

    def test_invalid_vlan_is_reported_and_not_flattened(self):
        result = load_json_payload(
            {
                "site_code": "BOS01",
                "private_ranges": [
                    {
                        "cidr": "10.20.0.0/16",
                        "vlans": [{"name": "bad", "cidr": "10.30.0.0/24"}],
                    }
                ],
            }
        )

        self.assertTrue(
            any(
                "outside parent private range" in issue.message
                for issue in result.validation_issues
            )
        )
        self.assertFalse(
            any(target.target_type == "VLAN" for target in result.coverage_targets)
        )

    def test_yaml_fallback_supports_subnet_as_code_site_definition(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            yaml_path = Path(temp_dir) / "abcnyc.yml"
            yaml_path.write_text(
                """
site_definition:
  - site_code: ABCNYC
    site_name: Company New York
    timezone: EST
    public_ranges:
      - supernet:
          network: 187.127.231.0
          cidr: /27
        subnets:
          - vlan_name: vl300-InternetDIA
            display_name: Direct Internet Access
            vlan: 300
            network: 187.127.231.0
            cidr: /27
            subnet_mask: 255.255.255.224
            tags:
              - internet
    private_ranges:
      - supernet:
          network: 192.168.0.0
          cidr: /16
        subnets:
          - vlan_name: vl16-it-services-static
            display_name: It Services Static
            vlan: 16
            network: 192.168.16.0
            cidr: /24
            subnet_mask: 255.255.255.0
            routing: core
            tags:
              - vlan-server
""".strip(),
                encoding="utf-8",
            )

            result = load_yaml_subnet_repo(temp_dir)

        self.assertEqual(result.files_failed, 0)
        self.assertEqual(result.site_definitions[0].site_code, "ABCNYC")
        self.assertEqual(len(result.site_definitions[0].private_ranges), 1)
        self.assertEqual(len(result.coverage_targets), 3)
        vlan_targets = [
            target for target in result.coverage_targets if target.target_type == "VLAN"
        ]
        self.assertEqual(vlan_targets[0].cidr, "192.168.16.0/24")
        self.assertEqual(vlan_targets[0].tags, ["vlan-server"])

    def test_local_json_has_priority_over_yaml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "sites.json"
            json_path.write_text(
                json.dumps({"site_code": "JSON01", "public_ranges": ["192.0.2.0/30"]}),
                encoding="utf-8",
            )
            with patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "load_yaml_subnet_repo"
            ) as yaml_loader:
                source_type, result = load_authoritative_source(
                    AuthoritativeSourceConfig(
                        json_file=json_path,
                        github_api_url="https://ghe/api/v3",
                        github_repository="acme/networks",
                        yaml_repo_path="unused",
                    )
                )

            self.assertEqual(source_type, "json_file")
            self.assertEqual(result.site_definitions[0].site_code, "JSON01")
            yaml_loader.assert_not_called()

    def test_github_yaml_has_priority_over_local_yaml(self):
        expected = SourceLoadResult(files_processed=2)
        with (
            patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "load_github_yaml_repo",
                return_value=expected,
            ) as github_loader,
            patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "load_yaml_subnet_repo"
            ) as yaml_loader,
        ):
            source_type, result = load_authoritative_source(
                AuthoritativeSourceConfig(
                    github_api_url="https://ghe/api/v3",
                    github_repository="acme/networks",
                    yaml_repo_path="local",
                )
            )

        self.assertEqual(source_type, "github_yaml")
        self.assertIs(result, expected)
        github_loader.assert_called_once()
        yaml_loader.assert_not_called()

    def test_duplicate_and_unexpected_overlap_are_reported(self):
        result = load_json_payload(
            {
                "sites": [
                    {"site_code": "ONE", "public_ranges": ["192.0.2.0/25"]},
                    {
                        "site_code": "TWO",
                        "public_ranges": ["192.0.2.0/25", "192.0.2.64/26"],
                    },
                ]
            }
        )

        messages = [issue.message for issue in result.validation_issues]
        self.assertTrue(any("Duplicate authoritative range" in m for m in messages))
        self.assertTrue(any("Overlapping authoritative ranges" in m for m in messages))

    def test_ipv6_is_rejected_during_definition_validation(self):
        result = load_json_payload(
            {"site_code": "V6", "public_ranges": ["2001:db8::/64"]}
        )

        self.assertEqual(result.coverage_targets, [])
        self.assertTrue(
            any("IPv6 scope" in issue.message for issue in result.validation_issues)
        )

    def test_xlsx_legacy_input_normalizes_to_common_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "networks.xlsx"
            workbook = Workbook()
            sheet = workbook.active
            sheet.title = "Networks"
            sheet.append(
                [
                    "Site Code",
                    "Site Name",
                    "Region",
                    "Target Type",
                    "Scope Item",
                    "VLAN Name",
                    "VLAN ID",
                    "Required Scan",
                ]
            )
            sheet.append(
                [
                    "DAL01",
                    "Dallas",
                    "US Central",
                    "VLAN",
                    "10.20.1.0-10.20.1.255",
                    "Servers",
                    120,
                    "Custom_Server_Scan",
                ]
            )
            workbook.save(path)

            result = load_xlsx_definitions(path)

            self.assertEqual(result.files_failed, 0)
            self.assertEqual(result.coverage_targets[0].cidr, "10.20.1.0/24")
            self.assertEqual(result.coverage_targets[0].target_type, "VLAN")
            self.assertEqual(
                result.coverage_targets[0].required_scan_name,
                "Custom_Server_Scan",
            )


if __name__ == "__main__":
    unittest.main()
