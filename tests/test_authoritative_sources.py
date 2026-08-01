import ipaddress
import unittest
from unittest.mock import patch

from src.tenable_coverage_workflow.subnet_source import (
    AuthoritativeSourceConfig,
    load_authoritative_source,
    load_json_payload,
)


def _subnet(
    vlan_name: str,
    vlan: int,
    network: str,
    cidr: str,
    tags: list[str] | None = None,
    **extra,
) -> dict[str, object]:
    return {
        "vlan_name": vlan_name,
        "display_name": vlan_name.replace("-", " ").title(),
        "vlan": vlan,
        "network": network,
        "subnet_mask": str(
            ipaddress.ip_network(f"{network}/{cidr.lstrip('/')}").netmask
        ),
        "cidr": cidr,
        "tags": tags or [],
        **extra,
    }


def _network_range(
    network: str,
    cidr: str,
    subnets: list[dict[str, object]],
    **extra,
) -> dict[str, object]:
    return {
        "supernet": {"network": network, "cidr": cidr},
        "subnets": subnets,
        **extra,
    }


def _site(
    site_code: str,
    public_ranges: list[dict[str, object]] | None = None,
    private_ranges: list[dict[str, object]] | None = None,
    **extra,
) -> dict[str, object]:
    return {
        "site_code": site_code,
        "site_name": f"{site_code} Site",
        "public_ranges": public_ranges or [],
        "private_ranges": private_ranges or [],
        **extra,
    }


class JsonAuthoritativeSourceTests(unittest.TestCase):
    def test_subnet_as_code_get_sites_receives_supported_filters(self):
        calls = []

        class Module:
            @staticmethod
            def get_sites(**kwargs):
                calls.append(kwargs)
                return [
                    _site(
                        "API01",
                        private_ranges=[
                            _network_range(
                                "10.9.0.0",
                                "/24",
                                [_subnet("vl9-servers", 9, "10.9.0.0", "/24")],
                            )
                        ],
                        site_name="Module Site",
                    )
                ]

        with patch(
            "src.tenable_coverage_workflow.subnet_source.source_loader."
            "importlib.import_module",
            return_value=Module,
        ):
            source_type, result = load_authoritative_source(
                AuthoritativeSourceConfig(
                    reference_id="ref-001",
                    sites=["NYC", "LON"],
                    tags=["production"],
                    name="New York",
                    network_type="private",
                    routing_type="core",
                )
            )

        self.assertEqual(source_type, "rsg_subnet_as_code")
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
            },
        )

    def test_subnet_as_code_can_query_all_sites_without_sites_filter(self):
        calls = []

        class Module:
            @staticmethod
            def get_sites(**kwargs):
                calls.append(kwargs)
                return [
                    _site(
                        "ALL01",
                        private_ranges=[
                            _network_range(
                                "10.42.0.0",
                                "/24",
                                [_subnet("vl42-servers", 42, "10.42.0.0", "/24")],
                            )
                        ],
                        site_name="All Sites Example",
                    )
                ]

        with patch(
            "src.tenable_coverage_workflow.subnet_source.source_loader."
            "importlib.import_module",
            return_value=Module,
        ):
            source_type, result = load_authoritative_source(AuthoritativeSourceConfig())

        self.assertEqual(source_type, "rsg_subnet_as_code")
        self.assertEqual(calls[0], {})
        self.assertEqual(result.site_definitions[0].site_code, "ALL01")

    def test_non_list_or_empty_api_response_is_rejected(self):
        result = load_json_payload({"site_definition": []})

        self.assertEqual(result.files_failed, 1)
        self.assertIn("must be a list", result.validation_issues[0].message)

        empty_result = load_json_payload([])
        self.assertEqual(empty_result.files_failed, 1)

    def test_stable_payload_flattens_public_private_and_vlan_scope(self):
        payload = [
            _site(
                    "NYC01",
                    public_ranges=[
                        _network_range(
                            "139.138.231.0",
                            "/27",
                            [
                                _subnet(
                                    "vl300-internet",
                                    300,
                                    "139.138.231.0",
                                    "/27",
                                    ["internet"],
                                )
                            ],
                        )
                    ],
                    private_ranges=[
                        _network_range(
                            "10.1.0.0",
                            "/16",
                            [
                                _subnet(
                                    "vl16-servers",
                                    120,
                                    "10.1.16.0",
                                    "/24",
                                    ["vlan-server"],
                                )
                            ],
                        )
                    ],
                    timezone="America/New_York",
            )
        ]

        result = load_json_payload(payload)

        self.assertEqual(result.files_failed, 0)
        self.assertEqual(len(result.site_definitions), 1)
        site = result.site_definitions[0]
        self.assertEqual(site.timezone, "America/New_York")
        targets = {
            (target.target_type, target.cidr) for target in result.coverage_targets
        }
        self.assertIn(("PUBLIC", "139.138.231.0/27"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "10.1.0.0/16"), targets)
        self.assertIn(("VLAN", "10.1.16.0/24"), targets)

    def test_exclude_tags_are_preserved_for_ranges_vlans_and_individual_ips(self):
        result = load_json_payload(
            [
                _site(
                        "EXC01",
                        public_ranges=[
                            _network_range(
                                "139.138.227.128",
                                "/26",
                                [
                                    _subnet(
                                        "vl300-internet",
                                        300,
                                        "139.138.227.128",
                                        "/26",
                                        ["exclude"],
                                        ip_addresses=[
                                            {
                                                "ip": "139.138.227.130",
                                                "name": "Excluded public host",
                                                "tags": ["exclude"],
                                            }
                                        ],
                                    )
                                ],
                            )
                        ],
                        private_ranges=[
                            _network_range(
                                "10.10.0.0",
                                "/16",
                                [
                                    _subnet(
                                        "vl56-workstation",
                                        56,
                                        "10.10.56.0",
                                        "/24",
                                        ["vlan-workstation"],
                                    )
                                ],
                                tags=["EXCLUDE"],
                            ),
                            _network_range(
                                "10.10.101.0",
                                "/24",
                                [
                                    _subnet(
                                        "vl101-mocap",
                                        101,
                                        "10.10.101.0",
                                        "/24",
                                        ["exclude"],
                                        ip_addresses=[
                                            {
                                                "ip": "10.10.101.25",
                                                "name": "Excluded host",
                                                "tags": ["exclude"],
                                            }
                                        ],
                                    )
                                ],
                            ),
                        ],
                )
            ]
        )

        targets = {
            (target.target_type, target.cidr): target
            for target in result.coverage_targets
        }

        self.assertIn(("PUBLIC", "139.138.227.128/26"), targets)
        self.assertIn(("IP_ADDRESS", "139.138.227.130/32"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "10.10.0.0/16"), targets)
        self.assertEqual(targets[("VLAN", "10.10.56.0/24")].tags, ["vlan-workstation"])
        self.assertIn(("VLAN", "10.10.101.0/24"), targets)
        self.assertIn(("IP_ADDRESS", "10.10.101.25/32"), targets)
        excluded_targets = (
            ("PUBLIC", "139.138.227.128/26"),
            ("IP_ADDRESS", "139.138.227.130/32"),
            ("PRIVATE_SUPERNET", "10.10.0.0/16"),
            ("VLAN", "10.10.101.0/24"),
            ("IP_ADDRESS", "10.10.101.25/32"),
        )
        for key in excluded_targets:
            self.assertIn(
                "exclude",
                [tag.lower() for tag in targets[key].tags],
            )

    def test_subnet_as_code_site_definition_json_is_normalized(self):
        payload = [
            {
                    "site_code": "ABCNYC",
                    "site_name": "Company New York",
                    "site_type": "Studio",
                    "email_domain": "@Company.com",
                    "everyone_at": "EveryoneCompanysNYC@Company.com",
                    "vcenter_endpoint": "companyadcvcn4.company.example.corp",
                    "content_library": "abcADC-ContentLibrary",
                    "timezone": "EST",
                    "utc_offset": -5,
                    "grid_code": "nyc",
                    "public_ranges": [
                        {
                            "supernet": {
                                "network": "139.138.231.0",
                                "cidr": "/27",
                            },
                            "subnets": [
                                {
                                    "vlan_name": "vl300-InternetDIA",
                                    "display_name": "Direct Internet Access",
                                    "vlan": 300,
                                    "network": "139.138.231.0",
                                    "subnet_mask": "255.255.255.224",
                                    "cidr": "/27",
                                    "gateway": "139.138.231.1",
                                    "routing": "edge",
                                    "tags": ["internet"],
                                }
                            ],
                        }
                    ],
                    "private_ranges": [
                        {
                            "supernet": {
                                "network": "10.1.0.0",
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
                                    "network": "10.1.16.0",
                                    "subnet_mask": "255.255.255.0",
                                    "cidr": "/24",
                                    "gateway": "10.1.16.1",
                                    "routing": "core",
                                    "dhcp-start": "10.1.16.130",
                                    "dhcp-end": "10.1.16.150",
                                    "tags": ["dhcp-dmc", "vlan-server"],
                                    "ip_addresses": [
                                        {
                                            "ip": "10.1.16.200",
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

        result = load_json_payload(payload)

        self.assertEqual(result.files_failed, 0)
        site = result.site_definitions[0]
        self.assertEqual(site.site_type, "Studio")
        self.assertEqual(site.utc_offset, "-5")
        self.assertEqual(site.email_domain, "@Company.com")
        self.assertEqual(site.everyone_at, "EveryoneCompanysNYC@Company.com")
        self.assertEqual(site.vcenter_endpoint, "companyadcvcn4.company.example.corp")
        self.assertEqual(site.content_library, "abcADC-ContentLibrary")
        self.assertEqual(site.grid_code, "nyc")
        self.assertEqual(site.public_ranges[0].cidr, "139.138.231.0/27")
        self.assertEqual(
            site.public_ranges[0].subnets[0].display_name,
            "Direct Internet Access",
        )
        self.assertEqual(site.private_ranges[0].cidr, "10.1.0.0/16")
        self.assertEqual(
            site.private_ranges[0].dhcp_options["domain-name"],
            "Company.example.corp",
        )

        vlan = site.private_ranges[0].vlans[0]
        self.assertEqual(vlan.vlan_name, "vl16-it-services-static")
        self.assertEqual(vlan.vlan, 16)
        self.assertEqual(vlan.routing, "core")
        self.assertEqual(vlan.gateway, "10.1.16.1")
        self.assertEqual(vlan.dhcp_start, "10.1.16.130")
        self.assertEqual(vlan.dhcp_end, "10.1.16.150")
        self.assertEqual(vlan.ip_addresses[0].ip, "10.1.16.200")

        targets = {
            (target.target_type, target.cidr): target
            for target in result.coverage_targets
        }
        self.assertIn(("PUBLIC", "139.138.231.0/27"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "10.1.0.0/16"), targets)
        self.assertIn(("VLAN", "10.1.16.0/24"), targets)
        self.assertEqual(targets[("PUBLIC", "139.138.231.0/27")].tags, ["internet"])
        self.assertEqual(
            targets[("VLAN", "10.1.16.0/24")].tags,
            ["dhcp-dmc", "vlan-server"],
        )

    def test_invalid_vlan_is_reported_and_not_flattened(self):
        result = load_json_payload(
            [
                _site(
                        "BOS01",
                        private_ranges=[
                            _network_range(
                                "10.24.0.0",
                                "/16",
                                [
                                    _subnet(
                                        "vl100-outside",
                                        100,
                                        "10.20.100.0",
                                        "/24",
                                    )
                                ],
                            )
                        ],
                )
            ]
        )

        self.assertTrue(
            any(
                "outside parent range" in issue.message
                for issue in result.validation_issues
            )
        )
        self.assertFalse(
            any(target.target_type == "VLAN" for target in result.coverage_targets)
        )

    def test_duplicate_and_unexpected_overlap_are_reported(self):
        result = load_json_payload(
            [
                _site(
                        "ONE",
                        public_ranges=[
                            _network_range(
                                "192.0.2.0",
                                "/25",
                                [
                                    _subnet(
                                        "vl100-one",
                                        100,
                                        "192.0.2.0",
                                        "/25",
                                    )
                                ],
                            )
                        ],
                    ),
                _site(
                        "TWO",
                        public_ranges=[
                            _network_range(
                                "192.0.2.0",
                                "/25",
                                [
                                    _subnet(
                                        "vl200-two",
                                        200,
                                        "192.0.2.0",
                                        "/25",
                                    ),
                                    _subnet(
                                        "vl201-overlap",
                                        201,
                                        "192.0.2.64",
                                        "/26",
                                    ),
                                ],
                            )
                        ],
                ),
            ]
        )

        messages = [issue.message for issue in result.validation_issues]
        self.assertTrue(any("Duplicate authoritative range" in m for m in messages))
        self.assertTrue(any("Overlapping authoritative ranges" in m for m in messages))

    def test_ipv6_is_rejected_during_definition_validation(self):
        result = load_json_payload(
            [
                _site(
                        "V6",
                        public_ranges=[
                            _network_range(
                                "2001:db8::",
                                "/64",
                                [
                                    _subnet(
                                        "vl6-internet",
                                        6,
                                        "2001:db8::",
                                        "/64",
                                    )
                                ],
                            )
                        ],
                )
            ]
        )

        self.assertEqual(result.coverage_targets, [])
        self.assertTrue(
            any("uses IPv6" in issue.message for issue in result.validation_issues)
        )


if __name__ == "__main__":
    unittest.main()
