import ipaddress
import unittest
from dataclasses import dataclass, field
from unittest.mock import patch

from src.tenable_coverage_workflow.models import NetworkRange, VlanRange
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
                return {
                    "site_definition": [
                        _site(
                            "API01",
                            private_ranges=[_network_range("10.9.0.0", "/24", [])],
                            site_name="Module Site",
                        )
                    ]
                }

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
                return {
                    "site_definition": [
                        _site(
                            "ALL01",
                            private_ranges=[_network_range("10.42.0.0", "/24", [])],
                            site_name="All Sites Example",
                        )
                    ]
                }

        with patch(
            "src.tenable_coverage_workflow.subnet_source.source_loader."
            "importlib.import_module",
            return_value=Module,
        ):
            source_type, result = load_authoritative_source(AuthoritativeSourceConfig())

        self.assertEqual(source_type, "rsg_subnet_as_code")
        self.assertEqual(calls[0], {})
        self.assertEqual(result.site_definitions[0].site_code, "ALL01")

    def test_object_records_and_sites_wrapper_create_coverage_targets(self):
        @dataclass(frozen=True)
        class SiteRecord:
            site_code: str
            site_name: str
            private_ranges: list[NetworkRange] = field(default_factory=list)
            public_ranges: list[NetworkRange] = field(default_factory=list)

        payload = {
            "sites": [
                SiteRecord(
                    site_code="OBJ01",
                    site_name="Object Site",
                    private_ranges=[
                        NetworkRange(
                            cidr="10.80.0.0/16",
                            vlans=[
                                VlanRange(
                                    vlan_name="Servers",
                                    display_name="Servers",
                                    vlan=120,
                                    cidr="10.80.16.0/24",
                                )
                            ],
                        )
                    ],
                )
            ]
        }

        result = load_json_payload(payload)

        self.assertEqual(result.files_failed, 0)
        targets = {
            (target.target_type, target.cidr) for target in result.coverage_targets
        }
        self.assertIn(("PRIVATE_SUPERNET", "10.80.0.0/16"), targets)
        self.assertIn(("VLAN", "10.80.16.0/24"), targets)

    def test_stable_payload_flattens_public_private_and_vlan_scope(self):
        payload = {
            "site_definition": [
                _site(
                    "NYC01",
                    public_ranges=[
                        _network_range(
                            "203.0.113.0",
                            "/29",
                            [
                                _subnet(
                                    "vl300-internet",
                                    300,
                                    "203.0.113.0",
                                    "/29",
                                    ["internet"],
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
                                    "vl120-servers",
                                    120,
                                    "10.10.16.0",
                                    "/24",
                                    ["vlan-server"],
                                )
                            ],
                        )
                    ],
                    timezone="America/New_York",
                )
            ]
        }

        result = load_json_payload(payload)

        self.assertEqual(result.files_failed, 0)
        self.assertEqual(len(result.site_definitions), 1)
        site = result.site_definitions[0]
        self.assertEqual(site.timezone, "America/New_York")
        targets = {
            (target.target_type, target.cidr) for target in result.coverage_targets
        }
        self.assertIn(("PUBLIC", "203.0.113.0/29"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "10.10.0.0/16"), targets)
        self.assertIn(("VLAN", "10.10.16.0/24"), targets)

    def test_exclude_tags_are_preserved_for_ranges_vlans_and_individual_ips(self):
        result = load_json_payload(
            {
                "site_definition": [
                    _site(
                        "EXC01",
                        public_ranges=[
                            _network_range(
                                "203.0.113.0",
                                "/24",
                                [
                                    _subnet(
                                        "vl300-internet",
                                        300,
                                        "203.0.113.0",
                                        "/24",
                                        ["exclude"],
                                        ip_addresses=[
                                            {
                                                "ip": "203.0.113.9",
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
                                "10.50.0.0",
                                "/24",
                                [],
                                tags=["EXCLUDE"],
                            ),
                            _network_range(
                                "10.51.0.0",
                                "/24",
                                [
                                    _subnet(
                                        "vl50-restricted",
                                        50,
                                        "10.51.0.0",
                                        "/24",
                                        ["exclude"],
                                        ip_addresses=[
                                            {
                                                "ip": "10.51.0.25",
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
            }
        )

        targets = {
            (target.target_type, target.cidr): target
            for target in result.coverage_targets
        }

        self.assertIn(("PUBLIC", "203.0.113.0/24"), targets)
        self.assertIn(("IP_ADDRESS", "203.0.113.9/32"), targets)
        self.assertIn(("PRIVATE_SUPERNET", "10.50.0.0/24"), targets)
        self.assertIn(("VLAN", "10.51.0.0/24"), targets)
        self.assertIn(("IP_ADDRESS", "10.51.0.25/32"), targets)
        excluded_targets = (
            ("PUBLIC", "203.0.113.0/24"),
            ("IP_ADDRESS", "203.0.113.9/32"),
            ("PRIVATE_SUPERNET", "10.50.0.0/24"),
            ("VLAN", "10.51.0.0/24"),
            ("IP_ADDRESS", "10.51.0.25/32"),
        )
        for key in excluded_targets:
            self.assertIn(
                "exclude",
                [tag.lower() for tag in targets[key].tags],
            )

    def test_subnet_as_code_site_definition_json_is_normalized(self):
        payload = {
            "site_definition": [
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
        self.assertEqual(site.email_domain, "@Company.com")
        self.assertEqual(site.everyone_at, "EveryoneCompanysNYC@Company.com")
        self.assertEqual(site.vcenter_endpoint, "companyadcvcn4.company.example.corp")
        self.assertEqual(site.content_library, "abcADC-ContentLibrary")
        self.assertEqual(site.grid_code, "nyc")
        self.assertEqual(site.public_ranges[0].cidr, "187.127.231.0/27")
        self.assertEqual(
            site.public_ranges[0].subnets[0].display_name,
            "Direct Internet Access",
        )
        self.assertEqual(site.private_ranges[0].cidr, "192.168.0.0/16")
        self.assertEqual(
            site.private_ranges[0].dhcp_options["domain-name"],
            "Company.example.corp",
        )

        vlan = site.private_ranges[0].vlans[0]
        self.assertEqual(vlan.vlan_name, "vl16-it-services-static")
        self.assertEqual(vlan.vlan, 16)
        self.assertEqual(vlan.routing, "core")
        self.assertEqual(vlan.gateway, "192.168.16.1")
        self.assertEqual(vlan.dhcp_start, "192.168.16.130")
        self.assertEqual(vlan.dhcp_end, "192.168.16.150")
        self.assertEqual(vlan.ip_addresses[0].ip, "192.168.16.200")

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
                "site_definition": [
                    _site(
                        "BOS01",
                        private_ranges=[
                            _network_range(
                                "10.20.0.0",
                                "/16",
                                [
                                    _subnet(
                                        "vl100-outside",
                                        100,
                                        "10.30.0.0",
                                        "/24",
                                    )
                                ],
                            )
                        ],
                    )
                ]
            }
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
            {
                "site_definition": [
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
            }
        )

        messages = [issue.message for issue in result.validation_issues]
        self.assertTrue(any("Duplicate authoritative range" in m for m in messages))
        self.assertTrue(any("Overlapping authoritative ranges" in m for m in messages))

    def test_ipv6_is_rejected_during_definition_validation(self):
        result = load_json_payload(
            {
                "site_definition": [
                    _site(
                        "V6",
                        public_ranges=[
                            _network_range(
                                "2001:db8::",
                                "/64",
                                [],
                            )
                        ],
                    )
                ]
            }
        )

        self.assertEqual(result.coverage_targets, [])
        self.assertTrue(
            any("uses IPv6" in issue.message for issue in result.validation_issues)
        )


if __name__ == "__main__":
    unittest.main()
