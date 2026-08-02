# Authoritative Network Schema

Production input is the subnet-as-code API JSON, obtained by calling the
internal `subnet_as_code.get_sites` Python method with query parameters such as
`names`, `sites`, `tags`, `referenceId`, `networkType`, and `routingType`.
The workflow normalizes the returned Python/JSON payload into the internal site
model before analysis.

`get_sites` always returns a JSON list of one or more site objects. The parser
accepts only this shape and the exact field names shown below. Optional fields
may be `null` or omitted.

The real subnet-as-code API response shape for this project is:

```json
[{"content_library": "abcADC-ContentLibrary",
  "email_domain": "@Company.com",
  "everyone_at": "EveryoneCompanysNYC@Company.com",
  "grid_code": "nyc",
  "private_ranges": [{"dhcp-options": {"dns": ["192.168.16.100", "10.70.0.200"],
									   "domain-name": "Company.example.corp"},
					  "site_code": None,
					  "subnets": [{"cidr": "/24",
								   "dhcp-end": "192.168.16.150",
								   "dhcp-start": "192.168.16.130",
								   "display_name": "It Services Static",
								   "gateway": "192.168.16.1",
								   "ip_addresses": None,
								   "network": "192.168.16.0",
								   "routing": "core",
								   "site_code": "abcnyc",
								   "subnet_mask": "255.255.255.0",
								   "tags": ["dhcp-dmc", "vlan-server"],
								   "vlan": 16,
								   "vlan_name": "vl30-management"},
								   {"cidr": "/24",
								   "dhcp-end": "192.168.30.100",
								   "dhcp-start": "192.168.30.20",
								   "display_name": "Management",
								   "gateway": "192.168.30.1",
								   "ip_addresses": None,
								   "network": "192.168.30.0",
								   "routing": "firewall",
								   "site_code": "abcnyc",
								   "subnet_mask": "255.255.255.0",
								   "tags": ["dhcp-dmc", "vlan-mgmt"],
								   "vlan": 30,
								   "vlan_name": "vl30-management"},
								   {"cidr": "/21",
								   "dhcp-end": "192.168.63.250",
								   "dhcp-start": "192.168.56.5",
								   "display_name": "Workstations 5th Floor",
								   "gateway": "192.168.56.1",
								   "ip_addresses": [{"ip": "192.168.57.130",
													 "name": "nycw-flast",
													 "site_code": "abcnyc",
													 "tags": ["livestream"]}],
								   "network": "192.168.56.0",
								   "routing": "core",
								   "site_code": "abcnyc",
								   "subnet_mask": "255.255.248.0",
								   "tags": ["dhcp-dmc", "vlan-workstation"],
								   "vlan": 56,
								   "vlan_name": "vl56-workstation-5th-floor"}],
					  "supernet": {"cidr": "/16",
								   "network": "192.168.0.0",
								   "site_code": None}}],
  "public_ranges": [{ "dhcp-options": None,
					  "site_code": None,
					            "subnets": [{"cidr": "/27",
											 "dhcp-end": None,
											 "dhcp-start": None,
											 "display_name": "Direct Internet Access",
											 "gateway": "187.138.231.1",
											 "ip_addresses": [{"ip": "187.1.1.1",
															   "name": None,
															   "site_code": "abcnyc",
															   "tags": ["trusted-pat"]}],
											 "network": "187.138.231.0",
											 "routing": "edge",
											 "site_code": "abcnyc",
											 "subnet_mask": "255.255.255.224",
											 "tags": ["internet"],
											 "vlan": 300,
											 "vlan_name": "vl300-InternetDIA"}],
							    "supernet": {"cidr": "/27",
											 "network": "187.138.231.0",
											 "site_code": "abcnyc"}}],
  "site_code": "abcnyc",
  "site_name": "Company New York",
  "site_type": "Studio",
  "tags": None,
  "timezone": "EST",
  "utc_offset": "-5",
  "vcenter_endpoint": "companyadcvcn4.company.example.corp",}]
```

NOTE: Do not use any values in the example above to replace actual data in the project/code. The example above is also not exhaustive. It is expected that sites will contain more values, more subnets, more VLANs, etc. The above is simply a snippet of the expected API response to show the structure and schema.

Normalization rules:

- public subnet entries become `PUBLIC` coverage targets;
- private `supernet` entries become `PRIVATE_SUPERNET` targets;
- private `subnets` become `VLAN` targets;
- tags remain attached only to the item where they appear; they are not
  inherited by nested coverage targets;
- extra source fields such as `email_domain`, `grid_code`, DHCP options, and
  explicit IP-address records are preserved in source metadata on the normalized
  site/range objects.

Validation rules:

- `site_code` is required;
- every range must provide a non-empty `subnets` list;
- network syntax must be valid IPv4 CIDR;
- subnet entries must have `vlan_name`;
- VLAN CIDRs must stay within their parent private supernet;
- duplicate and unexpected overlapping authoritative ranges are reported;
- public/private label mismatches produce warnings;
- IPv6 is rejected during definition validation.

Naming defaults still derive expected asset, scan, and policy names from site,
region, target type, VLAN name, and VLAN ID unless an upstream source provides
explicit required names.

Tags:

- Tags can be within any nested group and apply only to that group
- Tags that begin with "vlan-" are used to group subnets
- Current tags and their descriptions include:
  - "dhcp-dmc" - "DHCP: Domain Controller managed"
  - "dhcp-firewall" - "DHCP: Firewall managed"
  - "vlan-av" - "VLAN: Audio Visual"
  - "vlan-environment" - "VLAN: Environment (CCTV/doors/lighting/etc)"
  - "vlan-other" - "VLAN: Miscellaneous"
  - "vlan-mgmt" - "VLAN: Management"
  - "vlan-server" - "VLAN: Servers"
  - "vlan-storage" - "VLAN: Storage"
  - "vlan-wireless" - "VLAN: Wireless"
  - "internet" - "Public Internet"
  - "trusted-pat" - "Trusted PAT"
  - "global-protect-trusted" - "Global Protect Trusted IP"
  - "global-protect-untrusted" - "Global Protect Untrusted IP"
  - "livestream" - "Livestream IPs"
- This list is not exhaustive and it should be expected new tags will be added in the future
