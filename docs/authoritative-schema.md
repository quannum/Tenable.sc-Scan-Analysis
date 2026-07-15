# Authoritative Network Schema

Production input is the subnet-as-code API JSON, obtained by calling the
internal `subnet_as_code.get_sites` Python method with query parameters such as
`sites`, `tags`, `referenceId`, `networkType`, and `routingType`.
The workflow normalizes the returned Python/JSON payload into the internal site
model before analysis.

The loader accepts:

- one site object;
- a list of site objects;
- an object whose `site_definition`, `sites`, `locations`, `data`, or `items`
  property contains the site list.

The real subnet-as-code storage shape supplied for this project is:

```json
{
  "site_definition": [
    {
      "site_code": "abcnyc",
      "site_name": "Company New York",
      "site_type": "Studio",
      "email_domain": "@Company.com",
      "everyone_at": "EveryoneCompanysNYC@Company.com",
      "vcenter_endpoint": "companyadcvcn4.company.example.corp",
      "content_library": "abcADC-ContentLibrary",
      "timezone": "EST",
      "utc_offset": "-5",
      "grid_code": "nyc",
      "public_ranges": [
        {
          "supernet": {
            "network": "187.127.231.0",
            "cidr": "/27"
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
              "tags": ["internet"]
            }
          ]
        }
      ],
      "private_ranges": [
        {
          "supernet": {
            "network": "192.168.0.0",
            "cidr": "/16"
          },
          "dhcp-options": {
            "domain-name": "Company.example.corp",
            "dns": ["192.168.16.100", "10.70.0.200"]
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
              "tags": ["dhcp-dmc", "vlan-server"]
            }
          ]
        }
      ]
    }
  ]
}
```

The JSON normalizer also accepts already-normalized variants such as direct
CIDRs, explicit `start-end` IPv4 ranges, or simple `{network, cidr}` objects.
This keeps subnet-as-code payload variants source-neutral once normalized.

Normalization rules:

- public subnet entries become `PUBLIC` coverage targets;
- private `supernet` entries become `PRIVATE_SUPERNET` targets;
- private `subnets`/`vlans` become `VLAN` targets;
- subnet tags are preserved and merged with site tags on coverage targets;
- extra source fields such as `email_domain`, `grid_code`, DHCP options, and
  explicit IP-address records are preserved in source metadata on the normalized
  site/range objects.

Validation rules:

- `site_code` is required;
- network syntax must be valid IPv4 CIDR or IPv4 start-end range;
- VLAN entries must have a name;
- VLAN CIDRs must stay within their parent private supernet;
- duplicate and unexpected overlapping authoritative ranges are reported;
- public/private label mismatches produce warnings;
- IPv6 is rejected during definition validation.

Naming defaults still derive expected asset, scan, and policy names from site,
region, target type, VLAN name, and VLAN ID unless an upstream source provides
explicit required names.
