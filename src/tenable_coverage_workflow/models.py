from dataclasses import dataclass, field


@dataclass(frozen=True)
class GroupingConfig:
    mode: str = "default"
    vlan_tag_prefix: str = "vlan-"
    tag_map: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkRange:
    name: str | None
    description: str | None
    cidr: str
    network: str
    prefix_length: int
    subnetmask: str | None
    tags: list[str] = field(default_factory=list)
    source_metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class VlanRange:
    name: str
    vlan_tag: str | int | None
    description: str | None
    cidr: str
    network: str
    prefix_length: int
    subnetmask: str | None
    tags: list[str] = field(default_factory=list)
    routing: str | None = None
    gateway: str | None = None
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    ip_addresses: list[dict[str, object]] = field(default_factory=list)
    source_metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PrivateNetworkRange(NetworkRange):
    vlans: list[VlanRange] = field(default_factory=list)


@dataclass(frozen=True)
class SiteNetworkDefinition:
    source_file: str
    site_name: str
    site_code: str
    description: str | None
    location: str | None
    region: str | None
    timezone: str | None = None
    site_type: str | None = None
    utc_offset: str | None = None
    tags: list[str] = field(default_factory=list)
    environment: str | None = None
    business_function: str | None = None
    scan_classification: dict[str, object] = field(default_factory=dict)
    public_ranges: list[NetworkRange] = field(default_factory=list)
    private_ranges: list[PrivateNetworkRange] = field(default_factory=list)
    source_metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CoverageTarget:
    target_type: str
    cidr: str
    site_code: str
    site_name: str | None
    location: str | None
    region: str | None
    description: str | None
    vlan_name: str | None = None
    vlan_tag: str | int | None = None
    source_file: str | None = None
    required_asset_name: str | None = None
    required_scan_name: str | None = None
    required_policy_name: str | None = None
    timezone: str | None = None
    tags: list[str] = field(default_factory=list)
    environment: str | None = None
    business_function: str | None = None
    scan_classification: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationIssue:
    source_file: str
    message: str
    site_code: str | None = None
    field_name: str | None = None
    severity: str = "ERROR"


@dataclass
class SourceLoadResult:
    site_definitions: list[SiteNetworkDefinition] = field(default_factory=list)
    coverage_targets: list[CoverageTarget] = field(default_factory=list)
    validation_issues: list[ValidationIssue] = field(default_factory=list)
    files_processed: int = 0
    files_failed: int = 0


# Historical compatibility alias from when authoritative inputs were YAML-centric.
YamlConnectorResult = SourceLoadResult


@dataclass(frozen=True)
class CoverageValidationResult:
    status: str
    target_type: str
    cidr: str
    site_code: str
    site_name: str | None
    region: str | None
    location: str | None
    description: str | None
    vlan_name: str | None
    vlan_tag: str | int | None
    covering_scans: list[str]
    reason: str
    source_file: str | None
    required_asset_name: str | None
    required_scan_name: str | None
    required_policy_name: str | None
    required_scan_covered: str = ""
    expected_size: int = 0
    covered_count: int = 0
    gap_count: int = 0
    exclusion_ip_total: int = 0
    coverage_pct: float = 0.0
    required_asset_present: str = ""
    required_scan_present: str = ""
    configured_repository: str | None = None
    configured_policy: str | None = None
    required_policy_configured: str = ""
    timezone: str | None = None
    tags: list[str] = field(default_factory=list)
    excluded_by_tag: bool = False
    exclusion_tag: str | None = None
    environment: str | None = None
    business_function: str | None = None
    scan_classification: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ProposedChange:
    run_id: str
    site_code: str
    site_name: str | None
    target_type: str
    cidr: str
    vlan_name: str | None
    vlan_tag: str | int | None
    current_status: str
    issue: str
    proposed_action: str
    proposed_asset_name: str | None
    proposed_scan_name: str | None
    proposed_policy_name: str | None
    approval_status: str
    reviewer: str | None
    decision_notes: str | None
    source_file: str | None
    grouping_tag: str | None = None
