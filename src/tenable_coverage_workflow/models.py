from dataclasses import dataclass, field

VLAN_ASSESSMENT_BUCKETS = frozenset({"WORKSTATION", "SERVER", "NETWORK"})


@dataclass(frozen=True)
class GroupingConfig:
    mode: str = "default"
    vlan_tag_prefix: str = "vlan-"
    tag_map: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class IpAddress:
    ip: str
    name: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VlanRange:
    vlan_name: str
    display_name: str | None
    vlan: int | None
    cidr: str
    gateway: str | None = None
    routing: str | None = None
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    tags: list[str] = field(default_factory=list)
    ip_addresses: list[IpAddress] = field(default_factory=list)


@dataclass(frozen=True)
class PublicNetworkRange:
    cidr: str
    tags: list[str] = field(default_factory=list)
    subnets: list[VlanRange] = field(default_factory=list)


@dataclass(frozen=True)
class PrivateNetworkRange:
    cidr: str
    tags: list[str] = field(default_factory=list)
    dhcp_options: dict[str, object] = field(default_factory=dict)
    vlans: list[VlanRange] = field(default_factory=list)


@dataclass(frozen=True)
class SiteNetworkDefinition:
    source_file: str
    site_code: str
    site_name: str
    site_type: str | None = None
    email_domain: str | None = None
    everyone_at: str | None = None
    vcenter_endpoint: str | None = None
    content_library: str | None = None
    timezone: str | None = None
    utc_offset: str | None = None
    grid_code: str | None = None
    public_ranges: list[PublicNetworkRange] = field(default_factory=list)
    private_ranges: list[PrivateNetworkRange] = field(default_factory=list)


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
