from dataclasses import dataclass, field


@dataclass(frozen=True)
class NetworkRange:
    name: str | None
    description: str | None
    cidr: str
    network: str
    prefix_length: int
    subnetmask: str | None


@dataclass(frozen=True)
class VlanRange:
    name: str
    vlan_tag: str | int | None
    description: str | None
    cidr: str
    network: str
    prefix_length: int
    subnetmask: str | None


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
    public_ranges: list[NetworkRange] = field(default_factory=list)
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


@dataclass(frozen=True)
class ValidationIssue:
    source_file: str
    message: str
    site_code: str | None = None
    field_name: str | None = None
    severity: str = "ERROR"


@dataclass
class YamlConnectorResult:
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
