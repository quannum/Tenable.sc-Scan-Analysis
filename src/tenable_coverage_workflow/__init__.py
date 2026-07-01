"""GitOps-style Tenable.sc detect-and-plan workflow.

The package is intentionally split into ingestion, planning, and audit layers so
future approval and mutation modules can be added cleanly:

- approval_reader.py
- apply_approved_changes.py
- tenable_asset_writer.py
- tenable_scan_writer.py
- post_change_validation.py
"""

from .models import (
    CoverageTarget,
    CoverageValidationResult,
    NetworkRange,
    PrivateNetworkRange,
    ProposedChange,
    SiteNetworkDefinition,
    ValidationIssue,
    VlanRange,
    YamlConnectorResult,
)
from .run_detect_and_plan import DetectAndPlanConfig, run_detect_and_plan
from .service_config import ScheduledServiceConfig

__all__ = [
    "CoverageTarget",
    "CoverageValidationResult",
    "DetectAndPlanConfig",
    "NetworkRange",
    "PrivateNetworkRange",
    "ProposedChange",
    "ScheduledServiceConfig",
    "SiteNetworkDefinition",
    "ValidationIssue",
    "VlanRange",
    "YamlConnectorResult",
    "run_detect_and_plan",
]
