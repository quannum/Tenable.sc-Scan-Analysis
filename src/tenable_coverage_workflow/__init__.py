"""Tenable.sc coverage detection, planning, audit, and change application."""

from .models import (
    CoverageTarget,
    CoverageValidationResult,
    IpAddress,
    PrivateNetworkRange,
    ProposedChange,
    PublicNetworkRange,
    SiteNetworkDefinition,
    SourceLoadResult,
    ValidationIssue,
    VlanRange,
)
from .service_config import ScheduledServiceConfig

__all__ = [
    "CoverageTarget",
    "CoverageValidationResult",
    "DetectAndPlanConfig",
    "IpAddress",
    "PrivateNetworkRange",
    "ProposedChange",
    "PublicNetworkRange",
    "ScheduledServiceConfig",
    "SiteNetworkDefinition",
    "SourceLoadResult",
    "ValidationIssue",
    "VlanRange",
    "run_detect_and_plan",
]


def __getattr__(name: str):
    """Load a lazily imported attribute"""
    if name in {"DetectAndPlanConfig", "run_detect_and_plan"}:
        from .run_detect_and_plan import DetectAndPlanConfig, run_detect_and_plan

        values = {
            "DetectAndPlanConfig": DetectAndPlanConfig,
            "run_detect_and_plan": run_detect_and_plan,
        }
        return values[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
