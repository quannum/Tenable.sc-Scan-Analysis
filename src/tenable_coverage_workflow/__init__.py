"""Tenable.sc coverage detection, planning, audit, and change application."""

from .models import (
    CoverageTarget,
    CoverageValidationResult,
    NetworkRange,
    PrivateNetworkRange,
    ProposedChange,
    SiteNetworkDefinition,
    SourceLoadResult,
    ValidationIssue,
    VlanRange,
    YamlConnectorResult,
)
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
    "SourceLoadResult",
    "ValidationIssue",
    "VlanRange",
    "YamlConnectorResult",
    "run_detect_and_plan",
]


def __getattr__(name: str):
    if name in {"DetectAndPlanConfig", "run_detect_and_plan"}:
        from .run_detect_and_plan import DetectAndPlanConfig, run_detect_and_plan

        values = {
            "DetectAndPlanConfig": DetectAndPlanConfig,
            "run_detect_and_plan": run_detect_and_plan,
        }
        return values[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
