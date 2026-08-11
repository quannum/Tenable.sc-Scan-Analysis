from dataclasses import dataclass
from typing import Any, Callable

from .grouping_config import build_grouping_config
from .models import GroupingConfig
from .settings import parse_bool, parse_nonnegative_float, parse_positive_int

ScalarGetter = Callable[[str, str | None, Any], Any]
CsvGetter = Callable[[str, str | None, Any], list[str] | None]


@dataclass(frozen=True)
class TenableAccessConfig:
    mode: str
    scan_json_dir: str | None
    asset_json_dir: str | None
    sc_url: str | None
    sc_access_key: str | None
    sc_secret_key: str | None
    sc_timeout_seconds: int
    sc_retries: int
    sc_backoff_seconds: float
    sc_ssl_verify: bool


@dataclass(frozen=True)
class ScanFilterConfig:
    include_keywords: list[str]
    exclude_keywords: list[str]
    match_all_include: bool
    case_sensitive: bool
    filter_disabled_mode: str


def build_tenable_access_config(
    scalar_getter: ScalarGetter,
    *,
    optional_string: Callable[[Any], str | None] | None = None,
) -> TenableAccessConfig:
    """Build and validate Tenable.sc connection settings"""
    mode = str(scalar_getter("mode", None, "offline") or "").strip().lower()
    if mode not in {"offline", "live"}:
        raise ValueError("mode must be 'offline' or 'live'.")

    text = optional_string or _identity
    scan_json_dir = text(scalar_getter("scan_json_dir", None, None))
    asset_json_dir = text(scalar_getter("asset_json_dir", None, None))
    if mode == "offline" and (not scan_json_dir or not asset_json_dir):
        raise ValueError("Offline mode requires --scan-json-dir and --asset-json-dir.")

    return TenableAccessConfig(
        mode=mode,
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        sc_url=text(scalar_getter("sc_url", "SC_URL", None)),
        sc_access_key=text(scalar_getter("sc_access_key", "SC_ACCESS_KEY", None)),
        sc_secret_key=text(scalar_getter("sc_secret_key", "SC_SECRET_KEY", None)),
        sc_timeout_seconds=parse_positive_int(
            scalar_getter("sc_timeout_seconds", "SC_TIMEOUT_SECONDS", 60),
            "sc_timeout_seconds",
        ),
        sc_retries=parse_positive_int(
            scalar_getter("sc_retries", "SC_RETRIES", 3),
            "sc_retries",
        ),
        sc_backoff_seconds=parse_nonnegative_float(
            scalar_getter("sc_backoff_seconds", "SC_BACKOFF_SECONDS", 1.5),
            "sc_backoff_seconds",
        ),
        sc_ssl_verify=parse_bool(
            scalar_getter("sc_ssl_verify", "SC_SSL_VERIFY", True),
            "sc_ssl_verify",
        ),
    )


def build_scan_filter_config(
    scalar_getter: ScalarGetter,
    csv_getter: CsvGetter,
) -> ScanFilterConfig:
    """Build and validate shared scan-filter settings"""
    filter_disabled_mode = str(scalar_getter("filter_disabled_mode", None, "ALL"))
    if filter_disabled_mode not in {"ALL", "ENABLED_ONLY", "DISABLED_ONLY"}:
        raise ValueError(
            "filter_disabled_mode must be ALL, ENABLED_ONLY, or DISABLED_ONLY."
        )

    return ScanFilterConfig(
        include_keywords=csv_getter("include_keywords", None, None) or [],
        exclude_keywords=csv_getter("exclude_keywords", None, None) or [],
        match_all_include=parse_bool(
            scalar_getter("match_all_include", None, False),
            "match_all_include",
        ),
        case_sensitive=parse_bool(
            scalar_getter("case_sensitive", None, False),
            "case_sensitive",
        ),
        filter_disabled_mode=filter_disabled_mode,
    )


def build_grouping_config_from_settings(scalar_getter: ScalarGetter) -> GroupingConfig:
    """Build VLAN grouping settings using the shared setting precedence"""
    return build_grouping_config(
        mode_value=scalar_getter("grouping_mode", "GROUPING_MODE", "default"),
        prefix_value=scalar_getter(
            "grouping_vlan_tag_prefix",
            "GROUPING_VLAN_TAG_PREFIX",
            "vlan-",
        ),
        tag_map_value=scalar_getter("grouping_tag_map", "GROUPING_TAG_MAP", None),
    )


def _identity(value: Any) -> Any:
    return value
