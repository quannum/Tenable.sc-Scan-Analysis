import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .models import GroupingConfig, OsAssetClassification
from .os_asset_config import build_os_asset_classifications_from_settings
from .settings import (
    SettingsResolver,
    as_path,
    load_config_section,
    optional_string,
    parse_bool,
    parse_positive_int,
)
from .subnet_source.source_config import (
    add_authoritative_source_arguments,
    build_authoritative_source_config,
)
from .subnet_source.source_loader import AuthoritativeSourceConfig
from .workflow_settings import (
    build_grouping_config_from_settings,
    build_scan_filter_config,
    build_tenable_access_config,
)


@dataclass(frozen=True)
class ScheduledServiceConfig:
    job_name: str
    source_config: AuthoritativeSourceConfig
    output_dir: Path
    run_id_prefix: str
    latest_summary_file: Path
    lock_file: Path
    stale_lock_timeout_seconds: int
    dry_run: bool
    mode: str
    scan_json_dir: str | None
    asset_json_dir: str | None
    sc_access_key: str | None
    sc_secret_key: str | None
    sc_url: str | None
    include_keywords: list[str]
    exclude_keywords: list[str]
    match_all_include: bool
    case_sensitive: bool
    filter_disabled_mode: str
    log_level: str
    log_format: str
    log_file: Path | None = None
    config_file: Path | None = None
    sc_timeout_seconds: int = 60
    sc_retries: int = 3
    sc_backoff_seconds: float = 1.5
    sc_ssl_verify: bool = True
    grouping_config: GroupingConfig = field(default_factory=GroupingConfig)
    os_asset_classifications: tuple[OsAssetClassification, ...] = field(
        default_factory=tuple
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Build argument parser"""
    parser = argparse.ArgumentParser(
        description=(
            "Scheduler-friendly wrapper for the Tenable coverage detect-and-plan "
            "workflow"
        )
    )
    parser.add_argument("--config-file")
    parser.add_argument("--job-name")
    add_authoritative_source_arguments(parser)
    parser.add_argument("--output-dir")
    parser.add_argument("--run-id-prefix")
    parser.add_argument("--latest-summary-file")
    parser.add_argument("--lock-file")
    parser.add_argument("--stale-lock-timeout-seconds")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=None)
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--mode", choices=["offline", "live"])
    parser.add_argument("--scan-json-dir")
    parser.add_argument("--asset-json-dir")
    parser.add_argument("--include-keywords")
    parser.add_argument("--exclude-keywords")
    parser.add_argument("--match-all-include", action="store_true", default=None)
    parser.add_argument("--case-sensitive", action="store_true", default=None)
    parser.add_argument(
        "--filter-disabled-mode",
        choices=["ALL", "ENABLED_ONLY", "DISABLED_ONLY"],
    )
    parser.add_argument("--log-level")
    parser.add_argument("--log-format", choices=["text", "json"])
    parser.add_argument("--log-file")
    parser.add_argument("--sc-url")
    parser.add_argument("--sc-access-key")
    parser.add_argument("--sc-secret-key")
    parser.add_argument("--sc-timeout-seconds")
    parser.add_argument("--sc-retries")
    parser.add_argument("--sc-backoff-seconds")
    parser.add_argument("--grouping-mode", choices=["default", "vlan_tag"])
    parser.add_argument("--grouping-vlan-tag-prefix")
    parser.add_argument("--grouping-tag-map")
    parser.add_argument("--os-asset-classifications")
    parser.add_argument(
        "--no-sc-ssl-verify",
        dest="sc_ssl_verify",
        action="store_false",
        default=None,
    )
    return parser


def build_service_config(argv=None) -> ScheduledServiceConfig:
    load_dotenv()
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    config_file = as_path(args.config_file)
    try:
        config_data = load_config_file(config_file) if config_file else {}
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        parser.error(str(exc))

    resolver = SettingsResolver(
        args,
        config_data,
        legacy_env_names={
            "sc_access_key": ("SC_ACCESS_KEY",),
            "sc_secret_key": ("SC_SECRET_KEY",),
            "sc_url": ("SC_URL",),
        },
    )
    pick = resolver.get

    try:
        dry_run = parse_bool(pick("dry_run", True), "dry_run")
        stale_lock_timeout_seconds = parse_positive_int(
            pick("stale_lock_timeout_seconds", 21600),
            "stale_lock_timeout_seconds",
        )
    except ValueError as exc:
        parser.error(str(exc))

    if not dry_run:
        parser.error("Scheduled detect-and-plan runs do not support dry_run=false")

    def scalar_getter(
        name: str, environment_name: str | None, default: Any = None
    ) -> Any:
        """Read one scalar setting"""
        return pick(name, default, environment_name)

    def csv_getter(
        name: str, environment_name: str | None, default: Any = None
    ) -> list[str] | None:
        """Read one comma-separated setting"""
        return resolver.csv(name, default, environment_name)

    source_config = build_authoritative_source_config(
        scalar_getter=scalar_getter,
        csv_getter=csv_getter,
    )
    try:
        tenable = build_tenable_access_config(
            scalar_getter,
            optional_string=optional_string,
        )
        scan_filter = build_scan_filter_config(scalar_getter, csv_getter)
        grouping_config = build_grouping_config_from_settings(scalar_getter)
        os_asset_classifications = build_os_asset_classifications_from_settings(
            scalar_getter
        )
    except ValueError as exc:
        parser.error(str(exc))

    job_name = str(pick("job_name", "tenable-coverage-scheduled")).strip()
    output_dir = as_path(pick("output_dir")) or Path("output")
    run_id_prefix = str(
        pick("run_id_prefix", f"{normalize_job_name(job_name)}-")
    ).strip()
    latest_summary_file = as_path(pick("latest_summary_file")) or (
        output_dir / "latest_run.json"
    )
    lock_file = as_path(pick("lock_file")) or (output_dir / "scheduler.lock")

    log_format = str(pick("log_format", "text")).lower()
    if log_format not in {"text", "json"}:
        parser.error("--log-format must be 'text' or 'json'")
    log_file = as_path(pick("log_file"))
    if tenable.mode == "live":
        missing = []
        if not tenable.sc_url:
            missing.append("TCW_SC_URL/SC_URL")
        if not tenable.sc_access_key:
            missing.append("TCW_SC_ACCESS_KEY/SC_ACCESS_KEY")
        if not tenable.sc_secret_key:
            missing.append("TCW_SC_SECRET_KEY/SC_SECRET_KEY")
        if missing:
            parser.error("Live scheduled runs require: " + ", ".join(missing))

    return ScheduledServiceConfig(
        job_name=job_name,
        source_config=source_config,
        output_dir=output_dir,
        run_id_prefix=run_id_prefix,
        latest_summary_file=latest_summary_file,
        lock_file=lock_file,
        stale_lock_timeout_seconds=stale_lock_timeout_seconds,
        dry_run=dry_run,
        mode=tenable.mode,
        scan_json_dir=tenable.scan_json_dir,
        asset_json_dir=tenable.asset_json_dir,
        sc_access_key=tenable.sc_access_key,
        sc_secret_key=tenable.sc_secret_key,
        sc_url=tenable.sc_url,
        include_keywords=scan_filter.include_keywords,
        exclude_keywords=scan_filter.exclude_keywords,
        match_all_include=scan_filter.match_all_include,
        case_sensitive=scan_filter.case_sensitive,
        filter_disabled_mode=scan_filter.filter_disabled_mode,
        log_level=str(pick("log_level", "INFO")),
        log_format=log_format,
        log_file=log_file,
        config_file=config_file,
        sc_timeout_seconds=tenable.sc_timeout_seconds,
        sc_retries=tenable.sc_retries,
        sc_backoff_seconds=tenable.sc_backoff_seconds,
        sc_ssl_verify=tenable.sc_ssl_verify,
        grouping_config=grouping_config,
        os_asset_classifications=os_asset_classifications,
    )


def load_config_file(config_file_path: Path) -> dict[str, Any]:
    return load_config_section(
        config_file_path,
        section_name="tenable_coverage_workflow_service",
        root_error="Config file root must be an object/dictionary",
        section_error=(
            "Config 'tenable_coverage_workflow_service' section must be an "
            "object/dictionary"
        ),
        unsupported_error="Unsupported config file type. Use .yaml, .json, or .toml",
    )


def normalize_job_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "-", str(value).strip().lower())
    normalized = normalized.strip("-")
    return normalized or "tenable-coverage"
