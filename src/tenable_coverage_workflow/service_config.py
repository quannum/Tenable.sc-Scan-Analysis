import argparse
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from ..io.parsing import parse_csv_list
from .grouping_config import build_grouping_config
from .models import GroupingConfig
from .subnet_source.source_config import (
    add_authoritative_source_arguments,
    build_authoritative_source_config,
)
from .subnet_source.source_loader import (
    AuthoritativeSourceConfig,
    AuthoritativeSourceConfigMixin,
    has_configured_authoritative_source,
    validate_authoritative_source_config,
)

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # pyright: ignore[reportMissingImports]


ENV_PREFIX = "TCW_"


@dataclass(frozen=True)
class ScheduledServiceConfig(AuthoritativeSourceConfigMixin):
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


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scheduler-friendly wrapper for the Tenable coverage detect-and-plan "
            "workflow."
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
        "--no-dry-run", dest="dry_run", action="store_false", default=None
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

    config_file = _as_path(args.config_file)
    try:
        config_data = load_config_file(config_file) if config_file else {}
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        parser.error(str(exc))

    def pick(
        name: str,
        default: Any = None,
        environment_name: str | None = None,
    ) -> Any:
        cli_value = getattr(args, name, None)
        if cli_value is not None:
            return cli_value

        env_value = os.getenv(f"{ENV_PREFIX}{name.upper()}")
        if env_value is not None:
            return env_value

        if environment_name and os.getenv(environment_name) is not None:
            return os.getenv(environment_name)

        if name == "sc_access_key" and os.getenv("SC_ACCESS_KEY") is not None:
            return os.getenv("SC_ACCESS_KEY")
        if name == "sc_secret_key" and os.getenv("SC_SECRET_KEY") is not None:
            return os.getenv("SC_SECRET_KEY")
        if name == "sc_url" and os.getenv("SC_URL") is not None:
            return os.getenv("SC_URL")
        return config_data.get(name, default)

    try:
        dry_run = _parse_bool(pick("dry_run", True), "dry_run")
        match_all_include = _parse_bool(
            pick("match_all_include", False), "match_all_include"
        )
        case_sensitive = _parse_bool(pick("case_sensitive", False), "case_sensitive")
        sc_ssl_verify = _parse_bool(pick("sc_ssl_verify", True), "sc_ssl_verify")
        stale_lock_timeout_seconds = _parse_positive_int(
            pick("stale_lock_timeout_seconds", 21600),
            "stale_lock_timeout_seconds",
        )
        sc_timeout_seconds = _parse_positive_int(
            pick("sc_timeout_seconds", 60), "sc_timeout_seconds"
        )
        sc_retries = _parse_positive_int(pick("sc_retries", 3), "sc_retries")
        sc_backoff_seconds = float(pick("sc_backoff_seconds", 1.5))
        if sc_backoff_seconds < 0:
            raise ValueError("sc_backoff_seconds must be >= 0")
    except ValueError as exc:
        parser.error(str(exc))

    mode = str(pick("mode", "offline"))
    if mode not in {"offline", "live"}:
        parser.error("--mode must be 'offline' or 'live'")

    filter_disabled_mode = str(pick("filter_disabled_mode", "ALL"))
    if filter_disabled_mode not in {"ALL", "ENABLED_ONLY", "DISABLED_ONLY"}:
        parser.error(
            "--filter-disabled-mode must be ALL, ENABLED_ONLY, or DISABLED_ONLY"
        )

    def scalar_getter(
        name: str, environment_name: str | None, default: Any = None
    ) -> Any:
        return pick(name, default, environment_name)

    def csv_getter(
        name: str, environment_name: str | None, default: Any = None
    ) -> list[str] | None:
        return parse_csv_list(pick(name, default, environment_name)) or None

    source_config = build_authoritative_source_config(
        scalar_getter=scalar_getter,
        csv_getter=csv_getter,
    )
    if not has_configured_authoritative_source(source_config):
        parser.error(
            "An authoritative source is required. Configure subnet_as_code "
            "method/query settings."
        )
    try:
        validate_authoritative_source_config(source_config)
    except ValueError as exc:
        parser.error(str(exc))

    job_name = str(pick("job_name", "tenable-coverage-scheduled")).strip()
    output_dir = _as_path(pick("output_dir")) or Path("output")
    run_id_prefix = str(
        pick("run_id_prefix", f"{normalize_job_name(job_name)}-")
    ).strip()
    latest_summary_file = _as_path(pick("latest_summary_file")) or (
        output_dir / "latest_run.json"
    )
    lock_file = _as_path(pick("lock_file")) or (output_dir / "scheduler.lock")

    scan_json_dir = _optional_string(pick("scan_json_dir"))
    asset_json_dir = _optional_string(pick("asset_json_dir"))
    sc_url = _optional_string(pick("sc_url"))
    sc_access_key = _optional_string(pick("sc_access_key"))
    sc_secret_key = _optional_string(pick("sc_secret_key"))
    log_format = str(pick("log_format", "text")).lower()
    if log_format not in {"text", "json"}:
        parser.error("--log-format must be 'text' or 'json'")
    log_file = _as_path(pick("log_file"))
    try:
        grouping_config = build_grouping_config(
            mode_value=pick("grouping_mode", "default", "GROUPING_MODE"),
            prefix_value=pick(
                "grouping_vlan_tag_prefix",
                "vlan-",
                "GROUPING_VLAN_TAG_PREFIX",
            ),
            tag_map_value=pick("grouping_tag_map", None, "GROUPING_TAG_MAP"),
        )
    except ValueError as exc:
        parser.error(str(exc))

    if mode == "offline":
        missing = []
        if not scan_json_dir:
            missing.append("scan_json_dir")
        if not asset_json_dir:
            missing.append("asset_json_dir")
        if missing:
            parser.error("Offline scheduled runs require: " + ", ".join(missing))

    if mode == "live":
        missing = []
        if not sc_url:
            missing.append("SC_URL")
        if not sc_access_key:
            missing.append("SC_ACCESS_KEY")
        if not sc_secret_key:
            missing.append("SC_SECRET_KEY")
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
        mode=mode,
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        sc_access_key=sc_access_key,
        sc_secret_key=sc_secret_key,
        sc_url=sc_url,
        include_keywords=parse_csv_list(pick("include_keywords")),
        exclude_keywords=parse_csv_list(pick("exclude_keywords")),
        match_all_include=match_all_include,
        case_sensitive=case_sensitive,
        filter_disabled_mode=filter_disabled_mode,
        log_level=str(pick("log_level", "INFO")),
        log_format=log_format,
        log_file=log_file,
        config_file=config_file,
        sc_timeout_seconds=sc_timeout_seconds,
        sc_retries=sc_retries,
        sc_backoff_seconds=sc_backoff_seconds,
        sc_ssl_verify=sc_ssl_verify,
        grouping_config=grouping_config,
    )


def load_config_file(config_file_path: Path) -> dict[str, Any]:
    if not config_file_path.exists():
        raise ValueError(f"Config file does not exist: {config_file_path}")

    suffix = config_file_path.suffix.lower()
    if suffix == ".json":
        with config_file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    elif suffix in {".toml", ".tml"}:
        with config_file_path.open("rb") as handle:
            data = tomllib.load(handle)
    elif suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(config_file_path.read_text(encoding="utf-8"))
    else:
        raise ValueError("Unsupported config file type. Use .yaml, .json, or .toml.")

    if not isinstance(data, dict):
        raise ValueError("Config file root must be an object/dictionary.")

    section = data.get("tenable_coverage_workflow_service", data)
    if not isinstance(section, dict):
        raise ValueError(
            "Config 'tenable_coverage_workflow_service' section must be an "
            "object/dictionary."
        )

    return _normalize_config_keys(section)


def normalize_job_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "-", str(value).strip().lower())
    normalized = normalized.strip("-")
    return normalized or "tenable-coverage"


def _normalize_config_keys(config_data: dict[str, Any]) -> dict[str, Any]:
    normalized = {}
    for key, value in config_data.items():
        normalized[str(key).strip().replace("-", "_")] = value
    return normalized


def _parse_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    raise ValueError(f"Invalid boolean value for '{field_name}': {value}")


def _parse_positive_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer value for '{field_name}': {value}") from exc

    if parsed <= 0:
        raise ValueError(
            f"Invalid integer value for '{field_name}': {value}. Must be > 0."
        )

    return parsed


def _as_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    if isinstance(value, Path):
        return value

    text = str(value).strip()
    if not text:
        return None
    return Path(text)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
