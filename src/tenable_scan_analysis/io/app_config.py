import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from ..constants import VERSION, default_output_file
from .ui import prompt_for_inputs

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # pyright: ignore[reportMissingImports]


@dataclass
class Config:
    mode: str
    scan_json_dir: str | None
    asset_json_dir: str | None
    expected_scope_file: str | None
    expected_sheet: str | None
    output_file: Path
    sc_access_key: str | None
    sc_secret_key: str | None
    sc_url: str | None
    include_keywords: list[str]
    exclude_keywords: list[str]
    match_all_include: bool
    case_sensitive: bool
    filter_disabled_mode: str
    log_level: str
    log_file: Path | None
    log_format: str = "text"
    csv_output_dir: Path | None = None
    run_summary_file: Path | None = None
    config_file: Path | None = None
    run_started_at: datetime | None = None


def parse_csv_list(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in value.split(",") if item.strip()]


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Tenable.sc scan coverage and generate an Excel workbook."
    )
    parser.add_argument("--config-file")
    parser.add_argument("--mode", choices=["offline", "live"])
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=None,
        help="Fail instead of opening file pickers when required inputs are missing.",
    )
    parser.add_argument("--scan-json-dir")
    parser.add_argument("--asset-json-dir")
    parser.add_argument("--expected-scope-file")
    parser.add_argument(
        "--expected-sheet",
        help=(
            "Worksheet name to use for expected ranges. Defaults to rsg-all, "
            "then Expected_Ranges."
        ),
    )
    parser.add_argument(
        "--no-expected-scope",
        action="store_true",
        default=None,
        help="Skip expected-vs-actual analysis without opening a file picker.",
    )
    parser.add_argument("--output-file")
    parser.add_argument("--include-keywords")
    parser.add_argument("--exclude-keywords")
    parser.add_argument("--match-all-include", action="store_true", default=None)
    parser.add_argument("--case-sensitive", action="store_true", default=None)
    parser.add_argument(
        "--filter-disabled-mode",
        choices=["ALL", "ENABLED_ONLY", "DISABLED_ONLY"],
    )
    parser.add_argument("--log-level")
    parser.add_argument(
        "--log-file",
        help="Optional path to write logs (in addition to console output).",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        help="Console/file log format.",
    )
    parser.add_argument(
        "--csv-output-dir",
        help="Optional directory to export each workbook sheet as CSV.",
    )
    parser.add_argument(
        "--run-summary-file",
        help="Optional path for machine-readable run summary JSON output.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def _normalize_config_keys(config_data: dict[str, Any]) -> dict[str, Any]:
    normalized = {}
    for key, value in config_data.items():
        normalized[str(key).strip().replace("-", "_")] = value
    return normalized


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
    else:
        raise ValueError("Unsupported config file type. Use .json or .toml.")

    if not isinstance(data, dict):
        raise ValueError("Config file root must be an object/dictionary.")

    section = data.get("tenable_scan_analysis", data)
    if not isinstance(section, dict):
        raise ValueError(
            "Config 'tenable_scan_analysis' section must be an object/dictionary."
        )

    return _normalize_config_keys(section)


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


def _as_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    if isinstance(value, Path):
        return value

    text = str(value).strip()
    if not text:
        return None
    return Path(text)


def build_config(argv=None) -> Config:
    load_dotenv()
    run_started_at = datetime.now()
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    config_file = _as_path(args.config_file)
    try:
        config_data = load_config_file(config_file) if config_file else {}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    def pick(name: str, default: Any = None) -> Any:
        cli_value = getattr(args, name, None)
        if cli_value is not None:
            return cli_value
        return config_data.get(name, default)

    try:
        non_interactive = _parse_bool(pick("non_interactive", False), "non_interactive")
        no_expected_scope = _parse_bool(
            pick("no_expected_scope", False), "no_expected_scope"
        )
        match_all_include = _parse_bool(
            pick("match_all_include", False), "match_all_include"
        )
        case_sensitive = _parse_bool(pick("case_sensitive", False), "case_sensitive")
    except ValueError as exc:
        parser.error(str(exc))

    mode = str(pick("mode", "offline"))
    scan_json_dir = pick("scan_json_dir")
    asset_json_dir = pick("asset_json_dir")
    expected_scope_file_value = pick("expected_scope_file")
    expected_sheet = pick("expected_sheet")
    include_keywords_value = pick("include_keywords")
    exclude_keywords_value = pick("exclude_keywords")
    filter_disabled_mode = str(pick("filter_disabled_mode", "ALL"))
    log_level = str(pick("log_level", "INFO"))
    log_format = str(pick("log_format", "text")).lower()

    if mode not in {"offline", "live"}:
        parser.error("--mode must be 'offline' or 'live'")
    if filter_disabled_mode not in {"ALL", "ENABLED_ONLY", "DISABLED_ONLY"}:
        parser.error(
            "--filter-disabled-mode must be ALL, ENABLED_ONLY, or DISABLED_ONLY"
        )
    if log_format not in {"text", "json"}:
        parser.error("--log-format must be 'text' or 'json'")

    if no_expected_scope and expected_scope_file_value:
        parser.error("--no-expected-scope cannot be used with --expected-scope-file")

    expected_scope_file = None if no_expected_scope else expected_scope_file_value

    needs_scan_dir = mode == "offline" and not scan_json_dir
    needs_asset_dir = mode == "offline" and not asset_json_dir
    needs_expected_file = expected_scope_file is None and not no_expected_scope

    if non_interactive:
        missing = []
        if needs_scan_dir:
            missing.append("--scan-json-dir")
        if needs_asset_dir:
            missing.append("--asset-json-dir")
        if needs_expected_file:
            missing.append("--expected-scope-file or --no-expected-scope")

        if missing:
            parser.error("--non-interactive requires: " + ", ".join(missing))

    if needs_scan_dir or needs_asset_dir or needs_expected_file:
        prompted_scan_dir, prompted_asset_dir, prompted_expected_file = (
            prompt_for_inputs(
                ask_scan_dir=needs_scan_dir,
                ask_asset_dir=needs_asset_dir,
                ask_expected_file=needs_expected_file,
            )
        )
        scan_json_dir = scan_json_dir or prompted_scan_dir
        asset_json_dir = asset_json_dir or prompted_asset_dir
        if needs_expected_file:
            expected_scope_file = prompted_expected_file

    output_file_value = _as_path(pick("output_file"))
    output_file = output_file_value or default_output_file(run_started_at)
    log_file = _as_path(pick("log_file"))
    csv_output_dir = _as_path(pick("csv_output_dir"))
    run_summary_file = _as_path(pick("run_summary_file"))

    if scan_json_dir:
        os.makedirs(scan_json_dir, exist_ok=True)
    if asset_json_dir:
        os.makedirs(asset_json_dir, exist_ok=True)

    return Config(
        mode=mode,
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        expected_scope_file=expected_scope_file,
        expected_sheet=expected_sheet,
        output_file=output_file,
        sc_access_key=os.getenv("SC_ACCESS_KEY"),
        sc_secret_key=os.getenv("SC_SECRET_KEY"),
        sc_url=os.getenv("SC_URL"),
        include_keywords=parse_csv_list(include_keywords_value),
        exclude_keywords=parse_csv_list(exclude_keywords_value),
        match_all_include=match_all_include,
        case_sensitive=case_sensitive,
        filter_disabled_mode=filter_disabled_mode,
        log_level=log_level,
        log_file=log_file,
        log_format=log_format,
        csv_output_dir=csv_output_dir,
        run_summary_file=run_summary_file,
        config_file=config_file,
        run_started_at=run_started_at,
    )
