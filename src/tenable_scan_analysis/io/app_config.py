import argparse
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from ..constants import VERSION, default_output_file
from .ui import prompt_for_inputs


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
    run_started_at: datetime | None = None


def parse_csv_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Tenable.sc scan coverage and generate an Excel workbook."
    )
    parser.add_argument("--mode", choices=["offline", "live"], default="offline")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of opening file pickers when required inputs are missing.",
    )
    parser.add_argument("--scan-json-dir")
    parser.add_argument("--asset-json-dir")
    parser.add_argument("--expected-scope-file")
    parser.add_argument(
        "--expected-sheet",
        help="Worksheet name to use for expected ranges. Defaults to rsg-all, then Expected_Ranges.",
    )
    parser.add_argument(
        "--no-expected-scope",
        action="store_true",
        help="Skip expected-vs-actual analysis without opening a file picker.",
    )
    parser.add_argument("--output-file")
    parser.add_argument("--include-keywords")
    parser.add_argument("--exclude-keywords")
    parser.add_argument("--match-all-include", action="store_true")
    parser.add_argument("--case-sensitive", action="store_true")
    parser.add_argument(
        "--filter-disabled-mode",
        choices=["ALL", "ENABLED_ONLY", "DISABLED_ONLY"],
        default="ALL",
    )
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--log-file",
        help="Optional path to write logs (in addition to console output).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def build_config(argv=None) -> Config:
    load_dotenv()
    run_started_at = datetime.now()
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.no_expected_scope and args.expected_scope_file:
        parser.error("--no-expected-scope cannot be used with --expected-scope-file")

    scan_json_dir = args.scan_json_dir
    asset_json_dir = args.asset_json_dir
    expected_scope_file = None if args.no_expected_scope else args.expected_scope_file

    needs_scan_dir = args.mode == "offline" and not scan_json_dir
    needs_asset_dir = args.mode == "offline" and not asset_json_dir
    needs_expected_file = expected_scope_file is None and not args.no_expected_scope

    if args.non_interactive:
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

    output_file = (
        Path(args.output_file)
        if args.output_file
        else default_output_file(run_started_at)
    )
    log_file = Path(args.log_file) if args.log_file else None

    if scan_json_dir:
        os.makedirs(scan_json_dir, exist_ok=True)
    if asset_json_dir:
        os.makedirs(asset_json_dir, exist_ok=True)

    return Config(
        mode=args.mode,
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        expected_scope_file=expected_scope_file,
        expected_sheet=args.expected_sheet,
        output_file=output_file,
        sc_access_key=os.getenv("SC_ACCESS_KEY"),
        sc_secret_key=os.getenv("SC_SECRET_KEY"),
        sc_url=os.getenv("SC_URL"),
        include_keywords=parse_csv_list(args.include_keywords),
        exclude_keywords=parse_csv_list(args.exclude_keywords),
        match_all_include=args.match_all_include,
        case_sensitive=args.case_sensitive,
        filter_disabled_mode=args.filter_disabled_mode,
        log_level=args.log_level,
        log_file=log_file,
        run_started_at=run_started_at,
    )
