import argparse
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from ui import prompt_for_inputs


@dataclass
class Config:
    mode: str
    scan_json_dir: str
    asset_json_dir: str
    expected_scope_file: str
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


def parse_csv_list(value):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Analyze Tenable.sc scan coverage and generate an Excel workbook."
    )
    parser.add_argument("--mode", choices=["offline", "live"], default="offline")
    parser.add_argument("--scan-json-dir")
    parser.add_argument("--asset-json-dir")
    parser.add_argument("--expected-scope-file")
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
    return parser


def build_config(argv=None):
    load_dotenv()
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    scan_json_dir = args.scan_json_dir
    asset_json_dir = args.asset_json_dir
    expected_scope_file = args.expected_scope_file

    if not scan_json_dir or not asset_json_dir or expected_scope_file is None:
        prompted_scan_dir, prompted_asset_dir, prompted_expected_file = prompt_for_inputs()
        scan_json_dir = scan_json_dir or prompted_scan_dir
        asset_json_dir = asset_json_dir or prompted_asset_dir
        if expected_scope_file is None:
            expected_scope_file = prompted_expected_file

    output_file = (
        Path(args.output_file)
        if args.output_file
        else Path("output") / "tenable_scan_summary_v7.xlsx"
    )

    if scan_json_dir:
        os.makedirs(scan_json_dir, exist_ok=True)
    if asset_json_dir:
        os.makedirs(asset_json_dir, exist_ok=True)

    return Config(
        mode=args.mode,
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        expected_scope_file=expected_scope_file,
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
    )
