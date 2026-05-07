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


def build_config():
    load_dotenv()

    scan_json_dir, asset_json_dir, expected_scope_file = prompt_for_inputs()

    if scan_json_dir:
        os.makedirs(scan_json_dir, exist_ok=True)
    if asset_json_dir:
        os.makedirs(asset_json_dir, exist_ok=True)

    return Config(
        mode="offline",
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        expected_scope_file=expected_scope_file,
        output_file=Path("output") / "tenable_scan_summary_v7.xlsx",
        sc_access_key=os.getenv("SC_ACCESS_KEY"),
        sc_secret_key=os.getenv("SC_SECRET_KEY"),
        sc_url=os.getenv("SC_URL"),
        include_keywords=[],
        exclude_keywords=[],
        match_all_include=False,
        case_sensitive=False,
        filter_disabled_mode="ALL",
        log_level="INFO",
    )
