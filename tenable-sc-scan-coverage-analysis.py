"""
Tenable SC Scan Coverage Analysis
Ken Parker
19 February 2026
"""

import glob
import ipaddress
import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import tkinter as tk
from dotenv import load_dotenv
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from tkinter import filedialog


INCLUDE = "Include"
EXCLUDE = "Exclude"

STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"
STATUS_GAP = "GAP"

DEFAULT_EXPECTED_SHEET = "rsg-all"

HEADER_FONT = Font(bold=True)

GREEN = PatternFill("solid", fgColor="C6EFCE")
YELLOW = PatternFill("solid", fgColor="FFEB9C")
RED = PatternFill("solid", fgColor="F4CCCC")
GRAY = PatternFill("solid", fgColor="E7E6E6")
LOGGER = logging.getLogger(__name__)


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


class DataAccess:
    def __init__(self, config: Config):
        self.config = config
        self.sc = None
        self.offline_scans = {}
        self.offline_assets = {}

        if config.mode == "live":
            try:
                from tenable.sc import TenableSC
            except ImportError as exc:
                raise RuntimeError("pyTenable is required for live mode") from exc

            self.sc = TenableSC(
                url=config.sc_url,
                access_key=config.sc_access_key,
                secret_key=config.sc_secret_key,
            )
        else:
            self.offline_scans = load_json_folder(config.scan_json_dir)
            self.offline_assets = load_json_folder(config.asset_json_dir)

    def get_scans(self):
        if self.config.mode == "live":
            return self.sc.scans.list()["usable"]
        return list(self.offline_scans.values())

    def get_scan_details(self, scan_id):
        if self.config.mode == "live":
            return self.sc.scans.details(scan_id)
        return self.offline_scans[str(scan_id)]

    def get_asset(self, asset_id):
        if self.config.mode == "live":
            return self.sc.asset_lists.details(asset_id)
        return self.offline_assets.get(str(asset_id), {})


def prompt_for_inputs():
    root = tk.Tk()
    root.withdraw()

    try:
        scan_json_dir = filedialog.askdirectory(
            title="Select directory to save Scan json files"
        )
        asset_json_dir = filedialog.askdirectory(
            title="Select directory to save Asset json files"
        )
        expected_scope_file = filedialog.askopenfilename(
            title="Select XLSX of expected ranges (e.x. Global IP Address Tracker)",
            filetypes=[("Excel files", "*.xlsx")],
        )
    finally:
        root.destroy()

    return scan_json_dir, asset_json_dir, expected_scope_file


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


def load_json_folder(folder_path):
    data = {}
    if not folder_path:
        return data

    file_paths = glob.glob(os.path.join(folder_path, "*.json"))
    for file_path in file_paths:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                obj = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Skipping unreadable JSON file '%s': %s", file_path, exc)
            continue

        object_id = obj.get("id")
        if object_id in (None, ""):
            LOGGER.warning("Skipping JSON file without an 'id': %s", file_path)
            continue

        data[str(object_id)] = obj

    LOGGER.info("Loaded %s JSON objects from %s", len(data), folder_path)
    return data


def filter_scans(scans, config: Config):
    if (
        not config.include_keywords
        and not config.exclude_keywords
        and config.filter_disabled_mode == "ALL"
    ):
        LOGGER.info("No filtering applied. Using all %s scans", len(scans))
        return scans

    filtered = []

    include_keywords = (
        config.include_keywords
        if config.case_sensitive
        else [keyword.lower() for keyword in config.include_keywords]
    )
    exclude_keywords = (
        config.exclude_keywords
        if config.case_sensitive
        else [keyword.lower() for keyword in config.exclude_keywords]
    )

    for scan in scans:
        name = scan.get("info", {}).get("name") or scan.get("name", "")
        compare_name = name if config.case_sensitive else name.lower()

        schedule = scan.get("schedule", {})
        enabled_raw = schedule.get("enabled")

        if isinstance(enabled_raw, str):
            enabled = enabled_raw.lower() == "true"
        elif isinstance(enabled_raw, bool):
            enabled = enabled_raw
        else:
            enabled = True

        if config.filter_disabled_mode == "ENABLED_ONLY" and not enabled:
            continue
        if config.filter_disabled_mode == "DISABLED_ONLY" and enabled:
            continue

        include_pass = True
        if include_keywords:
            if config.match_all_include:
                include_pass = all(keyword in compare_name for keyword in include_keywords)
            else:
                include_pass = any(keyword in compare_name for keyword in include_keywords)

        exclude_pass = True
        if exclude_keywords and any(keyword in compare_name for keyword in exclude_keywords):
            exclude_pass = False

        if include_pass and exclude_pass:
            filtered.append(scan)

    LOGGER.info("Scans before filter: %s", len(scans))
    LOGGER.info("Scans after filter: %s", len(filtered))
    LOGGER.info("Disabled filter mode: %s", config.filter_disabled_mode)

    return filtered


_parsed_cache = {}


def parse_scope_item(scope):
    scope = str(scope).strip()
    if not scope:
        raise ValueError("Scope item is blank")

    if scope in _parsed_cache:
        return _parsed_cache[scope]

    try:
        if "/" in scope:
            parsed = ("cidr", ipaddress.ip_network(scope, strict=False))
        elif "-" in scope:
            start, end = scope.split("-", maxsplit=1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            if int(start_ip) > int(end_ip):
                raise ValueError(f"Invalid IP range order: '{scope}'")

            parsed = ("range", (start_ip, end_ip))
        else:
            ip = ipaddress.ip_address(scope)
            parsed = ("cidr", ipaddress.ip_network(f"{ip}/32"))
    except ValueError as exc:
        raise ValueError(f"Invalid scope item '{scope}': {exc}") from exc

    _parsed_cache[scope] = parsed
    return parsed


def split_scope_items(scope_string):
    return [item.strip() for item in scope_string.split(",") if item.strip()]


def scope_contains(actual, expected):
    actual_type, actual_value = actual
    expected_type, expected_value = expected

    if actual_type == "cidr" and expected_type == "cidr":
        return expected_value.subnet_of(actual_value)

    if actual_type == "cidr" and expected_type == "range":
        start, end = expected_value
        return start in actual_value and end in actual_value

    if actual_type == "range" and expected_type == "cidr":
        return (
            actual_value[0] <= expected_value.network_address
            and actual_value[1] >= expected_value.broadcast_address
        )

    if actual_type == "range" and expected_type == "range":
        return actual_value[0] <= expected_value[0] and actual_value[1] >= expected_value[1]

    return False


def scope_intersects(actual, expected):
    actual_start, actual_end = scope_to_interval(actual)
    expected_start, expected_end = scope_to_interval(expected)
    return actual_start <= expected_end and actual_end >= expected_start


def scope_to_interval(parsed):
    parsed_type, parsed_value = parsed
    if parsed_type == "cidr":
        return int(parsed_value.network_address), int(parsed_value.broadcast_address)
    return int(parsed_value[0]), int(parsed_value[1])


def merge_intervals(intervals):
    if not intervals:
        return []

    sorted_intervals = sorted(intervals)
    merged = [sorted_intervals[0]]

    for start, end in sorted_intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))

    return merged


def subtract_intervals(included, excluded):
    remaining_intervals = []

    for included_start, included_end in included:
        remaining = [(included_start, included_end)]

        for excluded_start, excluded_end in excluded:
            next_remaining = []

            for remaining_start, remaining_end in remaining:
                if excluded_end < remaining_start or excluded_start > remaining_end:
                    next_remaining.append((remaining_start, remaining_end))
                    continue

                if excluded_start > remaining_start:
                    next_remaining.append((remaining_start, excluded_start - 1))
                if excluded_end < remaining_end:
                    next_remaining.append((excluded_end + 1, remaining_end))

            remaining = next_remaining
            if not remaining:
                break

        remaining_intervals.extend(remaining)

    return remaining_intervals


def scope_size(parsed):
    parsed_type, parsed_value = parsed
    if parsed_type == "cidr":
        return parsed_value.num_addresses
    return int(parsed_value[1]) - int(parsed_value[0]) + 1


def build_workbook():
    workbook = Workbook()
    scope_ws = workbook.create_sheet("Scan_Scope_Summary")
    normalized_ws = workbook.create_sheet("Scan_Scope_Normalized")
    workbook.remove(workbook["Sheet"])

    scope_ws.append(
        ["Scan Name", "Inclusion Type", "Source Type", "Source Name", "Scope Definition"]
    )
    normalized_ws.append(["Scan Name", "Asset Name", "Inclusion Type", "Scope Item"])

    return workbook, scope_ws, normalized_ws


def normalize_scope(normalized_ws, scan_name, asset_name, inclusion_type, defined_string):
    for scope_item in split_scope_items(defined_string):
        normalized_ws.append([scan_name, asset_name, inclusion_type, scope_item])


def walk_combination(node, scan_name, scope_ws, normalized_ws, data_access, in_complement=False):
    if not isinstance(node, dict):
        return

    operator = node.get("operator")
    if operator == "complement":
        in_complement = True

    if "id" in node and operator is None:
        asset_id = node.get("id")
        if asset_id in (-1, None):
            return

        asset = data_access.get_asset(asset_id)
        if not asset:
            LOGGER.warning(
                "Scan '%s' references missing asset id '%s' in combination asset",
                scan_name,
                asset_id,
            )
            return

        defined = asset.get("typeFields", {}).get("definedIPs")
        asset_name = asset.get("name") or f"Asset {asset_id}"
        inclusion_type = EXCLUDE if in_complement else INCLUDE

        if defined:
            scope_ws.append([scan_name, inclusion_type, "Asset", asset_name, defined])
            normalize_scope(normalized_ws, scan_name, asset_name, inclusion_type, defined)
        else:
            LOGGER.warning(
                "Combination asset '%s' on scan '%s' has no defined IPs",
                asset_name,
                scan_name,
            )

        return

    walk_combination(
        node.get("operand1"),
        scan_name,
        scope_ws,
        normalized_ws,
        data_access,
        in_complement,
    )
    walk_combination(
        node.get("operand2"),
        scan_name,
        scope_ws,
        normalized_ws,
        data_access,
        in_complement,
    )


def build_scope_sheets(scope_ws, normalized_ws, data_access, config: Config):
    all_scans = data_access.get_scans()
    filtered_scans = filter_scans(all_scans, config)

    for scan in filtered_scans:
        scan_id = scan.get("id")
        scan_name = scan.get("name")
        if scan_id in (None, "") or not scan_name:
            LOGGER.warning("Skipping malformed scan record: %s", scan)
            continue

        details = data_access.get_scan_details(scan_id)

        ip_list = details.get("ipList")
        if ip_list and ip_list != "*":
            scope_ws.append([scan_name, INCLUDE, "Scan", "Direct IP List", ip_list])
            normalize_scope(normalized_ws, scan_name, "SCAN_IPLIST", INCLUDE, ip_list)

        for asset_ref in details.get("assets", []):
            asset_id = asset_ref.get("id")
            if asset_id in (None, ""):
                LOGGER.warning("Scan '%s' contains asset reference without id", scan_name)
                continue

            asset = data_access.get_asset(asset_id)
            if not asset:
                LOGGER.warning("Scan '%s' references missing asset id '%s'", scan_name, asset_id)
                continue

            asset_type = asset.get("type")

            if asset_type == "static":
                defined = asset.get("typeFields", {}).get("definedIPs")
                asset_name = asset.get("name") or f"Asset {asset_id}"

                if defined:
                    scope_ws.append([scan_name, INCLUDE, "Asset", asset_name, defined])
                    normalize_scope(normalized_ws, scan_name, asset_name, INCLUDE, defined)
                else:
                    LOGGER.warning(
                        "Static asset '%s' on scan '%s' has no defined IPs",
                        asset_name,
                        scan_name,
                    )

            elif asset_type == "combination":
                walk_combination(
                    asset.get("typeFields", {}).get("combinations", {}),
                    scan_name,
                    scope_ws,
                    normalized_ws,
                    data_access,
                )
            else:
                LOGGER.debug(
                    "Skipping unsupported asset type '%s' for asset '%s' on scan '%s'",
                    asset_type,
                    asset.get("name"),
                    scan_name,
                )


def build_coverage_data(normalized_ws):
    actual_scopes = []
    excluded_scopes = []
    actual_by_scan = defaultdict(list)
    excluded_by_scan = defaultdict(list)

    for row in normalized_ws.iter_rows(min_row=2, values_only=True):
        scan_name, asset_name, inclusion_type, scope_item = row
        if not scope_item:
            continue

        try:
            parsed = parse_scope_item(scope_item)
        except ValueError as exc:
            LOGGER.warning(
                "Skipping invalid normalized scope for scan '%s', asset '%s': %s",
                scan_name,
                asset_name,
                exc,
            )
            continue

        if inclusion_type == INCLUDE:
            entry = (parsed, scan_name, scope_item)
            actual_scopes.append(entry)
            actual_by_scan[scan_name].append(entry)
        elif inclusion_type == EXCLUDE:
            entry = (parsed, scan_name, asset_name, scope_item)
            excluded_scopes.append(entry)
            excluded_by_scan[scan_name].append(entry)

    return actual_scopes, excluded_scopes, actual_by_scan, excluded_by_scan


def resolve_expected_sheet(expected_workbook):
    if DEFAULT_EXPECTED_SHEET in expected_workbook.sheetnames:
        return expected_workbook[DEFAULT_EXPECTED_SHEET]
    if "Expected_Ranges" in expected_workbook.sheetnames:
        return expected_workbook["Expected_Ranges"]

    available = ", ".join(expected_workbook.sheetnames)
    raise KeyError(
        "Expected scope workbook must contain either "
        f"'{DEFAULT_EXPECTED_SHEET}' or 'Expected_Ranges'. Found: {available}"
    )


def validate_expected_row(row):
    if len(row) < 3:
        raise ValueError(
            "Expected range rows must include at least Scope Item, Location, and Environment columns"
        )

    scope_item = row[0]
    location = row[1] if len(row) > 1 else None
    environment = row[2] if len(row) > 2 else None
    required_scan = row[3] if len(row) > 3 else None

    if not scope_item:
        return None

    return scope_item, location, environment, required_scan


def append_executive_summary(workbook, totals):
    exec_ws = workbook.create_sheet("Executive_Summary")
    exec_ws.append(["Metric", "Value", "Note"])

    overall_coverage_pct = (
        round((totals["portfolio_covered_total"] / totals["portfolio_expected_total"]) * 100, 2)
        if totals["portfolio_expected_total"]
        else 0.0
    )

    portfolio_exclusion_loss_pct = (
        round(
            (totals["portfolio_exclusion_total"] / totals["portfolio_included_total"]) * 100,
            2,
        )
        if totals["portfolio_included_total"]
        else 0.0
    )

    exec_ws.append(
        [
            "Total Expected IPs",
            totals["portfolio_expected_total"],
            "Number of IP addresses from expected ranges (Global IP Address Trackers)",
        ]
    )
    exec_ws.append(
        [
            "Total Net Covered IPs",
            totals["portfolio_covered_total"],
            "Number of IP addresses covered by scans",
        ]
    )
    exec_ws.append(
        [
            "Total Gap IPs",
            totals["portfolio_gap_total"],
            "Number of IP addresses not covered by scans",
        ]
    )
    exec_ws.append(
        [
            "Overall Portfolio Coverage %",
            overall_coverage_pct,
            "Percentage of IP addresses covered by scans (Total Net Covered IPs/Total Expected IPs)",
        ]
    )
    exec_ws.append(
        [
            "Total IPs Lost Due To Exclusions",
            totals["portfolio_exclusion_total"],
            "Number of IP addresses excluded in scans",
        ]
    )
    exec_ws.append(
        [
            "% Coverage Lost Due To Exclusions",
            portfolio_exclusion_loss_pct,
            "Percentage of coverage lost due to exclusions (Total Excluded/Total Included)",
        ]
    )

    workbook.move_sheet(exec_ws, offset=1)
    return exec_ws


def analyze_expected_ranges(workbook, expected_scope_file, actual_scopes, actual_by_scan, excluded_by_scan):
    compare_ws = None
    compliance_ws = None
    exclusion_impact_by_scan = defaultdict(int)

    totals = {
        "portfolio_expected_total": 0,
        "portfolio_covered_total": 0,
        "portfolio_gap_total": 0,
        "portfolio_exclusion_total": 0,
        "portfolio_included_total": 0,
    }

    if not expected_scope_file:
        LOGGER.info("No expected scope workbook selected; skipping expected-vs-actual analysis")
        return compare_ws, compliance_ws, exclusion_impact_by_scan, totals

    expected_wb = load_workbook(expected_scope_file)
    expected_ws = resolve_expected_sheet(expected_wb)

    compare_ws = workbook.create_sheet("Expected_vs_Actual")
    compare_ws.append(
        [
            "Environment",
            "Location",
            "Expected",
            "Expected IPs",
            "Net Covered IPs",
            "Net Portfolio Gap",
            "% Scan Coverage Suppressed",
            "Covered",
            "Scans Covering",
            "Status",
            "Reason",
        ]
    )

    compliance_ws = workbook.create_sheet("Expected_Range_Compliance")
    compliance_ws.append(
        [
            "Environment",
            "Location",
            "Expected Range",
            "Expected IPs",
            "Covered IPs",
            "Gap IPs",
            "Coverage %",
        ]
    )

    for row_index, row in enumerate(expected_ws.iter_rows(min_row=2, values_only=True), start=2):
        try:
            validated_row = validate_expected_row(row)
        except ValueError as exc:
            LOGGER.warning("Skipping invalid expected range row %s: %s", row_index, exc)
            continue

        if validated_row is None:
            continue

        scope_item, location, environment, required_scan = validated_row

        try:
            expected = parse_scope_item(scope_item)
        except ValueError as exc:
            LOGGER.warning("Skipping invalid expected scope in row %s: %s", row_index, exc)
            continue

        expected_size = scope_size(expected)
        expected_start, expected_end = scope_to_interval(expected)

        full_cover_scans = set()
        partial_scans = set()

        for actual, scan_name, raw in actual_scopes:
            if scope_contains(actual, expected):
                full_cover_scans.add(scan_name)
            elif scope_intersects(actual, expected):
                partial_scans.add(scan_name)

        covering_scans = full_cover_scans.union(partial_scans)

        relevant_exclusions = defaultdict(list)
        cover_intervals = []
        total_included_ips = 0
        exclusion_ip_total = 0

        for scan_name in covering_scans:
            included = []
            excluded = []

            for actual, _, raw in actual_by_scan[scan_name]:
                if not scope_intersects(actual, expected):
                    continue

                actual_start, actual_end = scope_to_interval(actual)
                overlap_start = max(actual_start, expected_start)
                overlap_end = min(actual_end, expected_end)

                if overlap_start <= overlap_end:
                    included.append((overlap_start, overlap_end))

            for excluded_scope, _, asset_name, raw in excluded_by_scan[scan_name]:
                if not scope_intersects(excluded_scope, expected):
                    continue

                excluded_start, excluded_end = scope_to_interval(excluded_scope)
                overlap_start = max(excluded_start, expected_start)
                overlap_end = min(excluded_end, expected_end)

                if overlap_start > overlap_end:
                    continue

                interval = (overlap_start, overlap_end)
                excluded.append(interval)
                loss = overlap_end - overlap_start + 1

                relevant_exclusions[scan_name].append(
                    {"asset": asset_name, "scope": raw, "loss": loss}
                )

                exclusion_ip_total += loss
                exclusion_impact_by_scan[scan_name] += loss

            included = merge_intervals(included)
            excluded = merge_intervals(excluded)

            total_included_ips += sum(end - start + 1 for start, end in included)
            cover_intervals.extend(subtract_intervals(included, excluded))

        cover_intervals = merge_intervals(cover_intervals)
        covered_count = sum(end - start + 1 for start, end in cover_intervals)
        covered_count = min(covered_count, expected_size)
        gap_count = max(0, expected_size - covered_count)

        percent_lost = (
            round((exclusion_ip_total / total_included_ips) * 100, 2)
            if total_included_ips
            else 0.0
        )

        totals["portfolio_expected_total"] += expected_size
        totals["portfolio_covered_total"] += covered_count
        totals["portfolio_gap_total"] += gap_count
        totals["portfolio_exclusion_total"] += exclusion_ip_total
        totals["portfolio_included_total"] += total_included_ips

        if covered_count == expected_size:
            status = STATUS_OK
            covered = "Yes"
            reason = "Fully contained by scan scope"
        elif covered_count > 0:
            status = STATUS_PARTIAL
            covered = "Partial"

            if exclusion_ip_total > 0:
                exclusion_lines = []
                for excluded_scan_name in sorted(relevant_exclusions):
                    for entry in relevant_exclusions[excluded_scan_name]:
                        exclusion_lines.append(
                            f"{excluded_scan_name} | {entry['asset']} | "
                            f"{entry['scope']} ({entry['loss']} IPs)"
                        )

                reason = f"Excluded {exclusion_ip_total} IPs:\n" + "\n".join(exclusion_lines)
            else:
                reason = "Partial coverage detected"
        else:
            status = STATUS_GAP
            covered = "No"
            reason = "No scan scope intersects expected range"

        compare_ws.append(
            [
                environment,
                location,
                scope_item,
                expected_size,
                covered_count,
                gap_count,
                percent_lost,
                covered,
                ", ".join(sorted(covering_scans)),
                status,
                reason,
            ]
        )

        coverage_pct = round((covered_count / expected_size) * 100, 2) if expected_size else 0.0

        compliance_ws.append(
            [
                environment,
                location,
                scope_item,
                expected_size,
                covered_count,
                gap_count,
                coverage_pct,
            ]
        )

    return compare_ws, compliance_ws, exclusion_impact_by_scan, totals


def build_impact_sheet(workbook, exclusion_impact_by_scan):
    impact_ws = workbook.create_sheet("Top_Exclusion_Impact_Scans")
    impact_ws.append(["Scan Name", "Total IPs Excluded"])

    for scan_name, total in sorted(
        exclusion_impact_by_scan.items(), key=lambda item: item[1], reverse=True
    ):
        impact_ws.append([scan_name, total])

    return impact_ws


def find_column(ws, header_name):
    for idx, cell in enumerate(ws[1], start=1):
        if cell.value == header_name:
            return idx
    return None


def auto_wrap_and_adjust(ws, column_name):
    column_index = find_column(ws, column_name)
    if not column_index:
        return

    for row in ws.iter_rows(min_row=2):
        cell = row[column_index - 1]
        if not cell.value:
            continue

        cell.alignment = Alignment(wrap_text=True)
        line_count = str(cell.value).count("\n") + 1
        ws.row_dimensions[cell.row].height = 15 * line_count


def format_sheet(ws, status_col=None, include_exclude_col=None, percent_col=None, value_col=None):
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    for cell in ws[1]:
        cell.font = HEADER_FONT
        cell.fill = GRAY

    for col in ws.columns:
        max_length = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = min(max_length + 2, 60)

    if status_col:
        for row in ws.iter_rows(min_row=2):
            cell = row[status_col - 1]
            if cell.value == STATUS_OK:
                cell.fill = GREEN
            elif cell.value == STATUS_PARTIAL:
                cell.fill = YELLOW
            elif cell.value == STATUS_GAP:
                cell.fill = RED

    if include_exclude_col:
        for row in ws.iter_rows(min_row=2):
            cell = row[include_exclude_col - 1]
            if cell.value == INCLUDE:
                cell.fill = GREEN
            elif cell.value == EXCLUDE:
                cell.fill = RED

    if percent_col:
        for row in ws.iter_rows(min_row=2):
            cell = row[percent_col - 1]
            if isinstance(cell.value, (int, float)):
                cell.number_format = "0.00"
                if cell.value >= 90:
                    cell.fill = GREEN
                elif cell.value >= 70:
                    cell.fill = YELLOW
                else:
                    cell.fill = RED

    if value_col:
        for row in ws.iter_rows(min_row=2):
            metric_cell = row[0]
            target_cell = row[value_col - 1]

            if "Coverage %" in str(metric_cell.value):
                target_cell.number_format = "0.00"
                if isinstance(target_cell.value, (int, float)):
                    if target_cell.value >= 95:
                        target_cell.fill = GREEN
                    elif target_cell.value >= 85:
                        target_cell.fill = YELLOW
                    else:
                        target_cell.fill = RED

            if metric_cell.value == "Total Gap IPs" and isinstance(target_cell.value, (int, float)):
                if target_cell.value > 0:
                    target_cell.fill = RED


def format_workbook(scope_ws, normalized_ws, compare_ws, compliance_ws, impact_ws, exec_ws):
    format_sheet(scope_ws, include_exclude_col=find_column(scope_ws, "Inclusion Type"))

    if compare_ws:
        format_sheet(compare_ws, status_col=find_column(compare_ws, "Status"))
        auto_wrap_and_adjust(compare_ws, "Reason")

    if compliance_ws:
        format_sheet(compliance_ws, percent_col=find_column(compliance_ws, "Coverage %"))

    format_sheet(impact_ws)
    format_sheet(exec_ws, value_col=find_column(exec_ws, "Value"))

    normalized_ws.sheet_state = "hidden"


def configure_logging(level_name):
    level = getattr(logging, str(level_name).upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    config = build_config()
    configure_logging(config.log_level)
    LOGGER.info("Starting Tenable SC scan coverage analysis in %s mode", config.mode)
    data_access = DataAccess(config)

    workbook, scope_ws, normalized_ws = build_workbook()
    build_scope_sheets(scope_ws, normalized_ws, data_access, config)

    actual_scopes, excluded_scopes, actual_by_scan, excluded_by_scan = build_coverage_data(
        normalized_ws
    )

    compare_ws, compliance_ws, exclusion_impact_by_scan, totals = analyze_expected_ranges(
        workbook,
        config.expected_scope_file,
        actual_scopes,
        actual_by_scan,
        excluded_by_scan,
    )

    impact_ws = build_impact_sheet(workbook, exclusion_impact_by_scan)
    exec_ws = append_executive_summary(workbook, totals)

    format_workbook(scope_ws, normalized_ws, compare_ws, compliance_ws, impact_ws, exec_ws)

    config.output_file.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(config.output_file)
    LOGGER.info("Workbook saved to %s", config.output_file)


if __name__ == "__main__":
    main()
