'''
Tenable SC Scan Coverage Analysis
Ken Parker
19 February 2026
'''

import os
import re
import glob
from dotenv import load_dotenv
import json
import ipaddress
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
from collections import defaultdict
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

# ==========================================================
# CONFIG
# ==========================================================

root = tk.Tk()
root.withdraw()

MODE = "offline"  # "live" or "offline"

SCAN_JSON_DIR = filedialog.askdirectory(title="Select directory to save Scan json files")
ASSET_JSON_DIR = filedialog.askdirectory(title="Select directory to save Asset json files")

os.makedirs(SCAN_JSON_DIR, exist_ok=True)
os.makedirs(ASSET_JSON_DIR, exist_ok=True)

'''
Requires XLSX of expected ranges
'''

EXPECTED_SCOPE_FILE = filedialog.askopenfilename(
    title="Select XLSX of expected ranges (e.x. Global IP Address Tracker)",
    filetypes=[("Excel files", "*.xlsx")]
)

load_dotenv()

SC_ACCESS_KEY=os.getenv("SC_ACCESS_KEY")
SC_SECRET_KEY=os.getenv("SC_SECRET_KEY")
SC_URL=os.getenv("SC_URL")

OUTPUT_FILE = Path("output\\tenable_scan_summary_v7.xlsx")

INCLUDE = "Include"
EXCLUDE = "Exclude"

STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"
STATUS_GAP = "GAP"

# ==========================================================
# DATA ACCESS
# ==========================================================

if MODE == "live":
    try:
        from tenable.sc import TenableSC
    except ImportError:
        raise RuntimeError("pyTenable is required for live mode")

    sc = TenableSC(url=SC_URL, access_key=SC_ACCESS_KEY, secret_key=SC_SECRET_KEY)


def load_json_folder(folder_path):
    data = {}
    file_dirs = glob.glob(os.path.join(folder_path, '*.json'))
    for f in file_dirs:
        with open(f, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        data[str(obj["id"])] = obj
    return data


if MODE == "offline":
    # try:
    #     from tenable.sc import TenableSC
    # except ImportError:
    #     raise RuntimeError("pyTenable is required for live mode")

    # sc = TenableSC(url=SC_URL, access_key=SC_ACCESS_KEY, secret_key=SC_SECRET_KEY)

    # scan_lists = sc.scans.list()
    # usable_scan_lists = scan_lists['usable']

    # asset_lists = sc.asset_lists.list()
    # usable_asset_lists = asset_lists['usable']

    # for scan in usable_scan_lists:
    #     #print(f"Found {len(usable_scan_lists)} scans")
    #     scan_id = scan['id']
    #     scan_name = scan['name']

    #     # Clean filename (no special characters)
    #     safe_name = re.sub(r'[^A-Za-z0-9_\- ]+', '_', scan_name)
    #     output_filename = f"{scan_id}_{safe_name}.json"

    #     details = sc.scans.details(scan_id)

    #     output_filepath = os.path.join(SCAN_JSON_DIR, output_filename)

    #     with open(output_filepath, "w") as f:
    #         json.dump(details, f, indent=4)

    #     print(f"ID: {scan_id}, Name: {safe_name}")

    #     print(f"Exported: {output_filepath}")

    # for asset in usable_asset_lists:
    #     #print(f"Found {len(usable_asset_lists)} assets")
    #     asset_id = asset['id']
    #     asset_name = asset['name']

    #     # Clean filename (no special characters)
    #     safe_name = re.sub(r'[^A-Za-z0-9_\- ]+', '_', asset_name)
    #     output_filename = f"{asset_id}_{safe_name}.json"

    #     details = sc.asset_lists.details(asset_id)

    #     output_filepath = os.path.join(ASSET_JSON_DIR, output_filename)

    #     with open(output_filepath, "w") as f:
    #         json.dump(details, f, indent=4)

    #     print(f"ID: {asset_id}, Name: {safe_name}")

    #     print(f"Exported: {output_filepath}")

    OFFLINE_SCANS = load_json_folder(SCAN_JSON_DIR)
    OFFLINE_ASSETS = load_json_folder(ASSET_JSON_DIR)


def get_scans():
    if MODE == "live":
        return sc.scans.list()["usable"]
    return list(OFFLINE_SCANS.values())


def get_scan_details(scan_id):
    if MODE == "live":
        return sc.scans.details(scan_id)
    return OFFLINE_SCANS[str(scan_id)]


def get_asset(asset_id):
    if MODE == "live":
        return sc.asset_lists.details(asset_id)
    return OFFLINE_ASSETS.get(str(asset_id), {})

# ==========================================================
# SCAN FILTERING
# ==========================================================

INCLUDE_KEYWORDS = [] # e.g. ["Prod", "Weekly"]
EXCLUDE_KEYWORDS = [] # e.g. ["Discovery"]
MATCH_ALL_INCLUDE = False # True = must match all include keywords
CASE_SENSITIVE = False
FILTER_DISABLED_MODE = "ALL"
# Options:
# "ALL"             -> include enabled and disabled
# "ENABLED_ONLY"    -> exclude disabled
# "DISABLED_ONLY"   -> only disabled scans

def filter_scan(scans):
    if (not INCLUDE_KEYWORDS and not EXCLUDE_KEYWORDS and FILTER_DISABLED_MODE == "ALL"):
        print(f"[INFO] No filtering applied. Using all {len(scans)} scans")
        return scans
    
    filtered = []

    include_keywords = (INCLUDE_KEYWORDS if CASE_SENSITIVE else [k.lower() for k in INCLUDE_KEYWORDS])
    exclude_keywords = (EXCLUDE_KEYWORDS if CASE_SENSITIVE else [k.lower() for k in EXCLUDE_KEYWORDS])

    for scan in scans:
        name = (scan.get("info", {}).get("name") or scan.get("name", ""))

        compare_name = name if CASE_SENSITIVE else name.lower()

        # Enable state
        schedule = scan.get("schedule", {})
        enabled_raw = schedule.get("enabled")

        if isinstance(enabled_raw, str):
            enabled = enabled_raw.lower() == "true"
        elif isinstance(enabled_raw, bool):
            enabled = enabled_raw
        else:
            enabled = True # default assumption

        # Disable filtering
        if FILTER_DISABLED_MODE == "ENABLED_ONLY" and not enabled:
            continue
        if FILTER_DISABLED_MODE == "DISABLED_ONLY" and enabled:
            continue

        # Include
        include_pass = True
        if include_keywords:
            if MATCH_ALL_INCLUDE:
                include_pass = all(k in compare_name for k in include_keywords)
            else:
                include_pass = any(k in compare_name for k in include_keywords)

        # Exclude
        exclude_pass = True
        if exclude_keywords:
            if any(k in compare_name for k in exclude_keywords):
                exclude_pass = False

        if include_pass and exclude_pass:
            filtered.append(scan)

    #print(f"[INFO] Applying {EXCLUDE_KEYWORDS} as keyword to exclude")
    print(f"[INFO] Scans before filter: {len(scans)}")
    print(f"[INFO] Scans after filter: {len(filtered)}")
    print(f"[INFO] Disabled filter mode: {FILTER_DISABLED_MODE}")

    return filtered

# ==========================================================
# SCOPE UTILITIES
# ==========================================================

_parsed_cache = {}

def parse_scope_item(scope):
    scope = scope.strip()
    if scope in _parsed_cache:
        return _parsed_cache[scope]

    if "/" in scope:
        parsed = ("cidr", ipaddress.ip_network(scope, strict=False))
    elif "-" in scope:
        start, end = scope.split("-")
        parsed = ("range", (ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())))
    else:
        ip = ipaddress.ip_address(scope)
        parsed = ("cidr", ipaddress.ip_network(f"{ip}/32"))

    _parsed_cache[scope] = parsed
    return parsed


def split_scope_items(scope_string):
    return [x.strip() for x in scope_string.split(",") if x.strip()]


def scope_contains(actual, expected):
    at, av = actual
    et, ev = expected

    if at == "cidr" and et == "cidr":
        return ev.subnet_of(av)

    if at == "cidr" and et == "range":
        start, end = ev
        return start in av and end in av

    if at == "range" and et == "cidr":
        return av[0] <= ev.network_address and av[1] >= ev.broadcast_address

    if at == "range" and et == "range":
        return av[0] <= ev[0] and av[1] >= ev[1]

    return False


def scope_intersects(actual, expected):
    at, av = actual
    et, ev = expected

    if at == "cidr" and et == "cidr":
        return av.overlaps(ev)

    if at == "cidr" and et == "range":
        return ev[0] in av or ev[1] in av

    if at == "range" and et == "cidr":
        return av[0] <= ev.broadcast_address and av[1] >= ev.network_address

    if at == "range" and et == "range":
        return not (av[1] < ev[0] or av[0] > ev[1])

    return False


def scope_to_interval(parsed):
    t, v = parsed
    if t == "cidr":
        return (int(v.network_address), int(v.broadcast_address))
    return (int(v[0]), int(v[1]))


def merge_intervals(intervals):
    if not intervals:
        return []

    intervals.sort()
    merged = [intervals[0]]

    for start, end in intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))

    return merged


def scope_size(parsed):
    t, v = parsed
    if t == "cidr":
        return v.num_addresses
    return int(v[1]) - int(v[0]) + 1

# ==========================================================
# WORKBOOK INITIALIZATION
# ==========================================================

wb = Workbook()
scope_ws = wb.create_sheet("Scan_Scope_Summary")
normalized_ws = wb.create_sheet("Scan_Scope_Normalized")
wb.remove(wb['Sheet'])
#matrix_ws = wb.create_sheet("Coverage_Matrix")

scope_ws.append(["Scan Name", "Inclusion Type", "Source Type", "Source Name", "Scope Definition"])
normalized_ws.append(["Scan Name", "Asset Name", "Inclusion Type", "Scope Item"])

# ==========================================================
# NORMALIZATION PIPELINE AND DOG WALKER
# ==========================================================

def normalize_scope(scan_name, asset_name, inclusion_type, defined_string):
    for scope_item in split_scope_items(defined_string):
        normalized_ws.append([scan_name, asset_name, inclusion_type, scope_item])


def walk_combination(node, scan_name, in_complement=False):
    if not isinstance(node, dict):
        return

    op = node.get("operator")
    if op == "complement":
        in_complement = True

    if "id" in node and op is None:
        asset_id = node.get("id")
        if asset_id in (-1, None):
            return

        asset = get_asset(asset_id)
        defined = asset.get("typeFields", {}).get("definedIPs")
        asset_name = asset.get("name")

        inclusion_type = EXCLUDE if in_complement else INCLUDE

        if defined:
            scope_ws.append([
                scan_name,
                inclusion_type,
                "Asset",
                asset_name,
                defined
            ])
            normalize_scope(scan_name, asset_name, inclusion_type, defined)

        return

    walk_combination(node.get("operand1"), scan_name, in_complement)
    walk_combination(node.get("operand2"), scan_name, in_complement)

# ==========================================================
# BUILD SCOPE SHEETS
# ==========================================================

#-----------------------------------------------------------
# LOAD AND FILTER SCANS
#-----------------------------------------------------------

all_scans = get_scans()
filtered_scans = filter_scan(all_scans)

for scan in filtered_scans:
    scan_id = scan["id"]
    scan_name = scan["name"]
    details = get_scan_details(scan_id)

    # Direct IP List
    ip_list = details.get("ipList")
    if ip_list and ip_list != "*":
        scope_ws.append([scan_name, INCLUDE, "Scan", "Direct IP List", ip_list])
        normalize_scope(scan_name, "SCAN_IPLIST", INCLUDE, ip_list)

    # Assets
    for asset_ref in details.get("assets", []):
        asset = get_asset(asset_ref["id"])
        atype = asset.get("type")

        if atype == "static":
            defined = asset.get("typeFields", {}).get("definedIPs")
            asset_name = asset.get("name")

            if defined:
                scope_ws.append([scan_name, INCLUDE, "Asset", asset_name, defined])
                normalize_scope(scan_name, asset_name, INCLUDE, defined)

        elif atype == "combination":
            walk_combination(asset.get("typeFields", {}).get("combinations", {}), scan_name)

# ==========================================================
# BUILD COVERAGE DATA
# ==========================================================

actual_scopes = []
excluded_scopes = []

for row in normalized_ws.iter_rows(min_row=2, values_only=True):
    scan_name, asset_name, inclusion_type, scope_item = row
    if not scope_item:
        continue

    parsed = parse_scope_item(scope_item)

    if inclusion_type == INCLUDE:
        actual_scopes.append((parsed, scan_name, scope_item))
    elif inclusion_type == EXCLUDE:
        excluded_scopes.append((parsed, scan_name, asset_name, scope_item))

# ==============================
# BUILD MATRIX
# ==============================

# NOT AS USEFUL AS I THOUGHT. TO BE REMOVED IN LATER VERSION

# header = [cell.value for cell in next(normalized_ws.iter_rows(min_row=1, max_row=1))]

# col_idx = {name: idx for idx, name in enumerate(header)}

# # Build lookup (scope_item, scan_name) -> Inclusion Type
# matrix_map = defaultdict(dict)

# scan_names = set()
# scope_items = set()

# for row in normalized_ws.iter_rows(min_row=2, values_only=True):
#     scan_name = row[col_idx["Scan Name"]]
#     asset_name = row[col_idx["Asset Name"]]
#     inclusion_type = row[col_idx["Inclusion Type"]]
#     scope_item = row[col_idx["Scope Item"]]

#     if not scan_name or not scope_item:
#         continue

#     scan_names.add(scan_name)
#     scope_items.add(scope_item)

#     # Exclude overrides include if both
#     if scope_item in matrix_map and scan_name in matrix_map[scope_item]:
#         if matrix_map[scope_item][scan_name] == EXCLUDE:
#             continue

#     matrix_map[scope_item][scan_name] = inclusion_type

# ==============================
# CREATE MATRIX SHEET
# ==============================

#matrix_ws = wb.create_sheet("Coverage_Matrix")
# scan_names = sorted(scan_names)
# scope_items = sorted(scope_items)

# matrix_ws.append(["Scope Item"] + scan_names)

# for scope in scope_items:
#     row = [scope]

#     for scan in scan_names:
#         value = matrix_map.get(scope, {}).get(scan)

#         if value == INCLUDE:
#             row.append("I")
#         elif value == EXCLUDE:
#             row.append("E")
#         else:
#             row.append("")

#     matrix_ws.append(row)

# ==========================================================
# EXPECTED VS ACTUAL
# ==========================================================

portfolio_expected_total = 0
portfolio_covered_total = 0
portfolio_gap_total = 0
portfolio_exclusion_total = 0
portfolio_included_total = 0

exclusion_impact_by_scan = defaultdict(int)

if EXPECTED_SCOPE_FILE:
    expected_wb = load_workbook(EXPECTED_SCOPE_FILE)
    expected_ws = expected_wb["rsg-all"]

    compare_ws = wb.create_sheet("Expected_vs_Actual")
    compare_ws.append([
        "Environment",
        "Location",
        "Expected",
        "Expected IPs",
        "Net Covered IPs",
        "Net Portfolio Gap",
        "% Scan Coverage Suppressed",
        "Covered",
        "Scans Covering",
        #"Exclusion Scans",
        "Status",
        "Reason"
    ])

    compliance_ws = wb.create_sheet("Expected_Range_Compliance")
    compliance_ws.append([
        "Environment",
        "Location",
        "Expected Range",
        "Expected IPs",
        "Covered IPs",
        "Gap IPs",
        "Coverage %",
    ])

    for row in expected_ws.iter_rows(min_row=2, values_only=True):
        scope_item, location, environment, required_scan = row[:4]
        if not scope_item:
            continue

        expected = parse_scope_item(scope_item)
        expected_size = scope_size(expected)

        exp_start, exp_end = scope_to_interval(expected)

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

        for scan in covering_scans:
            included = []
            excluded = []

            for act, s, raw in actual_scopes:
                if s == scan and scope_intersects(act, expected):
                    act_start, act_end = scope_to_interval(act)

                    overlap_start = max(act_start, exp_start)
                    overlap_end = min(act_end, exp_end)

                    if overlap_start <= overlap_end:
                        included.append((overlap_start, overlap_end))

            for excl, s, asset_name, raw in excluded_scopes:
                if s == scan and scope_intersects(excl, expected):
                    excl_start, excl_end = scope_to_interval(excl)

                    overlap_start = max(excl_start, exp_start)
                    overlap_end = min(excl_end, exp_end)

                    if overlap_start <= overlap_end:
                        interval = (overlap_start, overlap_end)
                        excluded.append(interval)
                        loss = overlap_end - overlap_start + 1
                        
                        relevant_exclusions[scan].append({
                            "asset": asset_name,
                            "scope": raw,
                            "loss": loss
                        })

                        exclusion_ip_total += loss
                        exclusion_impact_by_scan[scan] += loss

            included = merge_intervals(included)
            excluded = merge_intervals(excluded)

            inc_count = sum(e - s + 1 for s, e in included)
            exc_count = sum(e - s + 1 for s, e in excluded)

            total_included_ips += inc_count

            net_intervals = []

            for inc_start, inc_end in included:
                remaining = [(inc_start, inc_end)]

                for exc_start, exc_end in excluded:
                    temp = []
                    for r_start, r_end in remaining:
                        if exc_end < r_start or exc_start > r_end:
                            temp.append((r_start, r_end))
                        else:
                            if exc_start > r_start:
                                temp.append((r_start, exc_start - 1))
                            if exc_end < r_end:
                                temp.append((exc_end + 1, r_end))
                    remaining = temp

                net_intervals.extend(remaining)

            cover_intervals.extend(net_intervals)

        cover_intervals = merge_intervals(cover_intervals)
        covered_count = sum(e - s + 1 for s, e in cover_intervals)

        # Safety
        covered_count = min(covered_count, expected_size)

        gap_count = max(0, expected_size - covered_count)

        percent_lost = (round((exclusion_ip_total / total_included_ips) * 100, 2) if total_included_ips else 0.0)

        portfolio_expected_total += expected_size
        portfolio_covered_total += covered_count
        portfolio_gap_total += gap_count
        portfolio_exclusion_total += exclusion_ip_total
        portfolio_included_total += total_included_ips

        exclusion_scans_list = sorted(scan for scan in relevant_exclusions if relevant_exclusions[scan])

        if covered_count == expected_size:
            status = STATUS_OK
            covered = "Yes"
            reason = "Fully contained by scan scope"

        elif covered_count > 0:
            status = STATUS_PARTIAL
            covered = "Partial"

            if exclusion_ip_total > 0:
                exclusion_lines = []

                for scan in sorted(relevant_exclusions):
                    for entry in relevant_exclusions[scan]:
                        exclusion_lines.append(
                            f"{scan} | {entry['asset']} | "
                            f"{entry['scope']} ({entry['loss']} IPs)"
                        )

                reason = (
                    f"Excluded {exclusion_ip_total} IPs:\n" +
                    "\n".join(exclusion_lines)
                )
            else:
                reason = "Partial coverage detected"

        else:
            status = STATUS_GAP
            covered = "No"
            reason = "No scan scope intersects expected range"

        compare_ws.append([
            environment,
            location,
            scope_item,
            expected_size,
            covered_count,
            gap_count,
            percent_lost,
            covered,
            ", ".join(sorted(covering_scans)),
            #", ".join(sorted(relevant_exclusions.keys())),
            status,
            reason
        ])

        coverage_pct = round((covered_count / expected_size) * 100, 2) if expected_size else 0.0

        compliance_ws.append([
            environment,
            location,
            scope_item,
            expected_size,
            covered_count,
            gap_count,
            coverage_pct
        ])

# ==============================
# TOP EXCLUSION IMPACT SHEET
# ==============================

impact_ws = wb.create_sheet("Top_Exclusion_Impact_Scans")

impact_ws.append(["Scan Name", "Total IPs Excluded"])

for scan, total in sorted(exclusion_impact_by_scan.items(), key=lambda x: x[1], reverse=True):
    impact_ws.append([scan, total])

# ==============================
# EXEC SHEET
# ==============================

exec_ws = wb.create_sheet("Executive_Summary")

exec_ws.append(["Metric", "Value", "Note"])

overall_coverage_pct = (
    round((portfolio_covered_total / portfolio_expected_total) * 100, 2)
    if portfolio_expected_total else 0.0
)

portfolio_exclusion_loss_pct = (
    round((portfolio_exclusion_total / portfolio_included_total) * 100, 2)
    if portfolio_included_total else 0.0
)

print(portfolio_included_total)

exec_ws.append(["Total Expected IPs", portfolio_expected_total, "Number of IP addresses from expected ranges (Global IP Address Trackers)"])
exec_ws.append(["Total Net Covered IPs", portfolio_covered_total, "Number of IP addresses covered by scans"])
exec_ws.append(["Total Gap IPs", portfolio_gap_total, "Number of IP addresses not covered by scans"])
exec_ws.append(["Overall Portfolio Coverage %", overall_coverage_pct, "Percentage of IP addresses not covered by scans (Total Net Covered IPs/Total Expected IPs)"])
exec_ws.append(["Total IPs Lost Due To Exclusions", portfolio_exclusion_total, "Number of IP addresses excluded in scans"])
exec_ws.append(["% Coverage Lost Due To Exclusions", portfolio_exclusion_loss_pct, "Percentage of coverage lost due to exclusions (Total Excluded/Total Included)"])

# ==============================
# FORMATTING
# ==============================

#wb.save("tenable_scan_scope_summary.xlsx")

HEADER_FONT = Font(bold=True)

GREEN = PatternFill("solid", fgColor="C6EFCE")
YELLOW = PatternFill("solid", fgColor="FFEB9C")
RED = PatternFill("solid", fgColor="F4CCCC")
GRAY = PatternFill("solid", fgColor="E7E6E6")

def find_column(ws, header_name):
    for idx, cell in enumerate(ws[1], start=1):
        if cell.value == header_name:
            return idx
    return None

def auto_wrap_and_adjust(ws, column_name):
    col_idx = None

    for idx, cell in enumerate(ws[1], start=1):
        if cell.value == column_name:
            col_idx = idx
            break

    if not col_idx:
        return
    
    for row in ws.iter_rows(min_row=2):
        cell = row[col_idx - 1]
        if not cell.value:
            continue

        cell.alignment = Alignment(wrap_text=True)

        line_count = str(cell.value).count("\n") + 1

        ws.row_dimensions[cell.row].height = 15 * line_count

def format_sheet(ws, status_col=None, include_exclude_col=None, percent_col=None, coverage_col=None):

    ws.freeze_panes = "A2"

    # Header style
    ws.auto_filter.ref = ws.dimensions
    for cell in ws[1]:
        cell.font = HEADER_FONT
        cell.fill = GRAY

    # Auto size columns
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            if cell.value:
                max_len = max(max_len, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = min(max_len + 2, 60)

    # Status coloring
    if status_col:
        for row in ws.iter_rows(min_row=2):
            cell = row[status_col - 1]
            if cell.value == STATUS_OK:
                cell.fill = GREEN
            elif cell.value == STATUS_PARTIAL:
                cell.fill = YELLOW
            elif cell.value == STATUS_GAP:
                cell.fill = RED

    # Include / Exclude color
    if include_exclude_col:
        for row in ws.iter_rows(min_row=2):
            cell = row[include_exclude_col - 1]
            if cell.value == INCLUDE:
                cell.fill = GREEN
            elif cell.value == EXCLUDE:
                cell.fill = RED 

    # Percent format
    if percent_col:
        for row in ws.iter_rows(min_row=2):
            cell = row[percent_col - 1]
            if isinstance(cell.value, (int, float)):
                #cell.number_format = "0.00%"
                if cell.value >= 90:
                    cell.fill = GREEN
                elif cell.value >= 70:
                    cell.fill = YELLOW
                else:
                    cell.fill = RED

    if coverage_col:
        for row in ws.iter_rows(min_row=2):
            metric = row[0].value
            value_cell = row[0]

            if "Coverage %" in str(metric):
                value_cell.number_format = "0.00%"
                if value_cell.value >= 95:
                    value_cell.fill = GREEN
                elif value_cell.value >= 85:
                    value_cell.fill = YELLOW
                else:
                    value_cell.fill = RED

            if metric == "Total Gap IPs" and value_cell.value > 0:
                value_cell.fill = RED

# ==============================
# FORMAT SHEETS
# ==============================

format_sheet(scope_ws, include_exclude_col=find_column(scope_ws, "Inclusion Type"))
#format_sheet(normalized_ws, include_exclude_col=find_column(normalized_ws, "Inclusion Type"))
format_sheet(compare_ws, status_col=find_column(compare_ws, "Status"))
format_sheet(compliance_ws, percent_col=find_column(compliance_ws, "Coverage %"))
format_sheet(exec_ws, coverage_col=find_column(exec_ws, "Overall Portfolio Coverage %"))

# for row in matrix_ws.iter_rows(min_row=2, min_col=2):
#     for cell in row:
#         if cell.value == "I":
#             cell.fill = GREEN
#         elif cell.value == "E":
#             cell.fill = RED

# format_sheet(matrix_ws)
format_sheet(impact_ws)

# auto_wrap_and_adjust(scope_ws, "Scope Definition")
#auto_wrap_and_adjust(normalized_ws, "Scope Item")

# if "Expected_vs_Actual" in wb.sheetnames:
#         auto_wrap_and_adjust(wb["Expected_vs_Actual"], "Reason")

normalized_ws.sheet_state = "hidden"

wb.move_sheet(exec_ws, offset=1)

# ==========================================================
# SAVE
# ==========================================================

wb.save(OUTPUT_FILE)
