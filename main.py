"""
Tenable SC Scan Coverage Analysis
Ken Parker
19 February 2026
"""

import logging

from analysis import (
    analyze_expected_ranges,
    build_coverage_data,
    build_scope_sheets,
    resolve_expected_sheet,
    validate_expected_row,
)
from app_config import build_config
from data_access import DataAccess, load_json_folder
from reporting import (
    append_executive_summary,
    auto_wrap_and_adjust,
    build_impact_sheet,
    build_workbook,
    find_column,
    format_sheet,
    format_workbook,
)
from scope_utils import (
    merge_intervals,
    parse_scope_item,
    scope_contains,
    scope_intersects,
    scope_size,
    scope_to_interval,
    split_scope_items,
    subtract_intervals,
)


LOGGER = logging.getLogger(__name__)


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
