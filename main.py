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
)
from app_config import build_config
from data_access import DataAccess
from reporting import (
    append_executive_summary,
    build_impact_sheet,
    build_run_metadata_sheet,
    build_warning_sheet,
    build_workbook,
    format_workbook,
)

LOGGER = logging.getLogger(__name__)


class WarningCollector(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append(
            {
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


def configure_logging(level_name):
    level = getattr(logging, str(level_name).upper(), logging.INFO)
    collector = WarningCollector()
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s", force=True)
    logging.getLogger().addHandler(collector)
    return collector


def run_analysis(config, warning_records=None):
    data_access = DataAccess(config)
    workbook, scope_ws, normalized_ws = build_workbook()

    build_scope_sheets(scope_ws, normalized_ws, data_access, config)
    actual_scopes, excluded_scopes, actual_by_scan, excluded_by_scan = (
        build_coverage_data(normalized_ws)
    )

    compare_ws, compliance_ws, exclusion_impact_by_scan, totals = (
        analyze_expected_ranges(
            workbook,
            config.expected_scope_file,
            actual_scopes,
            actual_by_scan,
            excluded_by_scan,
        )
    )

    impact_ws = build_impact_sheet(workbook, exclusion_impact_by_scan)
    exec_ws = append_executive_summary(workbook, totals)
    warning_ws = build_warning_sheet(workbook, warning_records or [])
    metadata_ws = build_run_metadata_sheet(workbook, config, config.output_file)
    format_workbook(
        scope_ws,
        normalized_ws,
        compare_ws,
        compliance_ws,
        impact_ws,
        exec_ws,
        warning_ws=warning_ws,
        metadata_ws=metadata_ws,
    )

    config.output_file.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(config.output_file)
    return config.output_file


def main(argv=None):
    config = build_config(argv)
    collector = configure_logging(config.log_level)
    LOGGER.info("Starting Tenable SC scan coverage analysis in %s mode", config.mode)

    output_path = run_analysis(config, warning_records=collector.records)
    LOGGER.info("Workbook saved to %s", output_path)


if __name__ == "__main__":
    main()
