"""
Tenable SC Scan Coverage Analysis
Ken Parker
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ..constants import VERSION
from ..core.analysis import analyze_expected_ranges
from ..core.tenable_scope_analysis import (
    build_coverage_data,
    build_scope_sheets,
)
from ..io.app_config import build_config
from ..io.data_access import DataAccess
from ..reporting.workbook import (
    append_executive_summary,
    build_impact_sheet,
    build_run_metadata_sheet,
    build_warning_sheet,
    build_workbook,
    export_workbook_sheets_to_csv,
    format_workbook,
)

LOGGER = logging.getLogger(__name__)


class WarningCollector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[dict[str, str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(
            {
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(
    level_name: str, log_file: Path | None = None, log_format: str = "text"
) -> WarningCollector:
    level = getattr(logging, str(level_name).upper(), logging.INFO)
    collector = WarningCollector()
    stream_handler = logging.StreamHandler()
    if str(log_format).lower() == "json":
        formatter: logging.Formatter = JsonLogFormatter()
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=level, handlers=[stream_handler], force=True)
    root_logger = logging.getLogger()
    root_logger.addHandler(collector)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    return collector


def run_analysis(config, warning_records=None) -> Path:
    data_access = DataAccess(config)
    workbook, scope_ws, normalized_ws = build_workbook()
    summary_path = config.run_summary_file or (
        config.output_file.parent / "run_summary.json"
    )
    if config.run_summary_file is None:
        config.run_summary_file = summary_path

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
            expected_sheet=config.expected_sheet,
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

    csv_exports = []
    if config.csv_output_dir:
        csv_exports = export_workbook_sheets_to_csv(workbook, config.csv_output_dir)

    atomic_save_workbook(workbook, config.output_file)
    summary_payload = build_run_summary(
        config=config,
        output_path=config.output_file,
        totals=totals,
        exclusion_impact_by_scan=exclusion_impact_by_scan,
        warning_records=warning_records or [],
        workbook=workbook,
        csv_exports=csv_exports,
    )
    atomic_write_json(summary_payload, summary_path)
    return config.output_file


def atomic_save_workbook(workbook, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".xlsx",
            prefix="tenable-scan-",
            dir=output_path.parent,
            delete=False,
        ) as tmp:
            temp_file = tmp.name

        workbook.save(temp_file)
        os.replace(temp_file, output_path)
    finally:
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)


def atomic_write_json(payload: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="tenable-scan-",
            dir=output_path.parent,
            delete=False,
            encoding="utf-8",
        ) as tmp:
            temp_file = tmp.name
            json.dump(payload, tmp, indent=2, sort_keys=True)
            tmp.write("\n")

        os.replace(temp_file, output_path)
    finally:
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)


def build_run_summary(
    config,
    output_path: Path,
    totals,
    exclusion_impact_by_scan,
    warning_records,
    workbook,
    csv_exports,
) -> dict:
    run_started_at = getattr(config, "run_started_at", None)
    coverage_pct = (
        round(
            (totals.portfolio_covered_total / totals.portfolio_expected_total) * 100,
            2,
        )
        if totals.portfolio_expected_total
        else 0.0
    )

    top_exclusion_scans = sorted(
        exclusion_impact_by_scan.items(), key=lambda item: item[1], reverse=True
    )[:10]

    return {
        "run_started_at": (
            run_started_at.isoformat(sep=" ", timespec="seconds")
            if run_started_at
            else None
        ),
        "mode": config.mode,
        "version": VERSION,
        "output_file": str(output_path),
        "run_summary_file": str(
            config.run_summary_file or (output_path.parent / "run_summary.json")
        ),
        "log_level": config.log_level,
        "log_format": getattr(config, "log_format", "text"),
        "log_file": str(config.log_file) if config.log_file else None,
        "csv_output_dir": str(config.csv_output_dir) if config.csv_output_dir else None,
        "csv_exports": [str(path) for path in csv_exports],
        "sheet_names": [sheet.title for sheet in workbook.worksheets],
        "sheet_row_counts": {
            sheet.title: max(0, sheet.max_row - 1) for sheet in workbook.worksheets
        },
        "warning_count": len(warning_records),
        "totals": {
            "expected_ips": totals.portfolio_expected_total,
            "covered_ips": totals.portfolio_covered_total,
            "gap_ips": totals.portfolio_gap_total,
            "excluded_ips": totals.portfolio_exclusion_total,
            "included_ips": totals.portfolio_included_total,
            "coverage_pct": coverage_pct,
        },
        "top_exclusion_scans": [
            {"scan_name": scan_name, "excluded_ips": excluded}
            for scan_name, excluded in top_exclusion_scans
        ],
    }


def main(argv=None) -> int:
    try:
        config = build_config(argv)
        collector = configure_logging(
            config.log_level, config.log_file, config.log_format
        )
        LOGGER.info(
            "Starting Tenable SC scan coverage analysis in %s mode", config.mode
        )

        output_path = run_analysis(config, warning_records=collector.records)
        LOGGER.info("Workbook saved to %s", output_path)
        return 0
    except SystemExit:
        raise
    except Exception:
        logging.getLogger().exception("Analysis failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
