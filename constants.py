from pathlib import Path

INCLUDE = "Include"
EXCLUDE = "Exclude"

STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"
STATUS_GAP = "GAP"

DEFAULT_EXPECTED_SHEET = "rsg-all"
FALLBACK_EXPECTED_SHEET = "Expected_Ranges"
DEFAULT_OUTPUT_FILE = Path("output") / "tenable_scan_summary_v7.xlsx"

SHEET_SCAN_SCOPE_SUMMARY = "Scan_Scope_Summary"
SHEET_SCAN_SCOPE_NORMALIZED = "Scan_Scope_Normalized"
SHEET_EXPECTED_VS_ACTUAL = "Expected_vs_Actual"
SHEET_EXPECTED_RANGE_COMPLIANCE = "Expected_Range_Compliance"
SHEET_TOP_EXCLUSION_IMPACT = "Top_Exclusion_Impact_Scans"
SHEET_EXECUTIVE_SUMMARY = "Executive_Summary"
SHEET_WARNINGS = "Warnings"
