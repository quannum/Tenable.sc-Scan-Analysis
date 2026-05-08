# Tenable SC Scan Coverage Analysis

## Overview

This script extracts scan scope definitions from Tenable Security Center and produces a structured Excel workbook that:

- Enumerates all scan scope definitions with union operator logic (exclusion-aware)
- Normalizes CIDR and IP ranges
- Compares actual scan coverage against expected IP ranges
- Calculates per-range compliance metrics
- Highlights coverage gaps and partial coverage

The output is a consolidated workbook:

output\tenable_scan_summary-YYYYMMDD-HHMMSS.xlsx


------

# Key Capabilities

## 1. Dual Mode Operation

Supports:
- Live Mode – Pulls data directly from Tenable.sc API
- Offline Mode – Loads asynchronously exported scan and asset JSON files

Switch via:

### MODE = "live"      # or "offline"

------

## 2. Keyword-based and Enabled Status Scan Filtering

Allows filtering enabled or disabled scans before scope processing.

Allows inclusion or exclusion of scans before scope processing.

Filtering occurs **before normalization**, ensuring all downstream sheets reflect the filtered scan criteria.

## Behavior

### No Filtering

```python
INCLUDE_KEYWORDS = []
EXCLUDE_KEYWORDS = []
FILTER_DISABLED_MODE = "ALL"
```

All scans are analyzed.

---

### Enabled Scans

```python
FILTER_DISABLED_MODE = "ENABLED_ONLY"
```

Includes enabled scans only

---

### Disabled Scans

```python
FILTER_DISABLED_MODE = "DISABLED_ONLY"
```

Includes disabled scans only

---

### Only Discovery Scans

```python
INCLUDE_KEYWORDS = ["Discovery"]
```

---

### Exclude Discovery

```python
EXCLUDE_KEYWORDS = ["Discovery"]
```

---

### Require Multiple Keywords

```python
INCLUDE_KEYWORDS = ["Online", "Weekly"]
MATCH_ALL_INCLUDE = True
```

Scan name must contain **both** words.

------

## 3. Scan Scope Extraction

Processes:
- Direct scan IP lists
- Static asset groups
- Combination asset groups (recursive walker)
- Include / Exclude logic

Combination assets are traversed recursively to resolve nested include/exclude relationships.

------

## 4. Scope Normalization

Scope items are parsed into comparable structures:
- CIDR blocks
- IP ranges
- Single IPs (treated as /32)

Internally converted to interval math for coverage calculations.

------

## 5. Coverage Matrix (Disabled)

The old matrix experiment is currently disabled in the script and is not generated in the workbook.

It previously created a 2D matrix like:

Scope Item	Scan A	Scan B	Scan C
10.0.0.0/24	I		E

Legend:
-I = Included
-E = Excluded
-Blank = Not referenced

Exclusions override inclusions.

------

## 6. Expected vs Actual Coverage Analysis

If `EXPECTED_SCOPE_FILE` is selected, the script:
- Loads expected ranges from sheet `rsg-all`
- Falls back to `Expected_Ranges` if `rsg-all` is not present
- Supports case-insensitive matching when `--expected-sheet` is provided
- Compares expected ranges to actual scan coverage
- Reports whether the optional `Required Scan` value is one of the scans covering each expected range
- Performs:
    - Full containment checks
    - Partial intersection checks
    - Exclusion subtraction
    - Interval merging
- Assigns status:
    - OK
    - PARTIAL
    - GAP

### Exclusion Impact Math

For each expected range:

1. Compute included intervals
2. Compute excluded intervals
3. Subtract exclusions from inclusion
4. Merge intervals
5. Calculate net coverage

Metrics:

* Expected IPs
* Covered IPs
* Gap IPs
* % Scan Coverage Suppressed (This is "how much of the scan configured coverage was suppressed by exclusions".
                             It is NOT "how much of the given range is excluded". This metric is meant to highlight
                             scans that have an usually high number of exclusions.)

------

## 7. Expected Range Compliance Metrics

For each expected range:
- Calculates total expected IP count
- Calculates covered IP count
- Computes coverage percentage
- Applies conditional formatting

------

## 8. Executive Summary

Aggregates:

* Total Expected IPs
* Total Covered IPs
* Total Gap IPs
* Overall Coverage %
* Total Exclusion Loss
* % Coverage Lost to Exclusions

Also generates:

```
Top_Exclusion_Impact_Scans
```

Sorted by exclusion IP impact.

------

# Output Workbook Structure

| Sheet                      | Purpose                       |
| -------------------------- | ----------------------------- |
| Scan_Scope_Summary         | Raw scan scope definitions    |
| Scan_Scope_Normalized      | One row per scope item        |
| Expected_vs_Actual         | Coverage analysis             |
| Expected_Range_Compliance  | % coverage per expected range |
| Top_Exclusion_Impact_Scans | Exclusion-heavy scans         |
| Executive_Summary          | Organization overview         |
| Warnings                   | Skipped records and validation warnings, when present |
| Run_Metadata               | Run timestamp, mode, input paths, filters, and output path |

------

# Expected Scope File Format

Workbook: expected_scope.xlsx
Sheet: `rsg-all` or `Expected_Ranges`

Minimum required columns, in order:

`Scope Item | Location | Environment | Required Scan`


Scope Item supports:
- CIDR notation (10.0.0.0/24)
- IP range (10.0.0.1-10.0.0.50)
- Single IP

------

# Configuration

MODE = "offline"

SCAN_JSON_DIR = chosen via file picker
ASSET_JSON_DIR = chosen via file picker

EXPECTED_SCOPE_FILE = chosen via file picker

SC_ACCESS_KEY = ""
SC_SECRET_KEY = ""
SC_URL = ""


------

# Environment and Location

Environment and location columns are gathered from IP address tracker data (expected_scope.xlsx) 


------

# Dependencies
- Python 3.10+
- openpyxl
- python-dotenv
- pyTenable (only required for live mode)

Install:

pip install -r requirements.txt

For live Tenable.sc API mode:

`pip install ".[live]"`

For an editable local install with the `tenable-scan-analysis` command:

`pip install -e .`


------

# Execution

python main.py

If installed as a package, run:

`tenable-scan-analysis`

Optional CLI arguments can be used instead of the file pickers:

`python main.py --scan-json-dir C:\Scans --asset-json-dir C:\Assets --expected-scope-file C:\expected.xlsx --output-file C:\output\report.xlsx`

Manual runs can omit paths and use file pickers. Future scheduled jobs should include `--non-interactive` so missing inputs fail immediately instead of waiting on a GUI prompt:

`python main.py --non-interactive --scan-json-dir C:\Scans --asset-json-dir C:\Assets --expected-scope-file C:\expected.xlsx --output-file C:\output\report.xlsx`

Use a specific expected-ranges worksheet:

`python main.py --scan-json-dir C:\Scans --asset-json-dir C:\Assets --expected-scope-file C:\expected.xlsx --expected-sheet Expected_Ranges`

To skip expected-vs-actual analysis intentionally:

`python main.py --scan-json-dir C:\Scans --asset-json-dir C:\Assets --no-expected-scope`

Non-interactive scope-only run:

`python main.py --non-interactive --scan-json-dir C:\Scans --asset-json-dir C:\Assets --no-expected-scope`

Live mode does not require offline JSON directory arguments:

`python main.py --mode live --expected-scope-file C:\expected.xlsx`

Live mode requires `SC_URL`, `SC_ACCESS_KEY`, and `SC_SECRET_KEY` to be set (for example in `.env`).
If any are missing, the run exits with a clear validation error before API calls.

Show the installed version:

`python main.py --version`

Write console logs to a file as well:

`python main.py --scan-json-dir C:\Scans --asset-json-dir C:\Assets --no-expected-scope --log-file C:\logs\tenable-scan-analysis.log`

Output:

output\tenable_scan_summary-YYYYMMDD-HHMMSS.xlsx

The default filename includes the run date and time to avoid overwriting earlier reports from the same day.

Console output includes `INFO` and `WARNING` messages for skipped records, invalid scope values, and workbook save completion.
If warnings are encountered during processing, they are also written into a `Warnings` sheet in the output workbook.
Each workbook also includes a `Run_Metadata` sheet with the selected inputs, filters, output path, optional log path, and run timestamp.


------

# Testing

Run the scope and interval math tests with:

`python -m unittest test_scope_math.py`

Run the full test suite with:

`python -m unittest test_scope_math.py test_analysis.py test_filtering.py test_end_to_end.py test_app_config.py test_data_access.py test_main.py`


------

# Architecture Summary

Scan Extraction
      ↓
Scan Filtering (if applicable)
      ↓
Scope Normalization
      ↓
Coverage Analytics
      ↓
Compliance Calculation
      ↓
Excel Reporting


------

# Design Characteristics
- Exclusion precedence is enforced
- Combination assets are recursively resolved
- Coverage is deterministic - calculated using interval merging
- Exclusion aware coverage logic
- Full containment and partial coverage are differentiated
- Excel formatting is applied programmatically
- Invalid JSON records and malformed scope values are skipped with warnings instead of aborting the run

------

# Intended Use Cases
- Scan coverage validation
- Audit preparation
- Compliance reporting
- Scope rationalization
- Gap detection

------

# Limitations
- Environment detection is name-based
- IPv6 scopes are intentionally rejected with a warning
- No automatic deduplication of overlapping expected ranges
- Required Scan matching is name-based

------

# Enhancement Ideas
- IPAM integration
- Environment tagging via metadata
- VLAN/CIDR containment validation
- GitOps integration
- CMDB pipeline validation

------
