# Tenable SC Scan Coverage Analysis

## Overview

This script extracts scan scope definitions from Tenable Security Center and produces a structured Excel workbook that:

- Enumerates all scan scope definitions with union operator logic (exclusion-aware)
- Normalizes CIDR and IP ranges
- Builds a scan-to-scope coverage matrix
- Compares actual scan coverage against expected IP ranges
- Calculates per-range compliance metrics
- Highlights coverage gaps and partial coverage

The output is a consolidated workbook:

tenable_scan_scope_summary.xlsx


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

## 5. Coverage Matrix (DEFUNCT)

* I commented this section out because it didn't turn out particularly useful

Creates a 2D matrix:

Scope Item	Scan A	Scan B	Scan C
10.0.0.0/24	I		E

Legend:
-I = Included
-E = Excluded
-Blank = Not referenced

Exclusions override inclusions.

------

## 6. Expected vs Actual Coverage Analysis

If EXPECTED_SCOPE_FILE is defined, the script:
- Loads expected ranges from sheet: Expected_Ranges (e.g., IP address tracker export)
- Compares expected ranges to actual scan coverage
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
| Coverage_Matrix            | Scan-to-scope mapping         |
| Expected_vs_Actual         | Coverage analysis             |
| Expected_Range_Compliance  | % coverage per expected range |
| Top_Exclusion_Impact_Scans | Exclusion-heavy scans         |
| Executive_Summary          | Organization overview         |

------

# Expected Scope File Format

Workbook: expected_scope.xlsx
Sheet: Expected_Ranges

Minimum required columns:

Scope Item	Location Environment


Scope Item supports:
- CIDR notation (10.0.0.0/24)
- IP range (10.0.0.1-10.0.0.50)
- Single IP

------

# Configuration

MODE = "offline"

SCAN_JSON_DIR = Path("C:\\Scans\\")
ASSET_JSON_DIR = Path("C:\\AssetGroups\\")

EXPECTED_SCOPE_FILE = "expected_scope.xlsx"

SC_ACCESS_KEY = ""
SC_SECRET_KEY = ""
SC_URL = ""


------

# Environment and Location

Environment and location columns are gathered from IP address tracker data (expected_scope.xlsx) 


------

# Dependencies
- Python 3.9+
- openpyxl
- ipaddress
- tenable.sc (only required for live mode)

Install:

pip install openpyxl tenable.sc


------

# Execution

python pytenable-scan-scope-summary.py

Output:

tenable_scan_scope_summary.xlsx


------

# Architecture Summary

Scan Extraction
      ↓
Scan Filtering (if applicable)
      ↓
Scope Normalization
      ↓
Matrix Construction
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
- No native support for IPv6
- No automatic deduplication of overlapping expected ranges
- Required Scan column is currently informational only

------

# Enhancement Ideas
- IPAM integration
- Environment tagging via metadata
- VLAN/CIDR containment validation
- CLI argument support
- GitOps integration
- CMDB pipeline validation

------