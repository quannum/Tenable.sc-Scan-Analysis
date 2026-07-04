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
- subnet_as_code>=0.0.1 (required for authoritative expected-range input; install from the internal package repository)
- pyTenable (only required for live mode)

Install:

pip install -r requirements.txt

Note: `subnet_as_code>=0.0.1` is a required internal dependency for the coverage workflow. Make sure your environment can install it from the internal package repository before running the authoritative expected-range commands.

For live Tenable.sc API mode:

`pip install ".[live]"`

For an editable local install with the `tenable-scan-analysis` command:

`pip install -e .`

For the scheduled detect-and-plan workflow command:

`tenable-coverage-scheduled --config-file examples/tenable-coverage-service.toml`


------

# Execution

python main.py

If installed as a package, run:

`tenable-scan-analysis`

The unified enterprise workflow is available as `tenable-sc-scan-analysis` and
provides the required command surface:

```text
validate-definitions  Normalize and validate authoritative network scope
collect-tenable       Collect a redacted Tenable.sc inventory snapshot
analyze-coverage      Compare authoritative scope with Tenable configuration
propose-changes       Generate dry-run CSV/Markdown/JSONL change artifacts
apply-changes         Apply an approved plan (explicit --apply is mandatory)
export-report         Create a portable report bundle from a completed run
```

Examples:

```powershell
tenable-sc-scan-analysis validate-definitions `
  --source-json-file C:\network\sites.json `
  --output-file C:\output\normalized-sites.json

tenable-sc-scan-analysis collect-tenable `
  --mode live `
  --output-file C:\output\tenable-inventory.json

tenable-sc-scan-analysis propose-changes `
  --source-json-file C:\network\sites.json `
  --scan-json-dir C:\tenable\scans `
  --asset-json-dir C:\tenable\assets `
  --output-dir C:\output
```

Live collection reads `SC_URL`, `SC_ACCESS_KEY`, and `SC_SECRET_KEY` from the
environment. The inventory artifact includes repositories, asset groups,
detailed scan definitions and schedules, policies, credential metadata, and
observed hosts. Secret-like fields are recursively redacted before the snapshot
is atomically written. A permission failure for one resource is recorded in
`collection_errors` without discarding the rest of the snapshot; use
`--fail-on-partial` when partial collection should fail the job.

Tenable connections default to certificate verification, a 60-second timeout,
three retries, and 1.5-second exponential backoff. Configure these with
`sc_ssl_verify`, `sc_timeout_seconds`, `sc_retries`, and `sc_backoff_seconds`.
Disabling certificate verification requires the explicit
`--no-sc-ssl-verify` option and is not recommended.

### Applying approved changes

`propose-changes` writes `proposed_changes.csv` with every row initially marked
`PENDING`. A reviewer must change selected rows to `APPROVED` and populate the
`Reviewer` column. Automatic application is limited to asset/scan creation and
target attachment actions; review-only exclusion, partial-coverage, and
wrong-scan actions are skipped rather than guessed.

Application requires every safety gate below:

- the `apply-changes` command
- the explicit `--apply` flag
- `--mode live`
- an approved CSV plan with one Run ID and a reviewer on every approved row
- a positive repository ID
- `SC_URL`, `SC_ACCESS_KEY`, and `SC_SECRET_KEY` from the environment
- unique exact asset, scan, and policy names
- all referenced policies present before the first mutation

```powershell
tenable-sc-scan-analysis apply-changes `
  --mode live `
  --plan-file C:\output\runs\run-001\proposed_changes.csv `
  --repository-id 7 `
  --result-file C:\output\runs\run-001\apply_result.json `
  --apply
```

Static assets and scan attachments are reconciled idempotently. Existing target
ranges and scan assets are retained, and matching reruns report `UNCHANGED`.
Existing scans are reconciled to the selected repository and named policy.
Every write is followed by a live details read; verification failure is recorded
as `FAILED`. The command writes machine-readable JSON plus a human-readable
Markdown apply audit, including the source plan SHA-256.

Detect-and-plan runs also produce `coverage_results.json`/`.csv`,
`coverage_summary.json`/`.md`, `extra_scan_targets.json`, and
`definition_validation_issues.json`. Summaries group expected, covered, and gap
IPs by region, site, VLAN, required scan type, configured repository, and
policy. They list missing asset groups, missing required scans, policy
mismatches, and wholly or partially extra scan target ranges.

All unified commands can load YAML, JSON, or TOML configuration with the global
`--config-file` option. Settings resolve in this order: explicit CLI flag,
environment variable, command-specific config, global config, built-in default.
See `config/example-config.yaml`. Keep credentials in environment variables or
mounted secrets rather than configuration files.

You can also run as a module after install:

`python -m src`

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

Use structured JSON logs for SIEM ingestion:

`python main.py --scan-json-dir C:\Scans --asset-json-dir C:\Assets --no-expected-scope --log-format json`

Export every workbook sheet as CSV files for BI tools:

`python main.py --scan-json-dir C:\Scans --asset-json-dir C:\Assets --expected-scope-file C:\expected.xlsx --csv-output-dir C:\output\csv`

Provide settings from a config file (`.toml` or `.json`), with CLI flags overriding config values:

`python main.py --config-file C:\config\tenable-scan.toml`

Output:

output\tenable_scan_summary-YYYYMMDD-HHMMSS.xlsx

The default filename includes the run date and time to avoid overwriting earlier reports from the same day.
Each run also writes a machine-readable summary JSON file to `output\run_summary.json` by default
(or the path provided by `--run-summary-file`).

Console output includes `INFO` and `WARNING` messages for skipped records, invalid scope values, and workbook save completion.
If warnings are encountered during processing, they are also written into a `Warnings` sheet in the output workbook.
Each workbook also includes a `Run_Metadata` sheet with selected inputs, filters, output path, log settings, optional CSV path, summary path, and run timestamp.

------

# Scheduled Detect-And-Plan Service

The GitOps subnet-as-code workflow is designed to run as a single-shot scheduled job rather than a permanently running daemon.
That makes it a good fit for:

- Kubernetes `CronJob`
- Jenkins or GitHub Actions scheduled pipelines
- Windows Task Scheduler
- `systemd` timers

Use the scheduler wrapper:

`tenable-coverage-scheduled --config-file examples/tenable-coverage-service.toml`

What it adds on top of `tenable-coverage-detect-plan`:

- Config-file and environment-driven startup
- A lock file to prevent overlapping scheduled runs
- Stale-lock recovery for interrupted jobs
- `RUNNING`, `SUCCESS`, and `FAILED` lifecycle state in `latest_run.json`
- A persisted `latest_run.json` pointer for external monitoring
- Optional JSON log output for SIEM and scheduler ingestion
- A reusable Docker image entrypoint

### Authoritative network sources

The detect-and-plan workflow normalizes every authoritative input into the same
site and coverage-target models. Configure any combination of these inputs; the
highest-priority configured source is selected:

1. `--source-api-url` / `NETWORK_SOURCE_API_URL` (normalized internal JSON API)
2. `--source-json-file` / `NETWORK_SOURCE_JSON_FILE` (local copy of that JSON)
3. `--github-api-url` plus `--github-repository` (direct GitHub Enterprise YAML)
4. `--subnet-repo-path` / `SUBNET_REPO_PATH` (local YAML checkout/fallback)
5. `--source-xlsx-file` / `NETWORK_SOURCE_XLSX_FILE` (legacy/manual workbook)

API bearer credentials are read from `NETWORK_SOURCE_API_TOKEN`. Direct GitHub
retrieval reads `GITHUB_TOKEN`; tokens are intentionally omitted from the
unified CLI flags so they do not appear in process listings. Mounted/environment
secrets are recommended. Requests
use a bounded timeout and retry transient network and server failures. The JSON
root may be a site, a list of sites, or an object containing `sites`,
`locations`, or `data`. CIDRs and explicit `start-end` IP ranges are normalized
with Python `ipaddress` before analysis.

Example local JSON invocation:

`tenable-coverage-detect-plan --source-json-file C:\network\sites.json --mode offline --scan-json-dir C:\tenable\scans --asset-json-dir C:\tenable\assets`

The exact strong schema will be finalized against the representative internal
API/YAML payload. Until then, validation issues are retained in audit output and
invalid sites or ranges are excluded from coverage planning.

The XLSX connector accepts a row-oriented worksheet with a scope column named
`Scope Item`, `Scope`, `CIDR`, `IP Range`, or `Network`. Optional columns include
site code/name, location, region, timezone, tags, environment, business function,
target type, VLAN name/ID, required asset, required scan, and required policy.
Explicit IP ranges are summarized into canonical CIDRs. Use
`--source-xlsx-sheet` when definitions are not on the first worksheet.

For GitHub Enterprise Server, set the REST base URL (typically
`https://HOSTNAME/api/v3`), repository as `OWNER/REPO`, optional ref, and optional
repository path. The connector recursively follows the Contents API, requests
raw YAML, preserves the selected ref on child requests, rejects unsafe paths,
and retries transient failures. The token needs read-only repository Contents
permission.

Important deployment note:

- The scheduler can retrieve YAML directly from GitHub Enterprise, or it can
  analyze an externally refreshed checkout mounted at `subnet_repo_path`.
- Scheduled detect-and-plan runs remain dry-run only; mutation is isolated to the
  separately invoked, explicitly gated `apply-changes --apply` command.

Container example:

```bash
docker build -t tenable-coverage-service .
docker run --rm \
  -v /srv/subnet-repo:/data/subnet-repo \
  -v /srv/tenable-output:/data/output \
  -v /srv/tenable-json/scans:/data/tenable/scans \
  -v /srv/tenable-json/assets:/data/tenable/assets \
  tenable-coverage-service \
  --config-file examples/tenable-coverage-service.toml
```

A hardened Kubernetes CronJob and ConfigMap example is provided at
`deploy/kubernetes/cronjob.yaml`. It forbids overlapping jobs, runs as a
non-root user with a read-only root filesystem, mounts credentials from a
Secret, and keeps authoritative input read-only. Replace the example image,
Secret, PVC names, and schedule before deployment.


------

# Testing

Run the scope and interval math tests with:

`python -m unittest tests/test_scope_math.py`

Run the full test suite with:

`python -m unittest discover -s tests -t . -p "test_*.py"`

------

# Project Layout

Core application code is in:

`src/`

Suggested internal boundaries:

- `core/` - scope parsing and coverage logic
- `io/` - config, prompts, and Tenable/offline data access
- `reporting/` - workbook generation and formatting
- `cli/` - orchestration entrypoint

Automated tests are in:

`tests/`


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
