# Tenable SC Scan Coverage Analysis

## Overview

This project validates Tenable.sc scan and asset coverage against an
authoritative `subnet_as_code` source.

It supports:

- offline analysis from exported scan JSON and asset JSON
- live analysis against the Tenable.sc API
- authoritative network loading from the internal `subnet_as_code` module
- dry-run coverage validation and proposed-change generation
- JSON, CSV, Markdown, and audit-log reporting for scheduled or manual runs

The current branch is focused on the subnet-as-code workflow only. The older
XLSX expected-range workflow lives separately in a legacy branch.

At a high level, each coverage run:

1. Calls the configured `subnet_as_code` method.
2. Normalizes returned site, public range, private range, and VLAN data.
3. Applies asset, scan, and policy naming rules.
4. Loads Tenable scan and asset configuration from live API or offline JSON.
5. Compares expected ranges against configured scan inclusions and exclusions.
6. Writes coverage results, proposed changes, audit logs, and summary reports.


------

# Key Capabilities

## 1. Dual Mode Operation

Supports:

- Live Mode – Pulls data directly from Tenable.sc API
- Offline Mode – Loads asynchronously exported scan and asset JSON files

Switch via the `--mode` CLI option or configuration file settings.

------

## 2. Keyword-based and Enabled Status Scan Filtering

Allows filtering enabled or disabled scans before scope processing.

Allows inclusion or exclusion of scans before scope processing.

Filtering occurs **before normalization**, so all downstream coverage outputs
reflect the filtered scan criteria.

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

The old matrix experiment is currently disabled and is not generated in the
current workflow outputs.

It previously created a 2D matrix like:

Scope Item	Scan A	Scan B	Scan C
10.0.0.0/24	I		E

Legend:
-I = Included
-E = Excluded
-Blank = Not referenced

Exclusions override inclusions.

------

## 6. Authoritative Coverage Analysis

The current workflow:

- loads authoritative ranges from `subnet_as_code`
- normalizes returned CIDRs, single IPs, and explicit `start-end` ranges
- compares authoritative ranges to actual Tenable.sc scan coverage
- reports whether the required scan name derived for each target is actually one
  of the scans covering that target
- assigns workflow status:
  - OK
  - PARTIAL
  - GAP
  - EXCLUDED

### Exclusion Impact Math

For each authoritative target range:

1. Compute included intervals
2. Compute excluded intervals
3. Subtract exclusions from inclusion
4. Merge intervals
5. Calculate net coverage

Metrics:

* Expected IPs
* Covered IPs
* Gap IPs
* Coverage percentage
* Excluded IP impact for ranges where scan exclusions reduce net coverage

------

## 7. Coverage Metrics

For each authoritative target:
- Calculates total expected IP count
- Calculates covered IP count
- Computes coverage percentage

------

## 8. Executive Summary

Aggregates:

* Total Expected IPs
* Total Covered IPs
* Total Gap IPs
* Overall Coverage %
* Status counts by coverage state
* Missing asset groups
* Missing required scans
* Policy mismatches
* Extra or stale scan target findings

Coverage and audit reporting also includes exclusion-heavy scans and proposed
exclusion candidates in the generated JSON, CSV, and Markdown artifacts.

------

# Output Artifacts

Primary workflow artifacts include:

- `coverage_results.json`
- `coverage_results.csv`
- `coverage_summary.json`
- `coverage_summary.md`
- `extra_scan_targets.json`
- `proposed_exclusions.json`
- `proposed_exclusions.csv`
- `definition_validation_issues.json`
- `proposed_changes.csv`
- `proposed_changes.md`
- `audit.jsonl`
- `final_audit_report.md`
- `run_summary.json`

------

# Authoritative Source Format

The authoritative source is the internal `subnet_as_code` Python module. The
workflow supports payloads that contain site data directly or under wrapper keys
such as `site_definition`, `sites`, `locations`, or `data`.

Authoritative-source validation keeps invalid records out of coverage planning
and records issues in `definition_validation_issues.json`. It rejects IPv6
scopes, reports invalid CIDRs/ranges, flags duplicate ranges, and warns on
unexpected overlaps except for expected private-supernet-to-VLAN containment.

------

# Configuration

The unified CLI and scheduled service accept YAML, JSON, or TOML config files.

For the unified CLI, the root config section is:

- `tenable_sc_scan_analysis`

For the scheduled service wrapper, the root config section is:

- `tenable_coverage_workflow_service`

The scheduler example is here:

- `examples/tenable-coverage-service.toml`


------

# Environment and Location

Environment and location fields come from the authoritative data returned by
the selected `subnet_as_code` query method.


------

# Dependencies
- Python 3.10+
- python-dotenv
- subnet_as_code>=0.0.1 (required authoritative-source dependency; install from the internal package repository)
- pyTenable (only required for live mode)

Install:

pip install -r requirements.txt

Note: `subnet_as_code>=0.0.1` is a required internal dependency for the coverage workflow. Make sure your environment can install it from the internal package repository before running authoritative-source commands.

To install this project as a package from the repository root:

- Standard install:

  `pip install .`

- Editable install for development:

  `pip install -e .`

For live Tenable.sc API mode:

`pip install ".[live]"`

For an editable local install with the console commands available immediately:

`pip install -e ".[live]"`

Package install provides these commands:

- `tenable-sc-scan-analysis` - unified authoritative-source workflow
- `tenable-coverage-detect-plan` - direct detect-and-plan workflow entry point
- `tenable-coverage-scheduled` - scheduled service wrapper

For the scheduled detect-and-plan workflow command:

`tenable-coverage-scheduled --config-file examples/tenable-coverage-service.toml`


------

# Execution

The unified workflow is available as `tenable-sc-scan-analysis` and provides
the required command surface:

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
  --subnet-as-code-method get_sites `
  --output-file C:\output\normalized-sites.json

tenable-sc-scan-analysis collect-tenable `
  --mode live `
  --output-file C:\output\tenable-inventory.json

tenable-sc-scan-analysis propose-changes `
  --subnet-as-code-method get_sites `
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
`Reviewer` column. The CSV includes a `Source Reference` column pointing back to
the `subnet_as_code` method/result item that produced the target. Automatic
application is limited to asset/scan creation and target attachment actions;
review-only exclusion, partial-coverage, and wrong-scan actions are skipped
rather than guessed.

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
mismatches, and wholly or partially extra scan target ranges. The Markdown
summary includes policy mismatch and extra/stale target sections for easier
human review.

At the moment, `analyze-coverage` and `propose-changes` both run the same
underlying detect-and-plan pipeline and emit the same core audit/report
artifacts. `propose-changes` is the clearer command when you explicitly want
the proposed-change outputs.

### Running the workflow correctly

The newer workflow modules use package-relative imports such as
`from ..core...` and `from .subnet_source...`.

Because of that, do not run files like these directly:

- `python src/tenable_coverage_workflow/run_detect_and_plan.py`
- `python src/tenable_coverage_workflow/application_cli.py`

Direct file execution makes Python treat the file as a standalone script, so
relative imports do not have a parent package to resolve from.

Use one of these supported launch methods instead:

- installed console scripts:
  - `tenable-sc-scan-analysis ...`
  - `tenable-coverage-detect-plan ...`
  - `tenable-coverage-scheduled ...`
- module execution from the repository root:
  - `python -m src.tenable_coverage_workflow.application_cli ...`
  - `python -m src.tenable_coverage_workflow.run_detect_and_plan ...`

Examples:

```powershell
tenable-sc-scan-analysis analyze-coverage `
  --subnet-as-code-method get_sites `
  --mode offline `
  --scan-json-dir C:\tenable\scans `
  --asset-json-dir C:\tenable\assets `
  --output-dir C:\output

python -m src.tenable_coverage_workflow.application_cli analyze-coverage `
  --subnet-as-code-method get_sites `
  --mode offline `
  --scan-json-dir C:\tenable\scans `
  --asset-json-dir C:\tenable\assets `
  --output-dir C:\output
```

All unified commands can load YAML, JSON, or TOML configuration with the global
`--config-file` option. Settings resolve in this order: explicit CLI flag,
environment variable, command-specific config, global config, built-in default.
Keep credentials in environment variables or mounted secrets rather than
configuration files.

You can also run the package entry point as a module:

`python -m src`

Example configuration-driven scheduled run:

`tenable-coverage-scheduled --config-file examples/tenable-coverage-service.toml`

Typical outputs from detect-and-plan and analyze-coverage runs include:

- `coverage_results.json`
- `coverage_results.csv`
- `coverage_summary.json`
- `coverage_summary.md`
- `extra_scan_targets.json`
- `proposed_exclusions.json`
- `proposed_exclusions.csv`
- `definition_validation_issues.json`
- `proposed_changes.csv`
- `proposed_changes.md`
- `audit.jsonl`
- `final_audit_report.md`
- `run_summary.json`

Console output includes `INFO` and `WARNING` messages for skipped records,
invalid scope values, and report generation. Warnings are also retained in the
run artifacts and audit outputs.

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

The detect-and-plan workflow now uses the internal `subnet_as_code` Python
module as the authoritative source. It imports the module at
runtime and calls the selected query method directly.

Default method:

1. `get_sites`

Configure `--subnet-as-code-method` / `SUBNET_AS_CODE_METHOD` explicitly when
you want a different `subnet_as_code` query method or when you prefer the
configuration to be self-documenting.

Optional filters are passed through only when the selected method supports them:

1. `--source-reference-id` / `SUBNET_AS_CODE_REFERENCE_ID`
2. `--source-sites` / `SUBNET_AS_CODE_SITES`
3. `--source-tags` / `SUBNET_AS_CODE_TAGS`
4. `--source-name` / `SUBNET_AS_CODE_NAME`
5. `--source-network-type` / `SUBNET_AS_CODE_NETWORK_TYPE`
6. `--source-routing-type` / `SUBNET_AS_CODE_ROUTING_TYPE`
7. `--source-desired-properties` / `SUBNET_AS_CODE_DESIRED_PROPERTIES`
8. `--source-address-type` / `SUBNET_AS_CODE_ADDRESS_TYPE`

When `--source-sites` is omitted, the workflow queries all sites returned by the
chosen `subnet_as_code` method. This is the recommended setup for scheduled runs
that should automatically detect newly added sites or VLANs.

Example all-sites invocation:

`tenable-coverage-detect-plan --subnet-as-code-method get_sites --mode offline --scan-json-dir C:\tenable\scans --asset-json-dir C:\tenable\assets`

Example filtered invocation:

`tenable-coverage-detect-plan --subnet-as-code-method get_sites_properties --source-sites NYC,LON --source-tags production --source-desired-properties site_code,private_ranges --mode offline --scan-json-dir C:\tenable\scans --asset-json-dir C:\tenable\assets`

Offline mode always requires both `--scan-json-dir` and `--asset-json-dir`.
Live mode requires `SC_URL`, `SC_ACCESS_KEY`, and `SC_SECRET_KEY` through
environment variables, config, or explicit CLI flags where supported.

The returned payload may be a site object, a list of sites, or an object
containing `site_definition`, `sites`, `locations`, or `data`. CIDRs and
explicit `start-end` IP ranges are normalized with Python `ipaddress` before
analysis. Validation issues are retained in audit output and invalid sites or
ranges are excluded from coverage planning.

### Optional VLAN tag grouping

Asset and scan grouping can optionally be driven by VLAN tags from
`subnet_as_code`.

When `grouping_mode = "vlan_tag"` is enabled:

- only tags starting with `grouping_vlan_tag_prefix` are considered
- the first matching tag wins
- `grouping_tag_map` can translate tags such as `vlan-workstation` into
  internal group roles such as `END_USER`
- if no matching prefixed tag is found, the workflow falls back to the current
  VLAN-name-based grouping logic

Example:

```toml
grouping_mode = "vlan_tag"
grouping_vlan_tag_prefix = "vlan-"
grouping_tag_map = { vlan-server = "SERVER", vlan-mgmt = "NETWORK", vlan-workstation = "END_USER", vlan-wireless = "WIRELESS" }
```

Important deployment note:

- The workflow itself does not reimplement repository access logic; that is
  delegated to the installed `subnet_as_code` module.
- Scheduled detect-and-plan runs remain dry-run only; mutation is isolated to the
  separately invoked, explicitly gated `apply-changes --apply` command.

Container example:

```bash
docker build -t tenable-coverage-service .
docker run --rm \
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
- `io/` - parsing and Tenable/offline data access
- `tenable_coverage_workflow/` - authoritative-source loading, orchestration, planning, reporting, and scheduling

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
Coverage / Gap Evaluation
      ↓
Audit + Report Artifacts


------

# Design Characteristics
- Exclusion precedence is enforced
- Combination assets are recursively resolved
- Coverage is deterministic - calculated using interval merging
- Exclusion aware coverage logic
- Full containment and partial coverage are differentiated
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
- No automatic deduplication of overlapping authoritative ranges
- Required Scan matching is name-based

------

# Enhancement Ideas
- IPAM integration
- Environment tagging via metadata
- VLAN/CIDR containment validation
- GitOps integration
- CMDB pipeline validation

------
