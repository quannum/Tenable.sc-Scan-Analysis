# Tenable SC Scan Coverage Analysis

Validate Tenable.sc scan and asset coverage against authoritative network data
from the internal `subnet_as_code` Python module.

The workflow can run against exported Tenable JSON files or the live Tenable.sc
API. It normalizes expected network scope, compares it with configured scan
inclusions and exclusions, and writes audit-friendly JSON, CSV, and Markdown
reports.

## What It Does

Each coverage run:

1. Calls the configured `subnet_as_code` method.
2. Normalizes returned site, public range, private range, VLAN, CIDR, single-IP,
   and explicit `start-end` range data.
3. Applies asset, scan, and policy naming rules.
4. Loads Tenable scan and asset configuration from live API or offline JSON.
5. Filters scans when requested.
6. Calculates net coverage after exclusions.
7. Writes coverage results, proposed changes, audit logs, and summaries.

## Modes

`offline` mode loads exported JSON files:

- `scan_json_dir`
- `asset_json_dir`

`live` mode connects to Tenable.sc:

- `TCW_SC_URL`
- `TCW_SC_ACCESS_KEY`
- `TCW_SC_SECRET_KEY`

Legacy `SC_*` environment names are accepted as fallbacks for live credentials.

Live Tenable connections default to certificate verification, a 60-second
timeout, three retries, and 1.5-second exponential backoff. Configure those with
`sc_ssl_verify`, `sc_timeout_seconds`, `sc_retries`, and `sc_backoff_seconds`.
Disabling certificate verification requires `--no-sc-ssl-verify`.

## Install

Requirements:

- Python 3.10+
- Access to the internal package source for `subnet_as_code>=0.0.1`
- `pyTenable` only when using live mode

Install base dependencies:

```powershell
pip install -r requirements.txt
```

Install the package from the repository root:

```powershell
pip install .
```

For live Tenable.sc API mode:

```powershell
pip install ".[live]"
```

For local development with console commands available immediately:

```powershell
pip install -e ".[live]"
```

Installed console commands:

- `tenable-sc-scan-analysis` - unified CLI
- `tenable-coverage-detect-plan` - direct detect-and-plan entry point
- `tenable-coverage-scheduled` - scheduler-friendly wrapper

## Unified CLI

Use `tenable-sc-scan-analysis` for manual validation, collection, analysis,
proposal generation, applying approved changes, and report export.

```text
validate-definitions  Normalize and validate authoritative network scope
collect-tenable       Collect a redacted Tenable.sc inventory snapshot
analyze-coverage      Compare authoritative scope with Tenable configuration
propose-changes       Generate dry-run proposed-change artifacts
apply-changes         Apply an approved plan; explicit --apply is required
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

tenable-sc-scan-analysis analyze-coverage `
  --subnet-as-code-method get_sites `
  --mode offline `
  --scan-json-dir C:\tenable\scans `
  --asset-json-dir C:\tenable\assets `
  --output-dir C:\output

tenable-sc-scan-analysis propose-changes `
  --subnet-as-code-method get_sites `
  --mode live `
  --output-dir C:\output
```

`collect-tenable` redacts secret-like fields before writing the inventory
snapshot. Permission failures for individual resource types are recorded in
`collection_errors`; add `--fail-on-partial` when partial collection should fail
the command.

`analyze-coverage` and `propose-changes` use the same detect-and-plan pipeline.
Use `propose-changes` when you explicitly want reviewer-facing proposed-change
artifacts.

## Configuration Files

The unified CLI accepts YAML, JSON, or TOML config files with the root section
`tenable_sc_scan_analysis`.

Settings resolve in this order:

1. Explicit CLI flag
2. Environment variable
3. Command-specific config
4. Global config
5. Built-in default

Keep credentials in environment variables or mounted secrets rather than config
files.

Minimal offline config:

```yaml
tenable_sc_scan_analysis:
  subnet_as_code_method: get_sites
  mode: offline
  scan_json_dir: C:/tenable/scans
  asset_json_dir: C:/tenable/assets

  commands:
    analyze_coverage:
      output_dir: C:/tenable-output
    propose_changes:
      output_dir: C:/tenable-output
```

Run with:

```powershell
tenable-sc-scan-analysis --config-file config\example-config.yaml analyze-coverage
```

The direct `tenable-coverage-detect-plan` entry point is intended for flag/env
use. Use the unified CLI or scheduled wrapper when you want config-file driven
runs.

Example config files:

- `config/example-config.yaml`
- `examples/tenable-coverage-service.toml`

## Authoritative Source

The authoritative source is `subnet_as_code`. By default the workflow calls
`get_sites`.

Configure another method with:

- `--subnet-as-code-method`
- `SUBNET_AS_CODE_METHOD`
- `subnet_as_code_method` in config

Optional source filters:

- `source_reference_id` / `--source-reference-id` / `SUBNET_AS_CODE_REFERENCE_ID`
- `source_sites` / `--source-sites` / `SUBNET_AS_CODE_SITES`
- `source_tags` / `--source-tags` / `SUBNET_AS_CODE_TAGS`
- `source_name` / `--source-name` / `SUBNET_AS_CODE_NAME`
- `source_network_type` / `--source-network-type` / `SUBNET_AS_CODE_NETWORK_TYPE`
- `source_routing_type` / `--source-routing-type` / `SUBNET_AS_CODE_ROUTING_TYPE`
- `source_desired_properties` / `--source-desired-properties` /
  `SUBNET_AS_CODE_DESIRED_PROPERTIES`
- `source_address_type` / `--source-address-type` /
  `SUBNET_AS_CODE_ADDRESS_TYPE`

When `source_sites` is omitted, the selected method queries all returned sites.
That is the recommended scheduled setup when new sites or VLANs should be
detected automatically.

The workflow supports payloads containing site data directly or under wrapper
keys such as `site_definition`, `sites`, `locations`, or `data`. Validation
rejects IPv6 scope, reports invalid CIDRs/ranges, flags duplicate ranges, and
warns on unexpected overlaps except for expected private-supernet-to-VLAN
containment.

## Scan Filtering

Filtering happens before coverage normalization, so downstream reports reflect
only the selected scans.

Available options:

- `include_keywords`
- `exclude_keywords`
- `match_all_include`
- `case_sensitive`
- `filter_disabled_mode`: `ALL`, `ENABLED_ONLY`, or `DISABLED_ONLY`

Examples:

```yaml
include_keywords: Discovery
exclude_keywords: Deprecated
match_all_include: false
case_sensitive: false
filter_disabled_mode: ENABLED_ONLY
```

With `match_all_include: true`, every include keyword must be present in the
scan name.

## Coverage Results

For each authoritative target, the workflow calculates:

- expected IP count
- covered IP count
- gap IP count
- coverage percentage
- exclusion impact
- required asset presence
- required scan presence
- policy match status
- extra or stale Tenable target findings

Coverage statuses:

- `OK`
- `PARTIAL`
- `GAP`
- `EXCLUDED`

Common output artifacts:

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

## Applying Approved Changes

`propose-changes` writes `proposed_changes.csv` with rows initially marked
`PENDING`. A reviewer must change selected rows to `APPROVED` and populate the
`Reviewer` column.

Application is intentionally gated. It requires:

- `apply-changes`
- explicit `--apply`
- `--mode live`
- one approved Run ID in the plan
- a reviewer on every approved row
- a positive repository ID
- Tenable.sc URL, access key, and secret key
- unique exact asset, scan, and policy names
- all referenced policies present before mutation

Example:

```powershell
tenable-sc-scan-analysis apply-changes `
  --mode live `
  --plan-file C:\output\runs\run-001\proposed_changes.csv `
  --repository-id 7 `
  --result-file C:\output\runs\run-001\apply_result.json `
  --apply
```

Static assets and scan attachments are reconciled idempotently. Existing target
ranges and scan assets are retained, matching reruns report `UNCHANGED`, and
each write is followed by a live details read.

## Scheduled Service

The scheduled workflow is a single-shot job, not a permanently running daemon.
Run it from Kubernetes `CronJob`, Jenkins, GitHub Actions schedules, Windows
Task Scheduler, or `systemd` timers.

Use:

```powershell
tenable-coverage-scheduled --config-file examples\tenable-coverage-service.toml
```

The scheduled wrapper adds:

- config-file and environment-driven startup
- lock file protection against overlapping runs
- stale-lock recovery
- `RUNNING`, `SUCCESS`, and `FAILED` state in `latest_run.json`
- optional JSON logs for scheduler or SIEM ingestion
- Docker entrypoint compatibility

The scheduled config root section is `tenable_coverage_workflow_service`.
Like the unified CLI, the scheduled wrapper accepts YAML, JSON, or TOML config
files.

Minimal live service config:

```toml
[tenable_coverage_workflow_service]
job_name = "tenable-coverage-all-sites"
subnet_as_code_method = "get_sites"

output_dir = "C:/tenable-output"
latest_summary_file = "C:/tenable-output/latest_run.json"
lock_file = "C:/tenable-output/scheduler.lock"
stale_lock_timeout_seconds = 21600

dry_run = true
mode = "live"

log_level = "INFO"
log_format = "json"
log_file = "C:/tenable-output/tenable-coverage-service.log"
```

Scheduled detect-and-plan runs are always dry-run. Mutation remains isolated to
the explicitly gated `apply-changes --apply` command.

Windows Task Scheduler example:

```text
Program/script:
powershell.exe

Arguments:
-NoProfile -ExecutionPolicy Bypass -Command "cd 'E:\Documents\GitHub\Tenable.sc-Scan-Analysis'; tenable-coverage-scheduled --config-file 'examples\tenable-coverage-service.toml'"
```

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
`deploy/kubernetes/cronjob.yaml`. Replace the example image, Secret, PVC names,
release tag, and schedule before deployment.

## VLAN Tag Grouping

Asset and scan grouping can optionally use VLAN tags from `subnet_as_code`.

When `grouping_mode` is `vlan_tag`:

- only tags starting with `grouping_vlan_tag_prefix` are considered
- the first matching tag wins
- `grouping_tag_map` translates tags into internal group roles
- missing matching tags fall back to VLAN-name-based grouping

Example:

```toml
grouping_mode = "vlan_tag"
grouping_vlan_tag_prefix = "vlan-"
grouping_tag_map = { vlan-server = "SERVER", vlan-mgmt = "NETWORK", vlan-workstation = "END_USER", vlan-wireless = "WIRELESS" }
```

## Running From Source

Do not run package files directly, such as:

- `python src/tenable_coverage_workflow/run_detect_and_plan.py`
- `python src/tenable_coverage_workflow/application_cli.py`

Those modules use package-relative imports. From the repository root, use
console scripts after installation or module execution:

```powershell
python -m src.tenable_coverage_workflow.application_cli analyze-coverage `
  --subnet-as-code-method get_sites `
  --mode offline `
  --scan-json-dir C:\tenable\scans `
  --asset-json-dir C:\tenable\assets `
  --output-dir C:\output

python -m src.tenable_coverage_workflow.service_runner `
  --config-file examples\tenable-coverage-service.toml
```

The package entry point also works:

```powershell
python -m src
```

## Testing

Run the scope and interval math tests:

```powershell
python -m unittest tests/test_scope_math.py
```

Run the full test suite:

```powershell
python -m unittest discover -s tests -t . -p "test_*.py"
```

## Project Layout

- `src/core/` - scope parsing and coverage logic
- `src/io/` - parsing and Tenable/offline data access
- `src/tenable_coverage_workflow/` - source loading, orchestration, planning,
  reporting, application, and scheduling
- `tests/` - automated tests
- `config/` - unified CLI config example
- `examples/` - scheduled service config example
- `deploy/` - deployment examples

## Design Notes

- Exclusions take precedence over inclusions.
- Combination assets are resolved recursively.
- Coverage math is deterministic and interval-based.
- Full containment and partial coverage are reported separately.
- Invalid JSON records and malformed scope values are skipped with warnings.
- Environment detection and required scan matching are name-based.
- IPv6 scope is intentionally rejected.
