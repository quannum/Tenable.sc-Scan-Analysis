# Goal Requirements Audit

This audit maps the active goal to current repository evidence. "Implemented"
means code and automated evidence exist in this worktree; it does not claim that
an external Tenable.sc or GitHub Enterprise tenant was modified during tests.

| Requirement | Status | Evidence |
|---|---|---|
| subnet_as_code API authoritative source | Implemented | `subnet_source/source_loader.py`; connector tests |
| Common internal source model | Implemented | `models.py`; `docs/authoritative-schema.md` |
| Site, region, timezone, tags, environment, business function, scan metadata | Implemented | source connectors and coverage detail reports |
| CIDR and IP-range normalization with `ipaddress` | Implemented | subnet-as-code normalization and parser tests |
| Public/private/VLAN validation | Implemented | malformed, IPv4, label warning, and VLAN containment checks |
| Missing, extra, overlap, duplicate, malformed, partial coverage | Implemented | source validation, coverage engine, extra target reporting |
| Expected asset and scan mapping | Implemented | naming rules, configuration index, coverage results |
| Region/site/VLAN/scan/repository/policy summaries | Implemented | `coverage_reporting.py` JSON and Markdown outputs |
| Site-aware scan designs | Implemented | naming rules compose region, site/location, description or role fallback, and assessment/discovery purpose |
| Dry-run proposed changes | Implemented | detect-and-plan defaults and CSV/Markdown audit |
| Idempotent asset/scan application | Implemented | exact-name reconciliation and repeat-run tests |
| Explicit mutation safety | Implemented | approved reviewer rows, live mode, repository, `apply-changes --apply` |
| Post-change validation | Implemented | live asset and scan detail rereads after writes |
| Human audit output | Implemented | proposed-change, coverage, apply, and final Markdown reports |
| SIEM/machine-readable output | Implemented | JSON, CSV, structured logs, JSONL audit events |
| Scheduled service and Kubernetes CronJob | Implemented | service runner, Dockerfile, hardened CronJob manifest |
| Environment/mounted secrets; no hardcoded secrets | Implemented | SC, API, and GitHub tokens loaded from environment/Secret refs |
| Error handling, retry, timeout, TLS, exit codes | Implemented | connectors, DataAccess, CLI exit constants, transport tests |
| Required six CLI commands | Implemented | `application_cli.py` and CLI tests |
| YAML-driven configuration | Implemented | unified and scheduled YAML config loaders and examples |
| Unit/integration-safe tests | Implemented | parsing, math, analysis, reports, planning, application, service tests |
| Representative payload defines final strong schema | Implemented | `docs/authoritative-schema.md`; subnet-as-code parser and source tests cover the supplied top-level site list with `supernet` / `subnets` and API-first JSON ingestion path |
| Real tenant smoke validation | Environment-dependent | Requires authorized non-production Tenable.sc/GitHub endpoints |

## Output Audit

The run directory contains evidence for all named output categories:

- coverage summaries by required dimensions;
- missing assets and scans;
- policy mismatches;
- full and partially extra/stale targets;
- overlap and partial coverage findings;
- proposed asset, scan, target, policy, and exclusion actions;
- pending approval CSV/Markdown;
- final audit Markdown and machine-readable run summary;
- apply JSON/Markdown with plan fingerprint and per-operation result.

## Remaining Completion Condition

Real tenant smoke validation remains environment-dependent. The authoritative
source schema itself is now grounded in the supplied subnet-as-code example and
API module contract; any future API version changes should be handled as
compatibility updates rather than as a missing-schema blocker.
