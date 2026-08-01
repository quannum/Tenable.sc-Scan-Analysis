import argparse
import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, TypedDict, cast

from dotenv import load_dotenv

from ..core.scope_utils import parse_scope_item, scope_to_interval
from ..core.tenable_scope_analysis import (
    build_coverage_data,
    build_scope_sheets,
    build_scope_tables,
    calculate_coverage_result,
    extract_scan_name,
)
from ..io.data_access import DataAccess
from ..io.parsing import parse_csv_list
from .audit import AuditLogger, write_proposed_change_audits
from .audit.audit_logger import atomic_write_json
from .coverage_reporting import write_coverage_reports, write_final_audit_report
from .exclusion_tags import find_exclusion_tag
from .grouping_config import build_grouping_config
from .models import CoverageTarget, CoverageValidationResult, GroupingConfig
from .planning import apply_naming_rules_to_targets, generate_proposed_changes
from .settings import (
    SettingsResolver,
    parse_bool,
    parse_nonnegative_float,
    parse_positive_int,
)
from .subnet_source import (
    AuthoritativeSourceConfig,
    load_authoritative_source,
)
from .subnet_source.source_config import (
    add_authoritative_source_arguments,
    build_authoritative_source_config,
)

LOGGER = logging.getLogger(__name__)


class ConfigurationDataAccess(Protocol):
    def get_asset_lists(self) -> list[dict[str, Any]]:
        """List asset groups"""
        ...

    def get_scans(self) -> list[dict[str, Any]]:
        """List scans"""
        ...

    def get_scan_details(self, scan_id: Any) -> dict[str, Any]:
        """Read one scan configuration"""
        ...


@dataclass
class DetectAndPlanConfig:
    source_config: AuthoritativeSourceConfig
    output_dir: Path
    run_id: str | None
    dry_run: bool
    mode: str
    scan_json_dir: str | None
    asset_json_dir: str | None
    sc_access_key: str | None
    sc_secret_key: str | None
    sc_url: str | None
    include_keywords: list[str]
    exclude_keywords: list[str]
    match_all_include: bool
    case_sensitive: bool
    filter_disabled_mode: str
    log_level: str = "INFO"
    log_format: str = "text"
    log_file: Path | None = None
    sc_timeout_seconds: int = 60
    sc_retries: int = 3
    sc_backoff_seconds: float = 1.5
    sc_ssl_verify: bool = True
    grouping_config: GroupingConfig = field(default_factory=GroupingConfig)


@dataclass
class CoverageSourceConfig:
    mode: str
    scan_json_dir: str | None
    asset_json_dir: str | None
    sc_access_key: str | None
    sc_secret_key: str | None
    sc_url: str | None
    include_keywords: list[str]
    exclude_keywords: list[str]
    match_all_include: bool
    case_sensitive: bool
    filter_disabled_mode: str
    sc_timeout_seconds: int = 60
    sc_retries: int = 3
    sc_backoff_seconds: float = 1.5
    sc_ssl_verify: bool = True


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Load subnet_as_code scope definitions, validate Tenable.sc "
            "coverage, and generate detect-and-plan audit outputs."
        )
    )
    add_authoritative_source_arguments(parser)
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--run-id")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--mode", choices=["offline", "live"], default="offline")
    parser.add_argument("--scan-json-dir")
    parser.add_argument("--asset-json-dir")
    parser.add_argument("--include-keywords")
    parser.add_argument("--exclude-keywords")
    parser.add_argument("--match-all-include", action="store_true", default=False)
    parser.add_argument("--case-sensitive", action="store_true", default=False)
    parser.add_argument(
        "--filter-disabled-mode",
        choices=["ALL", "ENABLED_ONLY", "DISABLED_ONLY"],
        default="ALL",
    )
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--sc-timeout-seconds", type=int)
    parser.add_argument("--sc-retries", type=int)
    parser.add_argument("--sc-backoff-seconds", type=float)
    parser.add_argument("--grouping-mode", choices=["default", "vlan_tag"])
    parser.add_argument("--grouping-vlan-tag-prefix")
    parser.add_argument(
        "--grouping-tag-map",
        help="JSON object or comma-separated key=value mappings for vlan tag groups.",
    )
    parser.add_argument(
        "--no-sc-ssl-verify",
        dest="sc_ssl_verify",
        action="store_false",
        default=None,
    )
    parser.add_argument(
        "--sc-url",
        help=(
            "Optional Tenable.sc URL override for live mode. Defaults to "
            "TCW_SC_URL or SC_URL."
        ),
    )
    parser.add_argument(
        "--sc-access-key",
        help=(
            "Optional Tenable.sc access key override for live mode. "
            "Defaults to TCW_SC_ACCESS_KEY or SC_ACCESS_KEY."
        ),
    )
    parser.add_argument(
        "--sc-secret-key",
        help=(
            "Optional Tenable.sc secret key override for live mode. "
            "Defaults to TCW_SC_SECRET_KEY or SC_SECRET_KEY."
        ),
    )
    return parser


def main(argv=None) -> int:
    load_dotenv()
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        config = build_detect_and_plan_config(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    configure_logging(
        config.log_level,
        log_format=config.log_format,
        log_file=config.log_file,
    )
    summary = run_detect_and_plan(config)
    print_run_summary(cast(str, summary["run_id"]), summary)
    return 0


class ServiceContextFilter(logging.Filter):
    def __init__(self, extra_context: dict[str, object] | None = None) -> None:
        super().__init__()
        self.extra_context = extra_context or {}

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in self.extra_context.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        if not hasattr(record, "run_id"):
            setattr(record, "run_id", None)
        if not hasattr(record, "job_name"):
            setattr(record, "job_name", None)
        return True


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
        run_id = getattr(record, "run_id", None)
        if run_id:
            payload["run_id"] = run_id
        job_name = getattr(record, "job_name", None)
        if job_name:
            payload["job_name"] = job_name
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(
    level_name: str,
    log_format: str = "text",
    log_file: Path | None = None,
    extra_context: dict[str, object] | None = None,
) -> None:
    level = getattr(logging, str(level_name).upper(), logging.INFO)
    stream_handler = logging.StreamHandler()
    if str(log_format).lower() == "json":
        formatter: logging.Formatter = JsonLogFormatter()
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(ServiceContextFilter(extra_context))

    logging.basicConfig(level=level, handlers=[stream_handler], force=True)
    root_logger = logging.getLogger()

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(ServiceContextFilter(extra_context))
        root_logger.addHandler(file_handler)


def build_detect_and_plan_config(args) -> DetectAndPlanConfig:
    resolver = SettingsResolver(args)

    def scalar_getter(
        name: str, environment_name: str | None, default: Any = None
    ) -> Any:
        return resolver.get(name, default, environment_name)

    def csv_getter(
        name: str, environment_name: str | None, default: Any = None
    ) -> list[str] | None:
        return resolver.csv(name, default, environment_name)

    if args.dry_run is False:
        raise ValueError("detect-and-plan does not support --no-dry-run")

    source_config = build_authoritative_source_config(
        scalar_getter=scalar_getter,
        csv_getter=csv_getter,
    )
    grouping_config = build_grouping_config(
        mode_value=scalar_getter("grouping_mode", "GROUPING_MODE", "default"),
        prefix_value=scalar_getter(
            "grouping_vlan_tag_prefix",
            "GROUPING_VLAN_TAG_PREFIX",
            "vlan-",
        ),
        tag_map_value=scalar_getter("grouping_tag_map", "GROUPING_TAG_MAP", None),
    )
    scan_json_dir = scalar_getter("scan_json_dir", None)
    asset_json_dir = scalar_getter("asset_json_dir", None)
    if args.mode == "offline" and (not scan_json_dir or not asset_json_dir):
        raise ValueError("Offline mode requires --scan-json-dir and --asset-json-dir.")

    sc_timeout_seconds = parse_positive_int(
        scalar_getter("sc_timeout_seconds", "SC_TIMEOUT_SECONDS", 60),
        "sc_timeout_seconds",
    )
    sc_retries = parse_positive_int(
        scalar_getter("sc_retries", "SC_RETRIES", 3),
        "sc_retries",
    )
    sc_backoff_seconds = parse_nonnegative_float(
        scalar_getter("sc_backoff_seconds", "SC_BACKOFF_SECONDS", 1.5),
        "sc_backoff_seconds",
    )
    sc_ssl_verify = parse_bool(
        scalar_getter("sc_ssl_verify", "SC_SSL_VERIFY", True),
        "sc_ssl_verify",
    )

    return DetectAndPlanConfig(
        source_config=source_config,
        output_dir=Path(args.output_dir),
        run_id=args.run_id,
        dry_run=bool(args.dry_run),
        mode=args.mode,
        scan_json_dir=scan_json_dir,
        asset_json_dir=asset_json_dir,
        sc_access_key=scalar_getter("sc_access_key", "SC_ACCESS_KEY"),
        sc_secret_key=scalar_getter("sc_secret_key", "SC_SECRET_KEY"),
        sc_url=scalar_getter("sc_url", "SC_URL"),
        include_keywords=parse_csv_list(args.include_keywords),
        exclude_keywords=parse_csv_list(args.exclude_keywords),
        match_all_include=bool(args.match_all_include),
        case_sensitive=bool(args.case_sensitive),
        filter_disabled_mode=args.filter_disabled_mode,
        log_level=args.log_level,
        log_format="text",
        log_file=None,
        sc_timeout_seconds=sc_timeout_seconds,
        sc_retries=sc_retries,
        sc_backoff_seconds=sc_backoff_seconds,
        sc_ssl_verify=sc_ssl_verify,
        grouping_config=grouping_config,
    )


def build_coverage_source_config(config: DetectAndPlanConfig) -> CoverageSourceConfig:
    return CoverageSourceConfig(
        mode=config.mode,
        scan_json_dir=config.scan_json_dir,
        asset_json_dir=config.asset_json_dir,
        sc_access_key=config.sc_access_key,
        sc_secret_key=config.sc_secret_key,
        sc_url=config.sc_url,
        include_keywords=list(config.include_keywords),
        exclude_keywords=list(config.exclude_keywords),
        match_all_include=bool(config.match_all_include),
        case_sensitive=bool(config.case_sensitive),
        filter_disabled_mode=config.filter_disabled_mode,
        sc_timeout_seconds=config.sc_timeout_seconds,
        sc_retries=config.sc_retries,
        sc_backoff_seconds=config.sc_backoff_seconds,
        sc_ssl_verify=config.sc_ssl_verify,
    )


def run_detect_and_plan(config: DetectAndPlanConfig) -> dict[str, object]:
    if not config.dry_run:
        raise ValueError("detect-and-plan runs do not support dry_run=false")

    started_at = datetime.now(timezone.utc)
    run_id = config.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(config.output_dir)
    run_dir = output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    audit_logger = AuditLogger(run_id=run_id, run_dir=run_dir)
    audit_logger.emit(
        "run_started",
        authoritative_source="subnet_as_code.get_sites",
        source_reference_id=config.source_config.reference_id,
        source_sites=config.source_config.sites,
        source_tags=config.source_config.tags,
        source_name=config.source_config.name,
        source_network_type=config.source_config.network_type,
        source_routing_type=config.source_config.routing_type,
        output_dir=output_dir,
        dry_run=config.dry_run,
        mode=config.mode,
    )

    # get expected targets first then compare them with the Tenable
    # scan targets collected below
    source_type, connector_result = load_authoritative_source(
        config.source_config,
        audit_logger=audit_logger,
    )
    named_targets = apply_naming_rules_to_targets(
        connector_result.coverage_targets,
        config.grouping_config,
    )

    actual_scopes, actual_by_scan, excluded_by_scan, configuration_index = (
        load_actual_scope_data(build_coverage_source_config(config))
    )
    coverage_results = validate_coverage_targets(
        named_targets,
        actual_scopes=actual_scopes,
        actual_by_scan=actual_by_scan,
        excluded_by_scan=excluded_by_scan,
        configuration_index=configuration_index,
        audit_logger=audit_logger,
    )
    proposed_changes = generate_proposed_changes(
        coverage_results,
        run_id=run_id,
        grouping_config=config.grouping_config,
    )

    # Record every proposal before writing the review files.
    for change in proposed_changes:
        audit_logger.emit(
            "proposed_change_created",
            site_code=change.site_code,
            target_type=change.target_type,
            cidr=change.cidr,
            current_status=change.current_status,
            proposed_action=change.proposed_action,
            source_file=change.source_file,
        )

    csv_path, md_path = write_proposed_change_audits(
        run_id=run_id,
        run_dir=run_dir,
        proposed_changes=proposed_changes,
        audit_logger=audit_logger,
    )
    coverage_report_paths = write_coverage_reports(
        run_dir=run_dir,
        coverage_results=coverage_results,
        targets=named_targets,
        actual_scopes=actual_scopes,
        validation_issues=connector_result.validation_issues,
    )

    status_counts = Counter(result.status for result in coverage_results)
    completed_at = datetime.now(timezone.utc)
    summary = {
        "run_id": run_id,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": round((completed_at - started_at).total_seconds(), 3),
        "mode": config.mode,
        "dry_run": config.dry_run,
        "authoritative_source_type": source_type,
        "authoritative_source": "subnet_as_code.get_sites",
        "authoritative_units_processed": connector_result.files_processed,
        "authoritative_units_failed": connector_result.files_failed,
        "validation_issue_count": len(connector_result.validation_issues),
        "coverage_targets_created": len(named_targets),
        "ok_count": status_counts.get("OK", 0),
        "gap_count": status_counts.get("GAP", 0),
        "partial_count": status_counts.get("PARTIAL", 0),
        "excluded_count": status_counts.get("EXCLUDED", 0),
        "tag_excluded_count": sum(
            result.excluded_by_tag for result in coverage_results
        ),
        "proposed_changes_count": len(proposed_changes),
        "missing_asset_group_count": sum(
            result.required_asset_present == "No" for result in coverage_results
        ),
        "missing_required_scan_count": sum(
            result.required_scan_present == "No" for result in coverage_results
        ),
        "scan_policy_mismatch_count": sum(
            result.required_policy_configured == "No" for result in coverage_results
        ),
        "output_directory": str(run_dir),
        "audit_log": str(audit_logger.path),
        "csv_audit": str(csv_path),
        "markdown_audit": str(md_path),
        **coverage_report_paths,
        "run_summary_file": str(run_dir / "run_summary.json"),
    }

    final_audit_path = write_final_audit_report(
        run_dir / "final_audit_report.md",
        summary,
        connector_result.validation_issues,
        coverage_results,
    )
    summary["final_audit_report"] = str(final_audit_path)
    atomic_write_json(run_dir / "run_summary.json", summary)
    audit_logger.emit("run_completed", **summary)
    return summary


def load_actual_scope_data(config: CoverageSourceConfig):
    data_access = DataAccess(config)
    scope_ws, normalized_ws = build_scope_tables()
    build_scope_sheets(scope_ws, normalized_ws, data_access, config)
    # coverage uses normalized scope rows, not the original Tenable text
    actual_scopes, _, actual_by_scan, excluded_by_scan = build_coverage_data(
        normalized_ws
    )
    return (
        actual_scopes,
        actual_by_scan,
        excluded_by_scan,
        build_configuration_index(data_access),
    )


class ConfigurationIndex(TypedDict):
    assets_by_name: dict[str, list[dict[str, Any]]]
    scans_by_name: dict[str, list[dict[str, Any]]]


def build_configuration_index(
    data_access: ConfigurationDataAccess,
) -> ConfigurationIndex:
    assets_by_name: dict[str, list[dict[str, object]]] = defaultdict(list)
    for asset in data_access.get_asset_lists():
        name = str(asset.get("name") or "").strip()
        if name:
            assets_by_name[name].append(asset)

    scans_by_name: dict[str, list[dict[str, object]]] = defaultdict(list)
    for scan in data_access.get_scans():
        scan_id = scan.get("id")
        details = (
            data_access.get_scan_details(scan_id) if scan_id not in (None, "") else scan
        )
        record = details if isinstance(details, dict) and details else scan
        name = extract_scan_name(record) or extract_scan_name(scan)
        if name:
            scans_by_name[name].append(record)
    return {
        "assets_by_name": dict(assets_by_name),
        "scans_by_name": dict(scans_by_name),
    }


def validate_coverage_targets(
    targets: list[CoverageTarget],
    actual_scopes,
    actual_by_scan,
    excluded_by_scan,
    configuration_index=None,
    audit_logger=None,
) -> list[CoverageValidationResult]:
    coverage_results: list[CoverageValidationResult] = []
    exclusion_impact_by_scan: dict[str, int] = defaultdict(int)
    configuration_index = configuration_index or {}
    assets_by_name = configuration_index.get("assets_by_name", {})
    scans_by_name = configuration_index.get("scans_by_name", {})

    for target in targets:
        exclusion_tag = find_exclusion_tag(target.tags)
        if exclusion_tag:
            # exclusion is reported, but doesn't make a change.
            coverage_result = _build_tag_excluded_result(target, exclusion_tag)
            coverage_results.append(coverage_result)
            if audit_logger:
                audit_logger.emit(
                    "coverage_tag_exclusion_detected",
                    site_code=coverage_result.site_code,
                    target_type=coverage_result.target_type,
                    cidr=coverage_result.cidr,
                    exclusion_tag=exclusion_tag,
                    source_file=coverage_result.source_file,
                )
            continue

        expected = parse_scope_item(target.cidr)
        base_result = calculate_coverage_result(
            scope_item=target.cidr,
            location=target.location,
            environment=target.target_type,
            required_scan=target.required_scan_name or "",
            expected=expected,
            actual_scopes=actual_scopes,
            actual_by_scan=actual_by_scan,
            excluded_by_scan=excluded_by_scan,
            exclusion_impact_by_scan=exclusion_impact_by_scan,
        )

        status = derive_workflow_status(
            base_result.status, base_result.exclusion_ip_total
        )
        # exact names distinguish missing resources from scans that cover
        # the same addresses
        matching_assets = assets_by_name.get(target.required_asset_name, [])
        matching_scans = scans_by_name.get(target.required_scan_name, [])
        required_asset_present = "Yes" if matching_assets else "No"
        required_scan_present = "Yes" if matching_scans else "No"
        required_scan = matching_scans[0] if len(matching_scans) == 1 else {}
        configured_repository = _resource_label(
            required_scan.get("repository"), required_scan.get("repositoryID")
        )
        configured_policy = _resource_label(
            required_scan.get("policy"), required_scan.get("policyID")
        )
        if not matching_scans:
            required_policy_configured = ""
        elif len(matching_scans) > 1:
            required_policy_configured = "No"
        else:
            policy_name = _resource_name(required_scan.get("policy"))
            required_policy_configured = (
                "Yes" if policy_name == target.required_policy_name else "No"
            )
        coverage_result = CoverageValidationResult(
            status=status,
            target_type=target.target_type,
            cidr=target.cidr,
            site_code=target.site_code,
            site_name=target.site_name,
            region=target.region,
            location=target.location,
            description=target.description,
            vlan_name=target.vlan_name,
            vlan_tag=target.vlan_tag,
            covering_scans=sorted(base_result.covering_scans),
            reason=base_result.reason,
            source_file=target.source_file,
            required_asset_name=target.required_asset_name,
            required_scan_name=target.required_scan_name,
            required_policy_name=target.required_policy_name,
            required_scan_covered=base_result.required_scan_covered,
            expected_size=base_result.expected_size,
            covered_count=base_result.covered_count,
            gap_count=base_result.gap_count,
            exclusion_ip_total=base_result.exclusion_ip_total,
            coverage_pct=base_result.coverage_pct,
            required_asset_present=required_asset_present,
            required_scan_present=required_scan_present,
            configured_repository=configured_repository,
            configured_policy=configured_policy,
            required_policy_configured=required_policy_configured,
            timezone=target.timezone,
            tags=list(target.tags),
            environment=target.environment,
            business_function=target.business_function,
            scan_classification=dict(target.scan_classification),
        )
        coverage_results.append(coverage_result)

        if audit_logger and coverage_result.status == "GAP":
            audit_logger.emit(
                "coverage_gap_detected",
                site_code=coverage_result.site_code,
                target_type=coverage_result.target_type,
                cidr=coverage_result.cidr,
                required_scan_name=coverage_result.required_scan_name,
                source_file=coverage_result.source_file,
            )
        elif audit_logger and coverage_result.status == "PARTIAL":
            audit_logger.emit(
                "coverage_partial_detected",
                site_code=coverage_result.site_code,
                target_type=coverage_result.target_type,
                cidr=coverage_result.cidr,
                reason=coverage_result.reason,
                source_file=coverage_result.source_file,
            )
        elif audit_logger and coverage_result.status == "EXCLUDED":
            audit_logger.emit(
                "coverage_exclusion_detected",
                site_code=coverage_result.site_code,
                target_type=coverage_result.target_type,
                cidr=coverage_result.cidr,
                exclusion_ip_total=coverage_result.exclusion_ip_total,
                reason=coverage_result.reason,
                source_file=coverage_result.source_file,
            )

    if audit_logger:
        status_counts = Counter(result.status for result in coverage_results)
        audit_logger.emit(
            "coverage_validation_completed",
            target_count=len(coverage_results),
            ok_count=status_counts.get("OK", 0),
            gap_count=status_counts.get("GAP", 0),
            partial_count=status_counts.get("PARTIAL", 0),
            excluded_count=status_counts.get("EXCLUDED", 0),
        )

    return coverage_results


def _build_tag_excluded_result(
    target: CoverageTarget, exclusion_tag: str
) -> CoverageValidationResult:
    expected_start, expected_end = scope_to_interval(parse_scope_item(target.cidr))
    return CoverageValidationResult(
        status="EXCLUDED",
        target_type=target.target_type,
        cidr=target.cidr,
        site_code=target.site_code,
        site_name=target.site_name,
        region=target.region,
        location=target.location,
        description=target.description,
        vlan_name=target.vlan_name,
        vlan_tag=target.vlan_tag,
        covering_scans=[],
        reason=f"Excluded by authoritative source tag '{exclusion_tag}'.",
        source_file=target.source_file,
        required_asset_name=None,
        required_scan_name=None,
        required_policy_name=None,
        exclusion_ip_total=expected_end - expected_start + 1,
        timezone=target.timezone,
        tags=list(target.tags),
        excluded_by_tag=True,
        exclusion_tag=exclusion_tag,
        environment=target.environment,
        business_function=target.business_function,
        scan_classification=dict(target.scan_classification),
    )


def _resource_name(value) -> str | None:
    """Read a resource name from a Tenable.sc value"""
    if isinstance(value, dict):
        name = str(value.get("name") or "").strip()
        return name or None
    return None


def _resource_label(value, fallback_id=None) -> str | None:
    """Read a readable resource label from a Tenable.sc value"""
    if isinstance(value, dict):
        name = str(value.get("name") or "").strip()
        if name:
            return name
        fallback_id = value.get("id", fallback_id)
    if fallback_id not in (None, ""):
        return str(fallback_id)
    return None


def derive_workflow_status(status: str, exclusion_ip_total: int) -> str:
    if status == "PARTIAL" and exclusion_ip_total > 0:
        return "EXCLUDED"
    return status


def print_run_summary(run_id: str, summary: dict[str, object]) -> None:
    """Print the summary for a completed run"""
    _print_lines(
        [
            f"Run ID: {run_id}",
            f"Authoritative source: {summary['authoritative_source_type']}",
            (
                "Authoritative units processed: "
                f"{summary['authoritative_units_processed']}"
            ),
            f"Authoritative units failed: {summary['authoritative_units_failed']}",
            f"Coverage targets created: {summary['coverage_targets_created']}",
            f"OK count: {summary['ok_count']}",
            f"GAP count: {summary['gap_count']}",
            f"PARTIAL count: {summary['partial_count']}",
            f"EXCLUDED count: {summary['excluded_count']}",
            f"Proposed changes count: {summary['proposed_changes_count']}",
            f"Output directory: {summary['output_directory']}",
        ]
    )


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        print(line)


if __name__ == "__main__":
    raise SystemExit(main())
