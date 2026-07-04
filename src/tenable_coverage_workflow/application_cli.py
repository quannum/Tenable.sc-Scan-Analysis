import argparse
import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml
from dotenv import load_dotenv

from ..constants import VERSION
from ..io.data_access import DataAccess
from .change_application import (
    ChangeApplier,
    load_approved_plan,
    write_apply_markdown,
)
from .run_detect_and_plan import DetectAndPlanConfig, run_detect_and_plan
from .subnet_source import load_authoritative_source
from .subnet_source.source_config import (
    add_authoritative_source_arguments,
    build_authoritative_source_config,
)
from .tenable_inventory import collect_tenable_inventory, write_inventory_snapshot

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_CONFIG = 3
EXIT_OPERATION = 4
EXIT_APPLY_REQUIRED = 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tenable-sc-scan-analysis")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--config-file")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser(
        "validate-definitions", help="Validate and normalize authoritative scope."
    )
    _add_source_arguments(validate)
    validate.add_argument("--output-file")

    collect = commands.add_parser(
        "collect-tenable", help="Collect a secret-safe Tenable.sc inventory snapshot."
    )
    _add_tenable_arguments(collect)
    collect.add_argument("--output-file")
    collect.add_argument("--fail-on-partial", action="store_true", default=None)

    for name, help_text in (
        ("analyze-coverage", "Analyze authoritative coverage against Tenable.sc."),
        ("propose-changes", "Generate dry-run, reviewable proposed changes."),
    ):
        command = commands.add_parser(name, help=help_text)
        _add_source_arguments(command)
        _add_tenable_arguments(command)
        command.add_argument("--output-dir")
        command.add_argument("--run-id")

    apply_command = commands.add_parser(
        "apply-changes", help="Apply an explicitly approved change plan."
    )
    _add_tenable_arguments(apply_command)
    apply_command.add_argument("--plan-file")
    apply_command.add_argument("--repository-id", type=int)
    apply_command.add_argument("--result-file")
    apply_command.add_argument("--apply", action="store_true", default=None)

    export = commands.add_parser(
        "export-report", help="Export a portable report bundle from a completed run."
    )
    export.add_argument("--run-dir")
    export.add_argument("--output-dir")
    return parser


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    add_authoritative_source_arguments(parser)


def _add_tenable_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=("offline", "live"))
    parser.add_argument("--scan-json-dir")
    parser.add_argument("--asset-json-dir")
    parser.add_argument("--sc-url")
    parser.add_argument("--sc-timeout-seconds", type=int)
    parser.add_argument("--sc-retries", type=int)
    parser.add_argument("--sc-backoff-seconds", type=float)
    parser.add_argument(
        "--no-sc-ssl-verify",
        dest="sc_ssl_verify",
        action="store_false",
        default=None,
    )


def main(argv=None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        args._config = _load_cli_config(args.config_file)
        if args.command == "validate-definitions":
            return _validate_definitions(args)
        if args.command == "collect-tenable":
            return _collect_tenable(args)
        if args.command in {"analyze-coverage", "propose-changes"}:
            return _analyze_or_propose(args)
        if args.command == "apply-changes":
            return _apply_changes(args)
        if args.command == "export-report":
            return _export_report(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return EXIT_OPERATION
    return EXIT_CONFIG


def _source_config(args):
    return build_authoritative_source_config(
        scalar_getter=lambda name, environment_name, default=None: _setting(
            args, name, environment_name, default
        ),
        csv_getter=lambda name, environment_name, default=None: _csv_setting(
            args, name, environment_name, default
        ),
    )


def _validate_definitions(args) -> int:
    source_type, result = load_authoritative_source(_source_config(args))
    payload = {
        "schema_version": 1,
        "source_type": source_type,
        "sites": [asdict(site) for site in result.site_definitions],
        "coverage_targets": [asdict(target) for target in result.coverage_targets],
        "validation_issues": [asdict(issue) for issue in result.validation_issues],
    }
    output_file = _setting(args, "output_file")
    if output_file:
        write_inventory_snapshot(payload, output_file)
    print(
        f"Validated {len(result.site_definitions)} site(s), "
        f"{len(result.coverage_targets)} target(s), "
        f"{len(result.validation_issues)} issue(s)."
    )
    has_errors = any(issue.severity == "ERROR" for issue in result.validation_issues)
    return EXIT_VALIDATION if has_errors else EXIT_OK


def _tenable_config(args):
    mode = _setting(args, "mode", default="offline")
    scan_dir = _setting(args, "scan_json_dir")
    asset_dir = _setting(args, "asset_json_dir")
    if mode == "offline" and (not scan_dir or not asset_dir):
        raise ValueError("Offline mode requires --scan-json-dir and --asset-json-dir.")
    return SimpleNamespace(
        mode=mode,
        scan_json_dir=scan_dir,
        asset_json_dir=asset_dir,
        sc_url=_setting(args, "sc_url", "SC_URL"),
        sc_access_key=_setting(args, "sc_access_key", "SC_ACCESS_KEY"),
        sc_secret_key=_setting(args, "sc_secret_key", "SC_SECRET_KEY"),
        sc_timeout_seconds=int(
            _setting(args, "sc_timeout_seconds", "SC_TIMEOUT_SECONDS", 60)
        ),
        sc_retries=int(_setting(args, "sc_retries", "SC_RETRIES", 3)),
        sc_backoff_seconds=float(
            _setting(args, "sc_backoff_seconds", "SC_BACKOFF_SECONDS", 1.5)
        ),
        sc_ssl_verify=_as_bool(_setting(args, "sc_ssl_verify", "SC_SSL_VERIFY", True)),
    )


def _collect_tenable(args) -> int:
    snapshot = collect_tenable_inventory(DataAccess(_tenable_config(args)))
    output_file = _setting(args, "output_file")
    if not output_file:
        raise ValueError(
            "collect-tenable requires --output-file or config output_file."
        )
    output = write_inventory_snapshot(snapshot, output_file)
    print(f"Tenable.sc inventory written to {output}")
    if (
        _as_bool(_setting(args, "fail_on_partial", default=False))
        and snapshot["collection_errors"]
    ):
        return EXIT_OPERATION
    return EXIT_OK


def _analyze_or_propose(args) -> int:
    source = _source_config(args)
    tenable = _tenable_config(args)
    config = DetectAndPlanConfig(
        source_config=source,
        output_dir=Path(_setting(args, "output_dir", default="output")),
        run_id=_setting(args, "run_id"),
        dry_run=True,
        mode=tenable.mode,
        scan_json_dir=tenable.scan_json_dir,
        asset_json_dir=tenable.asset_json_dir,
        sc_access_key=tenable.sc_access_key,
        sc_secret_key=tenable.sc_secret_key,
        sc_url=tenable.sc_url,
        include_keywords=[],
        exclude_keywords=[],
        match_all_include=False,
        case_sensitive=False,
        filter_disabled_mode="ALL",
        sc_timeout_seconds=tenable.sc_timeout_seconds,
        sc_retries=tenable.sc_retries,
        sc_backoff_seconds=tenable.sc_backoff_seconds,
        sc_ssl_verify=tenable.sc_ssl_verify,
    )
    summary = run_detect_and_plan(config)
    print(f"Run {summary['run_id']} completed: {summary['output_directory']}")
    return EXIT_OK


def _apply_changes(args) -> int:
    if args.apply is not True:
        print("Refusing mutation: apply-changes requires the explicit --apply flag.")
        return EXIT_APPLY_REQUIRED
    plan_file = _setting(args, "plan_file")
    if not plan_file:
        raise ValueError("apply-changes requires --plan-file or config plan_file.")
    plan = Path(plan_file)
    if not plan.is_file():
        raise ValueError(f"Plan file does not exist: {plan}")
    repository_id = _setting(args, "repository_id")
    if repository_id is None:
        raise ValueError("apply-changes requires --repository-id or config value.")
    approved_plan = load_approved_plan(plan)
    data_access = DataAccess(_tenable_config(args))
    result = ChangeApplier(data_access, int(repository_id)).apply(approved_plan)
    result_file = _setting(
        args,
        "result_file",
        default=str(plan.with_name("apply_result.json")),
    )
    output = write_inventory_snapshot(result, result_file)
    markdown_output = write_apply_markdown(result, Path(result_file).with_suffix(".md"))
    failed = int(result["status_counts"].get("FAILED", 0))
    print(
        f"Apply results written to {output} and {markdown_output}; "
        f"{result['status_counts'].get('APPLIED', 0)} applied, "
        f"{result['status_counts'].get('UNCHANGED', 0)} unchanged, "
        f"{failed} failed."
    )
    return EXIT_OPERATION if failed else EXIT_OK


def _export_report(args) -> int:
    run_dir_value = _setting(args, "run_dir")
    output_dir_value = _setting(args, "output_dir")
    if not run_dir_value or not output_dir_value:
        raise ValueError("export-report requires run_dir and output_dir.")
    run_dir = Path(run_dir_value)
    if not run_dir.is_dir():
        raise ValueError(f"Run directory does not exist: {run_dir}")
    output_dir = Path(output_dir_value)
    output_dir.mkdir(parents=True, exist_ok=True)
    names = (
        "run_summary.json",
        "proposed_changes.csv",
        "proposed_changes.md",
        "audit.jsonl",
        "coverage_results.json",
        "coverage_results.csv",
        "coverage_summary.json",
        "coverage_summary.md",
        "extra_scan_targets.json",
        "definition_validation_issues.json",
        "proposed_exclusions.json",
        "proposed_exclusions.csv",
        "final_audit_report.md",
        "apply_result.json",
        "apply_result.md",
    )
    copied = []
    for name in names:
        source = run_dir / name
        if source.is_file():
            target = output_dir / name
            shutil.copy2(source, target)
            copied.append(str(target))
    if not copied:
        raise ValueError(f"No report artifacts found in {run_dir}")
    manifest = {"schema_version": 1, "source_run_dir": str(run_dir), "files": copied}
    write_inventory_snapshot(manifest, output_dir / "report_manifest.json")
    print(f"Exported {len(copied)} report artifact(s) to {output_dir}")
    return EXIT_OK


def _load_cli_config(path_value: str | None) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.is_file():
        raise ValueError(f"Config file does not exist: {path}")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    elif suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    elif suffix in {".toml", ".tml"}:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    else:
        raise ValueError("Config file must use .yaml, .yml, .json, or .toml.")
    if not isinstance(data, dict):
        raise ValueError("Config file root must be an object/mapping.")
    section = data.get("tenable_sc_scan_analysis", data)
    if not isinstance(section, dict):
        raise ValueError("tenable_sc_scan_analysis config must be a mapping.")
    return {_normalize_key(key): value for key, value in section.items()}


def _setting(
    args,
    name: str,
    environment_name: str | None = None,
    default: Any = None,
) -> Any:
    cli_value = getattr(args, name, None)
    if cli_value is not None:
        return cli_value
    if environment_name and os.getenv(environment_name) is not None:
        return os.getenv(environment_name)
    config = getattr(args, "_config", {})
    command_key = _normalize_key(args.command)
    commands = config.get("commands", {})
    if not isinstance(commands, dict):
        commands = {}
    command_config = config.get(command_key, commands.get(command_key, {}))
    if isinstance(command_config, dict):
        normalized = {
            _normalize_key(key): value for key, value in command_config.items()
        }
        if name in normalized:
            return normalized[name]
    return config.get(name, default)


def _normalize_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_")


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "on"}:
            return True
        if normalized in {"false", "no", "0", "off", ""}:
            return False
    return bool(value)


def _csv_setting(
    args,
    name: str,
    environment_name: str | None = None,
    default: Any = None,
) -> list[str] | None:
    value = _setting(args, name, environment_name, default)
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return None
    return [item.strip() for item in text.split(",") if item.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
