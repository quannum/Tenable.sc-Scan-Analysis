import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .audit.audit_logger import atomic_write_json
from .run_detect_and_plan import (
    DetectAndPlanConfig,
    configure_logging,
    run_detect_and_plan,
)
from .service_config import ScheduledServiceConfig, build_service_config

LOGGER = logging.getLogger(__name__)


def main(argv=None) -> int:
    config = build_service_config(argv)
    configure_logging(config.log_level)

    try:
        with scheduler_lock(config.lock_file, config.job_name):
            run_id = build_run_id(config.run_id_prefix)
            LOGGER.info(
                "Starting scheduled job '%s' as run '%s'",
                config.job_name,
                run_id,
            )
            summary = run_detect_and_plan(build_detect_config(config, run_id))
            latest_payload = {
                "job_name": config.job_name,
                "status": "SUCCESS",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "run_summary": summary,
            }
            atomic_write_json(config.latest_summary_file, latest_payload)
            LOGGER.info(
                "Scheduled job '%s' completed successfully. Latest summary: %s",
                config.job_name,
                config.latest_summary_file,
            )
            return 0
    except RuntimeError as exc:
        LOGGER.error("%s", exc)
        return 2
    except Exception as exc:
        LOGGER.exception("Scheduled job '%s' failed", config.job_name)
        atomic_write_json(
            config.latest_summary_file,
            {
                "job_name": config.job_name,
                "status": "FAILED",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
            },
        )
        return 1


def build_detect_config(
    config: ScheduledServiceConfig,
    run_id: str,
) -> DetectAndPlanConfig:
    return DetectAndPlanConfig(
        subnet_repo_path=config.subnet_repo_path,
        output_dir=config.output_dir,
        run_id=run_id,
        dry_run=config.dry_run,
        mode=config.mode,
        scan_json_dir=config.scan_json_dir,
        asset_json_dir=config.asset_json_dir,
        sc_access_key=config.sc_access_key,
        sc_secret_key=config.sc_secret_key,
        sc_url=config.sc_url,
        include_keywords=list(config.include_keywords),
        exclude_keywords=list(config.exclude_keywords),
        match_all_include=config.match_all_include,
        case_sensitive=config.case_sensitive,
        filter_disabled_mode=config.filter_disabled_mode,
        log_level=config.log_level,
    )


def build_run_id(run_id_prefix: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{run_id_prefix}{timestamp}"


@contextmanager
def scheduler_lock(lock_file: Path, job_name: str):
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    try:
        descriptor = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"Scheduled job '{job_name}' is already running or left a stale lock: "
            f"{lock_file}"
        ) from exc

    try:
        payload = (
            f"job_name={job_name}\n"
            f"acquired_at={datetime.now(timezone.utc).isoformat()}\n"
            f"pid={os.getpid()}\n"
        )
        os.write(descriptor, payload.encode("utf-8"))
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if lock_file.exists():
            lock_file.unlink()
