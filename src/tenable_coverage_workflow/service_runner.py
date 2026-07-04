import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    run_id = build_run_id(config.run_id_prefix)
    started_at = datetime.now(timezone.utc).isoformat()
    configure_logging(
        config.log_level,
        log_format=config.log_format,
        log_file=config.log_file,
        extra_context={"job_name": config.job_name, "run_id": run_id},
    )

    try:
        with scheduler_lock(
            config.lock_file,
            config.job_name,
            stale_timeout_seconds=config.stale_lock_timeout_seconds,
        ):
            latest_payload = build_latest_summary_payload(
                job_name=config.job_name,
                run_id=run_id,
                status="RUNNING",
                started_at=started_at,
                output_dir=config.output_dir / "runs" / run_id,
            )
            atomic_write_json(config.latest_summary_file, latest_payload)
            logger = logging.LoggerAdapter(
                LOGGER, {"run_id": run_id, "job_name": config.job_name}
            )
            logger.info("Starting scheduled run")
            summary = run_detect_and_plan(build_detect_config(config, run_id))
            latest_payload = build_latest_summary_payload(
                job_name=config.job_name,
                run_id=run_id,
                status="SUCCESS",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                output_dir=summary.get("output_directory"),
                run_summary=summary,
            )
            atomic_write_json(config.latest_summary_file, latest_payload)
            logger.info(
                "Scheduled run completed successfully. Latest summary: %s",
                config.latest_summary_file,
            )
            return 0
    except RuntimeError as exc:
        LOGGER.error("%s", exc)
        return 2
    except Exception as exc:
        logging.LoggerAdapter(
            LOGGER,
            {"run_id": run_id, "job_name": config.job_name},
        ).exception("Scheduled run failed")
        atomic_write_json(
            config.latest_summary_file,
            build_latest_summary_payload(
                job_name=config.job_name,
                run_id=run_id,
                status="FAILED",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                output_dir=config.output_dir / "runs" / run_id,
                error=str(exc),
            ),
        )
        return 1


def build_detect_config(
    config: ScheduledServiceConfig,
    run_id: str,
) -> DetectAndPlanConfig:
    return DetectAndPlanConfig(
        source_config=config.as_authoritative_source_config(),
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
        log_format=config.log_format,
        log_file=config.log_file,
        sc_timeout_seconds=config.sc_timeout_seconds,
        sc_retries=config.sc_retries,
        sc_backoff_seconds=config.sc_backoff_seconds,
        sc_ssl_verify=config.sc_ssl_verify,
    )


def build_run_id(run_id_prefix: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{run_id_prefix}{timestamp}"


def build_latest_summary_payload(
    job_name: str,
    run_id: str,
    status: str,
    started_at: str,
    output_dir,
    completed_at: str | None = None,
    run_summary: dict[str, object] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "job_name": job_name,
        "run_id": run_id,
        "status": status,
        "started_at": started_at,
        "output_directory": str(output_dir),
    }
    if completed_at:
        payload["completed_at"] = completed_at
    if run_summary is not None:
        payload["run_summary"] = run_summary
    if error:
        payload["error"] = error
    return payload


@contextmanager
def scheduler_lock(lock_file: Path, job_name: str, stale_timeout_seconds: int):
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    descriptor = _acquire_lock_descriptor(
        lock_file=lock_file,
        job_name=job_name,
        stale_timeout_seconds=stale_timeout_seconds,
    )

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


def _acquire_lock_descriptor(
    lock_file: Path,
    job_name: str,
    stale_timeout_seconds: int,
):
    while True:
        try:
            return os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            if _lock_is_stale(lock_file, stale_timeout_seconds):
                LOGGER.warning(
                    "Removing stale scheduler lock for job '%s': %s",
                    job_name,
                    lock_file,
                )
                try:
                    lock_file.unlink()
                except FileNotFoundError:
                    continue
                continue

            raise RuntimeError(
                f"Scheduled job '{job_name}' is already running: {lock_file}"
            ) from exc


def _lock_is_stale(lock_file: Path, stale_timeout_seconds: int) -> bool:
    if not lock_file.exists():
        return False

    try:
        stat = lock_file.stat()
    except OSError:
        return False

    age_seconds = datetime.now(timezone.utc).timestamp() - stat.st_mtime
    if age_seconds >= stale_timeout_seconds:
        return True

    lock_details = _read_lock_details(lock_file)
    pid_value = lock_details.get("pid")
    if not pid_value:
        return False

    try:
        pid = int(pid_value)
    except ValueError:
        return age_seconds >= stale_timeout_seconds

    return not _pid_is_running(pid)


def _read_lock_details(lock_file: Path) -> dict[str, str]:
    details: dict[str, str] = {}
    try:
        for line in lock_file.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            details[key.strip()] = value.strip()
    except OSError:
        return {}
    return details


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True
