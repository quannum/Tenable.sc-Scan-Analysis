import glob
import json
import logging
import os
import time
from typing import Any, Callable

LOGGER = logging.getLogger(__name__)


def load_json_folder(folder_path: str | None) -> dict[str, dict[str, Any]]:
    data = {}
    if not folder_path:
        return data

    file_paths = glob.glob(os.path.join(folder_path, "*.json"))
    for file_path in file_paths:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                obj = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Skipping unreadable JSON file '%s': %s", file_path, exc)
            continue

        object_id = obj.get("id")
        if object_id in (None, ""):
            LOGGER.warning("Skipping JSON file without an 'id': %s", file_path)
            continue

        object_id = str(object_id)
        if object_id in data:
            LOGGER.warning(
                "Duplicate object id '%s' in '%s'; replacing previously loaded object",
                object_id,
                file_path,
            )
        data[object_id] = obj

    LOGGER.info("Loaded %s JSON objects from %s", len(data), folder_path)
    return data


class DataAccess:
    LIVE_CALL_MAX_RETRIES = 3
    LIVE_RETRY_BACKOFF_SECONDS = 1.5

    def __init__(self, config) -> None:
        self.config = config
        self.sc = None
        self.offline_scans = {}
        self.offline_assets = {}

        if config.mode == "live":
            self._validate_live_config(config)
            try:
                from tenable.sc import TenableSC
            except ImportError as exc:
                raise RuntimeError("pyTenable is required for live mode") from exc

            self.sc = TenableSC(
                url=config.sc_url,
                access_key=config.sc_access_key,
                secret_key=config.sc_secret_key,
            )
        else:
            self.offline_scans = load_json_folder(config.scan_json_dir)
            self.offline_assets = load_json_folder(config.asset_json_dir)

    @staticmethod
    def _validate_live_config(config) -> None:
        missing = []
        if not config.sc_url:
            missing.append("SC_URL")
        if not config.sc_access_key:
            missing.append("SC_ACCESS_KEY")
        if not config.sc_secret_key:
            missing.append("SC_SECRET_KEY")

        if missing:
            raise ValueError(
                "Live mode is missing required environment values: "
                + ", ".join(missing)
            )

    def get_scans(self) -> list[dict[str, Any]]:
        if self.config.mode == "live":
            scans_payload = self._call_live(
                self.sc.scans.list,
                operation_name="scans.list",
            )
            usable = scans_payload.get("usable")
            if isinstance(usable, list):
                return usable
            LOGGER.warning(
                "Unexpected live scan payload shape; expected key 'usable' as list"
            )
            return []
        return list(self.offline_scans.values())

    def get_scan_details(self, scan_id) -> dict[str, Any]:
        if self.config.mode == "live":
            return self._call_live(
                lambda: self.sc.scans.details(scan_id),
                operation_name=f"scans.details({scan_id})",
            )
        details = self.offline_scans.get(str(scan_id))
        if not details:
            LOGGER.warning("Missing offline scan details for scan id '%s'", scan_id)
            return {}
        return details

    def get_asset(self, asset_id) -> dict[str, Any]:
        if self.config.mode == "live":
            return self._call_live(
                lambda: self.sc.asset_lists.details(asset_id),
                operation_name=f"asset_lists.details({asset_id})",
            )
        return self.offline_assets.get(str(asset_id), {})

    def _call_live(self, call_fn: Callable[[], Any], operation_name: str) -> Any:
        attempts = self.LIVE_CALL_MAX_RETRIES

        for attempt in range(1, attempts + 1):
            try:
                result = call_fn()
            except Exception as exc:
                if not self._is_retryable_exception(exc) or attempt >= attempts:
                    raise

                delay = self.LIVE_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1))
                LOGGER.warning(
                    "Live API call '%s' failed on attempt %s/%s: %s. Retrying in %.1fs",
                    operation_name,
                    attempt,
                    attempts,
                    exc,
                    delay,
                )
                time.sleep(delay)
                continue

            if result is None:
                raise RuntimeError(f"Live API call '{operation_name}' returned no data")

            return result

        raise RuntimeError(
            f"Live API call '{operation_name}' failed after {attempts} attempts"
        )

    @staticmethod
    def _is_retryable_exception(exc: Exception) -> bool:
        retryable_types = (TimeoutError, ConnectionError, OSError)
        if isinstance(exc, retryable_types):
            return True

        message = str(exc).lower()
        if "timeout" in message or "timed out" in message:
            return True
        if "connection" in message or "temporarily unavailable" in message:
            return True

        return False
