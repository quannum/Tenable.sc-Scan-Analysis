import glob
import json
import logging
import os
import time
from typing import Any, Callable

LOGGER = logging.getLogger(__name__)


def load_json_folder(folder_path: str | None) -> dict[str, dict[str, Any]]:
    data: dict[str, dict[str, Any]] = {}
    if not folder_path:
        return data

    file_paths = sorted(glob.glob(os.path.join(folder_path, "*.json")))
    for file_path in file_paths:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                obj = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Skipping unreadable JSON file '%s': %s", file_path, exc)
            continue

        if not isinstance(obj, dict):
            LOGGER.warning(
                "Skipping JSON file whose root is not an object: %s", file_path
            )
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
        self.sc: Any = None
        self.offline_scans = {}
        self.offline_assets = {}

        if config.mode == "live":
            self._validate_live_config(config)
            try:
                from tenable.sc import TenableSC
            except ImportError as exc:
                raise RuntimeError("pyTenable is required for live mode") from exc

            timeout = int(getattr(config, "sc_timeout_seconds", 60))
            retries = int(getattr(config, "sc_retries", 3))
            backoff = float(getattr(config, "sc_backoff_seconds", 1.5))
            ssl_verify = _parse_bool(getattr(config, "sc_ssl_verify", True))
            if timeout <= 0 or retries <= 0 or backoff < 0:
                raise ValueError(
                    "Tenable timeout/retries must be positive and backoff non-negative"
                )
            self.live_call_max_retries = retries
            self.live_retry_backoff_seconds = backoff
            self.sc = TenableSC(
                url=config.sc_url,
                access_key=config.sc_access_key,
                secret_key=config.sc_secret_key,
                timeout=timeout,
                retries=retries,
                backoff=backoff,
                ssl_verify=ssl_verify,
            )
        else:
            self.offline_scans = load_json_folder(config.scan_json_dir)
            self.offline_assets = load_json_folder(config.asset_json_dir)

    @staticmethod
    def _validate_live_config(config) -> None:
        missing = []
        if not config.sc_url:
            missing.append("TCW_SC_URL/SC_URL")
        if not config.sc_access_key:
            missing.append("TCW_SC_ACCESS_KEY/SC_ACCESS_KEY")
        if not config.sc_secret_key:
            missing.append("TCW_SC_SECRET_KEY/SC_SECRET_KEY")

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
            scans = normalize_resource_list(scans_payload)
            if not scans:
                LOGGER.warning("Unexpected live scan payload shape; no scans found")
            return scans
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

    def get_repositories(self) -> list[dict[str, Any]]:
        return self._list_live_resource("repositories")

    def get_asset_lists(self) -> list[dict[str, Any]]:
        if self.config.mode != "live":
            return list(self.offline_assets.values())
        return self._list_live_resource("asset_lists")

    def get_policies(self) -> list[dict[str, Any]]:
        return self._list_live_resource("policies")

    def get_credentials(self) -> list[dict[str, Any]]:
        return self._list_live_resource("credentials")

    def get_observed_hosts(self) -> list[dict[str, Any]]:
        return self._list_live_resource("hosts")

    def create_static_asset(
        self, name: str, ips: list[str], description: str
    ) -> dict[str, Any]:
        self._require_live_mutation()
        return self._call_live(
            lambda: self.sc.asset_lists.create(
                name,
                "static",
                ips=ips,
                description=description,
            ),
            operation_name=f"asset_lists.create({name})",
        )

    def update_static_asset(
        self, asset_id: int, ips: list[str], description: str | None = None
    ) -> dict[str, Any]:
        self._require_live_mutation()
        kwargs: dict[str, Any] = {"ips": ips}
        if description:
            kwargs["description"] = description
        return self._call_live(
            lambda: self.sc.asset_lists.edit(asset_id, **kwargs),
            operation_name=f"asset_lists.edit({asset_id})",
        )

    def create_scan(
        self,
        name: str,
        repository_id: int,
        asset_ids: list[int],
        policy_id: int,
    ) -> dict[str, Any]:
        self._require_live_mutation()
        return self._call_live(
            lambda: self.sc.scans.create(
                name,
                repository_id,
                asset_lists=asset_ids,
                policy_id=policy_id,
            ),
            operation_name=f"scans.create({name})",
        )

    def update_scan_configuration(
        self,
        scan_id: int,
        asset_ids: list[int],
        repository_id: int,
        policy_id: int,
    ) -> dict[str, Any]:
        self._require_live_mutation()
        return self._call_live(
            lambda: self.sc.scans.edit(
                scan_id,
                asset_lists=asset_ids,
                repo=repository_id,
                policy_id=policy_id,
            ),
            operation_name=f"scans.edit({scan_id})",
        )

    def _require_live_mutation(self) -> None:
        if self.config.mode != "live":
            raise RuntimeError("Tenable.sc mutations require live mode")

    def _list_live_resource(self, resource_name: str) -> list[dict[str, Any]]:
        if self.config.mode != "live":
            return []
        endpoint = getattr(self.sc, resource_name, None)
        list_method = getattr(endpoint, "list", None)
        if not callable(list_method):
            raise RuntimeError(
                f"Installed pyTenable does not expose sc.{resource_name}.list"
            )
        payload = self._call_live(
            list_method,
            operation_name=f"{resource_name}.list",
        )
        return normalize_resource_list(payload)

    def _call_live(self, call_fn: Callable[[], Any], operation_name: str) -> Any:
        attempts = getattr(self, "live_call_max_retries", self.LIVE_CALL_MAX_RETRIES)

        for attempt in range(1, attempts + 1):
            try:
                result = call_fn()
            except Exception as exc:
                if not self._is_retryable_exception(exc) or attempt >= attempts:
                    raise

                backoff = getattr(
                    self,
                    "live_retry_backoff_seconds",
                    self.LIVE_RETRY_BACKOFF_SECONDS,
                )
                delay = backoff * (2 ** (attempt - 1))
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


def normalize_resource_list(payload: Any) -> list[dict[str, Any]]:
    """Normalize the list and usable/manageable response shapes used by pyTenable."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in ("usable", "manageable", "repositories", "hosts", "response"):
        values = payload.get(key)
        if isinstance(values, dict):
            values = values.get("results", values.get("items"))
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            identity = str(item.get("id", item.get("uuid", repr(sorted(item.items())))))
            if identity in seen:
                continue
            seen.add(identity)
            records.append(item)
    return records


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
    return bool(value)
