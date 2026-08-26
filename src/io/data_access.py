import glob
import json
import logging
import os
import time
from typing import Any, Callable, Iterator, Protocol

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
            LOGGER.warning("Skipping unreadable json file '%s': %s", file_path, exc)
            continue

        if not isinstance(obj, dict):
            LOGGER.warning(
                "Skipping json file whose root is not an object: %s", file_path
            )
            continue

        object_id = obj.get("id")
        if object_id in (None, ""):
            LOGGER.warning("Skipping json file without an 'id': %s", file_path)
            continue

        object_id = str(object_id)
        if object_id in data:
            LOGGER.warning(
                "Duplicate object id '%s' in '%s'; replacing previously loaded object",
                object_id,
                file_path,
            )
        data[object_id] = obj

    LOGGER.info("Loaded %s json objects from %s", len(data), folder_path)
    return data


class DataAccessConfig(Protocol):
    @property
    def mode(self) -> str:
        """Return the selected data-access mode"""
        ...

    @property
    def scan_json_dir(self) -> str | None:
        """Return the offline scan json directory"""
        ...

    @property
    def asset_json_dir(self) -> str | None:
        """Return the offline asset json directory"""
        ...

    @property
    def sc_url(self) -> str | None:
        """Return the Tenable.sc URL"""
        ...

    @property
    def sc_access_key(self) -> str | None:
        """Return the Tenable.sc access key"""
        ...

    @property
    def sc_secret_key(self) -> str | None:
        """Return the Tenable.sc secret key"""
        ...


class DataAccess:
    LIVE_CALL_MAX_RETRIES = 3
    LIVE_RETRY_BACKOFF_SECONDS = 1.5

    def __init__(self, config: DataAccessConfig) -> None:
        if config.mode not in {"offline", "live"}:
            raise ValueError("mode must be 'offline' or 'live'")
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
            # offline mode gets scan and asset json folders
            self.offline_scans = load_json_folder(config.scan_json_dir)
            self.offline_assets = load_json_folder(config.asset_json_dir)

    @staticmethod
    def _validate_live_config(config: DataAccessConfig) -> None:
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

    def get_usable_asset_lists(self) -> list[dict[str, Any]]:
        """List asset groups that are 'usable'"""
        if self.config.mode != "live":
            return list(self.offline_assets.values())
        return self._list_live_usable_resource("asset_lists")

    def get_policies(self) -> list[dict[str, Any]]:
        return self._list_live_resource("policies")

    def get_usable_policies(self) -> list[dict[str, Any]]:
        """List policies that are 'usable'"""
        return self._list_live_usable_resource("policies")

    def get_usable_scans(self) -> list[dict[str, Any]]:
        """List scan definitions that are 'usable'"""
        if self.config.mode != "live":
            return list(self.offline_scans.values())
        return self._list_live_usable_resource("scans")

    def get_credentials(self) -> list[dict[str, Any]]:
        return self._list_live_resource("credentials")

    def get_observed_hosts(self) -> list[dict[str, Any]]:
        return self._list_live_resource("hosts")

    def create_static_asset(
        self,
        name: str,
        ips: list[str],
        description: str,
        label: str | None = None,
    ) -> dict[str, Any]:
        self._require_live_mutation()
        kwargs: dict[str, Any] = {"ips": ips, "description": description}
        if label is not None:
            # Tenable.sc calls the Label UI field `tags` in the Asset API.
            kwargs["tags"] = label
        return self._call_live(
            lambda: self.sc.asset_lists.create(
                name,
                "static",
                **kwargs,
            ),
            operation_name=f"asset_lists.create({name})",
        )

    def update_static_asset(
        self,
        asset_id: int,
        ips: list[str],
        description: str | None = None,
        label: str | None = None,
    ) -> dict[str, Any]:
        self._require_live_mutation()
        kwargs: dict[str, Any] = {"ips": ips}
        if description is not None:
            kwargs["description"] = description
        if label is not None:
            kwargs["tags"] = label
        return self._call_live(
            lambda: self.sc.asset_lists.edit(asset_id, **kwargs),
            operation_name=f"asset_lists.edit({asset_id})",
        )

    def create_dynamic_asset(
        self,
        name: str,
        rules: dict[str, Any],
        description: str,
        label: str | None = None,
    ) -> dict[str, Any]:
        """Create a dynamic asset from its saved rule definition"""
        self._require_live_mutation()
        kwargs: dict[str, Any] = {
            "rules": _dynamic_rules_as_tuple(rules),
            "description": description,
        }
        if label is not None:
            kwargs["tags"] = label
        return self._call_live(
            lambda: self.sc.asset_lists.create(
                name,
                "dynamic",
                **kwargs,
            ),
            operation_name=f"asset_lists.create({name})",
        )

    def update_dynamic_asset(
        self,
        asset_id: int,
        rules: dict[str, Any],
        description: str | None = None,
        label: str | None = None,
    ) -> dict[str, Any]:
        """Update the dynamic asset rules and optional description"""
        self._require_live_mutation()
        kwargs: dict[str, Any] = {"rules": _dynamic_rules_as_tuple(rules)}
        if description is not None:
            kwargs["description"] = description
        if label is not None:
            kwargs["tags"] = label
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
        description: str | None = None,
    ) -> dict[str, Any]:
        self._require_live_mutation()
        kwargs: dict[str, Any] = {
            "asset_lists": asset_ids,
            "policy_id": policy_id,
        }
        if description is not None:
            kwargs["description"] = description
        return self._call_live(
            lambda: self.sc.scans.create(
                name,
                repository_id,
                **kwargs,
            ),
            operation_name=f"scans.create({name})",
        )

    def update_scan_configuration(
        self,
        scan_id: int,
        asset_ids: list[int],
        repository_id: int,
        policy_id: int,
        description: str | None = None,
    ) -> dict[str, Any]:
        self._require_live_mutation()
        kwargs: dict[str, Any] = {
            "asset_lists": asset_ids,
            "repo": repository_id,
            "policy_id": policy_id,
        }
        if description is not None:
            kwargs["description"] = description
        return self._call_live(
            lambda: self.sc.scans.edit(
                scan_id,
                **kwargs,
            ),
            operation_name=f"scans.edit({scan_id})",
        )

    def _require_live_mutation(self) -> None:
        """Raise an error when a live change is not allowed"""
        if self.config.mode != "live":
            raise RuntimeError("Tenable.sc mutations require live mode")

    def _list_live_resource(self, resource_name: str) -> list[dict[str, Any]]:
        """List one type of resource from Tenable.sc"""
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

    def _list_live_usable_resource(self, resource_name: str) -> list[dict[str, Any]]:
        """List only usable scans/assets/policies in Tenable.sc"""
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
        return normalize_usable_resource_list(payload)

    def _call_live(self, call_fn: Callable[[], Any], operation_name: str) -> Any:
        """Call Tenable.sc and retry temporary failures"""
        attempts = getattr(self, "live_call_max_retries", self.LIVE_CALL_MAX_RETRIES)

        for attempt in range(1, attempts + 1):
            try:
                result = call_fn()
            except Exception as exc:
                if not self._is_retryable_exception(exc) or attempt >= attempts:
                    raise

                # Retry connection-style failures with a longer wait each time
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
        """Check whether retryable exception"""
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
    """Normalize the list and usable/manageable responses from pyTenable"""
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _iter_resource_records(payload):
        identity = str(item.get("id", item.get("uuid", repr(sorted(item.items())))))
        if identity in seen:
            continue
        seen.add(identity)
        records.append(item)
    return records


def normalize_usable_resource_list(payload: Any) -> list[dict[str, Any]]:
    """Normalize only the usable list when usable/manageable lists returned"""
    usable_payload = _usable_payload(payload)
    return normalize_resource_list(
        payload if usable_payload is None else usable_payload
    )


def _usable_payload(payload: Any) -> Any | None:
    if not isinstance(payload, dict):
        return None
    if "usable" in payload:
        return payload["usable"]
    return _usable_payload(payload.get("response"))


def _dynamic_rules_as_tuple(rules: dict[str, Any]) -> tuple[Any, ...]:
    """Turn dynamic rules into filter, operator, value tuple"""
    operator = str(rules.get("operator") or "").lower()
    children = rules.get("children")
    if operator not in {"all", "any"} or not isinstance(children, list):
        raise ValueError("Dynamic rules must start with an 'all' or 'any' group")
    return (operator, *(_dynamic_rule_as_tuple(child) for child in children))


def _dynamic_rule_as_tuple(rule: Any) -> tuple[Any, ...]:
    if not isinstance(rule, dict):
        raise ValueError("Dynamic rule entries must be objects")
    children = rule.get("children")
    if isinstance(children, list):
        operator = str(rule.get("operator") or "").lower()
        if operator not in {"all", "any"}:
            raise ValueError("Dynamic rule groups must use 'all' or 'any'")
        return (operator, *(_dynamic_rule_as_tuple(child) for child in children))

    filter_name = str(rule.get("filterName") or rule.get("filtername") or "").strip()
    operator = str(rule.get("operator") or "").lower()
    value = rule.get("value")
    if not filter_name or not operator or value in (None, ""):
        raise ValueError(
            "Dynamic rule clauses require filter name, operator, and value"
        )
    plugin_constraint = rule.get("pluginIDConstraint")
    if plugin_constraint in (None, ""):
        return (filter_name, operator, str(value))
    try:
        return (filter_name, operator, str(value), int(plugin_constraint))
    except (TypeError, ValueError) as exc:
        raise ValueError("Dynamic rule pluginIDConstraint must be an integer") from exc


def _iter_resource_records(payload: Any) -> Iterator[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    if not isinstance(payload, dict):
        return

    # if response has no asset / scan / policy wrapper,
    # treat it as the record itself
    if "id" in payload or "uuid" in payload:
        yield payload
        return

    # 'usable' list is what the running account can...use
    # 'manageable' list is what running account can see from api
    # output but cannot use
    for key in (
        "usable",
        "manageable",
        "repositories",
        "hosts",
        "assetLists",
        "asset_lists",
        "scans",
        "policies",
        "credentials",
        "response",
        "results",
        "items",
    ):
        if key in payload:
            yield from _iter_resource_records(payload[key])


def _parse_bool(value: Any) -> bool:
    """Parse a boolean value for ssl_verify"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
    return bool(value)
