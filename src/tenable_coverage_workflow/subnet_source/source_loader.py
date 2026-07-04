import importlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import (
    NetworkRange,
    PrivateNetworkRange,
    SiteNetworkDefinition,
    SourceLoadResult,
    ValidationIssue,
)
from .json_connector import load_json_payload
from .xlsx_connector import load_xlsx_definitions
from .yaml_connector import flatten_site_definition

_SUBNET_AS_CODE_METHOD_PARAMETER_MAP: dict[str, dict[str, str]] = {
    "get_ipaddress": {
        "reference_id": "referenceId",
        "sites": "sites",
        "tags": "tags",
        "address_type": "type",
    },
    "get_ranges": {
        "reference_id": "referenceId",
        "network_type": "networktype",
        "sites": "sites",
    },
    "get_ranges_properties": {
        "reference_id": "referenceId",
        "sites": "sites",
        "tags": "tags",
        "desired_properties": "desiredProperties",
    },
    "get_sites": {
        "reference_id": "referenceId",
        "name": "name",
        "network_type": "networkType",
        "routing_type": "routingType",
        "tags": "tags",
        "sites": "sites",
    },
    "get_sites_properties": {
        "reference_id": "referenceId",
        "name": "name",
        "network_type": "networkType",
        "routing_type": "routingType",
        "tags": "tags",
        "sites": "sites",
        "desired_properties": "desiredProperties",
    },
    "get_subnets": {
        "reference_id": "referenceId",
        "name": "name",
        "network_type": "networkType",
        "routing_type": "routingType",
        "tags": "tags",
        "sites": "sites",
    },
    "get_subnet_properties": {
        "reference_id": "referenceId",
        "name": "name",
        "network_type": "networkType",
        "routing_type": "routingType",
        "tags": "tags",
        "sites": "sites",
        "desired_properties": "desiredProperties",
    },
    "get_tags": {},
}
_SUBNET_AS_CODE_DEFAULT_METHOD = "get_sites"
_SUBNET_AS_CODE_CONFIG_FIELDS = (
    "subnet_as_code_method",
    "subnet_as_code_reference_id",
    "subnet_as_code_sites",
    "subnet_as_code_tags",
    "subnet_as_code_name",
    "subnet_as_code_network_type",
    "subnet_as_code_routing_type",
    "subnet_as_code_desired_properties",
    "subnet_as_code_address_type",
)
_SUBNET_AS_CODE_QUERY_VALUE_FIELDS = {
    "reference_id": "subnet_as_code_reference_id",
    "sites": "subnet_as_code_sites",
    "tags": "subnet_as_code_tags",
    "name": "subnet_as_code_name",
    "network_type": "subnet_as_code_network_type",
    "routing_type": "subnet_as_code_routing_type",
    "desired_properties": "subnet_as_code_desired_properties",
    "address_type": "subnet_as_code_address_type",
}
_SUBNET_AS_CODE_REQUIRES_EXPLICIT_METHOD = {
    "subnet_as_code_name",
    "subnet_as_code_network_type",
    "subnet_as_code_routing_type",
    "subnet_as_code_desired_properties",
    "subnet_as_code_address_type",
}


@dataclass(frozen=True)
class AuthoritativeSourceConfig:
    subnet_as_code_method: str | None = None
    subnet_as_code_reference_id: str | None = None
    subnet_as_code_sites: list[str] | None = None
    subnet_as_code_tags: list[str] | None = None
    subnet_as_code_name: str | None = None
    subnet_as_code_network_type: str | None = None
    subnet_as_code_routing_type: str | None = None
    subnet_as_code_desired_properties: list[str] | None = None
    subnet_as_code_address_type: str | None = None
    xlsx_file: str | Path | None = None
    xlsx_sheet: str | None = None


class AuthoritativeSourceConfigMixin:
    source_config: AuthoritativeSourceConfig

    def as_authoritative_source_config(self) -> AuthoritativeSourceConfig:
        return self.source_config

    @property
    def subnet_as_code_method(self) -> str | None:
        return self.source_config.subnet_as_code_method

    @property
    def subnet_as_code_reference_id(self) -> str | None:
        return self.source_config.subnet_as_code_reference_id

    @property
    def subnet_as_code_sites(self) -> list[str] | None:
        return self.source_config.subnet_as_code_sites

    @property
    def subnet_as_code_tags(self) -> list[str] | None:
        return self.source_config.subnet_as_code_tags

    @property
    def subnet_as_code_name(self) -> str | None:
        return self.source_config.subnet_as_code_name

    @property
    def subnet_as_code_network_type(self) -> str | None:
        return self.source_config.subnet_as_code_network_type

    @property
    def subnet_as_code_routing_type(self) -> str | None:
        return self.source_config.subnet_as_code_routing_type

    @property
    def subnet_as_code_desired_properties(self) -> list[str] | None:
        return self.source_config.subnet_as_code_desired_properties

    @property
    def subnet_as_code_address_type(self) -> str | None:
        return self.source_config.subnet_as_code_address_type

    @property
    def source_xlsx_file(self) -> str | None:
        return _stringify_pathlike(self.source_config.xlsx_file)

    @property
    def source_xlsx_sheet(self) -> str | None:
        return self.source_config.xlsx_sheet


def load_authoritative_source(
    config: AuthoritativeSourceConfig, audit_logger=None
) -> tuple[str, SourceLoadResult]:
    """Load the highest-priority configured source.

    Expected-range input is intentionally limited to subnet_as_code and the
    legacy XLSX workflow.
    """
    validate_authoritative_source_config(config)
    if _uses_subnet_as_code(config):
        return "subnet_as_code", _load_subnet_as_code(config, audit_logger=audit_logger)
    if config.xlsx_file:
        return "xlsx_file", load_xlsx_definitions(
            config.xlsx_file,
            sheet_name=config.xlsx_sheet,
            audit_logger=audit_logger,
        )
    raise ValueError(
        "No supported authoritative source configured. Use subnet_as_code "
        "query settings or a legacy XLSX file."
    )


def has_configured_authoritative_source(config: AuthoritativeSourceConfig) -> bool:
    return any(
        (
            _uses_subnet_as_code(config),
            config.xlsx_file,
        )
    )


def validate_authoritative_source_config(config: AuthoritativeSourceConfig) -> None:
    if _uses_subnet_as_code(config):
        _validate_subnet_as_code_config(config)


def _uses_subnet_as_code(config: AuthoritativeSourceConfig) -> bool:
    return any(
        getattr(config, field_name)
        for field_name in _SUBNET_AS_CODE_CONFIG_FIELDS
    )


def _load_subnet_as_code(
    config: AuthoritativeSourceConfig,
    audit_logger=None,
    module: Any = None,
) -> SourceLoadResult:
    method_name, kwargs = _build_subnet_as_code_request(config)
    if module is None:
        try:
            module = importlib.import_module("subnet_as_code")
        except ImportError as exc:
            raise RuntimeError(
                "subnet_as_code module is not installed or importable in this "
                "environment."
            ) from exc

    loader = getattr(module, method_name, None)
    if not callable(loader):
        raise RuntimeError(
            f"subnet_as_code does not expose a callable '{method_name}'."
        )
    payload = loader(**kwargs)
    return _normalize_subnet_as_code_payload(
        method_name=method_name,
        payload=payload,
        audit_logger=audit_logger,
    )


def _build_subnet_as_code_request(
    config: AuthoritativeSourceConfig,
) -> tuple[str, dict[str, Any]]:
    method_name = _resolve_subnet_as_code_method(config)
    return method_name, _build_subnet_as_code_kwargs(
        method_name,
        _build_subnet_as_code_query_values(config),
    )


def _build_subnet_as_code_query_values(
    config: AuthoritativeSourceConfig,
) -> dict[str, Any]:
    query_values: dict[str, Any] = {}
    for query_name, config_field in _SUBNET_AS_CODE_QUERY_VALUE_FIELDS.items():
        value = getattr(config, config_field)
        if isinstance(value, list):
            query_values[query_name] = list(value)
            continue
        query_values[query_name] = value
    return query_values


def _build_subnet_as_code_kwargs(
    method_name: str,
    query_values: dict[str, Any],
) -> dict[str, Any]:
    parameter_map = _SUBNET_AS_CODE_METHOD_PARAMETER_MAP[method_name]
    unsupported = [
        internal_name
        for internal_name, value in query_values.items()
        if _subnet_as_code_has_value(value) and internal_name not in parameter_map
    ]
    if unsupported:
        raise ValueError(
            f"{method_name} does not support query parameters: "
            + ", ".join(sorted(unsupported))
        )

    kwargs: dict[str, Any] = {}
    for internal_name, external_name in parameter_map.items():
        value = query_values[internal_name]
        if not _subnet_as_code_has_value(value):
            continue
        kwargs[external_name] = value
    return kwargs


def _subnet_as_code_has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    return True


def _stringify_pathlike(value: str | Path | None) -> str | None:
    if value is None:
        return None
    return str(value)


def _resolve_subnet_as_code_method(config: AuthoritativeSourceConfig) -> str:
    method_name = str(config.subnet_as_code_method or "").strip()
    if method_name:
        _validate_supported_subnet_as_code_method(method_name)
        return method_name
    return _SUBNET_AS_CODE_DEFAULT_METHOD


def _validate_subnet_as_code_config(config: AuthoritativeSourceConfig) -> None:
    method_name = str(config.subnet_as_code_method or "").strip()
    if method_name:
        _validate_supported_subnet_as_code_method(method_name)
        return

    explicit_method_fields = [
        field_name
        for field_name in sorted(_SUBNET_AS_CODE_REQUIRES_EXPLICIT_METHOD)
        if _subnet_as_code_has_value(getattr(config, field_name))
    ]
    if explicit_method_fields:
        pretty = ", ".join(explicit_method_fields)
        raise ValueError(
            "subnet_as_code_method is required when using method-specific "
            f"filters: {pretty}."
        )


def _validate_supported_subnet_as_code_method(method_name: str) -> None:
    if method_name not in _SUBNET_AS_CODE_METHOD_PARAMETER_MAP:
        raise ValueError(
            "Unsupported subnet_as_code method. Supported methods: "
            + ", ".join(sorted(_SUBNET_AS_CODE_METHOD_PARAMETER_MAP))
        )


def _normalize_subnet_as_code_payload(
    method_name: str,
    payload: Any,
    audit_logger=None,
) -> SourceLoadResult:
    source_file = f"subnet_as_code.{method_name}"
    if method_name == "get_ipaddress":
        return _load_ipaddress_payload(
            payload,
            source_file=source_file,
            audit_logger=audit_logger,
        )
    if method_name == "get_tags":
        raise ValueError(
            "subnet_as_code.get_tags only returns allowed tag names and cannot "
            "be used as the authoritative scope source for coverage analysis."
        )
    return load_json_payload(
        payload,
        source_file=source_file,
        audit_logger=audit_logger,
    )


def _load_ipaddress_payload(
    payload: Any,
    source_file: str,
    audit_logger=None,
) -> SourceLoadResult:
    result = SourceLoadResult(files_processed=1)
    if not isinstance(payload, list):
        result.files_failed = 1
        result.validation_issues.append(
            ValidationIssue(
                source_file=source_file,
                message="subnet_as_code.get_ipaddress must return a list.",
            )
        )
        return result

    grouped: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(payload):
        field_name = f"records[{index}]"
        if not isinstance(item, dict):
            result.validation_issues.append(
                ValidationIssue(
                    source_file=source_file,
                    field_name=field_name,
                    message=f"{field_name} must be an object.",
                )
            )
            continue

        site_code = str(item.get("site_code") or "").strip().upper()
        ip_value = str(item.get("ip") or "").strip()
        if not site_code:
            result.validation_issues.append(
                ValidationIssue(
                    source_file=source_file,
                    field_name=f"{field_name}.site_code",
                    message="get_ipaddress record must include site_code.",
                )
            )
            continue
        if not ip_value:
            result.validation_issues.append(
                ValidationIssue(
                    source_file=source_file,
                    field_name=f"{field_name}.ip",
                    message="get_ipaddress record must include ip.",
                    site_code=site_code,
                )
            )
            continue

        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError as exc:
            result.validation_issues.append(
                ValidationIssue(
                    source_file=source_file,
                    field_name=f"{field_name}.ip",
                    message=f"Invalid IP address '{ip_value}': {exc}",
                    site_code=site_code,
                )
            )
            continue
        if ip_obj.version != 4:
            result.validation_issues.append(
                ValidationIssue(
                    source_file=source_file,
                    field_name=f"{field_name}.ip",
                    message=(
                        f"IPv6 address '{ip_value}' is not supported by Tenable "
                        "scope analysis."
                    ),
                    site_code=site_code,
                )
            )
            continue

        site_bucket = grouped.setdefault(
            site_code,
            {
                "public_ranges": [],
                "private_ranges": [],
            },
        )
        tags = _coerce_record_tags(item.get("tags"))
        record_name = str(item.get("name") or "").strip() or None
        metadata = {
            str(key): value
            for key, value in item.items()
            if str(key) not in {"site_code", "ip", "name", "tags"}
        }
        network = ipaddress.ip_network(f"{ip_obj}/32", strict=False)
        record = NetworkRange(
            name=record_name,
            description=record_name,
            cidr=str(network),
            network=str(network.network_address),
            prefix_length=network.prefixlen,
            subnetmask=str(network.netmask),
            tags=tags,
            source_metadata=metadata,
        )
        if ip_obj.is_private:
            site_bucket["private_ranges"].append(
                PrivateNetworkRange(**record.__dict__, vlans=[])
            )
        else:
            site_bucket["public_ranges"].append(record)

    for site_code, bucket in sorted(grouped.items()):
        if not bucket["public_ranges"] and not bucket["private_ranges"]:
            continue
        definition = SiteNetworkDefinition(
            source_file=source_file,
            site_name=site_code,
            site_code=site_code,
            description="Normalized from subnet_as_code.get_ipaddress",
            location=None,
            region=None,
            public_ranges=bucket["public_ranges"],
            private_ranges=bucket["private_ranges"],
        )
        result.site_definitions.append(definition)
        targets = flatten_site_definition(definition)
        result.coverage_targets.extend(targets)
        if audit_logger:
            audit_logger.emit(
                "authoritative_site_loaded",
                source_file=source_file,
                site_code=definition.site_code,
                target_count=len(targets),
            )

    if not result.site_definitions:
        result.files_failed = 1
    return result


def _coerce_record_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []
