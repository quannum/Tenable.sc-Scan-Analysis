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
from .github_connector import load_github_yaml_repo
from .json_connector import load_json_api, load_json_file, load_json_payload
from .xlsx_connector import load_xlsx_definitions
from .yaml_connector import flatten_site_definition, load_yaml_subnet_repo

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
    api_url: str | None = None
    api_token: str | None = None
    json_file: str | Path | None = None
    yaml_repo_path: str | Path | None = None
    xlsx_file: str | Path | None = None
    xlsx_sheet: str | None = None
    github_api_url: str | None = None
    github_repository: str | None = None
    github_ref: str = "main"
    github_path: str = ""
    github_token: str | None = None
    github_timeout_seconds: float = 30.0
    github_max_retries: int = 3
    api_timeout_seconds: float = 30.0
    api_max_retries: int = 3


def load_authoritative_source(
    config: AuthoritativeSourceConfig, audit_logger=None
) -> tuple[str, SourceLoadResult]:
    """Load the highest-priority configured source.

    XLSX remains supported by the legacy expected-scope workflow. This loader owns
    the normalized API/JSON/YAML paths used by detect-and-plan.
    """
    if _uses_subnet_as_code(config):
        return "subnet_as_code", _load_subnet_as_code(
            method=config.subnet_as_code_method or "get_sites",
            reference_id=config.subnet_as_code_reference_id,
            sites=config.subnet_as_code_sites,
            tags=config.subnet_as_code_tags,
            name=config.subnet_as_code_name,
            network_type=config.subnet_as_code_network_type,
            routing_type=config.subnet_as_code_routing_type,
            desired_properties=config.subnet_as_code_desired_properties,
            address_type=config.subnet_as_code_address_type,
            audit_logger=audit_logger,
        )
    if config.api_url:
        return "json_api", load_json_api(
            config.api_url,
            token=config.api_token,
            timeout_seconds=config.api_timeout_seconds,
            max_retries=config.api_max_retries,
            audit_logger=audit_logger,
        )
    if config.json_file:
        return "json_file", load_json_file(config.json_file, audit_logger=audit_logger)
    if config.github_api_url or config.github_repository:
        if not config.github_api_url or not config.github_repository:
            raise ValueError(
                "GitHub YAML source requires both github_api_url and "
                "github_repository."
            )
        return "github_yaml", load_github_yaml_repo(
            api_url=config.github_api_url,
            repository=config.github_repository,
            ref=config.github_ref,
            source_path=config.github_path,
            token=config.github_token,
            timeout_seconds=config.github_timeout_seconds,
            max_retries=config.github_max_retries,
            audit_logger=audit_logger,
        )
    if config.yaml_repo_path:
        return "yaml_repo", load_yaml_subnet_repo(
            config.yaml_repo_path, audit_logger=audit_logger
        )
    if config.xlsx_file:
        return "xlsx_file", load_xlsx_definitions(
            config.xlsx_file,
            sheet_name=config.xlsx_sheet,
            audit_logger=audit_logger,
        )
    raise ValueError(
        "No authoritative source configured. Set a subnet_as_code method, API "
        "URL, local JSON file, GitHub repository, YAML repository path, or "
        "XLSX file."
    )


def _uses_subnet_as_code(config: AuthoritativeSourceConfig) -> bool:
    return any(
        (
            config.subnet_as_code_method,
            config.subnet_as_code_reference_id,
            config.subnet_as_code_sites,
            config.subnet_as_code_tags,
            config.subnet_as_code_name,
            config.subnet_as_code_network_type,
            config.subnet_as_code_routing_type,
            config.subnet_as_code_desired_properties,
            config.subnet_as_code_address_type,
        )
    )


def _load_subnet_as_code(
    method: str = "get_sites",
    reference_id: str | None = None,
    sites: list[str] | None = None,
    tags: list[str] | None = None,
    name: str | None = None,
    network_type: str | None = None,
    routing_type: str | None = None,
    desired_properties: list[str] | None = None,
    address_type: str | None = None,
    audit_logger=None,
    module: Any = None,
) -> SourceLoadResult:
    method_name = str(method or "get_sites").strip()
    if method_name not in _SUBNET_AS_CODE_METHOD_PARAMETER_MAP:
        raise ValueError(
            "Unsupported subnet_as_code method. Supported methods: "
            + ", ".join(sorted(_SUBNET_AS_CODE_METHOD_PARAMETER_MAP))
        )

    kwargs = _build_subnet_as_code_kwargs(
        method_name,
        {
            "reference_id": reference_id,
            "sites": list(sites or []),
            "tags": list(tags or []),
            "name": name,
            "network_type": network_type,
            "routing_type": routing_type,
            "desired_properties": list(desired_properties or []),
            "address_type": address_type,
        },
    )
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
