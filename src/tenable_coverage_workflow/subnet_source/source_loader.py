import importlib
from dataclasses import dataclass
from typing import Any

from ..models import SourceLoadResult
from .json_connector import load_json_payload


@dataclass(frozen=True)
class AuthoritativeSourceConfig:
    reference_id: str | None = None
    sites: list[str] | None = None
    tags: list[str] | None = None
    name: str | None = None
    network_type: str | None = None
    routing_type: str | None = None


def load_authoritative_source(
    config: AuthoritativeSourceConfig, audit_logger=None
) -> tuple[str, SourceLoadResult]:
    """Load complete site definitions from subnet-as-code."""
    try:
        module = importlib.import_module("subnet_as_code")
    except ImportError as exc:
        raise RuntimeError(
            "subnet_as_code module is not installed or importable in this "
            "environment."
        ) from exc

    try:
        get_sites = module.get_sites
    except AttributeError:
        raise RuntimeError("subnet_as_code module does not have method 'get_sites'.")
    if not callable(get_sites):
        raise RuntimeError("subnet_as_code.get_sites must be callable.")

    payload = get_sites(**_build_get_sites_kwargs(config))
    return "subnet_as_code", load_json_payload(
        payload,
        source_file="subnet_as_code.get_sites",
        audit_logger=audit_logger,
    )


def _build_get_sites_kwargs(config: AuthoritativeSourceConfig) -> dict[str, Any]:
    values = {
        "referenceId": config.reference_id,
        "sites": config.sites,
        "tags": config.tags,
        "name": config.name,
        "networkType": config.network_type,
        "routingType": config.routing_type,
    }
    return {
        name: list(value) if isinstance(value, list) else value
        for name, value in values.items()
        if _has_value(value)
    }


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    return True
