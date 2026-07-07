import argparse
from typing import Any, Callable

from .source_loader import AuthoritativeSourceConfig

AUTHORITATIVE_SOURCE_ARGUMENTS: tuple[tuple[str, str], ...] = (
    ("subnet_as_code_method", "--subnet-as-code-method"),
    ("source_reference_id", "--source-reference-id"),
    ("source_sites", "--source-sites"),
    ("source_tags", "--source-tags"),
    ("source_name", "--source-name"),
    ("source_network_type", "--source-network-type"),
    ("source_routing_type", "--source-routing-type"),
    ("source_desired_properties", "--source-desired-properties"),
    ("source_address_type", "--source-address-type"),
)

SOURCE_ENVIRONMENT_MAP = {
    "subnet_as_code_method": "SUBNET_AS_CODE_METHOD",
    "source_reference_id": "SUBNET_AS_CODE_REFERENCE_ID",
    "source_sites": "SUBNET_AS_CODE_SITES",
    "source_tags": "SUBNET_AS_CODE_TAGS",
    "source_name": "SUBNET_AS_CODE_NAME",
    "source_network_type": "SUBNET_AS_CODE_NETWORK_TYPE",
    "source_routing_type": "SUBNET_AS_CODE_ROUTING_TYPE",
    "source_desired_properties": "SUBNET_AS_CODE_DESIRED_PROPERTIES",
    "source_address_type": "SUBNET_AS_CODE_ADDRESS_TYPE",
}


def add_authoritative_source_arguments(parser: argparse.ArgumentParser) -> None:
    for _, flag in AUTHORITATIVE_SOURCE_ARGUMENTS:
        parser.add_argument(flag)


def build_authoritative_source_config(
    scalar_getter: Callable[[str, str | None, Any], Any],
    csv_getter: Callable[[str, str | None, Any], list[str] | None],
) -> AuthoritativeSourceConfig:
    return AuthoritativeSourceConfig(
        subnet_as_code_method=scalar_getter(
            "subnet_as_code_method",
            SOURCE_ENVIRONMENT_MAP["subnet_as_code_method"],
            "get_sites",
        ),
        subnet_as_code_reference_id=scalar_getter(
            "source_reference_id",
            SOURCE_ENVIRONMENT_MAP["source_reference_id"],
            None,
        ),
        subnet_as_code_sites=csv_getter(
            "source_sites",
            SOURCE_ENVIRONMENT_MAP["source_sites"],
            None,
        ),
        subnet_as_code_tags=csv_getter(
            "source_tags",
            SOURCE_ENVIRONMENT_MAP["source_tags"],
            None,
        ),
        subnet_as_code_name=scalar_getter(
            "source_name",
            SOURCE_ENVIRONMENT_MAP["source_name"],
            None,
        ),
        subnet_as_code_network_type=scalar_getter(
            "source_network_type",
            SOURCE_ENVIRONMENT_MAP["source_network_type"],
            None,
        ),
        subnet_as_code_routing_type=scalar_getter(
            "source_routing_type",
            SOURCE_ENVIRONMENT_MAP["source_routing_type"],
            None,
        ),
        subnet_as_code_desired_properties=csv_getter(
            "source_desired_properties",
            SOURCE_ENVIRONMENT_MAP["source_desired_properties"],
            None,
        ),
        subnet_as_code_address_type=scalar_getter(
            "source_address_type",
            SOURCE_ENVIRONMENT_MAP["source_address_type"],
            None,
        ),
    )
