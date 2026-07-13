import argparse
from typing import Any, Callable

from .source_loader import AuthoritativeSourceConfig

AUTHORITATIVE_SOURCE_ARGUMENTS: tuple[tuple[str, str], ...] = (
    ("source_reference_id", "--source-reference-id"),
    ("source_sites", "--source-sites"),
    ("source_tags", "--source-tags"),
    ("source_name", "--source-name"),
    ("source_network_type", "--source-network-type"),
    ("source_routing_type", "--source-routing-type"),
)

SOURCE_ENVIRONMENT_MAP = {
    "source_reference_id": "SUBNET_AS_CODE_REFERENCE_ID",
    "source_sites": "SUBNET_AS_CODE_SITES",
    "source_tags": "SUBNET_AS_CODE_TAGS",
    "source_name": "SUBNET_AS_CODE_NAME",
    "source_network_type": "SUBNET_AS_CODE_NETWORK_TYPE",
    "source_routing_type": "SUBNET_AS_CODE_ROUTING_TYPE",
}


def add_authoritative_source_arguments(parser: argparse.ArgumentParser) -> None:
    for _, flag in AUTHORITATIVE_SOURCE_ARGUMENTS:
        parser.add_argument(flag)


def build_authoritative_source_config(
    scalar_getter: Callable[[str, str | None, Any], Any],
    csv_getter: Callable[[str, str | None, Any], list[str] | None],
) -> AuthoritativeSourceConfig:
    return AuthoritativeSourceConfig(
        reference_id=scalar_getter(
            "source_reference_id",
            SOURCE_ENVIRONMENT_MAP["source_reference_id"],
            None,
        ),
        sites=csv_getter(
            "source_sites",
            SOURCE_ENVIRONMENT_MAP["source_sites"],
            None,
        ),
        tags=csv_getter(
            "source_tags",
            SOURCE_ENVIRONMENT_MAP["source_tags"],
            None,
        ),
        name=scalar_getter(
            "source_name",
            SOURCE_ENVIRONMENT_MAP["source_name"],
            None,
        ),
        network_type=scalar_getter(
            "source_network_type",
            SOURCE_ENVIRONMENT_MAP["source_network_type"],
            None,
        ),
        routing_type=scalar_getter(
            "source_routing_type",
            SOURCE_ENVIRONMENT_MAP["source_routing_type"],
            None,
        ),
    )
