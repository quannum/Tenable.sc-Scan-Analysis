import os
from typing import Any

ENV_PREFIX = "TCW_"


def normalize_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_")


def normalize_config_keys(config_data: dict[str, Any]) -> dict[str, Any]:
    return {normalize_key(key): value for key, value in config_data.items()}


def env_setting(
    name: str,
    environment_name: str | None = None,
    legacy_names: tuple[str, ...] = (),
) -> Any:
    prefixed_environment_name = f"{ENV_PREFIX}{name.upper()}"
    if os.getenv(prefixed_environment_name) is not None:
        return os.getenv(prefixed_environment_name)
    if environment_name and os.getenv(environment_name) is not None:
        return os.getenv(environment_name)
    for legacy_name in legacy_names:
        if os.getenv(legacy_name) is not None:
            return os.getenv(legacy_name)
    return None


def parse_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
    raise ValueError(f"Invalid boolean value for '{field_name}': {value}")


def parse_positive_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer value for '{field_name}': {value}") from exc

    if parsed <= 0:
        raise ValueError(
            f"Invalid integer value for '{field_name}': {value}. Must be > 0."
        )
    return parsed


def parse_nonnegative_float(value: Any, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric value for '{field_name}': {value}") from exc

    if parsed < 0:
        raise ValueError(
            f"Invalid numeric value for '{field_name}': {value}. Must be >= 0."
        )
    return parsed
