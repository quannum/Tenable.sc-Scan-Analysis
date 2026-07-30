import json
import os
from pathlib import Path
from typing import Any

import yaml

from ..io.parsing import parse_csv_list

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # pyright: ignore[reportMissingImports]

ENV_PREFIX = "TCW_"


def normalize_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_")


def normalize_config_keys(config_data: dict[str, Any]) -> dict[str, Any]:
    return {normalize_key(key): value for key, value in config_data.items()}


def load_config_section(
    config_file_path: Path,
    section_name: str,
    root_error: str,
    section_error: str,
    unsupported_error: str,
) -> dict[str, Any]:
    if not config_file_path.is_file():
        raise ValueError(f"Config file does not exist: {config_file_path}")

    suffix = config_file_path.suffix.lower()
    if suffix == ".json":
        with config_file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    elif suffix in {".toml", ".tml"}:
        with config_file_path.open("rb") as handle:
            data = tomllib.load(handle)
    elif suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(config_file_path.read_text(encoding="utf-8"))
    else:
        raise ValueError(unsupported_error)

    if not isinstance(data, dict):
        raise ValueError(root_error)

    section = data.get(section_name, data)
    if not isinstance(section, dict):
        raise ValueError(section_error)

    return normalize_config_keys(section)


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


class SettingsResolver:
    def __init__(
        self,
        args: Any,
        config_data: dict[str, Any] | None = None,
        command_name: str | None = None,
        legacy_env_names: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        self.args = args
        self.config_data = config_data or {}
        self.command_name = command_name
        self.legacy_env_names = legacy_env_names or {}

    def get(
        self,
        name: str,
        default: Any = None,
        environment_name: str | None = None,
    ) -> Any:
        cli_value = getattr(self.args, name, None)
        if cli_value is not None:
            return cli_value

        env_value = env_setting(
            name,
            environment_name,
            self.legacy_env_names.get(name, ()),
        )
        if env_value is not None:
            return env_value

        command_config = self._command_config()
        if name in command_config:
            return command_config[name]

        return self.config_data.get(name, default)

    def csv(
        self,
        name: str,
        default: Any = None,
        environment_name: str | None = None,
    ) -> list[str] | None:
        """Read a comma-separated setting as a list"""
        return parse_csv_list(self.get(name, default, environment_name)) or None

    def _command_config(self) -> dict[str, Any]:
        """Read settings for the active command"""
        if not self.command_name:
            return {}

        command_key = normalize_key(self.command_name)
        commands = self.config_data.get("commands", {})
        if not isinstance(commands, dict):
            commands = {}
        normalized_commands = {
            normalize_key(key): value for key, value in commands.items()
        }
        command_config = self.config_data.get(
            command_key,
            normalized_commands.get(command_key, {}),
        )
        if not isinstance(command_config, dict):
            return {}
        return normalize_config_keys(command_config)


def as_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    if isinstance(value, Path):
        return value

    text = str(value).strip()
    if not text:
        return None
    return Path(text)


def optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


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
