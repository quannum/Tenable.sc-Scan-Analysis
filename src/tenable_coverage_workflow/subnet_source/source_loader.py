from dataclasses import dataclass
from pathlib import Path

from ..models import SourceLoadResult
from .github_connector import load_github_yaml_repo
from .json_connector import load_json_api, load_json_file
from .xlsx_connector import load_xlsx_definitions
from .yaml_connector import load_yaml_subnet_repo


@dataclass(frozen=True)
class AuthoritativeSourceConfig:
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
        "No authoritative source configured. Set an API URL, local JSON file, "
        "GitHub repository, YAML repository path, or XLSX file."
    )
