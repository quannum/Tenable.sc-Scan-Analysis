import json
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..models import SourceLoadResult, ValidationIssue
from .site_parser import extract_site_objects, parse_site_object
from .validation import add_relationship_issues
from .yaml_connector import flatten_site_definition


def load_json_file(path: str | Path, audit_logger=None) -> SourceLoadResult:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result = SourceLoadResult(files_processed=1, files_failed=1)
        result.validation_issues.append(
            ValidationIssue(source_file=str(source), message=str(exc))
        )
        return result
    return load_json_payload(
        payload, source_file=str(source), audit_logger=audit_logger
    )


def load_json_api(
    url: str,
    token: str | None = None,
    timeout_seconds: float = 30.0,
    max_retries: int = 3,
    audit_logger=None,
    opener: Callable[..., Any] = urlopen,
) -> SourceLoadResult:
    if timeout_seconds <= 0 or max_retries <= 0:
        raise ValueError("JSON API timeout and max retries must be positive")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)

    for attempt in range(1, max_retries + 1):
        try:
            with opener(request, timeout=timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return load_json_payload(
                payload, source_file=url, audit_logger=audit_logger
            )
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            retryable = (
                not isinstance(exc, HTTPError)
                or exc.code == 429
                or exc.code >= 500
            )
            if not retryable or attempt == max_retries:
                raise RuntimeError(
                    f"Authoritative JSON API request failed after {attempt} "
                    f"attempt(s): {exc}"
                ) from exc
            time.sleep(min(2 ** (attempt - 1), 8))
        except json.JSONDecodeError as exc:
            raise ValueError("Authoritative JSON API returned invalid JSON") from exc

    raise RuntimeError("Authoritative JSON API request failed")


def load_json_payload(
    payload: Any, source_file: str = "json-payload", audit_logger=None
) -> SourceLoadResult:
    result = SourceLoadResult(files_processed=1)
    sites = extract_site_objects(payload)
    if sites is None:
        result.files_failed = 1
        result.validation_issues.append(
            ValidationIssue(
                source_file=source_file,
                message=(
                    "JSON root must be a site object, a list of sites, or an "
                    "object containing a 'site_definition', 'sites', "
                    "'locations', or 'data' list."
                ),
            )
        )
        return result

    for index, raw_site in enumerate(sites):
        item_source = f"{source_file}#sites[{index}]"
        definition, issues = parse_site_object(raw_site, item_source)
        result.validation_issues.extend(issues)
        if definition is None:
            result.files_failed += 1
            continue
        result.site_definitions.append(definition)
        targets = flatten_site_definition(definition)
        result.coverage_targets.extend(targets)
        if audit_logger:
            audit_logger.emit(
                "authoritative_site_loaded",
                source_file=item_source,
                site_code=definition.site_code,
                target_count=len(targets),
            )
    return add_relationship_issues(result)
