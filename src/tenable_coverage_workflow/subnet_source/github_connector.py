import json
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from ..models import SourceLoadResult
from .yaml_connector import load_yaml_subnet_repo

GitHubRequester = Callable[[str, dict[str, str], float], bytes]


def load_github_yaml_repo(
    api_url: str,
    repository: str,
    ref: str = "main",
    source_path: str = "",
    token: str | None = None,
    timeout_seconds: float = 30.0,
    max_retries: int = 3,
    audit_logger=None,
    requester: GitHubRequester | None = None,
) -> SourceLoadResult:
    owner, repo = _parse_repository(repository)
    base_url = api_url.rstrip("/")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "tenable-sc-scan-analysis",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    requester = requester or _default_requester

    root_path = _safe_repo_path(source_path)
    contents_url = _contents_url(base_url, owner, repo, root_path, ref)
    yaml_files = _walk_contents(
        contents_url,
        headers,
        timeout_seconds,
        max_retries,
        requester,
    )
    if not yaml_files:
        raise ValueError(
            f"GitHub repository {repository}@{ref} path '{source_path}' "
            "contains no YAML files."
        )

    with tempfile.TemporaryDirectory(prefix="tenable-network-source-") as directory:
        root = Path(directory)
        for repo_path, content in yaml_files:
            relative = _safe_repo_path(repo_path)
            destination = root.joinpath(*relative.parts)
            resolved = destination.resolve()
            if root.resolve() not in resolved.parents:
                raise ValueError(f"Unsafe GitHub repository path: {repo_path}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        result = load_yaml_subnet_repo(root, audit_logger=audit_logger)

    if audit_logger:
        audit_logger.emit(
            "github_yaml_repository_loaded",
            api_url=base_url,
            repository=repository,
            ref=ref,
            source_path=source_path,
            yaml_file_count=len(yaml_files),
        )
    return result


def _walk_contents(
    url: str,
    headers: dict[str, str],
    timeout_seconds: float,
    max_retries: int,
    requester: GitHubRequester,
) -> list[tuple[str, bytes]]:
    payload = _request_json(
        url, headers, timeout_seconds, max_retries, requester
    )
    entries = payload if isinstance(payload, list) else [payload]
    collected: list[tuple[str, bytes]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type")
        entry_url = entry.get("url")
        entry_path = str(entry.get("path") or "")
        if entry_type == "dir" and entry_url:
            child_url = _inherit_ref(url, str(entry_url))
            collected.extend(
                _walk_contents(
                    child_url,
                    headers,
                    timeout_seconds,
                    max_retries,
                    requester,
                )
            )
        elif (
            entry_type == "file"
            and entry_url
            and Path(entry_path).suffix.lower() in {".yaml", ".yml"}
        ):
            file_url = _inherit_ref(url, str(entry_url))
            raw_headers = dict(headers)
            raw_headers["Accept"] = "application/vnd.github.raw+json"
            collected.append(
                (
                    entry_path,
                    _request_bytes(
                        file_url,
                        raw_headers,
                        timeout_seconds,
                        max_retries,
                        requester,
                    ),
                )
            )
    return collected


def _request_json(
    url: str,
    headers: dict[str, str],
    timeout_seconds: float,
    max_retries: int,
    requester: GitHubRequester,
):
    data = _request_bytes(
        url, headers, timeout_seconds, max_retries, requester
    )
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"GitHub API returned invalid JSON for {url}") from exc


def _request_bytes(
    url: str,
    headers: dict[str, str],
    timeout_seconds: float,
    max_retries: int,
    requester: GitHubRequester,
) -> bytes:
    if timeout_seconds <= 0 or max_retries <= 0:
        raise ValueError("GitHub timeout and max retries must be positive")
    for attempt in range(1, max_retries + 1):
        try:
            return requester(url, headers, timeout_seconds)
        except HTTPError as exc:
            retryable = exc.code == 429 or exc.code >= 500
            if not retryable or attempt == max_retries:
                raise RuntimeError(
                    f"GitHub API request failed ({exc.code}) for {url}"
                ) from exc
            delay = _retry_delay(exc, attempt)
        except (URLError, TimeoutError, OSError) as exc:
            if attempt == max_retries:
                raise RuntimeError(
                    f"GitHub API request failed after {attempt} attempts for {url}: "
                    f"{exc}"
                ) from exc
            delay = min(2 ** (attempt - 1), 8)
        time.sleep(delay)
    raise RuntimeError(f"GitHub API request failed for {url}")


def _default_requester(
    url: str, headers: dict[str, str], timeout_seconds: float
) -> bytes:
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def _contents_url(
    api_url: str,
    owner: str,
    repo: str,
    source_path: PurePosixPath,
    ref: str,
) -> str:
    encoded_path = "/".join(quote(part, safe="") for part in source_path.parts)
    suffix = f"/{encoded_path}" if encoded_path else ""
    return (
        f"{api_url}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/contents{suffix}?{urlencode({'ref': ref})}"
    )


def _parse_repository(value: str) -> tuple[str, str]:
    parts = [part.strip() for part in str(value).split("/") if part.strip()]
    if len(parts) != 2:
        raise ValueError("GitHub repository must use OWNER/REPO format")
    return parts[0], parts[1]


def _safe_repo_path(value: str) -> PurePosixPath:
    normalized = str(value or "").strip().replace("\\", "/").strip("/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe GitHub repository path: {value}")
    return path


def _retry_delay(exc: HTTPError, attempt: int) -> float:
    retry_after = exc.headers.get("Retry-After") if exc.headers else None
    try:
        return min(max(float(retry_after), 0.0), 60.0)
    except (TypeError, ValueError):
        return min(2 ** (attempt - 1), 8)


def _inherit_ref(parent_url: str, child_url: str) -> str:
    parent_query = parse_qs(urlsplit(parent_url).query)
    child = urlsplit(child_url)
    child_query = parse_qs(child.query)
    if "ref" not in child_query and parent_query.get("ref"):
        child_query["ref"] = parent_query["ref"]
    query = urlencode(child_query, doseq=True)
    return urlunsplit((child.scheme, child.netloc, child.path, query, child.fragment))
