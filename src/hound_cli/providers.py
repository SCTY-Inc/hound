"""Centralized, credential-safe provider transport for Hound."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import stat
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .evidence import EvidenceError, make_lead
from .packs import provider_pack
from .packs.scholarly import ARXIV_FIELDS, arxiv_request_url, parse_arxiv_response
from .safety import (
    contains_credential,
    credential_forms,
    normalized_key,
    public_hostname,
    secret_key,
    url_text_safe,
)


REQUEST_SCHEMA = "hound.provider.request.v1"
RESPONSE_SCHEMA = "hound.provider.response.v1"
MAX_REQUEST_BYTES = 1 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_CREDENTIAL_FILE_BYTES = 1 * 1024 * 1024
MAX_NESTING_DEPTH = 32

_ENDPOINTS = {
    ("exa", "search"): "https://api.exa.ai/search",
    ("exa", "contents"): "https://api.exa.ai/contents",
    ("firecrawl", "search"): "https://api.firecrawl.dev/v2/search",
    ("firecrawl", "scrape"): "https://api.firecrawl.dev/v2/scrape",
    ("arxiv", "search"): "https://export.arxiv.org/api/query",
}
_ENV_KEYS: dict[str, str | None] = {
    "exa": "EXA_API_KEY",
    "firecrawl": "FIRECRAWL_API_KEY",
    "arxiv": None,
}
_REQUIRED_FIELDS = {"schema_version", "provider", "operation", "parameters"}
_OPTIONAL_FIELDS = {"retrieved_at"}
_EXA_CONTENT_FIELDS = {
    "text",
    "highlights",
    "summary",
    "subpages",
    "subpageTarget",
    "extras",
    "livecrawl",
    "livecrawlTimeout",
    "context",
}
_EXA_CONTENT_OBJECT_FIELDS = {
    "text": {"maxCharacters", "includeHtmlTags"},
    "highlights": {"query", "numSentences", "highlightsPerUrl"},
    "summary": {"query", "schema"},
    "extras": {"links", "imageLinks"},
    "context": {"maxCharacters"},
}
_ALLOWED_PARAMETER_FIELDS = {
    ("exa", "search"): {
        "query",
        "additionalQueries",
        "type",
        "category",
        "userLocation",
        "numResults",
        "includeDomains",
        "excludeDomains",
        "startCrawlDate",
        "endCrawlDate",
        "startPublishedDate",
        "endPublishedDate",
        "includeText",
        "excludeText",
        "context",
        "moderation",
        "contents",
        "text",
        "highlights",
        "summary",
        "livecrawl",
        "systemPrompt",
        "structuredOutput",
        "outputSchema",
        "searchQueries",
    },
    ("exa", "contents"): {"ids", "urls", *_EXA_CONTENT_FIELDS},
    ("firecrawl", "search"): {
        "query",
        "limit",
        "sources",
        "categories",
        "tbs",
        "location",
        "country",
        "timeout",
        "ignoreInvalidURLs",
    },
    ("firecrawl", "scrape"): {
        "url",
        "formats",
        "onlyMainContent",
        "includeTags",
        "excludeTags",
        "maxAge",
        "waitFor",
        "timeout",
        "mobile",
        "parsers",
        "location",
        "removeBase64Images",
        "blockAds",
        "storeInCache",
        "zeroDataRetention",
    },
    ("arxiv", "search"): ARXIV_FIELDS,
}
_PROHIBITED_ACTIVE_PARAMETER_KEYS = {
    "actions",
    "headers",
    "proxy",
    "scrapeoptions",
    "skiptlsverification",
}

Transport = Callable[..., tuple[int, bytes]]


class ProviderError(ValueError):
    """A provider request is invalid or cannot be completed safely."""


def load_provider_environment(
    path: str | Path, provider: str
) -> dict[str, str]:
    """Load only one provider credential from a private dotenv-style file."""

    env_key = _ENV_KEYS.get(provider)
    if not env_key:
        raise ProviderError("provider has no credential binding")
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise ProviderError("provider credential file is unreadable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProviderError("provider credential file must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise ProviderError("provider credential file must be owned by the current user")
        if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ProviderError(
                "provider credential file must not be accessible by group or other users"
            )
        if metadata.st_size > MAX_CREDENTIAL_FILE_BYTES:
            raise ProviderError("provider credential file exceeds size limit")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(MAX_CREDENTIAL_FILE_BYTES + 1)
    except OSError as error:
        raise ProviderError("provider credential file is unreadable") from error
    finally:
        os.close(descriptor)
    if len(raw) > MAX_CREDENTIAL_FILE_BYTES:
        raise ProviderError("provider credential file exceeds size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise ProviderError("provider credential file is not UTF-8") from error

    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, separator, value = line.partition("=")
        if not separator or name.strip() != env_key:
            continue
        value = value.strip()
        if value[:1] in {"'", '"'}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise ProviderError("provider credential file has malformed quoting")
            value = value[1:-1]
        values.append(value)
    if not values or not values[0].strip():
        raise ProviderError(f"provider credential {env_key} is missing")
    if len(values) != 1:
        raise ProviderError(f"provider credential {env_key} is duplicated")
    return {env_key: values[0]}


def validate_public_url(value: str) -> None:
    if len(value) > 8192:
        raise ProviderError("parameters contain an overlong URL")
    if not url_text_safe(value):
        raise ProviderError("parameters contain an invalid URL")
    try:
        parsed = urlsplit(value)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        fragment = parse_qsl(parsed.fragment, keep_blank_values=True)
        username = parsed.username
        password = parsed.password
        parsed.port
    except ValueError as error:
        raise ProviderError("parameters contain an invalid URL") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or not public_hostname(parsed.hostname)
    ):
        raise ProviderError("parameters contain an invalid HTTP URL")
    if username is not None or password is not None:
        raise ProviderError("parameters must not embed URL credentials")
    if ";" in parsed.query or ";" in parsed.fragment:
        raise ProviderError("parameters contain ambiguous URL parameters")
    if any(secret_key(key) for key, _ in [*query, *fragment]):
        raise ProviderError("parameters must not embed URL credentials")


def _clean_parameter(value: object, path: str, depth: int = 0) -> Any:
    if depth > MAX_NESTING_DEPTH:
        raise ProviderError(f"{path} is nested too deeply")
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProviderError(f"{path} keys must be strings")
            if secret_key(key):
                raise ProviderError(f"{path} contains a prohibited credential field")
            if normalized_key(key).replace("_", "") in _PROHIBITED_ACTIVE_PARAMETER_KEYS:
                raise ProviderError(f"{path}.{key} is not allowed at the provider boundary")
            cleaned[key] = _clean_parameter(item, f"{path}.{key}", depth + 1)
        return cleaned
    if isinstance(value, list):
        return [_clean_parameter(item, f"{path}[]", depth + 1) for item in value]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProviderError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, str):
        if value.casefold().startswith(("http://", "https://")):
            validate_public_url(value)
        return value
    raise ProviderError(f"{path} must contain only JSON values")


def _bounded_integer(parameters: Mapping[str, object], field: str) -> None:
    if field not in parameters:
        return
    value = parameters[field]
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise ProviderError(f"parameters.{field} must be an integer from 1 through 100")


def _require_query(parameters: Mapping[str, object]) -> None:
    query = parameters.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ProviderError("search parameters.query must be a non-empty string")
    if len(query) > 10_000:
        raise ProviderError("search parameters.query exceeds 10,000 characters")


def _reject_unknown_fields(
    value: object, allowed: set[str], label: str
) -> None:
    if not isinstance(value, Mapping):
        return
    unknown = set(value) - allowed
    if unknown:
        raise ProviderError(f"{label} fields are not allowed: {sorted(unknown)!r}")


def _validate_exa_parameter_objects(
    operation: str, parameters: Mapping[str, object]
) -> None:
    containers = [parameters]
    contents = parameters.get("contents")
    if operation == "search" and isinstance(contents, Mapping):
        _reject_unknown_fields(contents, _EXA_CONTENT_FIELDS, "Exa contents")
        containers.append(contents)
    for container in containers:
        for field, allowed in _EXA_CONTENT_OBJECT_FIELDS.items():
            _reject_unknown_fields(
                container.get(field), allowed, f"Exa {field} options"
            )


def _validate_operation_parameters(
    provider: str, operation: str, parameters: Mapping[str, object]
) -> None:
    unknown = set(parameters) - _ALLOWED_PARAMETER_FIELDS[(provider, operation)]
    if unknown:
        raise ProviderError(
            f"{provider.title()} {operation} parameters are not allowed: {sorted(unknown)!r}"
        )
    if provider == "exa":
        _validate_exa_parameter_objects(operation, parameters)
    _bounded_integer(parameters, "numResults")
    _bounded_integer(parameters, "limit")
    _bounded_integer(parameters, "maxResults")
    if operation == "search":
        _require_query(parameters)
    if provider == "arxiv":
        categories = parameters.get("categories", [])
        if (
            not isinstance(categories, list)
            or len(categories) > 20
            or any(
                not isinstance(category, str)
                or not re.fullmatch(r"[a-z-]+(?:\.[A-Za-z-]+)+", category)
                for category in categories
            )
        ):
            raise ProviderError("arxiv categories must be a bounded array of category IDs")
        start = parameters.get("startPublishedDate")
        if start is not None and (
            not isinstance(start, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", start) is None
        ):
            raise ProviderError("arxiv startPublishedDate must be YYYY-MM-DD")
    elif provider == "exa" and operation == "contents":
        ids = parameters.get("ids")
        urls = parameters.get("urls")
        if (ids is None) == (urls is None):
            raise ProviderError("Exa contents requires exactly one of parameters.ids or parameters.urls")
        values = ids if ids is not None else urls
        if not isinstance(values, list) or not 1 <= len(values) <= 100 or any(
            not isinstance(item, str) or not item or len(item) > 2048 for item in values
        ):
            raise ProviderError("Exa contents IDs or URLs must contain 1 through 100 strings")
        if urls is not None:
            for url in urls:
                validate_public_url(url)
    elif provider == "firecrawl" and operation == "scrape":
        url = parameters.get("url")
        if not isinstance(url, str):
            raise ProviderError("Firecrawl scrape parameters.url must be an HTTP URL")
        validate_public_url(url)


def validate_request(obj: object) -> dict[str, Any]:
    """Validate and copy a strict ``hound.provider.request.v1`` object."""

    if not isinstance(obj, dict):
        raise ProviderError("provider request must be an object")
    if any(not isinstance(key, str) for key in obj):
        raise ProviderError("provider request field names must be strings")
    missing = _REQUIRED_FIELDS - obj.keys()
    if missing:
        raise ProviderError(f"provider request is missing fields: {sorted(missing)!r}")
    unknown = obj.keys() - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
    if unknown:
        raise ProviderError(f"provider request has unknown fields: {sorted(unknown)!r}")
    if obj["schema_version"] != REQUEST_SCHEMA:
        raise ProviderError(f"schema_version must be {REQUEST_SCHEMA!r}")

    provider = obj["provider"]
    operation = obj["operation"]
    if (
        not isinstance(provider, str)
        or provider not in _ENV_KEYS
        or provider_pack(provider) is None
    ):
        raise ProviderError("provider must name a built-in Hound source adapter")
    if not isinstance(operation, str) or (provider, operation) not in _ENDPOINTS:
        raise ProviderError(f"operation is not supported by provider {provider!r}")
    if not isinstance(obj["parameters"], dict):
        raise ProviderError("parameters must be an object")
    parameters = _clean_parameter(obj["parameters"], "parameters")
    _validate_operation_parameters(provider, operation, parameters)

    validated: dict[str, Any] = {
        "schema_version": REQUEST_SCHEMA,
        "provider": provider,
        "operation": operation,
        "parameters": parameters,
    }
    if "retrieved_at" in obj:
        retrieved_at = obj["retrieved_at"]
        if not isinstance(retrieved_at, str) or not retrieved_at.strip():
            raise ProviderError("retrieved_at must be a non-empty string")
        validated["retrieved_at"] = retrieved_at
    if (
        provider == "arxiv"
        and "startPublishedDate" in parameters
        and "retrieved_at" not in validated
    ):
        raise ProviderError("arxiv date-bounded search requires retrieved_at")
    return validated


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (OverflowError, TypeError, ValueError) as error:
        raise ProviderError("value is not valid canonical JSON") from error


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _default_transport(
    *,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
    method: str = "POST",
) -> tuple[int, bytes]:
    deadline = time.monotonic() + timeout
    request = Request(
        url,
        data=body if method == "POST" else None,
        headers=dict(headers),
        method=method,
    )
    opener = build_opener(_NoRedirects())
    completed: queue.Queue[
        tuple[Exception | None, tuple[int, bytes] | None]
    ] = queue.Queue(maxsize=1)

    def perform_request() -> None:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError("provider request timed out")
            with opener.open(request, timeout=remaining) as response:
                chunks: list[bytes] = []
                size = 0
                read = getattr(response, "read1", response.read)
                while True:
                    if time.monotonic() >= deadline:
                        raise ProviderError("provider request timed out")
                    chunk = read(min(64 * 1024, MAX_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ProviderError("provider response exceeded size limit")
                outcome = (
                    None,
                    (int(response.getcode()), b"".join(chunks)),
                )
        except HTTPError as error:
            try:
                error.close()
            except OSError:
                pass
            outcome = (None, (error.code, b""))
        except Exception as error:
            outcome = (error, None)
        completed.put_nowait(outcome)

    worker = threading.Thread(
        target=perform_request,
        name="hound-provider-http",
        daemon=True,
    )
    worker.start()
    try:
        error, result = completed.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        raise ProviderError("provider request timed out") from None
    if error is not None:
        raise error
    if result is None:
        raise ProviderError("provider transport returned an invalid response")
    return result


def _credential_headers(provider: str, api_key: str) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if provider == "exa":
        headers["x-api-key"] = api_key
    elif provider == "firecrawl":
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _decode_response(status: object, body: object, api_key: str) -> dict[str, Any]:
    if isinstance(status, bool) or not isinstance(status, int):
        raise ProviderError("provider transport returned an invalid status")
    if status < 200 or status >= 300:
        raise ProviderError(f"provider returned HTTP status {status}")
    if not isinstance(body, bytes):
        raise ProviderError("provider transport returned an invalid body")
    if len(body) > MAX_RESPONSE_BYTES:
        raise ProviderError("provider response exceeded size limit")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProviderError("provider returned malformed JSON") from error
    if not isinstance(data, dict):
        raise ProviderError("provider returned a non-object JSON response")
    _canonical_json(data)
    if "success" in data:
        if not isinstance(data["success"], bool):
            raise ProviderError("provider returned an invalid success flag")
        if data["success"] is False:
            raise ProviderError("provider reported an unsuccessful request")
    if contains_credential(data, credential_forms(api_key)):
        raise ProviderError("provider response contained credential material")
    return data


def _result_leads(
    provider: str, parameters: Mapping[str, object], raw_data: Mapping[str, object]
) -> list[dict[str, Any]]:
    query = parameters["query"]
    if provider in {"exa", "arxiv"}:
        results = raw_data.get("results")
    else:
        data = raw_data.get("data")
        results = data.get("web") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ProviderError("provider search response does not contain a result list")

    leads: list[dict[str, Any]] = []
    for rank, result in enumerate(results, start=1):
        if not isinstance(result, dict):
            raise ProviderError("provider search result must be an object")
        url = result.get("url")
        title = result.get("title")
        if not isinstance(url, str) or (title is not None and not isinstance(title, str)):
            raise ProviderError("provider search result has invalid URL or title")
        try:
            metadata: dict[str, object] = {"rank": rank}
            if provider == "arxiv":
                metadata["source_profile"] = "academic_preprint"
            leads.append(
                make_lead(
                    provider,
                    query,
                    url,
                    title=title,
                    metadata=metadata,
                )
            )
        except EvidenceError as error:
            raise ProviderError("provider search result is unsafe") from error
    return leads


def execute_request(
    request: object,
    *,
    env: Mapping[str, str] | None = None,
    transport: Transport | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    """Execute a validated provider request without exposing its credential."""

    validated = validate_request(request)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ProviderError("timeout must be a positive finite number")
    timeout_seconds = float(timeout)

    provider = validated["provider"]
    operation = validated["operation"]
    environment = os.environ if env is None else env
    if not isinstance(environment, Mapping):
        raise ProviderError("env must be a mapping")
    env_key = _ENV_KEYS[provider]
    api_key = environment.get(env_key) if env_key else ""
    if env_key and (not isinstance(api_key, str) or not api_key.strip()):
        raise ProviderError(f"provider credential {env_key} is missing")
    forms = credential_forms(api_key) if api_key else []
    if forms and contains_credential(validated["parameters"], forms):
        raise ProviderError("provider parameters must not contain its credential")

    payload = _canonical_json(validated["parameters"])
    if len(payload) > MAX_REQUEST_BYTES:
        raise ProviderError("provider request exceeded size limit")
    endpoint = _ENDPOINTS[(provider, operation)]
    headers = _credential_headers(provider, api_key)
    body = payload
    method = "POST"
    if provider == "arxiv":
        endpoint = arxiv_request_url(validated["parameters"], validated.get("retrieved_at"))
        headers = {"Accept": "application/atom+xml", "User-Agent": "hound-scholarly/1"}
        body = b""
        method = "GET"
    try:
        if transport is None:
            transport_result = _default_transport(
                url=endpoint,
                headers=headers,
                body=body,
                timeout=timeout_seconds,
                method=method,
            )
        else:
            transport_result = transport(
                url=endpoint,
                headers=headers,
                body=body,
                timeout=timeout_seconds,
            )
    except Exception:
        raise ProviderError("provider transport failed") from None
    if not isinstance(transport_result, tuple) or len(transport_result) != 2:
        raise ProviderError("provider transport returned an invalid response")
    status, response_body = transport_result
    if provider == "arxiv":
        if not isinstance(status, int) or status < 200 or status >= 300:
            raise ProviderError(f"provider returned HTTP status {status}")
        if not isinstance(response_body, bytes) or len(response_body) > MAX_RESPONSE_BYTES:
            raise ProviderError("provider response exceeded size limit")
        try:
            raw_data = parse_arxiv_response(response_body)
        except Exception:
            raise ProviderError("provider returned malformed Atom XML") from None
        _canonical_json(raw_data)
    else:
        raw_data = _decode_response(status, response_body, api_key)

    response: dict[str, Any] = {
        "schema_version": RESPONSE_SCHEMA,
        "pack": provider_pack(provider),
        "provider": provider,
        "operation": operation,
        "request_sha256": hashlib.sha256(_canonical_json(validated)).hexdigest(),
        "raw_data": raw_data,
    }
    if "retrieved_at" in validated:
        response["retrieved_at"] = validated["retrieved_at"]
    if operation == "search":
        response["leads"] = _result_leads(provider, validated["parameters"], raw_data)
    if forms and contains_credential(response, forms):
        raise ProviderError("provider response contained credential material")
    return response


__all__ = [
    "ProviderError",
    "execute_request",
    "load_provider_environment",
    "validate_public_url",
    "validate_request",
]
