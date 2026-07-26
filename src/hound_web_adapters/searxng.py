"""SearXNG federated discovery adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from hound_cli.evidence import EvidenceError, make_lead
from hound_cli.web import ADAPTER_SCHEMA, SEARCH_SCHEMA, validate_web_input
from ._http import AdapterError, Transport, json_object, request, service_url

MAX_PAGES = 5
MAX_ROUTES = 20
_LANGUAGE = re.compile(r"(?:[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})?|all|auto)\Z")


def _retrieved_at(value: str | None) -> str:
    return value or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _names(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ROUTES:
        raise AdapterError(f"SearXNG {label} must contain 1 through {MAX_ROUTES} names")
    names: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item.strip()
            or len(item) > 100
            or any(ord(character) < 32 for character in item)
        ):
            raise AdapterError(f"SearXNG {label} contains an invalid name")
        name = item.strip()
        if name not in names:
            names.append(name)
    return names


def _query(value: str) -> str:
    for token in value.split():
        if token.startswith(("!", ":")) or re.fullmatch(r"<\d+", token):
            raise AdapterError(
                "SearXNG query control syntax is disabled; use explicit search options"
            )
    return value


def _options(search_input: dict[str, Any]) -> dict[str, Any]:
    raw = search_input.get("options", {})
    if not isinstance(raw, dict):
        raise AdapterError("SearXNG options must be an object")
    allowed = {"engines", "categories", "language", "time_range", "safesearch", "max_pages"}
    unknown = set(raw) - allowed
    if unknown:
        raise AdapterError(f"SearXNG options are not supported: {sorted(unknown)!r}")

    engines = _names(raw["engines"], "engines") if "engines" in raw else []
    categories = _names(raw["categories"], "categories") if "categories" in raw else []
    if engines and categories:
        raise AdapterError("SearXNG routing accepts engines or categories, not both")

    normalized: dict[str, Any] = {"engines": engines, "categories": categories, "max_pages": 1}
    if "language" in raw:
        language = raw["language"]
        if not isinstance(language, str) or _LANGUAGE.fullmatch(language) is None:
            raise AdapterError("SearXNG language is invalid")
        normalized["language"] = language.replace("_", "-")
    if "time_range" in raw:
        if raw["time_range"] not in {"day", "month", "year"}:
            raise AdapterError("SearXNG time_range must be day, month, or year")
        normalized["time_range"] = raw["time_range"]
    if "safesearch" in raw:
        safesearch = raw["safesearch"]
        if (
            isinstance(safesearch, bool)
            or not isinstance(safesearch, int)
            or safesearch not in {0, 1, 2}
        ):
            raise AdapterError("SearXNG safesearch must be 0, 1, or 2")
        normalized["safesearch"] = safesearch
    if "max_pages" in raw:
        max_pages = raw["max_pages"]
        if (
            isinstance(max_pages, bool)
            or not isinstance(max_pages, int)
            or not 1 <= max_pages <= MAX_PAGES
        ):
            raise AdapterError(f"SearXNG max_pages must be 1 through {MAX_PAGES}")
        normalized["max_pages"] = max_pages
    return normalized


def _configured_routes(
    config: dict[str, Any], options: dict[str, Any]
) -> tuple[list[str], list[str]]:
    categories = config.get("categories")
    engines = config.get("engines")
    if not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
        raise AdapterError("SearXNG config categories are malformed")
    if not isinstance(engines, list):
        raise AdapterError("SearXNG config engines are malformed")

    enabled: dict[str, str] = {}
    for item in engines:
        if not isinstance(item, dict):
            raise AdapterError("SearXNG config engine is malformed")
        name = item.get("name")
        if isinstance(name, str) and item.get("enabled") is True:
            enabled[name.casefold()] = name

    selected_engines: list[str] = []
    for requested in options["engines"]:
        actual = enabled.get(requested.casefold())
        if actual is None:
            raise AdapterError(f"SearXNG engine is not enabled: {requested}")
        selected_engines.append(actual)

    configured_categories = {item.casefold(): item for item in categories}
    selected_categories: list[str] = []
    for requested in options["categories"]:
        actual = configured_categories.get(requested.casefold())
        if actual is None:
            raise AdapterError(f"SearXNG category is not enabled: {requested}")
        selected_categories.append(actual)
    return selected_engines, selected_categories


def _exchange(url: str, status: int, body: bytes) -> dict[str, Any]:
    return {
        "url": url,
        "status": status,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _raw_envelope(config: dict[str, Any], pages: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {
            "schema_version": "hound.searxng.raw.v1",
            "config": config,
            "pages": pages,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _provenance_error(
    message: str, config: dict[str, Any], pages: list[dict[str, Any]]
) -> AdapterError:
    return AdapterError(
        message,
        raw=_raw_envelope(config, pages),
        media_type="application/vnd.hound.searxng.raw+json",
        requests=1 + len(pages),
    )


def _routing_texts(response: dict[str, Any], field: str) -> list[str]:
    value = response.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AdapterError(f"SearXNG {field} are malformed")
    return value


def search(
    payload: object,
    *,
    env: Mapping[str, str],
    transport: Transport = request,
    retrieved_at: str | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    search_input = validate_web_input("search", payload)
    owner_query = _query(search_input["query"])
    options = _options(search_input)
    base = service_url(env.get("SEARXNG_ENDPOINT"), "SEARXNG_ENDPOINT")
    headers = {"Accept": "application/json", "User-Agent": "hound-searxng/0.3"}

    config_url = f"{base}/config"
    config_status, config_body = transport(
        method="GET",
        url=config_url,
        headers=headers,
        body=b"",
        timeout=timeout,
    )
    config_exchange = _exchange(config_url, config_status, config_body)
    try:
        config = json_object(config_status, config_body, "SearXNG config")
        selected_engines, selected_categories = _configured_routes(config, options)
    except AdapterError as error:
        raise _provenance_error(str(error), config_exchange, []) from error

    provider_query = owner_query
    if selected_engines:
        bangs = " ".join(f"!{name.replace(' ', '_')}" for name in selected_engines)
        provider_query = f"{bangs} {provider_query}"

    leads_by_url: dict[str, dict[str, Any]] = {}
    suggestions: list[str] = []
    corrections: list[str] = []
    unresponsive: list[dict[str, str]] = []
    pages: list[dict[str, Any]] = []

    for page in range(1, options["max_pages"] + 1):
        parameters: dict[str, object] = {
            "q": provider_query,
            "format": "json",
            "pageno": page,
        }
        if selected_categories:
            parameters["categories"] = ",".join(selected_categories)
        for field in ("language", "time_range", "safesearch"):
            if field in options:
                parameters[field] = options[field]
        url = f"{base}/search?{urlencode(parameters)}"
        status, body = transport(
            method="GET",
            url=url,
            headers=headers,
            body=b"",
            timeout=timeout,
        )
        pages.append(_exchange(url, status, body))
        try:
            response = json_object(status, body, "SearXNG")
            results = response.get("results")
            if not isinstance(results, list):
                raise AdapterError("SearXNG JSON does not contain results")
            page_suggestions = _routing_texts(response, "suggestions")
            page_corrections = _routing_texts(response, "corrections")
        except AdapterError as error:
            raise _provenance_error(str(error), config_exchange, pages) from error

        for value in page_suggestions:
            if value not in suggestions and len(suggestions) < 50:
                suggestions.append(value)
        for value in page_corrections:
            if value not in corrections and len(corrections) < 50:
                corrections.append(value)
        failures = response.get("unresponsive_engines", [])
        if not isinstance(failures, list):
            raise _provenance_error(
                "SearXNG unresponsive_engines are malformed", config_exchange, pages
            )
        for failure in failures:
            if (
                not isinstance(failure, list)
                or len(failure) != 2
                or not all(isinstance(item, str) and item for item in failure)
            ):
                raise _provenance_error(
                    "SearXNG unresponsive engine is malformed", config_exchange, pages
                )
            item = {"engine": failure[0], "error": failure[1]}
            if item not in unresponsive and len(unresponsive) < 50:
                unresponsive.append(item)

        for item in results:
            if not isinstance(item, dict):
                raise _provenance_error("SearXNG result must be an object", config_exchange, pages)
            metadata: dict[str, object] = {"rank": len(leads_by_url) + 1}
            engines = item.get("engines")
            if isinstance(engines, list) and all(isinstance(engine, str) for engine in engines):
                metadata["engines"] = engines[:20]
            score = item.get("score")
            if (
                isinstance(score, (int, float))
                and not isinstance(score, bool)
                and math.isfinite(score)
            ):
                metadata["score"] = score
            category = item.get("category")
            if isinstance(category, str):
                metadata["category"] = category
            published_date = item.get("publishedDate")
            if isinstance(published_date, str) and published_date:
                metadata["publishedDate"] = published_date[:200]
            content = item.get("content")
            if isinstance(content, str) and content:
                metadata["snippet"] = content[:4_000]
            try:
                lead = make_lead(
                    "searxng",
                    owner_query,
                    item.get("url"),
                    title=item.get("title") if isinstance(item.get("title"), str) else None,
                    metadata=metadata,
                )
            except EvidenceError as error:
                raise _provenance_error(
                    f"SearXNG returned an unsafe result: {error}", config_exchange, pages
                ) from error
            leads_by_url.setdefault(lead["url"], lead)
            if len(leads_by_url) >= search_input["limit"]:
                break
        if len(leads_by_url) >= search_input["limit"] or not results:
            break

    if not leads_by_url:
        # A category or default route requests every engine carrying it, so any
        # failure is implicated; an explicit route is implicated only by its own
        # engines. Either way, zero leads plus a failure is indistinguishable
        # from zero matches, so refuse to report it as an empty success.
        requested = {engine.casefold() for engine in selected_engines}
        implicated = [
            failure["engine"]
            for failure in unresponsive
            if not requested or failure["engine"].casefold() in requested
        ]
        if implicated:
            raise _provenance_error(
                "SearXNG returned no leads while requested engines were unresponsive: "
                f"{', '.join(implicated)}",
                config_exchange,
                pages,
            )

    raw_body = _raw_envelope(config_exchange, pages)
    return {
        "schema_version": ADAPTER_SCHEMA,
        "retrieved_at": _retrieved_at(retrieved_at),
        "raw": {
            "media_type": "application/vnd.hound.searxng.raw+json",
            "body_base64": base64.b64encode(raw_body).decode("ascii"),
            "sha256": hashlib.sha256(raw_body).hexdigest(),
        },
        "output": {
            "schema_version": SEARCH_SCHEMA,
            "trust": "untrusted",
            "evidence_status": "not-evidence",
            "leads": list(leads_by_url.values()),
            "routing": {
                "completed_pages": len(pages),
                "config_sha256": hashlib.sha256(config_body).hexdigest(),
                "corrections": corrections,
                "requested_categories": selected_categories,
                "requested_engines": selected_engines,
                "suggestions": suggestions,
                "unresponsive_engines": unresponsive,
            },
        },
        "usage": {"requests": 1 + len(pages), "bytes": len(raw_body)},
    }
