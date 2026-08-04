"""Exa discovery adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from hound_research.evidence import EvidenceError, make_lead
from hound_research.web import ADAPTER_SCHEMA, SEARCH_SCHEMA, validate_web_input

from ._http import AdapterError, Transport, json_object, request


API_URL = "https://api.exa.ai/search"
_SEARCH_TYPES = {"auto", "fast"}
_CATEGORIES = {
    "company",
    "publication",
    "news",
    "personal site",
    "financial report",
    "people",
}
_OPTIONS = {
    "type",
    "category",
    "startPublishedDate",
    "endPublishedDate",
    "includeDomains",
    "excludeDomains",
    "userLocation",
}
_DOMAIN = re.compile(r"(?:\*\.)?[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[^\s?#]*)?\Z")
_LOCATION = re.compile(r"[A-Z]{2}\Z")


def _retrieved_at(value: str | None) -> str:
    return value or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise AdapterError(f"Exa {label} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AdapterError(f"Exa {label} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AdapterError(f"Exa {label} must include a timezone")
    return value, parsed


def _domains(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 100:
        raise AdapterError(f"Exa {label} must contain 1 through 100 domains")
    domains: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 500
            or _DOMAIN.fullmatch(item) is None
        ):
            raise AdapterError(f"Exa {label} contains an invalid domain")
        if item not in domains:
            domains.append(item)
    return domains


def normalize_search_options(raw: object) -> dict[str, Any]:
    """Normalize one search options object into the exact provider request fields.

    This is the single vocabulary for search options.  The daemon validates
    caller-supplied options through this function so a committed record can
    never bind an option the provider would refuse.
    """

    if not isinstance(raw, dict):
        raise AdapterError("Exa options must be an object")
    unknown = set(raw) - _OPTIONS
    if unknown:
        raise AdapterError(f"Exa options are not supported: {sorted(unknown)!r}")

    normalized: dict[str, Any] = {"type": raw.get("type", "auto")}
    if normalized["type"] not in _SEARCH_TYPES:
        raise AdapterError("Exa type must be auto or fast")

    category = raw.get("category")
    if category is not None:
        if category not in _CATEGORIES:
            raise AdapterError(f"Exa category must be one of {sorted(_CATEGORIES)!r}")
        normalized["category"] = category

    parsed_dates: dict[str, datetime] = {}
    for field in ("startPublishedDate", "endPublishedDate"):
        if field in raw:
            normalized[field], parsed_dates[field] = _timestamp(raw[field], field)
    if (
        "startPublishedDate" in parsed_dates
        and "endPublishedDate" in parsed_dates
        and parsed_dates["startPublishedDate"] > parsed_dates["endPublishedDate"]
    ):
        raise AdapterError("Exa startPublishedDate must not follow endPublishedDate")

    for field in ("includeDomains", "excludeDomains"):
        if field in raw:
            normalized[field] = _domains(raw[field], field)
    if set(normalized.get("includeDomains", [])) & set(normalized.get("excludeDomains", [])):
        raise AdapterError("Exa includeDomains and excludeDomains must not overlap")

    if "userLocation" in raw:
        location = raw["userLocation"]
        if not isinstance(location, str) or _LOCATION.fullmatch(location) is None:
            raise AdapterError("Exa userLocation must be a two-letter uppercase country code")
        normalized["userLocation"] = location

    if normalized.get("category") in {"company", "people"} and any(
        field in normalized
        for field in ("startPublishedDate", "endPublishedDate", "excludeDomains")
    ):
        raise AdapterError(
            "Exa company and people categories do not support publication dates or exclusions"
        )
    return normalized


def _provider_error(
    message: str,
    raw: bytes,
    *,
    media_type: str,
    requests: int,
) -> AdapterError:
    return AdapterError(
        message,
        raw=raw,
        media_type=media_type,
        requests=requests,
    )


def search(
    payload: object,
    *,
    env: Mapping[str, str],
    transport: Transport = request,
    retrieved_at: str | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    search_input = validate_web_input("search", payload)
    options = normalize_search_options(search_input.get("options", {}))
    api_key = env.get("EXA_API_KEY")
    if (
        not isinstance(api_key, str)
        or not api_key
        or any(ord(character) < 33 for character in api_key)
    ):
        raise AdapterError("EXA_API_KEY is required")

    owner_query = search_input["query"]
    provider_request = {
        "query": owner_query,
        "numResults": search_input["limit"],
        **options,
        "contents": {
            "highlights": {
                "query": owner_query,
                "maxCharacters": 1_000,
            }
        },
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "hound-exa/0.4",
        "x-api-key": api_key,
    }
    request_body = json.dumps(
        provider_request,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    try:
        status, provider_raw = transport(
            method="POST",
            url=API_URL,
            headers=headers,
            body=request_body,
            timeout=timeout,
        )
    except AdapterError as error:
        raise AdapterError(
            str(error), raw=error.raw, media_type=error.media_type, requests=1
        ) from error
    try:
        response = json_object(status, provider_raw, "Exa")
    except AdapterError as error:
        raise AdapterError(
            str(error), raw=error.raw, media_type=error.media_type, requests=1
        ) from error
    recorded_raw = provider_raw
    media_type = "application/json"
    request_count = 1
    results = response.get("results")
    if not isinstance(results, list):
        raise _provider_error(
            "Exa JSON does not contain results",
            recorded_raw,
            media_type=media_type,
            requests=request_count,
        )

    leads_by_url: dict[str, dict[str, Any]] = {}
    for item in results:
        if not isinstance(item, dict):
            raise _provider_error(
                "Exa result must be an object",
                recorded_raw,
                media_type=media_type,
                requests=request_count,
            )
        metadata: dict[str, object] = {"rank": len(leads_by_url) + 1}
        for source, target in (
            ("publishedDate", "publishedDate"),
            ("author", "author"),
            ("id", "providerId"),
        ):
            value = item.get(source)
            if isinstance(value, str) and value:
                metadata[target] = value[:4_000]
        score = item.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score):
            metadata["score"] = score
        highlights = item.get("highlights")
        if isinstance(highlights, list) and all(isinstance(value, str) for value in highlights):
            snippet = "\n".join(value.strip() for value in highlights if value.strip())
            if snippet:
                metadata["snippet"] = snippet[:4_000]
        if "category" in options:
            metadata["category"] = options["category"]
        try:
            lead = make_lead(
                "exa",
                owner_query,
                item.get("url"),
                title=item.get("title") if isinstance(item.get("title"), str) else None,
                metadata=metadata,
            )
        except EvidenceError as error:
            raise _provider_error(
                f"Exa returned an unsafe result: {error}",
                recorded_raw,
                media_type=media_type,
                requests=request_count,
            ) from error
        leads_by_url.setdefault(lead["url"], lead)
        if len(leads_by_url) >= search_input["limit"]:
            break

    return {
        "schema_version": ADAPTER_SCHEMA,
        "retrieved_at": _retrieved_at(retrieved_at),
        "raw": {
            "media_type": media_type,
            "body_base64": base64.b64encode(recorded_raw).decode("ascii"),
            "sha256": hashlib.sha256(recorded_raw).hexdigest(),
        },
        "output": {
            "schema_version": SEARCH_SCHEMA,
            "trust": "untrusted",
            "evidence_status": "not-evidence",
            "leads": list(leads_by_url.values()),
        },
        "usage": {"requests": request_count, "bytes": len(recorded_raw)},
    }
