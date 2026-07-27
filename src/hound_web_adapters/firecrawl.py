"""Firecrawl known-URL extraction adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from hound_cli.contracts import canonical_json
from hound_research.evidence import EvidenceError, validate_public_url
from hound_research.web import ADAPTER_SCHEMA, EXTRACT_SCHEMA, validate_web_input
from ._http import AdapterError, Transport, json_object, request, service_url


Sleep = Callable[[float], None]
MAX_CRAWL_POLLS = 40


def _retrieved_at(value: str | None) -> str:
    return value or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _headers(api_key: str) -> dict[str, str]:
    if not api_key:
        raise AdapterError("FIRECRAWL_API_KEY is required")
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _json_body(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _exchange(method: str, url: str, status: int, body: bytes) -> dict[str, object]:
    return {
        "method": method,
        "url": url,
        "status": status,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _safe_links(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    links: list[str] = []
    for item in value:
        try:
            link = validate_public_url(item, "Firecrawl link")
        except EvidenceError:
            continue
        if link not in links:
            links.append(link)
    return links[:500]


def _crawl_envelope(exchanges: list[dict[str, object]]) -> bytes:
    return canonical_json({"exchanges": exchanges}).encode("utf-8")


def _crawl_error(message: str, exchanges: list[dict[str, object]]) -> AdapterError:
    return AdapterError(
        message,
        raw=_crawl_envelope(exchanges),
        media_type="application/vnd.hound.http-exchanges+json",
        requests=len(exchanges),
    )


def _document(value: object, fallback_url: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AdapterError("Firecrawl document must be an object")
    markdown = value.get("markdown")
    if not isinstance(markdown, str) or not markdown.strip():
        raise AdapterError("Firecrawl document has no markdown")
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise AdapterError("Firecrawl document metadata must be an object")
    source_url = metadata.get("sourceURL", fallback_url)
    try:
        source_url = validate_public_url(source_url, "Firecrawl document URL")
    except EvidenceError as error:
        raise AdapterError(str(error)) from error
    canonical_json(metadata)
    return {
        "url": source_url,
        "markdown": markdown,
        "markdown_sha256": hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
        "links": _safe_links(value.get("links", [])),
        "metadata": metadata,
    }


def extract(
    payload: object,
    *,
    env: Mapping[str, str],
    transport: Transport = request,
    sleep: Sleep = time.sleep,
    retrieved_at: str | None = None,
) -> dict[str, Any]:
    extract_input = validate_web_input("extract", payload)
    base = service_url(
        env.get("FIRECRAWL_ENDPOINT", "https://api.firecrawl.dev"), "FIRECRAWL_ENDPOINT"
    )
    headers = _headers(env.get("FIRECRAWL_API_KEY", ""))
    exchanges: list[dict[str, object]] = []

    if "max_pages" not in extract_input:
        url = f"{base}/v2/scrape"
        request_body = _json_body(
            {
                "url": extract_input["url"],
                "formats": ["markdown", "links"],
                "onlyMainContent": True,
            }
        )
        status, body = transport(
            method="POST", url=url, headers=headers, body=request_body, timeout=30
        )
        exchanges.append(_exchange("POST", url, status, body))
        response = json_object(status, body, "Firecrawl scrape")
        if response.get("success") is not True:
            raise AdapterError(
                "Firecrawl scrape reported failure",
                raw=body,
                media_type="application/json",
                requests=1,
            )
        try:
            documents = [_document(response.get("data"), extract_input["url"])]
        except AdapterError as error:
            raise error.with_raw(body) from error
        raw = body
        media_type = "application/json"
    else:
        max_pages = extract_input["max_pages"]
        url = f"{base}/v2/crawl"
        request_body = _json_body(
            {
                "url": extract_input["url"],
                "limit": max_pages,
                "scrapeOptions": {
                    "formats": ["markdown", "links"],
                    "onlyMainContent": True,
                },
            }
        )
        status, body = transport(
            method="POST", url=url, headers=headers, body=request_body, timeout=30
        )
        exchanges.append(_exchange("POST", url, status, body))
        started = json_object(status, body, "Firecrawl crawl")
        crawl_id = started.get("id")
        if started.get("success") is not True or not isinstance(crawl_id, str) or not crawl_id:
            raise _crawl_error("Firecrawl crawl did not return a job ID", exchanges)
        status_url = f"{base}/v2/crawl/{quote(crawl_id, safe='')}"
        completed: dict[str, Any] | None = None
        for _ in range(MAX_CRAWL_POLLS):
            poll_status, poll_body = transport(
                method="GET", url=status_url, headers=headers, body=b"", timeout=30
            )
            exchanges.append(_exchange("GET", status_url, poll_status, poll_body))
            try:
                polled = json_object(poll_status, poll_body, "Firecrawl crawl status")
            except AdapterError as error:
                raise _crawl_error(str(error), exchanges) from error
            state = polled.get("status")
            if state == "completed":
                completed = polled
                break
            if state in {"failed", "cancelled"}:
                raise _crawl_error(f"Firecrawl crawl ended with status {state}", exchanges)
            sleep(0.5)
        if completed is None:
            raise _crawl_error("Firecrawl crawl polling limit exceeded", exchanges)
        raw_documents = completed.get("data")
        if not isinstance(raw_documents, list) or len(raw_documents) > max_pages:
            raise _crawl_error(
                "Firecrawl crawl returned an invalid or over-limit document set", exchanges
            )
        try:
            documents = [_document(item, extract_input["url"]) for item in raw_documents]
        except AdapterError as error:
            raise _crawl_error(str(error), exchanges) from error
        raw = _crawl_envelope(exchanges)
        media_type = "application/vnd.hound.http-exchanges+json"

    return {
        "schema_version": ADAPTER_SCHEMA,
        "retrieved_at": _retrieved_at(retrieved_at),
        "raw": {
            "media_type": media_type,
            "body_base64": base64.b64encode(raw).decode("ascii"),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "output": {
            "schema_version": EXTRACT_SCHEMA,
            "trust": "untrusted",
            "evidence_class": "provider-derived",
            "documents": documents,
        },
        "usage": {"requests": len(exchanges), "bytes": len(raw)},
    }
