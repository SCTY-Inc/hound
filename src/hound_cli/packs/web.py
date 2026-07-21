"""Origin-page capture for the Web source pack."""

from __future__ import annotations

import json
import queue
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from scrapling import Selector

from ..contracts import canonical_json
from ..providers import execute_request, validate_public_url

MAX_ORIGIN_BYTES = 4 * 1024 * 1024
DirectTransport = Callable[..., tuple[int, str, Mapping[str, str], bytes]]
ProviderExecutor = Callable[..., dict[str, Any]]


class WebFetchError(ValueError):
    """A selected web origin could not be captured honestly."""


@dataclass(frozen=True)
class WebCapture:
    method: str
    body: bytes
    media_type: str
    document: dict[str, Any]
    attempts: list[dict[str, str]]


class _SafeRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        validate_public_url(new_url)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _default_direct_transport(
    *, url: str, timeout: float
) -> tuple[int, str, Mapping[str, str], bytes]:
    validate_public_url(url)
    deadline = time.monotonic() + timeout
    request = Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml,text/plain,application/json",
            "User-Agent": "hound-web/1",
        },
        method="GET",
    )
    opener = build_opener(_SafeRedirects())
    completed: queue.Queue[
        tuple[Exception | None, tuple[int, str, Mapping[str, str], bytes] | None]
    ] = queue.Queue(maxsize=1)

    def perform() -> None:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WebFetchError("direct fetch timed out")
            with opener.open(request, timeout=remaining) as response:
                chunks: list[bytes] = []
                size = 0
                read = getattr(response, "read1", response.read)
                while True:
                    if time.monotonic() >= deadline:
                        raise WebFetchError("direct fetch timed out")
                    chunk = read(min(64 * 1024, MAX_ORIGIN_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_ORIGIN_BYTES:
                        raise WebFetchError("direct response exceeded size limit")
                outcome = (
                    None,
                    (
                        int(response.getcode()),
                        response.geturl(),
                        {key.lower(): value for key, value in response.headers.items()},
                        b"".join(chunks),
                    ),
                )
        except HTTPError as error:
            try:
                error.close()
            except OSError:
                pass
            outcome = (WebFetchError(f"direct fetch returned HTTP {error.code}"), None)
        except Exception as error:
            outcome = (error, None)
        completed.put_nowait(outcome)

    worker = threading.Thread(target=perform, name="hound-web-origin", daemon=True)
    worker.start()
    try:
        error, result = completed.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        raise WebFetchError("direct fetch timed out") from None
    if error is not None:
        raise WebFetchError(str(error)) from None
    if result is None:
        raise WebFetchError("direct fetch returned an invalid response")
    return result


def fetch_web_capture(
    url: str,
    discovered: Mapping[str, object],
    *,
    retrieved_at: str,
    env: Mapping[str, str] | None = None,
    direct_transport: DirectTransport = _default_direct_transport,
    provider_execute: ProviderExecutor = execute_request,
    timeout: float = 30,
) -> WebCapture:
    """Capture one selected origin, using Firecrawl only after direct extraction fails."""

    validate_public_url(url)
    attempts: list[dict[str, str]] = []
    try:
        status, final_url, headers, body = direct_transport(url=url, timeout=timeout)
        if status < 200 or status >= 300:
            raise WebFetchError(f"direct fetch returned HTTP {status}")
        if not isinstance(body, bytes) or len(body) > MAX_ORIGIN_BYTES:
            raise WebFetchError("direct response exceeded size limit")
        validate_public_url(final_url)
        media_type = headers.get("content-type", "application/octet-stream").split(";", 1)[0]
        document = _origin_document(body, media_type, final_url, discovered)
        attempts.append({"method": "direct-scrapling", "outcome": "captured"})
        return WebCapture(
            method="direct-scrapling",
            body=body,
            media_type=media_type,
            document=document,
            attempts=attempts,
        )
    except Exception as error:
        attempts.append(
            {
                "method": "direct-scrapling",
                "outcome": "failed",
                "reason": _safe_reason(error),
            }
        )

    request = {
        "schema_version": "hound.provider.request.v1",
        "provider": "firecrawl",
        "operation": "scrape",
        "parameters": {
            "url": url,
            "formats": ["markdown"],
            "onlyMainContent": True,
            "removeBase64Images": True,
            "blockAds": True,
        },
        "retrieved_at": retrieved_at,
    }
    try:
        response = provider_execute(request, env=env)
        raw_data = response.get("raw_data")
        if not isinstance(raw_data, dict):
            raise WebFetchError("Firecrawl returned no data")
        data = raw_data.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("markdown"), str):
            raise WebFetchError("Firecrawl returned no markdown")
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        title = _string(metadata.get("title")) or _string(discovered.get("title"))
        published = _string(metadata.get("publishedTime")) or _string(
            discovered.get("publishedDate")
        )
        if not title or not published or not data["markdown"].strip():
            raise WebFetchError("Firecrawl capture lacks title, date, or content")
        attempts.append({"method": "firecrawl", "outcome": "captured"})
        return WebCapture(
            method="firecrawl",
            body=canonical_json(raw_data).encode("utf-8"),
            media_type="application/json",
            document={
                "publishedDate": published,
                "text": data["markdown"].strip(),
                "title": title,
                "url": url,
            },
            attempts=attempts,
        )
    except Exception as error:
        attempts.append({"method": "firecrawl", "outcome": "failed", "reason": _safe_reason(error)})
        raise WebFetchError("origin capture failed") from None


def _origin_document(
    body: bytes,
    media_type: str,
    final_url: str,
    discovered: Mapping[str, object],
) -> dict[str, Any]:
    if media_type in {"text/html", "application/xhtml+xml"}:
        title, published, text = _extract_html(body, final_url)
    elif media_type.startswith("text/"):
        title, published, text = "", "", body.decode("utf-8").strip()
    else:
        raise WebFetchError(f"direct response media type is unsupported: {media_type}")
    title = title or _string(discovered.get("title"))
    published = published or _string(discovered.get("publishedDate"))
    if not title or not published or not text:
        raise WebFetchError("direct capture lacks title, date, or content")
    return {
        "publishedDate": published,
        "text": text,
        "title": title,
        "url": final_url,
    }


def _extract_html(body: bytes, url: str) -> tuple[str, str, str]:
    page = Selector(body, url=url)
    structured = _article_json_ld(page)
    title = _string(structured.get("headline")) or _first(page, "title::text")
    published = (
        _string(structured.get("datePublished"))
        or _first(page, 'meta[property="article:published_time"]::attr(content)')
        or _first(page, 'meta[name="date"]::attr(content)')
    )
    text = _string(structured.get("articleBody"))
    if not text:
        for css in (
            "article",
            ".RichTextBody",
            ".StoryBody",
            ".article-body",
            ".content",
            "main",
            '[role="main"]',
            "body",
        ):
            matches = page.css(css)
            if matches:
                text = matches[0].get_all_text()
                if text:
                    break
    return _clean(title), _clean(published), _clean(text)


def _article_json_ld(page: Selector) -> dict[str, object]:
    for raw in page.css('script[type="application/ld+json"]::text').getall():
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for item in _json_objects(value):
            kind = item.get("@type")
            kinds = kind if isinstance(kind, list) else [kind]
            if any(
                value in {"Article", "NewsArticle", "Report", "ScholarlyArticle"} for value in kinds
            ):
                return item
    return {}


def _json_objects(value: object) -> list[dict[str, object]]:
    if isinstance(value, list):
        return [item for nested in value for item in _json_objects(nested)]
    if not isinstance(value, dict):
        return []
    graph = value.get("@graph")
    return [value, *(_json_objects(graph) if graph is not None else [])]


def _first(page: Selector, css: str) -> str:
    value = page.css(css).get()
    return value if isinstance(value, str) else ""


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _clean(value: str) -> str:
    return " ".join(value.split())


def _safe_reason(error: Exception) -> str:
    text = str(error).strip()
    return text[:200] if text else error.__class__.__name__


__all__ = ["WebCapture", "WebFetchError", "fetch_web_capture"]
