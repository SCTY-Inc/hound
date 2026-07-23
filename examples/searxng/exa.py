# SPDX-License-Identifier: AGPL-3.0-or-later
"""SearXNG engine for Exa's bounded publication or web search."""

from __future__ import annotations

import os
import typing as t
from datetime import datetime, timedelta, timezone

from searx.exceptions import SearxEngineAPIException
from searx.result_types import EngineResults
from searx.utils import html_to_text

if t.TYPE_CHECKING:
    from searx.extended_types import SXNG_Response
    from searx.search.processors import OnlineParams


about = {
    "website": "https://exa.ai/",
    "wikidata_id": None,
    "official_api_documentation": "https://docs.exa.ai/reference/search",
    "use_official_api": True,
    "require_api_key": True,
    "results": "JSON",
}

categories = ["science", "scientific publications"]
paging = False
safesearch = False
time_range_support = True

api_url = "https://api.exa.ai/search"
api_key = ""
results_per_page = 16
search_category = "publication"

_TIME_RANGE_DAYS = {
    "day": 1,
    "week": 7,
    "month": 30,
    "year": 365,
}


def init(engine_settings: dict[str, t.Any]) -> None:
    """Load the service-owned credential without putting it in settings.yml."""
    global api_key, search_category  # pylint: disable=global-statement
    api_key = os.environ.get("EXA_API_KEY", "").strip()
    if not api_key:
        raise SearxEngineAPIException("EXA_API_KEY is required")
    configured_category = engine_settings.get("search_category", search_category)
    if not isinstance(configured_category, str):
        raise SearxEngineAPIException("Exa search_category must be a string")
    search_category = configured_category.strip()


def _published_after(time_range: str) -> str | None:
    days = _TIME_RANGE_DAYS.get(time_range)
    if days is None:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return cutoff.isoformat(timespec="seconds").replace("+00:00", "Z")


def request(query: str, params: "OnlineParams") -> None:
    """Build one bounded publication search request."""
    body: dict[str, t.Any] = {
        "query": query,
        "type": "auto",
        "numResults": max(1, min(results_per_page, 100)),
        "contents": {
            "highlights": {
                "query": query,
                "maxCharacters": 1_000,
            }
        },
    }
    if search_category:
        body["category"] = search_category
    published_after = _published_after(params.get("time_range") or "")
    if published_after:
        body["startPublishedDate"] = published_after

    params["url"] = api_url
    params["method"] = "POST"
    params["headers"]["x-api-key"] = api_key
    params["headers"]["Content-Type"] = "application/json"
    params["json"] = body


def _published_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _content(result: dict[str, t.Any]) -> str:
    highlights = result.get("highlights")
    if isinstance(highlights, list):
        content = " ".join(item.strip() for item in highlights if isinstance(item, str))
        if content:
            return content
    text = result.get("text")
    return text if isinstance(text, str) else ""


def response(resp: "SXNG_Response") -> EngineResults:
    """Normalize Exa publication leads into SearXNG's ordinary result type."""
    output = EngineResults()
    payload = resp.json()
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return output

    for item in results:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url:
            continue
        title = item.get("title")
        author = item.get("author")
        output.add(
            output.types.MainResult(
                url=url,
                title=html_to_text(title if isinstance(title, str) else url),
                content=html_to_text(_content(item)),
                publishedDate=_published_date(item.get("publishedDate")),
                author=html_to_text(author) if isinstance(author, str) else "",
            )
        )

    return output
