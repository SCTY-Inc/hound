"""Native scholarly source adapters."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping
from urllib.parse import urlencode
from xml.etree import ElementTree

ARXIV_ENDPOINT = "https://export.arxiv.org/api/query"
ARXIV_FIELDS = {"query", "categories", "maxResults", "startPublishedDate"}

_ATOM = "{http://www.w3.org/2005/Atom}"


def arxiv_request_url(parameters: Mapping[str, object], retrieved_at: str | None) -> str:
    query = str(parameters["query"])
    terms = [part.strip() for part in query.split(" OR ") if part.strip()]
    topic = " OR ".join(f'all:"{_escape_term(term)}"' for term in terms)
    categories = parameters.get("categories", [])
    if isinstance(categories, list) and categories:
        category_query = " OR ".join(f"cat:{category}" for category in categories)
        topic = f"({topic}) AND ({category_query})"
    start = parameters.get("startPublishedDate")
    if isinstance(start, str):
        end = _retrieval_day(retrieved_at)
        topic = (
            f"({topic}) AND submittedDate:"
            f"[{start.replace('-', '')}0000 TO {end.replace('-', '')}2359]"
        )
    query_parameters = {
        "search_query": topic,
        "start": 0,
        "max_results": parameters.get("maxResults", 10),
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }
    return f"{ARXIV_ENDPOINT}?{urlencode(query_parameters)}"


def parse_arxiv_response(body: bytes) -> dict[str, Any]:
    upper = body.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("active XML declarations are not allowed")
    root = ElementTree.fromstring(body)
    results: list[dict[str, Any]] = []
    for entry in root.findall(f"{_ATOM}entry"):
        identifier = _text(entry, "id").rsplit("/", 1)[-1]
        url = next(
            (
                link.get("href", "")
                for link in entry.findall(f"{_ATOM}link")
                if link.get("rel") == "alternate" and link.get("href")
            ),
            _text(entry, "id"),
        ).replace("http://arxiv.org/", "https://arxiv.org/")
        results.append(
            {
                "arxivId": identifier,
                "authors": [
                    _clean(author.findtext(f"{_ATOM}name", default=""))
                    for author in entry.findall(f"{_ATOM}author")
                    if _clean(author.findtext(f"{_ATOM}name", default=""))
                ],
                "categories": [
                    category.get("term", "")
                    for category in entry.findall(f"{_ATOM}category")
                    if category.get("term")
                ],
                "publishedDate": _text(entry, "published"),
                "text": _text(entry, "summary"),
                "title": _text(entry, "title"),
                "url": url,
            }
        )
    return {"results": results}


def _text(entry: ElementTree.Element, name: str) -> str:
    return _clean(entry.findtext(f"{_ATOM}{name}", default=""))


def _clean(value: str) -> str:
    return " ".join(value.split())


def _escape_term(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _retrieval_day(value: str | None) -> str:
    if not value:
        return datetime.now().date().isoformat()
    return value[:10]


__all__ = [
    "ARXIV_ENDPOINT",
    "ARXIV_FIELDS",
    "arxiv_request_url",
    "parse_arxiv_response",
]
