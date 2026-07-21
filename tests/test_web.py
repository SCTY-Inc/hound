from __future__ import annotations

import json

import pytest

from hound_cli.packs.web import WebFetchError, fetch_web_capture

DISCOVERED = {
    "url": "https://example.test/story",
    "title": "Discovery title",
    "publishedDate": "2026-07-20T08:00:00Z",
    "text": "Discovery excerpt.",
}


def test_web_capture_fetches_origin_and_extracts_article_with_scrapling() -> None:
    body = b"""<!doctype html>
<html>
  <head>
    <title>Fallback page title</title>
    <script type="application/ld+json">
      {"@type":"NewsArticle","headline":"Origin headline","datePublished":"2026-07-20T07:30:00Z"}
    </script>
  </head>
  <body>
    <nav>Navigation</nav>
    <article>
      <p>Caregivers can apply on September 1.</p>
      <p>The agency published eligibility rules.</p>
    </article>
  </body>
</html>"""

    capture = fetch_web_capture(
        "https://example.test/story",
        DISCOVERED,
        retrieved_at="2026-07-20T10:00:00Z",
        env={},
        direct_transport=lambda **_: (
            200,
            "https://example.test/story",
            {"content-type": "text/html; charset=utf-8"},
            body,
        ),
    )

    assert capture.method == "direct-scrapling"
    assert capture.body == body
    assert capture.media_type == "text/html"
    assert capture.document == {
        "publishedDate": "2026-07-20T07:30:00Z",
        "text": "Caregivers can apply on September 1. The agency published eligibility rules.",
        "title": "Origin headline",
        "url": "https://example.test/story",
    }
    assert capture.attempts == [{"method": "direct-scrapling", "outcome": "captured"}]


def test_web_capture_falls_back_to_firecrawl_with_explicit_provenance() -> None:
    seen: list[dict[str, object]] = []

    def firecrawl(request: object, **_: object) -> dict[str, object]:
        assert isinstance(request, dict)
        seen.append(request)
        return {
            "schema_version": "hound.provider.response.v1",
            "provider": "firecrawl",
            "operation": "scrape",
            "request_sha256": "a" * 64,
            "raw_data": {
                "success": True,
                "data": {
                    "markdown": "# Rendered title\n\nRendered article body.",
                    "metadata": {
                        "title": "Rendered title",
                        "publishedTime": "2026-07-20T08:00:00Z",
                        "sourceURL": "https://example.test/story",
                    },
                },
            },
        }

    capture = fetch_web_capture(
        "https://example.test/story",
        DISCOVERED,
        retrieved_at="2026-07-20T10:00:00Z",
        env={"FIRECRAWL_API_KEY": "test-secret"},
        direct_transport=lambda **_: (_ for _ in ()).throw(WebFetchError("direct fetch failed")),
        provider_execute=firecrawl,
    )

    assert seen == [
        {
            "schema_version": "hound.provider.request.v1",
            "provider": "firecrawl",
            "operation": "scrape",
            "parameters": {
                "url": "https://example.test/story",
                "formats": ["markdown"],
                "onlyMainContent": True,
                "removeBase64Images": True,
                "blockAds": True,
            },
            "retrieved_at": "2026-07-20T10:00:00Z",
        }
    ]
    assert capture.method == "firecrawl"
    assert json.loads(capture.body)["data"]["markdown"].startswith("# Rendered")
    assert capture.document["text"] == "# Rendered title\n\nRendered article body."
    assert capture.attempts == [
        {"method": "direct-scrapling", "outcome": "failed", "reason": "direct fetch failed"},
        {"method": "firecrawl", "outcome": "captured"},
    ]
    assert "test-secret" not in json.dumps(capture.attempts)


def test_web_capture_fails_without_pretending_discovery_text_is_origin_evidence() -> None:
    with pytest.raises(WebFetchError, match="origin capture failed"):
        fetch_web_capture(
            "https://example.test/story",
            DISCOVERED,
            retrieved_at="2026-07-20T10:00:00Z",
            env={},
            direct_transport=lambda **_: (_ for _ in ()).throw(WebFetchError("blocked")),
            provider_execute=lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("no key")),
        )
