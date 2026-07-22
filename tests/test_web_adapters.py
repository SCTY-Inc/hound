from __future__ import annotations

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from hound_web_adapters import camofox, firecrawl, searxng
from hound_web_adapters._http import AdapterError


def test_searxng_normalizes_bounded_candidates_with_engine_attribution() -> None:
    calls: list[dict[str, object]] = []
    body = json.dumps(
        {
            "query": "used Lexus GX 460 Long Island",
            "results": [
                {
                    "url": "https://dealer.example.test/gx-460",
                    "title": "2020 Lexus GX 460",
                    "content": "One-owner SUV",
                    "engines": ["brave", "duckduckgo"],
                    "score": 8.5,
                    "category": "general",
                }
            ],
            "unresponsive_engines": [["google", "timeout"]],
        },
        separators=(",", ":"),
    ).encode()

    config_body = json.dumps(
        {
            "categories": ["general", "government"],
            "engines": [
                {
                    "categories": ["general"],
                    "enabled": True,
                    "name": "brave",
                    "shortcut": "br",
                },
                {
                    "categories": ["general"],
                    "enabled": True,
                    "name": "duckduckgo",
                    "shortcut": "ddg",
                },
            ],
        },
        separators=(",", ":"),
    ).encode()

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return (200, config_body) if str(call["url"]).endswith("/config") else (200, body)

    data = searxng.search(
        {"query": "used Lexus GX 460 Long Island", "limit": 5},
        env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
        transport=transport,
        retrieved_at="2026-07-21T12:00:00Z",
    )

    assert calls[0]["url"] == "http://127.0.0.1:8080/config"
    parsed = urlsplit(str(calls[1]["url"]))
    assert calls[1]["method"] == "GET"
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "http://127.0.0.1:8080/search"
    assert parse_qs(parsed.query) == {
        "format": ["json"],
        "pageno": ["1"],
        "q": ["used Lexus GX 460 Long Island"],
    }
    raw = json.loads(base64.b64decode(data["raw"]["body_base64"]))
    assert raw["config"]["url"] == "http://127.0.0.1:8080/config"
    assert raw["config"]["status"] == 200
    assert base64.b64decode(raw["config"]["body_base64"]) == config_body
    assert raw["pages"][0]["url"] == calls[1]["url"]
    assert raw["pages"][0]["status"] == 200
    assert base64.b64decode(raw["pages"][0]["body_base64"]) == body
    assert data["usage"]["requests"] == 2
    assert data["output"]["evidence_status"] == "not-evidence"
    assert data["output"]["routing"]["unresponsive_engines"] == [
        {"engine": "google", "error": "timeout"}
    ]
    assert data["output"]["leads"] == [
        {
            "schema_version": "hound.lead.v1",
            "evidence_status": "not-evidence",
            "provider": "searxng",
            "query": "used Lexus GX 460 Long Island",
            "url": "https://dealer.example.test/gx-460",
            "title": "2020 Lexus GX 460",
            "metadata": {
                "category": "general",
                "engines": ["brave", "duckduckgo"],
                "rank": 1,
                "score": 8.5,
                "snippet": "One-owner SUV",
            },
        }
    ]


def test_searxng_routes_engines_and_collects_bounded_pages() -> None:
    calls: list[dict[str, object]] = []
    config = {
        "categories": ["general", "government"],
        "engines": [
            {
                "categories": ["government", "news"],
                "enabled": True,
                "name": "federal register",
                "shortcut": "fr",
            }
        ],
    }
    page_one = {
        "results": [
            {
                "url": "https://www.federalregister.gov/documents/2026/01/01/a",
                "title": "Caregiver rule",
                "content": "A proposed rule",
                "engines": ["federal register"],
            }
        ],
        "suggestions": ["family caregiver benefits"],
        "corrections": ["family caregiver"],
        "unresponsive_engines": [],
    }
    page_two = {
        "results": [
            {
                "url": "https://www.federalregister.gov/documents/2026/01/02/b",
                "title": "Respite notice",
                "engines": ["federal register"],
            }
        ],
        "suggestions": [],
        "corrections": [],
        "unresponsive_engines": [["federal register", "timeout"]],
    }

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        url = str(call["url"])
        if url.endswith("/config"):
            return 200, json.dumps(config, separators=(",", ":")).encode()
        page = int(parse_qs(urlsplit(url).query)["pageno"][0])
        value = page_one if page == 1 else page_two
        return 200, json.dumps(value, separators=(",", ":")).encode()

    data = searxng.search(
        {
            "query": "caregiver benefits",
            "limit": 5,
            "options": {
                "engines": ["federal register"],
                "language": "en",
                "time_range": "month",
                "safesearch": 1,
                "max_pages": 2,
            },
        },
        env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
        transport=transport,
        retrieved_at="2026-07-21T12:00:00Z",
    )

    first_query = parse_qs(urlsplit(str(calls[1]["url"])).query)
    second_query = parse_qs(urlsplit(str(calls[2]["url"])).query)
    assert first_query == {
        "format": ["json"],
        "language": ["en"],
        "pageno": ["1"],
        "q": ["!federal_register caregiver benefits"],
        "safesearch": ["1"],
        "time_range": ["month"],
    }
    assert second_query["pageno"] == ["2"]
    assert [lead["title"] for lead in data["output"]["leads"]] == [
        "Caregiver rule",
        "Respite notice",
    ]
    assert data["output"]["routing"] == {
        "completed_pages": 2,
        "config_sha256": hashlib.sha256(
            json.dumps(config, separators=(",", ":")).encode()
        ).hexdigest(),
        "corrections": ["family caregiver"],
        "requested_categories": [],
        "requested_engines": ["federal register"],
        "suggestions": ["family caregiver benefits"],
        "unresponsive_engines": [{"engine": "federal register", "error": "timeout"}],
    }


def test_searxng_rejects_unknown_or_ambiguous_routing() -> None:
    config = json.dumps(
        {
            "categories": ["general"],
            "engines": [
                {
                    "categories": ["general"],
                    "enabled": True,
                    "name": "brave",
                    "shortcut": "br",
                }
            ],
        }
    ).encode()

    def transport(**call: object) -> tuple[int, bytes]:
        assert str(call["url"]).endswith("/config")
        return 200, config

    with pytest.raises(AdapterError, match="not enabled") as caught:
        searxng.search(
            {
                "query": "benefits",
                "options": {"engines": ["federal register"]},
            },
            env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
            transport=transport,
        )
    failed_raw = json.loads(caught.value.raw)
    assert base64.b64decode(failed_raw["config"]["body_base64"]) == config
    assert failed_raw["pages"] == []
    assert caught.value.requests == 1

    with pytest.raises(AdapterError, match="not both"):
        searxng.search(
            {
                "query": "benefits",
                "options": {"engines": ["brave"], "categories": ["general"]},
            },
            env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
            transport=transport,
        )


def test_searxng_requires_explicit_options_instead_of_query_control_syntax() -> None:
    with pytest.raises(AdapterError, match="options"):
        searxng.search(
            {"query": "!federal_register caregiver benefits"},
            env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
            transport=lambda **_: pytest.fail("query controls must fail before transport"),
        )


def test_searxng_failure_preserves_config_and_every_attempted_page() -> None:
    config = b'{"categories":["general"],"engines":[]}'
    page_one = b'{"results":[{"url":"https://example.com/a","title":"A"}]}'
    failed_page = b"upstream unavailable"
    responses = iter([(200, config), (200, page_one), (503, failed_page)])

    with pytest.raises(AdapterError, match="HTTP status 503") as caught:
        searxng.search(
            {
                "query": "caregiver support",
                "limit": 5,
                "options": {"max_pages": 2},
            },
            env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
            transport=lambda **_: next(responses),
        )

    raw = json.loads(caught.value.raw)
    assert base64.b64decode(raw["config"]["body_base64"]) == config
    assert [base64.b64decode(page["body_base64"]) for page in raw["pages"]] == [
        page_one,
        failed_page,
    ]
    assert caught.value.requests == 3


def test_searxng_config_failure_keeps_the_attempt() -> None:
    with pytest.raises(AdapterError, match="HTTP status 503") as caught:
        searxng.search(
            {"query": "family SUV", "limit": 5},
            env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
            transport=lambda **_: (503, b"config unavailable"),
        )

    raw = json.loads(caught.value.raw)
    assert raw["config"]["url"] == "http://127.0.0.1:8080/config"
    assert raw["config"]["status"] == 503
    assert base64.b64decode(raw["config"]["body_base64"]) == b"config unavailable"
    assert raw["pages"] == []


def test_searxng_rejects_disabled_json_output() -> None:
    config = b'{"categories":["general"],"engines":[]}'
    responses = iter([(200, config), (403, b"format disabled")])
    with pytest.raises(AdapterError, match="HTTP status 403"):
        searxng.search(
            {"query": "family SUV", "limit": 5},
            env={"SEARXNG_ENDPOINT": "http://127.0.0.1:8080"},
            transport=lambda **_: next(responses),
        )


def test_firecrawl_single_url_scrape_is_the_default() -> None:
    calls: list[dict[str, object]] = []
    response_body = json.dumps(
        {
            "success": True,
            "data": {
                "markdown": "# 2020 Lexus GX 460\nPrice: $31,000",
                "links": ["https://dealer.example.test/contact", "mailto:sales@example.test"],
                "metadata": {
                    "sourceURL": "https://dealer.example.test/gx-460",
                    "title": "2020 Lexus GX 460",
                    "statusCode": 200,
                },
            },
        },
        separators=(",", ":"),
    ).encode()

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return 200, response_body

    data = firecrawl.extract(
        {
            "url": "https://dealer.example.test/gx-460",
            "lineage": {"kind": "direct"},
        },
        env={"FIRECRAWL_API_KEY": "firecrawl-secret"},
        transport=transport,
        retrieved_at="2026-07-21T12:00:00Z",
    )

    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "https://api.firecrawl.dev/v2/scrape"
    assert calls[0]["headers"]["Authorization"] == "Bearer firecrawl-secret"
    assert json.loads(calls[0]["body"]) == {
        "formats": ["markdown", "links"],
        "onlyMainContent": True,
        "url": "https://dealer.example.test/gx-460",
    }
    document = data["output"]["documents"][0]
    assert document["url"] == "https://dealer.example.test/gx-460"
    assert document["links"] == ["https://dealer.example.test/contact"]
    assert document["markdown_sha256"] == hashlib.sha256(document["markdown"].encode()).hexdigest()
    assert data["output"]["evidence_class"] == "provider-derived"


def test_firecrawl_crawl_requires_and_forwards_the_explicit_page_cap() -> None:
    calls: list[dict[str, object]] = []
    responses = iter(
        [
            (200, b'{"success":true,"id":"crawl-1"}'),
            (200, b'{"status":"scraping","completed":0,"total":2}'),
            (
                200,
                json.dumps(
                    {
                        "status": "completed",
                        "data": [
                            {
                                "markdown": "# Inventory",
                                "links": ["https://dealer.example.test/gx-460"],
                                "metadata": {"sourceURL": "https://dealer.example.test/inventory"},
                            },
                            {
                                "markdown": "# GX 460",
                                "links": [],
                                "metadata": {"sourceURL": "https://dealer.example.test/gx-460"},
                            },
                        ],
                    },
                    separators=(",", ":"),
                ).encode(),
            ),
        ]
    )

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return next(responses)

    data = firecrawl.extract(
        {
            "url": "https://dealer.example.test/inventory",
            "lineage": {"kind": "direct"},
            "max_pages": 2,
        },
        env={"FIRECRAWL_API_KEY": "firecrawl-secret"},
        transport=transport,
        sleep=lambda _: None,
    )

    assert calls[0]["url"] == "https://api.firecrawl.dev/v2/crawl"
    assert json.loads(calls[0]["body"])["limit"] == 2
    assert calls[1]["method"] == "GET"
    assert calls[1]["url"] == "https://api.firecrawl.dev/v2/crawl/crawl-1"
    assert len(data["output"]["documents"]) == 2
    assert data["usage"]["requests"] == 3
    raw = json.loads(base64.b64decode(data["raw"]["body_base64"]))
    assert len(raw["exchanges"]) == 3


def test_camofox_open_uses_an_isolated_anonymous_session() -> None:
    calls: list[dict[str, object]] = []
    body = b'{"tabId":"tab-1","url":"https://dealer.example.test/inventory"}'

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return 200, body

    data = camofox.interact(
        {"action": "open", "url": "https://dealer.example.test/inventory"},
        env={
            "CAMOFOX_ENDPOINT": "http://127.0.0.1:9377",
            "CAMOFOX_ACCESS_KEY": "camofox-secret",
        },
        transport=transport,
        session_factory=lambda: "hound-session-1",
        retrieved_at="2026-07-21T12:00:00Z",
    )

    assert calls[0]["url"] == "http://127.0.0.1:9377/tabs"
    assert calls[0]["headers"]["Authorization"] == "Bearer camofox-secret"
    assert json.loads(calls[0]["body"]) == {
        "sessionKey": "hound-session-1",
        "trace": False,
        "url": "https://dealer.example.test/inventory",
        "userId": "hound-session-1",
    }
    assert data["output"] == {
        "schema_version": "hound.web.interact.v1",
        "trust": "untrusted",
        "evidence_class": "provider-derived",
        "action": "open",
        "session_id": "hound-session-1",
        "result": {
            "tab_id": "tab-1",
            "url": "https://dealer.example.test/inventory",
        },
    }


def test_camofox_snapshot_and_close_are_explicit_actions() -> None:
    calls: list[dict[str, object]] = []
    responses = iter(
        [
            (
                200,
                b'{"url":"https://dealer.example.test/inventory",'
                b'"snapshot":"- link \\"2020 GX 460\\" [ref=e1]",'
                b'"refsCount":1,"truncated":false,"hasMore":false}',
            ),
            (200, b'{"ok":true}'),
        ]
    )

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return next(responses)

    snapshot = camofox.interact(
        {
            "action": "snapshot",
            "session_id": "hound-session-1",
            "tab_id": "tab-1",
            "include_screenshot": False,
        },
        env={"CAMOFOX_ENDPOINT": "http://127.0.0.1:9377", "CAMOFOX_ACCESS_KEY": "secret"},
        transport=transport,
    )
    closed = camofox.interact(
        {"action": "close", "session_id": "hound-session-1"},
        env={"CAMOFOX_ENDPOINT": "http://127.0.0.1:9377", "CAMOFOX_ACCESS_KEY": "secret"},
        transport=transport,
    )

    assert calls[0]["method"] == "GET"
    assert "userId=hound-session-1" in calls[0]["url"]
    assert (
        snapshot["output"]["result"]["snapshot_sha256"]
        == hashlib.sha256(snapshot["output"]["result"]["snapshot"].encode()).hexdigest()
    )
    assert calls[1]["method"] == "DELETE"
    assert calls[1]["url"].endswith("/sessions/hound-session-1")
    assert closed["output"]["result"] == {"ok": True}
