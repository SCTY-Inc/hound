from __future__ import annotations

import base64
import hashlib
import json

import pytest

from hound_web_adapters import _http, camofox, exa, firecrawl
from hound_web_adapters._http import AdapterError


def test_http_transport_marks_a_no_response_failure_as_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingOpener:
        def open(self, *_: object, **__: object) -> None:
            raise TimeoutError

    monkeypatch.setattr(_http, "build_opener", lambda *_: FailingOpener())

    with pytest.raises(AdapterError, match="provider transport failed") as caught:
        _http.request(
            method="POST",
            url="https://api.exa.ai/search",
            headers={},
            body=b"{}",
            timeout=0.1,
        )

    assert caught.value.retryable is True
    assert caught.value.requests == 1
    assert caught.value.raw == b""


def test_exa_normalizes_bounded_candidates_and_preserves_provider_cost_receipt() -> None:
    calls: list[dict[str, object]] = []
    body = json.dumps(
        {
            "results": [
                {
                    "id": "https://example.test/care-workforce",
                    "url": "https://example.test/care-workforce",
                    "title": "States test a new care-workforce model",
                    "publishedDate": "2026-07-28T09:00:00Z",
                    "author": "Casey Writer",
                    "score": 0.91,
                    "highlights": ["A state pilot changes how home-care workers are paid."],
                }
            ],
            "requestId": "request-123",
            "costDollars": {"total": 0.008},
        },
        separators=(",", ":"),
    ).encode()

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return 200, body

    data = exa.search(
        {
            "query": "care workforce policy",
            "limit": 5,
            "options": {
                "type": "fast",
                "category": "news",
                "startPublishedDate": "2026-07-22T00:00:00Z",
                "endPublishedDate": "2026-07-29T23:59:59Z",
                "userLocation": "US",
            },
        },
        env={"EXA_API_KEY": "secret-test-key"},
        transport=transport,
        retrieved_at="2026-07-29T12:00:00Z",
    )

    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "https://api.exa.ai/search"
    assert calls[0]["headers"]["x-api-key"] == "secret-test-key"
    assert json.loads(calls[0]["body"]) == {
        "category": "news",
        "contents": {
            "highlights": {
                "maxCharacters": 1_000,
                "query": "care workforce policy",
            }
        },
        "endPublishedDate": "2026-07-29T23:59:59Z",
        "numResults": 5,
        "query": "care workforce policy",
        "startPublishedDate": "2026-07-22T00:00:00Z",
        "type": "fast",
        "userLocation": "US",
    }
    assert json.loads(base64.b64decode(data["raw"]["body_base64"]))["costDollars"] == {
        "total": 0.008
    }
    assert data["usage"] == {"requests": 1, "bytes": len(body)}
    assert data["output"]["leads"] == [
        {
            "schema_version": "hound.lead.v1",
            "evidence_status": "not-evidence",
            "provider": "exa",
            "query": "care workforce policy",
            "url": "https://example.test/care-workforce",
            "title": "States test a new care-workforce model",
            "metadata": {
                "rank": 1,
                "publishedDate": "2026-07-28T09:00:00Z",
                "author": "Casey Writer",
                "providerId": "https://example.test/care-workforce",
                "score": 0.91,
                "snippet": "A state pilot changes how home-care workers are paid.",
                "category": "news",
            },
        }
    ]


@pytest.mark.parametrize(
    "options, message",
    [
        ({"type": "deep"}, "type must be auto or fast"),
        (
            {"category": "company", "startPublishedDate": "2026-07-01T00:00:00Z"},
            "do not support",
        ),
        (
            {
                "startPublishedDate": "2026-07-30T00:00:00Z",
                "endPublishedDate": "2026-07-29T00:00:00Z",
            },
            "must not follow",
        ),
        ({"includeDomains": ["https://example.com"]}, "invalid domain"),
        ({"unsupported": True}, "not supported"),
    ],
)
def test_exa_refuses_ambiguous_or_high_cost_options(
    options: dict[str, object], message: str
) -> None:
    with pytest.raises(AdapterError, match=message):
        exa.search(
            {"query": "caregiving", "options": options},
            env={"EXA_API_KEY": "secret-test-key"},
            transport=lambda **_: (200, b'{"results":[]}'),
        )


def test_exa_structural_failure_retains_exact_provider_bytes() -> None:
    raw = b'{"requestId":"broken","costDollars":{"total":0.007}}'
    with pytest.raises(AdapterError, match="does not contain results") as caught:
        exa.search(
            {"query": "caregiving"},
            env={"EXA_API_KEY": "secret-test-key"},
            transport=lambda **_: (200, raw),
        )
    assert caught.value.raw == raw
    assert caught.value.requests == 1


def test_exa_retries_transient_auth_failure_and_preserves_each_exchange() -> None:
    unauthorized = (
        b'{"requestId":"transient-auth","error":"Invalid API key",'
        b'"tag":"INVALID_API_KEY"}'
    )
    success = (
        b'{"results":[{"url":"https://example.test/care-policy",'
        b'"title":"Care policy"}]}'
    )
    responses = iter([(401, unauthorized), (200, success)])
    calls: list[dict[str, object]] = []
    delays: list[float] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return next(responses)

    data = exa.search(
        {"query": "care policy"},
        env={"EXA_API_KEY": "known-good-key"},
        transport=transport,
        sleep=delays.append,
    )

    assert len(calls) == 2
    assert delays == [0.25]
    assert data["usage"]["requests"] == 2
    assert data["raw"]["media_type"] == "application/vnd.hound.http-exchanges+json"
    raw = base64.b64decode(data["raw"]["body_base64"])
    assert data["usage"]["bytes"] == len(raw)
    exchanges = json.loads(raw)["exchanges"]
    assert [exchange["status"] for exchange in exchanges] == [401, 200]
    for exchange, expected_body in zip(exchanges, (unauthorized, success), strict=True):
        assert base64.b64decode(exchange["body_base64"]) == expected_body
        assert exchange["sha256"] == hashlib.sha256(expected_body).hexdigest()


def test_exa_retries_transport_failure_and_counts_the_attempt_without_a_response() -> None:
    responses: list[AdapterError | tuple[int, bytes]] = [
        AdapterError("provider transport failed", requests=1, retryable=True),
        (
            200,
            b'{"results":[{"url":"https://example.test/care-policy",'
            b'"title":"Care policy"}]}',
        ),
    ]
    calls: list[dict[str, object]] = []
    delays: list[float] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        response = responses.pop(0)
        if isinstance(response, AdapterError):
            raise response
        return response

    data = exa.search(
        {"query": "care policy"},
        env={"EXA_API_KEY": "known-good-key"},
        transport=transport,
        sleep=delays.append,
    )

    assert len(calls) == 2
    assert delays == [0.25]
    assert data["usage"]["requests"] == 2
    assert data["raw"]["media_type"] == "application/vnd.hound.http-exchanges+json"
    raw = base64.b64decode(data["raw"]["body_base64"])
    exchanges = json.loads(raw)["exchanges"]
    assert len(exchanges) == 1
    assert set(exchanges[0]) == {"method", "url", "status", "body_base64", "sha256"}
    assert exchanges[0]["status"] == 200


def test_exa_transport_retry_exhaustion_counts_attempts_without_fabricating_responses() -> None:
    calls: list[dict[str, object]] = []
    delays: list[float] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        raise AdapterError("provider transport failed", requests=1, retryable=True)

    with pytest.raises(AdapterError, match="provider transport failed") as caught:
        exa.search(
            {"query": "care policy"},
            env={"EXA_API_KEY": "known-good-key"},
            transport=transport,
            sleep=delays.append,
        )

    assert len(calls) == 3
    assert delays == [0.25, 1.0]
    assert caught.value.requests == 3
    assert caught.value.media_type == "application/vnd.hound.http-exchanges+json"
    assert json.loads(caught.value.raw) == {"exchanges": []}


def test_exa_mixed_retry_path_preserves_responses_before_terminal_transport_error() -> None:
    responses: list[tuple[int, bytes] | AdapterError] = [
        (503, b'{"requestId":"unavailable-1","error":"Unavailable"}'),
        AdapterError("provider response exceeded the byte ceiling", requests=1),
    ]

    def transport(**_: object) -> tuple[int, bytes]:
        response = responses.pop(0)
        if isinstance(response, AdapterError):
            raise response
        return response

    with pytest.raises(AdapterError, match="byte ceiling") as caught:
        exa.search(
            {"query": "care policy"},
            env={"EXA_API_KEY": "known-good-key"},
            transport=transport,
            sleep=lambda _: None,
        )

    assert caught.value.requests == 2
    assert caught.value.media_type == "application/vnd.hound.http-exchanges+json"
    assert [
        exchange["status"] for exchange in json.loads(caught.value.raw)["exchanges"]
    ] == [503]


def test_exa_one_shot_nonretryable_transport_error_is_unchanged() -> None:
    failure = AdapterError("provider response exceeded the byte ceiling", requests=1)

    def transport(**_: object) -> tuple[int, bytes]:
        raise failure

    with pytest.raises(AdapterError) as caught:
        exa.search(
            {"query": "care policy"},
            env={"EXA_API_KEY": "known-good-key"},
            transport=transport,
        )

    assert caught.value is failure


def test_exa_retry_exhaustion_preserves_every_failure() -> None:
    calls: list[dict[str, object]] = []
    delays: list[float] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        request_number = len(calls)
        return (
            503,
            json.dumps(
                {"requestId": f"unavailable-{request_number}", "error": "Unavailable"},
                separators=(",", ":"),
            ).encode(),
        )

    with pytest.raises(AdapterError, match="HTTP status 503") as caught:
        exa.search(
            {"query": "care policy"},
            env={"EXA_API_KEY": "known-good-key"},
            transport=transport,
            sleep=delays.append,
        )

    assert len(calls) == 3
    assert delays == [0.25, 1.0]
    assert caught.value.requests == 3
    assert caught.value.media_type == "application/vnd.hound.http-exchanges+json"
    assert [
        exchange["status"] for exchange in json.loads(caught.value.raw)["exchanges"]
    ] == [503, 503, 503]


@pytest.mark.parametrize("status", [400, 402, 403, 404, 422])
def test_exa_deterministic_client_failure_is_not_retried(status: int) -> None:
    calls: list[dict[str, object]] = []
    raw = b"not-json"

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return status, raw

    with pytest.raises(AdapterError, match=f"HTTP status {status}") as caught:
        exa.search(
            {"query": "care policy"},
            env={"EXA_API_KEY": "known-good-key"},
            transport=transport,
            sleep=lambda _: pytest.fail("deterministic failure must not sleep"),
        )

    assert len(calls) == 1
    assert caught.value.requests == 1
    assert caught.value.media_type == "application/octet-stream"
    assert caught.value.raw == raw


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
