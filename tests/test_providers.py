from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote

import pytest

from hound_cli import providers
from hound_cli.providers import ProviderError, execute_request, validate_request


def _request(
    provider: str = "exa",
    operation: str = "search",
    parameters: dict[str, object] | None = None,
    **extra: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "hound.provider.request.v1",
        "provider": provider,
        "operation": operation,
        "parameters": (
            {"query": "caregiving", "numResults": 2}
            if parameters is None
            else parameters
        ),
    }
    value.update(extra)
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def test_validate_request_accepts_only_the_versioned_provider_contract() -> None:
    request = _request(retrieved_at="2026-07-17T12:00:00Z")

    validated = validate_request(request)

    assert validated == request
    assert validated is not request
    assert validated["parameters"] is not request["parameters"]


@pytest.mark.parametrize(
    "candidate",
    [
        {},
        _request(schema_version="hound.provider.request.v2"),
        _request(provider="other"),
        _request(operation="scrape"),
        _request(parameters=[]),
        _request(extra=True),
        _request(parameters={"query": ""}),
        _request(parameters={"query": "caregiving", "numResults": 0}),
        _request(parameters={"query": "caregiving", "numResults": 101}),
        _request(parameters={"query": "q" * 10_001, "numResults": 1}),
        _request(
            provider="firecrawl",
            parameters={"query": "caregiving", "limit": True},
        ),
        _request(
            provider="firecrawl",
            parameters={"query": "caregiving", "limit": 101},
        ),
    ],
)
def test_validate_request_rejects_malformed_or_unbounded_requests(
    candidate: object,
) -> None:
    with pytest.raises(ProviderError):
        validate_request(candidate)


@pytest.mark.parametrize(
    "parameters",
    [
        {"query": "caregiving", "futureActiveMode": True},
        {"query": "caregiving", "secretKey": "must-not-cross"},
        {"query": "caregiving", "options": {}},
        {"query": "caregiving", "contents": {"secretKey": "must-not-cross"}},
    ],
)
def test_exa_rejects_undeclared_operation_parameters(
    parameters: dict[str, object],
) -> None:
    with pytest.raises(ProviderError, match="not allowed") as caught:
        validate_request(_request(parameters=parameters))

    assert "must-not-cross" not in str(caught.value)


def test_exa_contents_accepts_urls_or_ids_but_not_both() -> None:
    by_urls = _request(
        operation="contents",
        parameters={
            "urls": ["https://example.test/page"],
            "text": {"maxCharacters": 2_000},
            "highlights": {"numSentences": 3, "highlightsPerUrl": 2},
            "summary": {},
        },
    )

    assert validate_request(by_urls)["parameters"]["urls"] == ["https://example.test/page"]
    with pytest.raises(ProviderError):
        validate_request(
            _request(
                operation="contents",
                parameters={
                    "ids": ["doc-id"],
                    "urls": ["https://example.test/page"],
                },
            )
        )
    with pytest.raises(ProviderError):
        validate_request(_request(operation="contents", parameters={"ids": ["id"] * 101}))


def test_provider_request_rejects_excessive_nesting() -> None:
    nested: dict[str, object] = {"value": "leaf"}
    for _ in range(40):
        nested = {"nested": nested}

    with pytest.raises(ProviderError, match="nested"):
        validate_request(
            _request(parameters={"query": "caregiving", "options": nested})
        )


@pytest.mark.parametrize(
    ("operation", "parameters"),
    [
        (
            "scrape",
            {
                "url": "https://example.test/page",
                "actions": [{"type": "click", "selector": "#delete"}],
            },
        ),
        (
            "search",
            {
                "query": "caregiving",
                "limit": 2,
                "scrapeOptions": {"actions": [{"type": "executeJavascript"}]},
            },
        ),
        (
            "scrape",
            {
                "url": "https://example.test/page",
                "headers": {"X-Unsafe": "value"},
            },
        ),
        (
            "scrape",
            {
                "url": "https://example.test/page",
                "skipTlsVerification": True,
            },
        ),
    ],
)
def test_firecrawl_transport_rejects_active_or_unsafe_browser_options(
    operation: str, parameters: dict[str, object]
) -> None:
    with pytest.raises(ProviderError, match="not allowed"):
        validate_request(
            _request(provider="firecrawl", operation=operation, parameters=parameters)
        )


def test_firecrawl_scrape_accepts_passive_capture_options() -> None:
    parameters = {
        "url": "https://example.test/page",
        "formats": ["markdown", "html"],
        "onlyMainContent": True,
        "includeTags": ["article"],
        "excludeTags": ["nav"],
        "removeBase64Images": True,
        "blockAds": True,
    }

    validated = validate_request(
        _request(provider="firecrawl", operation="scrape", parameters=parameters)
    )

    assert validated["parameters"] == parameters


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/private",
        "http://[::1]/private",
        "http://localhost/private",
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1\\example.com/private",
        "http://169.254.169.254\\public.example/private",
        "https://exa mple.test/report",
        "https://example.test/line\nbreak",
        "https://-invalid.example/report",
        "https://invalid_.example/report",
        "https://example.test:not-a-port/report",
    ],
)
def test_provider_urls_reject_local_and_non_global_hosts(url: str) -> None:
    with pytest.raises(ProviderError, match="URL"):
        validate_request(
            _request(
                provider="firecrawl",
                operation="scrape",
                parameters={"url": url},
            )
        )


@pytest.mark.parametrize(
    "parameters",
    [
        {"query": "caregiving", "api_key": "must-not-land"},
        {"query": "caregiving", "headers": {"Authorization": "must-not-land"}},
        {"query": "caregiving", "token": "must-not-land"},
        {"url": "https://user:password@example.test/page"},
        {"url": "https://example.test/page?access_token=must-not-land"},
        {"url": "https://example.test/page#access_token=must-not-land"},
        {"url": "https://example.test/page?safe=1;access_token=must-not-land"},
        {"url": "https://example.test/page?sig=must-not-land"},
        {"ids": ["https://example.test/page?api-key=must-not-land"]},
    ],
)
def test_validate_request_rejects_credentials_in_parameters_and_urls(
    parameters: dict[str, object],
) -> None:
    operation = "contents" if "ids" in parameters else "search"

    with pytest.raises(ProviderError) as error:
        validate_request(_request(operation=operation, parameters=parameters))

    assert "must-not-land" not in str(error.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/page#access_token=must-not-land",
        "https://example.test/page?safe=1;access_token=must-not-land",
    ],
)
def test_provider_url_rejects_fragment_and_ambiguous_query_credentials(
    url: str,
) -> None:
    with pytest.raises(ProviderError) as error:
        validate_request(
            _request(
                provider="firecrawl",
                operation="scrape",
                parameters={"url": url},
            )
        )

    assert "must-not-land" not in str(error.value)


def test_execute_exa_search_uses_official_endpoint_and_normalizes_leads() -> None:
    request = _request(retrieved_at="2026-07-17T12:00:00Z")
    calls: list[dict[str, object]] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return (
            200,
            json.dumps(
                {
                    "results": [
                        {
                            "url": "https://example.test/one",
                            "title": "First result",
                            "score": 0.91,
                        },
                        {"url": "https://example.test/two"},
                    ]
                }
            ).encode("utf-8"),
        )

    response = execute_request(
        request,
        env={"EXA_API_KEY": "exa-test-secret"},
        transport=transport,
        timeout=9,
    )

    assert calls == [
        {
            "url": "https://api.exa.ai/search",
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-api-key": "exa-test-secret",
            },
            "body": b'{"numResults":2,"query":"caregiving"}',
            "timeout": 9.0,
        }
    ]
    assert response["schema_version"] == "hound.provider.response.v1"
    assert response["provider"] == "exa"
    assert response["operation"] == "search"
    assert response["request_sha256"] == _canonical_sha256(request)
    assert response["retrieved_at"] == "2026-07-17T12:00:00Z"
    assert response["raw_data"]["results"][0]["score"] == 0.91
    assert response["leads"] == [
        {
            "schema_version": "hound.lead.v1",
            "evidence_status": "not-evidence",
            "provider": "exa",
            "query": "caregiving",
            "url": "https://example.test/one",
            "title": "First result",
            "metadata": {"rank": 1},
        },
        {
            "schema_version": "hound.lead.v1",
            "evidence_status": "not-evidence",
            "provider": "exa",
            "query": "caregiving",
            "url": "https://example.test/two",
            "metadata": {"rank": 2},
        },
    ]
    assert "exa-test-secret" not in json.dumps(response)


def test_execute_firecrawl_search_normalizes_data_web() -> None:
    request = _request(
        provider="firecrawl",
        parameters={"query": "caregiving", "limit": 1},
    )
    calls: list[dict[str, object]] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return (
            200,
            json.dumps(
                {
                    "success": True,
                    "data": {
                        "web": [
                            {
                                "url": "https://example.test/firecrawl",
                                "title": "Firecrawl result",
                            }
                        ]
                    },
                }
            ).encode("utf-8"),
        )

    response = execute_request(
        request,
        env={"FIRECRAWL_API_KEY": "firecrawl-test-secret"},
        transport=transport,
    )

    assert calls[0]["url"] == "https://api.firecrawl.dev/v2/search"
    assert calls[0]["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer firecrawl-test-secret",
        "Content-Type": "application/json",
    }
    assert response["leads"][0]["evidence_status"] == "not-evidence"
    assert response["leads"][0]["provider"] == "firecrawl"
    assert response["leads"][0]["url"] == "https://example.test/firecrawl"
    assert "retrieved_at" not in response
    assert "firecrawl-test-secret" not in json.dumps(response)


@pytest.mark.parametrize(
    ("provider", "operation", "parameters", "key_name", "endpoint"),
    [
        (
            "exa",
            "contents",
            {"ids": ["https://example.test/page"]},
            "EXA_API_KEY",
            "https://api.exa.ai/contents",
        ),
        (
            "firecrawl",
            "scrape",
            {"url": "https://example.test/page"},
            "FIRECRAWL_API_KEY",
            "https://api.firecrawl.dev/v2/scrape",
        ),
    ],
)
def test_execute_non_search_operations_use_official_endpoints_without_leads(
    provider: str,
    operation: str,
    parameters: dict[str, object],
    key_name: str,
    endpoint: str,
) -> None:
    calls: list[dict[str, object]] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return 200, b'{"success":true,"data":{"content":"captured"}}'

    response = execute_request(
        _request(provider=provider, operation=operation, parameters=parameters),
        env={key_name: "test-secret"},
        transport=transport,
    )

    assert calls[0]["url"] == endpoint
    assert "leads" not in response


@pytest.mark.parametrize(
    ("env", "provider_request"),
    [
        ({}, _request()),
        ({"EXA_API_KEY": ""}, _request()),
        (
            {},
            _request(
                provider="firecrawl",
                parameters={"query": "caregiving", "limit": 1},
            ),
        ),
    ],
)
def test_execute_fails_closed_before_transport_when_key_is_missing(
    env: dict[str, str], provider_request: dict[str, object]
) -> None:
    called = False

    def transport(**call: object) -> tuple[int, bytes]:
        nonlocal called
        called = True
        return 200, b"{}"

    with pytest.raises(ProviderError, match="credential"):
        execute_request(provider_request, env=env, transport=transport)

    assert called is False


@pytest.mark.parametrize(
    "transport",
    [
        lambda **_: (429, b'{"error":"rate limited"}'),
        lambda **_: (200, b"not-json"),
        lambda **_: (200, b"[]"),
        lambda **_: (200, b'{"success":false,"error":"provider failed"}'),
        lambda **_: (200, b'{"results":{}}'),
    ],
)
def test_execute_fails_closed_on_bad_provider_responses(transport: object) -> None:
    with pytest.raises(ProviderError):
        execute_request(
            _request(),
            env={"EXA_API_KEY": "test-secret"},
            transport=transport,
        )


def test_execute_caps_provider_response_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(providers, "MAX_RESPONSE_BYTES", 16)

    with pytest.raises(ProviderError, match="size"):
        execute_request(
            _request(),
            env={"EXA_API_KEY": "test-secret"},
            transport=lambda **_: (200, b'{"results":[]}' + b" " * 20),
        )


def test_default_transport_does_not_buffer_http_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ErrorBody:
        def read(self, *_: object) -> bytes:
            raise AssertionError("HTTP error body must not be read")

        def close(self) -> None:
            pass

    class FailingOpener:
        def open(self, *_: object, **__: object) -> object:
            raise HTTPError(
                "https://api.exa.ai/search",
                429,
                "rate limited",
                {},
                ErrorBody(),
            )

    monkeypatch.setattr(providers, "build_opener", lambda *_: FailingOpener())

    status, body = providers._default_transport(
        url="https://api.exa.ai/search",
        headers={},
        body=b"{}",
        timeout=1,
    )

    assert status == 429
    assert body == b""


def test_default_transport_enforces_total_deadline_for_slow_drip_response() -> None:
    class SlowDripHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            payload = b'{"results":[]}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                for byte in payload:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.03)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_: object) -> None:
            pass

    class SlowDripServer(ThreadingHTTPServer):
        daemon_threads = True

    server = SlowDripServer(("127.0.0.1", 0), SlowDripHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(ProviderError, match="timed out"):
            providers._default_transport(
                url=f"http://127.0.0.1:{server.server_port}/search",
                headers={},
                body=b"{}",
                timeout=0.1,
            )
        assert time.monotonic() - started < 0.3
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1)


def test_execute_never_leaks_key_from_transport_error_or_echoed_response() -> None:
    key = "transport-test-secret"

    def failed_transport(**_: object) -> tuple[int, bytes]:
        raise RuntimeError(f"connection failed with {key}")

    with pytest.raises(ProviderError) as transport_error:
        execute_request(
            _request(), env={"EXA_API_KEY": key}, transport=failed_transport
        )
    assert key not in str(transport_error.value)

    def echoed_transport(**_: object) -> tuple[int, bytes]:
        return 200, json.dumps({"results": [], "echo": key}).encode("utf-8")

    with pytest.raises(ProviderError) as echo_error:
        execute_request(
            _request(), env={"EXA_API_KEY": key}, transport=echoed_transport
        )
    assert key not in str(echo_error.value)


@pytest.mark.parametrize(
    "transformed",
    [
        lambda value: quote(value, safe=""),
        lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii"),
    ],
)
def test_execute_rejects_encoded_credential_echoes(transformed) -> None:
    key = "provider:key/with+unsafe=characters"
    echo = transformed(key)

    with pytest.raises(ProviderError, match="credential") as caught:
        execute_request(
            _request(),
            env={"EXA_API_KEY": key},
            transport=lambda **_: (
                200,
                json.dumps({"results": [], "echo": echo}).encode("utf-8"),
            ),
        )

    assert key not in str(caught.value)
    assert echo not in str(caught.value)
