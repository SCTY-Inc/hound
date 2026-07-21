from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hound_cli.contracts import canonical_hash
from hound_cli.providers import ProviderError
from hound_cli.source import capture_sources, discover_sources, inspect_sources


def provider_request() -> dict[str, object]:
    return {
        "schema_version": "hound.provider.request.v1",
        "provider": "exa",
        "operation": "search",
        "parameters": {
            "query": "care workforce",
            "numResults": 2,
            "text": {"maxCharacters": 4_000},
        },
        "retrieved_at": "2026-07-20T10:00:00Z",
    }


def provider_response(request: dict[str, object]) -> dict[str, object]:
    raw = {
        "results": [
            {
                "url": "https://example.test/one",
                "title": "First result",
                "publishedDate": "2026-07-20T08:00:00Z",
                "text": "A state raised its direct-care wage floor.",
            },
            {
                "url": "https://example.test/two",
                "title": "Second result",
                "publishedDate": "2026-07-20T09:00:00Z",
                "text": "A provider opened a respite program.",
            },
        ]
    }
    return {
        "schema_version": "hound.provider.response.v1",
        "provider": "exa",
        "operation": "search",
        "request_sha256": hashlib.sha256(
            json.dumps(
                request,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
        "retrieved_at": "2026-07-20T10:00:00Z",
        "raw_data": raw,
        "leads": [
            {
                "schema_version": "hound.lead.v1",
                "evidence_status": "not-evidence",
                "provider": "exa",
                "query": "care workforce",
                "url": result["url"],
                "title": result["title"],
                "metadata": {"rank": rank},
            }
            for rank, result in enumerate(raw["results"], start=1)
        ],
    }


def test_discovery_composes_owner_policy_with_kernel_provider_transport(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest_path = driver_repo
    request = provider_request()
    seen: list[dict[str, object]] = []

    def execute(value: object) -> dict[str, object]:
        assert isinstance(value, dict)
        seen.append(value)
        return provider_response(value)

    monkeypatch.setenv("EXA_API_KEY", "kernel-only-secret")
    result = discover_sources(
        manifest_path,
        {
            "requests": [request],
            "forbid_env": "EXA_API_KEY",
            "limits": {"max_requests": 1, "max_leads": 2, "max_bytes": 20_000},
        },
        provider_execute=execute,
    )

    assert seen == [request]
    assert result["data_schema"] == "hound.source.discovery.v1"
    assert result["data"]["schema_version"] == "hound.source.discovery.v1"
    assert len(result["data"]["leads"]) == 2
    assert result["data"]["leads"][0]["evidence_status"] == "not-evidence"
    assert "kernel-only-secret" not in json.dumps(result)


def test_discovery_fails_closed_when_owner_budget_is_exceeded(
    driver_repo: tuple[Path, Path]
) -> None:
    _, manifest_path = driver_repo
    request = provider_request()

    with pytest.raises(ValueError, match="max_leads exceeded"):
        discover_sources(
            manifest_path,
            {
                "requests": [request],
                "limits": {"max_requests": 1, "max_leads": 1, "max_bytes": 20_000},
            },
            provider_execute=lambda value: provider_response(value),
        )


def test_discovery_keeps_request_identity_when_one_provider_call_fails(
    driver_repo: tuple[Path, Path]
) -> None:
    _, manifest_path = driver_repo
    first = provider_request()
    second = provider_request()
    second["parameters"] = {**second["parameters"], "query": "respite access"}
    def execute(value: object) -> dict[str, object]:
        assert isinstance(value, dict)
        if value["parameters"]["query"] == "care workforce":
            raise ProviderError("temporary provider failure")
        response = provider_response(value)
        response["leads"] = [
            {**lead, "query": "respite access"}
            for lead in response["leads"]
        ]
        return response

    result = discover_sources(
        manifest_path,
        {
            "requests": [first, second],
            "limits": {"max_requests": 2, "max_leads": 2, "max_bytes": 20_000},
        },
        provider_execute=execute,
    )

    assert result["data"]["requests"] == [second]
    assert result["data"]["responses"][0]["request_sha256"] == canonical_hash(second)


def test_capture_persists_selected_results_and_inspect_verifies_them(
    driver_repo: tuple[Path, Path]
) -> None:
    repo, manifest_path = driver_repo
    request = provider_request()
    discovery = discover_sources(
        manifest_path,
        {
            "requests": [request],
            "limits": {"max_requests": 1, "max_leads": 2, "max_bytes": 20_000},
        },
        provider_execute=lambda value: provider_response(value),
    )["data"]

    captured = capture_sources(
        manifest_path,
        {
            "schema_version": "hound.source.capture.input.v1",
            "discovery": discovery,
            "selected_urls": ["https://example.test/one"],
        },
    )

    assert captured["data_schema"] == "hound.source.capture-set.v1"
    assert captured["data"]["retrieved_at"] == "2026-07-20T10:00:00Z"
    entry = captured["data"]["captures"][0]
    assert entry["document"]["title"] == "First result"
    capture_id = entry["manifest"]["capture_id"]
    assert (repo / ".hound" / "captures" / "manifests" / f"{capture_id}.json").exists()

    inspected = inspect_sources(
        manifest_path,
        {
            "schema_version": "fake.inspect.input.v1",
            "capture_set": captured["data"],
        },
    )
    assert inspected["outcome"] == "completed"
    assert inspected["data"]["echo"]["capture_set"] == captured["data"]


def test_empty_discovery_can_flow_to_owner_no_edition(
    driver_repo: tuple[Path, Path]
) -> None:
    _, manifest_path = driver_repo
    request = provider_request()
    empty_response = provider_response(request)
    empty_response["raw_data"] = {"results": []}
    empty_response["leads"] = []
    discovery = discover_sources(
        manifest_path,
        {
            "requests": [request],
            "limits": {"max_requests": 1, "max_leads": 2, "max_bytes": 20_000},
        },
        provider_execute=lambda value: empty_response,
    )["data"]

    captured = capture_sources(
        manifest_path,
        {
            "schema_version": "hound.source.capture.input.v1",
            "discovery": discovery,
            "selected_urls": [],
        },
    )
    assert captured["data"] == {
        "schema_version": "hound.source.capture-set.v1",
        "retrieved_at": "2026-07-20T10:00:00Z",
        "captures": [],
    }
    assert inspect_sources(
        manifest_path,
        {"schema_version": "fake.inspect.input.v1", "capture_set": captured["data"]},
    )["outcome"] == "completed"


def test_inspect_rejects_document_tampering(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    request = provider_request()
    discovery = discover_sources(
        manifest_path,
        {
            "requests": [request],
            "limits": {"max_requests": 1, "max_leads": 2, "max_bytes": 20_000},
        },
        provider_execute=lambda value: provider_response(value),
    )["data"]
    captured = capture_sources(
        manifest_path,
        {
            "schema_version": "hound.source.capture.input.v1",
            "discovery": discovery,
            "selected_urls": ["https://example.test/one"],
        },
    )["data"]
    captured["captures"][0]["document"]["text"] = "tampered"

    with pytest.raises(ValueError, match="capture document hash"):
        inspect_sources(
            manifest_path,
            {"schema_version": "fake.inspect.input.v1", "capture_set": captured},
        )


def test_capture_rejects_discovery_lead_tampering(
    driver_repo: tuple[Path, Path]
) -> None:
    _, manifest_path = driver_repo
    request = provider_request()
    discovery = discover_sources(
        manifest_path,
        {
            "requests": [request],
            "limits": {"max_requests": 1, "max_leads": 2, "max_bytes": 20_000},
        },
        provider_execute=lambda value: provider_response(value),
    )["data"]
    discovery["leads"][0]["query"] = "tampered"

    with pytest.raises(ValueError, match="leads do not match"):
        capture_sources(
            manifest_path,
            {
                "schema_version": "hound.source.capture.input.v1",
                "discovery": discovery,
                "selected_urls": ["https://example.test/one"],
            },
        )
