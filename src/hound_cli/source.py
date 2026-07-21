"""Kernel composition for owner-defined source discovery and capture."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .contracts import canonical_hash, canonical_json, load_manifest
from .evidence import EvidenceError, make_lead, store_capture, verify_capture
from .orchestrator import HoundError, invoke_read
from .packs import provider_pack
from .packs.web import WebCapture, WebFetchError, fetch_web_capture
from .providers import ProviderError, execute_request, validate_request

DISCOVERY_SPEC_SCHEMA = "hound.source.discovery-spec.v1"
DISCOVERY_SCHEMA = "hound.source.discovery.v1"
CAPTURE_INPUT_SCHEMA = "hound.source.capture.input.v1"
CAPTURE_SPEC_SCHEMA = "hound.source.capture-spec.v1"
CAPTURE_SET_SCHEMA = "hound.source.capture-set.v1"

MAX_SOURCE_REQUESTS = 16
MAX_SOURCE_LEADS = 500
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_CAPTURES = 100

ProviderExecutor = Callable[[object], dict[str, Any]]
WebFetcher = Callable[..., WebCapture]


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _strict(value: dict[str, Any], required: set[str], label: str) -> None:
    missing = required - value.keys()
    extra = set(value) - required
    if missing or extra:
        raise EvidenceError(f"{label} has missing or unknown fields")


def _positive_int(value: object, label: str, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EvidenceError(f"{label} must be a positive integer")
    if value > ceiling:
        raise EvidenceError(f"{label} exceeds the kernel ceiling {ceiling}")
    return value


def _discovery_spec(response: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if response.get("data_schema") != DISCOVERY_SPEC_SCHEMA:
        raise EvidenceError(f"source.discover must return {DISCOVERY_SPEC_SCHEMA}")
    data = _object(response.get("data"), "source discovery spec")
    _strict(data, {"schema_version", "requests", "limits"}, "source discovery spec")
    if data["schema_version"] != DISCOVERY_SPEC_SCHEMA:
        raise EvidenceError("source discovery spec has an unsupported schema version")
    raw_requests = data["requests"]
    if not isinstance(raw_requests, list) or not raw_requests:
        raise EvidenceError("source discovery requests must be a non-empty array")
    limits = _object(data["limits"], "source discovery limits")
    _strict(limits, {"max_requests", "max_leads", "max_bytes"}, "source discovery limits")
    validated_limits = {
        "max_requests": _positive_int(limits["max_requests"], "max_requests", MAX_SOURCE_REQUESTS),
        "max_leads": _positive_int(limits["max_leads"], "max_leads", MAX_SOURCE_LEADS),
        "max_bytes": _positive_int(limits["max_bytes"], "max_bytes", MAX_SOURCE_BYTES),
    }
    if len(raw_requests) > validated_limits["max_requests"]:
        raise EvidenceError(
            f"max_requests exceeded: {len(raw_requests)} > {validated_limits['max_requests']}"
        )
    requests: list[dict[str, Any]] = []
    for raw in raw_requests:
        try:
            request = validate_request(raw)
        except ProviderError as error:
            raise EvidenceError(str(error)) from error
        if request["operation"] != "search":
            raise EvidenceError("source discovery accepts provider search requests only")
        if "retrieved_at" not in request:
            raise EvidenceError("source discovery requests must bind retrieved_at")
        requests.append(request)
    if len({request["retrieved_at"] for request in requests}) != 1:
        raise EvidenceError("source discovery requests must share one retrieved_at")
    return requests, validated_limits


def _provider_response(value: object, request: dict[str, Any]) -> dict[str, Any]:
    response = _object(value, "provider response")
    required = {
        "schema_version",
        "pack",
        "provider",
        "operation",
        "request_sha256",
        "retrieved_at",
        "raw_data",
        "leads",
    }
    _strict(response, required, "provider response")
    if response["schema_version"] != "hound.provider.response.v1":
        raise EvidenceError("provider response has an unsupported schema version")
    if (
        response["provider"] != request["provider"]
        or response["pack"] != provider_pack(request["provider"])
        or response["operation"] != "search"
    ):
        raise EvidenceError("provider response does not match its request")
    if response["request_sha256"] != canonical_hash(request):
        raise EvidenceError("provider response request hash does not match")
    if response["retrieved_at"] != request["retrieved_at"]:
        raise EvidenceError("provider response retrieval time does not match")
    _object(response["raw_data"], "provider response raw_data")
    if not isinstance(response["leads"], list):
        raise EvidenceError("provider response leads must be an array")
    query = request["parameters"].get("query")
    if not isinstance(query, str) or not query:
        raise EvidenceError("provider search request query is invalid")
    leads: list[dict[str, Any]] = []
    for raw in response["leads"]:
        lead = _object(raw, "source lead")
        expected = make_lead(
            response["provider"],
            query,
            lead.get("url"),
            title=lead.get("title"),
            metadata=lead.get("metadata"),
        )
        if lead != expected:
            raise EvidenceError("provider response lead is malformed or does not match its request")
        leads.append(lead)
    validated = {**response, "leads": leads}
    canonical_json(validated)
    return validated


def _validate_discovery(value: object) -> dict[str, Any]:
    discovery = _object(value, "source discovery")
    required = {"schema_version", "requests", "responses", "leads", "usage"}
    _strict(discovery, required, "source discovery")
    if discovery["schema_version"] != DISCOVERY_SCHEMA:
        raise EvidenceError("source discovery has an unsupported schema version")
    requests = discovery["requests"]
    responses = discovery["responses"]
    if not isinstance(requests, list) or not isinstance(responses, list):
        raise EvidenceError("source discovery requests and responses must be arrays")
    if len(requests) != len(responses):
        raise EvidenceError("source discovery request and response counts differ")
    validated_requests = [validate_request(request) for request in requests]
    validated_responses = [
        _provider_response(response, request)
        for response, request in zip(responses, validated_requests, strict=True)
    ]
    leads = discovery["leads"]
    if not isinstance(leads, list):
        raise EvidenceError("source discovery leads must be an array")
    expected_leads: dict[str, dict[str, Any]] = {}
    for response in validated_responses:
        for lead in response["leads"]:
            expected_leads.setdefault(lead["url"], lead)
    if leads != list(expected_leads.values()):
        raise EvidenceError("source discovery leads do not match its provider responses")
    usage = _object(discovery["usage"], "source discovery usage")
    _strict(usage, {"requests", "leads", "bytes"}, "source discovery usage")
    expected_bytes = sum(
        len(canonical_json(response).encode("utf-8")) for response in validated_responses
    )
    if usage != {
        "requests": len(validated_requests),
        "leads": len(leads),
        "bytes": expected_bytes,
    }:
        raise EvidenceError("source discovery usage does not match its contents")
    return discovery


def discover_sources(
    manifest_path: str | Path,
    payload: dict[str, Any] | None,
    *,
    as_of: str | None = None,
    provider_execute: ProviderExecutor = execute_request,
) -> dict[str, Any]:
    """Run owner query policy through Hound's credential-safe provider boundary."""

    response = invoke_read(manifest_path, "source.discover", payload, as_of=as_of)
    if not response.get("ok") or response.get("outcome") != "completed":
        raise HoundError("source discovery driver did not complete")
    requests, limits = _discovery_spec(response)
    completed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    diagnostics = list(response.get("diagnostics", []))
    with ThreadPoolExecutor(max_workers=min(4, len(requests))) as executor:
        futures = [executor.submit(provider_execute, request) for request in requests]
        for index, (request, future) in enumerate(zip(requests, futures, strict=True)):
            try:
                completed.append((request, _provider_response(future.result(), request)))
            except (ProviderError, EvidenceError) as error:
                diagnostics.append(f"provider request {index + 1} failed: {error}")
    if not completed:
        raise EvidenceError("all source discovery provider requests failed")
    completed_requests = [request for request, _ in completed]
    provider_responses = [provider_response for _, provider_response in completed]

    leads_by_url: dict[str, dict[str, Any]] = {}
    for provider_response in provider_responses:
        for lead in provider_response["leads"]:
            item = _object(lead, "source lead")
            url = item.get("url")
            if not isinstance(url, str) or not url:
                raise EvidenceError("source lead URL must be a non-empty string")
            leads_by_url.setdefault(url, deepcopy(item))
    leads = list(leads_by_url.values())
    byte_count = sum(len(canonical_json(item).encode("utf-8")) for item in provider_responses)
    if len(leads) > limits["max_leads"]:
        raise EvidenceError(f"max_leads exceeded: {len(leads)} > {limits['max_leads']}")
    if byte_count > limits["max_bytes"]:
        raise EvidenceError(f"max_bytes exceeded: {byte_count} > {limits['max_bytes']}")
    data = {
        "schema_version": DISCOVERY_SCHEMA,
        "requests": completed_requests,
        "responses": provider_responses,
        "leads": leads,
        "usage": {
            "requests": len(provider_responses),
            "leads": len(leads),
            "bytes": byte_count,
        },
    }
    return {
        **response,
        "data_schema": DISCOVERY_SCHEMA,
        "data": data,
        "proofs": [
            *response.get("proofs", []),
            {"kind": "provider-boundary", "passed": True},
        ],
        "diagnostics": diagnostics,
    }


def _owner_repo(manifest: dict[str, Any], manifest_path: Path) -> Path:
    raw = Path(manifest["owner"]["repo"])
    return (raw if raw.is_absolute() else manifest_path.parent / raw).resolve()


def _capture_root(manifest_path: str | Path) -> Path:
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    if "capture_root" not in manifest:
        raise EvidenceError("source.capture requires manifest.capture_root")
    repo = _owner_repo(manifest, path)
    root = (repo / manifest["capture_root"]).resolve()
    try:
        root.relative_to(repo)
    except ValueError as error:
        raise EvidenceError("capture_root must remain inside the owner repository") from error
    return root


def _search_results(response: dict[str, Any]) -> list[dict[str, Any]]:
    raw_data = _object(response["raw_data"], "provider raw_data")
    results = raw_data.get("results")
    if not isinstance(results, list):
        data = raw_data.get("data")
        results = data.get("web") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise EvidenceError("provider search response does not contain results")
    return [_object(result, "provider search result") for result in results]


def capture_sources(
    manifest_path: str | Path,
    payload: dict[str, Any],
    *,
    as_of: str | None = None,
    web_fetch: WebFetcher = fetch_web_capture,
) -> dict[str, Any]:
    """Persist owner-selected discovery documents in the kernel capture store."""

    value = _object(payload, "source capture input")
    if value.get("schema_version") != CAPTURE_INPUT_SCHEMA:
        raise EvidenceError("source capture input has an unsupported schema version")
    discovery = _validate_discovery(value.get("discovery"))
    response = invoke_read(manifest_path, "source.capture", payload, as_of=as_of)
    if not response.get("ok") or response.get("outcome") != "completed":
        raise HoundError("source capture driver did not complete")
    if response.get("data_schema") != CAPTURE_SPEC_SCHEMA:
        raise EvidenceError(f"source.capture must return {CAPTURE_SPEC_SCHEMA}")
    spec = _object(response.get("data"), "source capture spec")
    _strict(spec, {"schema_version", "captures"}, "source capture spec")
    if spec["schema_version"] != CAPTURE_SPEC_SCHEMA:
        raise EvidenceError("source capture spec has an unsupported schema version")
    raw_requests = spec["captures"]
    if not isinstance(raw_requests, list):
        raise EvidenceError("source capture captures must be an array")
    capture_requests: list[dict[str, str]] = []
    for raw in raw_requests:
        item = _object(raw, "source capture request")
        _strict(item, {"url", "mode"}, "source capture request")
        url = item["url"]
        mode = item["mode"]
        if not isinstance(url, str) or not url:
            raise EvidenceError("source capture request URL must be a non-empty string")
        if mode not in {"origin", "provider-result"}:
            raise EvidenceError("source capture request mode is unsupported")
        capture_requests.append({"url": url, "mode": mode})
    selected_urls = [item["url"] for item in capture_requests]
    if len(selected_urls) != len(set(selected_urls)):
        raise EvidenceError("source capture requests must contain unique URLs")
    if len(selected_urls) > MAX_SOURCE_CAPTURES:
        raise EvidenceError(
            f"source capture request count exceeds the kernel ceiling {MAX_SOURCE_CAPTURES}"
        )

    available: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
    leads = {
        lead["url"]: lead
        for lead in discovery["leads"]
        if isinstance(lead, dict) and isinstance(lead.get("url"), str)
    }
    for provider_response in discovery["responses"]:
        for document in _search_results(provider_response):
            url = document.get("url")
            if isinstance(url, str) and url in leads:
                available.setdefault(url, (provider_response, document, leads[url]))
    unknown = [url for url in selected_urls if url not in available]
    if unknown:
        raise EvidenceError("source capture selected a URL absent from discovery")

    def prepare_capture(
        capture_request: dict[str, str],
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        WebCapture | None,
        str | None,
    ]:
        url = capture_request["url"]
        provider_response, discovered_document, lead = available[url]
        if capture_request["mode"] == "origin":
            try:
                fetched = web_fetch(
                    url,
                    discovered_document,
                    retrieved_at=provider_response["retrieved_at"],
                )
                return provider_response, discovered_document, lead, fetched, None
            except WebFetchError as error:
                return provider_response, discovered_document, lead, None, str(error)
        document_body = canonical_json(discovered_document).encode("utf-8")
        fetched = WebCapture(
            method=f"{provider_response['provider']}-api",
            body=document_body,
            media_type="application/json",
            document=deepcopy(discovered_document),
            attempts=[
                {
                    "method": f"{provider_response['provider']}-api",
                    "outcome": "captured",
                }
            ],
        )
        return provider_response, discovered_document, lead, fetched, None

    prepared: list[
        tuple[
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            WebCapture | None,
            str | None,
        ]
    ] = []
    if capture_requests:
        with ThreadPoolExecutor(max_workers=min(4, len(capture_requests))) as executor:
            prepared = list(executor.map(prepare_capture, capture_requests))

    root = _capture_root(manifest_path)
    captures: list[dict[str, Any]] = []
    diagnostics = list(response.get("diagnostics", []))
    for capture_request, (provider_response, _discovered, lead, fetched, failure) in zip(
        capture_requests, prepared, strict=True
    ):
        url = capture_request["url"]
        if fetched is None:
            diagnostics.append(f"origin capture failed for {url}: {failure}")
            continue
        document = fetched.document
        document_sha256 = hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
        metadata = {
            "attempts": fetched.attempts,
            "capture_method": fetched.method,
            "discovery_pack": provider_response["pack"],
            "discovery_provider": provider_response["provider"],
            "document_sha256": document_sha256,
            "request_sha256": provider_response["request_sha256"],
            "query": lead.get("query"),
            "rank": _object(lead.get("metadata", {}), "lead metadata").get("rank"),
            **({"title": document["title"]} if isinstance(document.get("title"), str) else {}),
            **(
                {"published_at": document["publishedDate"]}
                if isinstance(document.get("publishedDate"), str)
                else {}
            ),
        }
        manifest = store_capture(
            root,
            provider=fetched.method,
            source_url=url,
            body=fetched.body,
            media_type=fetched.media_type,
            retrieved_at=provider_response["retrieved_at"],
            metadata={key: item for key, item in metadata.items() if item is not None},
        )
        captures.append({"manifest": manifest, "document": document, "lead": lead})
    return {
        **response,
        "data_schema": CAPTURE_SET_SCHEMA,
        "data": {
            "schema_version": CAPTURE_SET_SCHEMA,
            "retrieved_at": discovery["responses"][0]["retrieved_at"],
            "captures": captures,
        },
        "proofs": [
            *response.get("proofs", []),
            {"kind": "immutable-capture-store", "passed": True, "count": len(captures)},
        ],
        "diagnostics": diagnostics,
    }


def _validate_capture_set(manifest_path: str | Path, value: object) -> dict[str, Any]:
    capture_set = _object(value, "source capture set")
    _strict(
        capture_set,
        {"schema_version", "retrieved_at", "captures"},
        "source capture set",
    )
    if capture_set["schema_version"] != CAPTURE_SET_SCHEMA:
        raise EvidenceError("source capture set has an unsupported schema version")
    captures = capture_set["captures"]
    if not isinstance(capture_set["retrieved_at"], str) or not capture_set["retrieved_at"]:
        raise EvidenceError("source capture set retrieved_at must be a non-empty string")
    if not isinstance(captures, list):
        raise EvidenceError("source capture set captures must be an array")
    root = _capture_root(manifest_path)
    for raw in captures:
        entry = _object(raw, "source capture entry")
        _strict(entry, {"manifest", "document", "lead"}, "source capture entry")
        manifest = _object(entry["manifest"], "source capture manifest")
        document = _object(entry["document"], "source capture document")
        metadata = _object(manifest.get("metadata"), "source capture metadata")
        document_sha256 = hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
        if manifest.get("retrieved_at") != capture_set["retrieved_at"]:
            raise EvidenceError("capture retrieval time does not match its capture set")
        if metadata.get("document_sha256") != document_sha256:
            raise EvidenceError("capture document hash does not match its manifest")
        capture_id = manifest.get("capture_id")
        if not isinstance(capture_id, str) or not verify_capture(root, capture_id):
            raise EvidenceError("capture manifest or stored blob is invalid")
    return capture_set


def inspect_sources(
    manifest_path: str | Path,
    payload: dict[str, Any],
    *,
    as_of: str | None = None,
) -> dict[str, Any]:
    """Verify captured bytes before the owner interprets them."""

    value = _object(payload, "source inspect input")
    _validate_capture_set(manifest_path, value.get("capture_set"))
    return invoke_read(manifest_path, "source.inspect", payload, as_of=as_of)


__all__ = ["capture_sources", "discover_sources", "inspect_sources"]
