from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from hound_cli.contracts import canonical_json
from hound_cli.evidence import EvidenceError
from hound_cli.source import capture_sources, discover_sources, inspect_sources
from hound_cli.web import verify_web_run


def _raw(value: object) -> tuple[str, str]:
    body = canonical_json(value).encode("utf-8")
    return base64.b64encode(body).decode("ascii"), hashlib.sha256(body).hexdigest()


def _configure(repo: Path, data: dict[str, object]) -> None:
    (repo / "fake-web-response.json").write_text(
        json.dumps(data, sort_keys=True) + "\n", encoding="utf-8"
    )


def _search_data(query: str = "care workforce") -> dict[str, object]:
    body_base64, sha256 = _raw({"query": query, "results": []})
    return {
        "schema_version": "hound.web.adapter.v1",
        "retrieved_at": "2026-07-21T12:00:00Z",
        "raw": {
            "media_type": "application/json",
            "body_base64": body_base64,
            "sha256": sha256,
        },
        "output": {
            "schema_version": "hound.web.search.v1",
            "trust": "untrusted",
            "evidence_status": "not-evidence",
            "leads": [
                {
                    "schema_version": "hound.lead.v1",
                    "evidence_status": "not-evidence",
                    "provider": "searxng",
                    "query": query,
                    "url": "https://example.test/one",
                    "title": "First result",
                    "metadata": {"engines": ["federal register"], "rank": 1},
                }
            ],
        },
        "usage": {"requests": 1, "bytes": len(base64.b64decode(body_base64))},
    }


def _extract_data(markdown: str = "Verified source document") -> dict[str, object]:
    body_base64, sha256 = _raw({"markdown": markdown})
    return {
        "schema_version": "hound.web.adapter.v1",
        "retrieved_at": "2026-07-21T12:01:00Z",
        "raw": {
            "media_type": "application/json",
            "body_base64": body_base64,
            "sha256": sha256,
        },
        "output": {
            "schema_version": "hound.web.extract.v1",
            "trust": "untrusted",
            "evidence_class": "provider-derived",
            "documents": [
                {
                    "url": "https://example.test/one",
                    "markdown": markdown,
                    "markdown_sha256": hashlib.sha256(markdown.encode()).hexdigest(),
                    "links": [],
                    "metadata": {"publishedDate": "2026-07-20T09:00:00Z"},
                }
            ],
        },
        "usage": {"requests": 1, "bytes": len(base64.b64decode(body_base64))},
    }


def _discover_payload(count: int = 1) -> dict[str, object]:
    return {
        "searches": [
            {
                "adapter": "search",
                "input": {"query": "care workforce", "limit": 2},
            }
            for _ in range(count)
        ],
        "limits": {"max_requests": count, "max_leads": count * 2, "max_bytes": 1_000_000},
    }


def test_discovery_composes_explicit_adapters_into_verified_record_references(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path = driver_repo
    _configure(repo, _search_data())
    monkeypatch.setenv("OWNER_MUST_NOT_SEE", "secret")
    payload = {**_discover_payload(), "forbid_env": "OWNER_MUST_NOT_SEE"}

    result = discover_sources(manifest_path, payload)

    assert result["data_schema"] == "hound.source.discovery.v2"
    discovery = result["data"]
    assert discovery["usage"]["requests"] == 1
    assert discovery["usage"]["leads"] == 1
    reference = discovery["leads"][0]
    assert reference["record_id"] == discovery["records"][0]
    assert reference["lead_id"] == reference["lead"]["lead_id"]
    assert reference["lead"]["evidence_status"] == "not-evidence"
    assert verify_web_run(repo / ".hound" / "web" / reference["record_id"])["valid"] is True
    assert "secret" not in json.dumps(result)


def test_discovery_keeps_duplicate_urls_as_distinct_record_lead_references(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    _configure(repo, _search_data())

    result = discover_sources(manifest_path, _discover_payload(count=2))

    references = result["data"]["leads"]
    assert len(references) == 2
    assert references[0]["lead"]["url"] == references[1]["lead"]["url"]
    assert references[0]["record_id"] != references[1]["record_id"]
    assert len({(reference["record_id"], reference["lead_id"]) for reference in references}) == 2


def test_capture_and_inspect_bind_the_exact_selected_search_lead(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    _configure(repo, _search_data())
    discovery = discover_sources(manifest_path, _discover_payload())["data"]
    selected = discovery["leads"][0]
    _configure(repo, _extract_data())
    capture_input = {
        "schema_version": "hound.source.capture.input.v2",
        "discovery": discovery,
        "owner_input": {
            "captures": [
                {
                    "search_record_id": selected["record_id"],
                    "lead_id": selected["lead_id"],
                    "adapter": "extract",
                }
            ]
        },
    }

    captured = capture_sources(manifest_path, capture_input)

    assert captured["data_schema"] == "hound.source.capture-set.v2"
    reference = captured["data"]["captures"][0]
    assert reference["search_record_id"] == selected["record_id"]
    assert reference["lead_id"] == selected["lead_id"]
    assert verify_web_run(repo / ".hound" / "web" / reference["extract_record_id"])["valid"] is True

    inspected = inspect_sources(
        manifest_path,
        {"capture_set": captured["data"]},
    )

    assert inspected["data_schema"] == "hound.source.capture-set.v2"
    evidence = inspected["data"]["captures"][0]
    assert evidence["capture_id"] == reference["extract_record_id"]
    assert evidence["lead"]["lead_id"] == selected["lead_id"]
    assert evidence["documents"][0]["markdown"] == "Verified source document"


def test_capture_rejects_duplicated_discovery_references(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    _configure(repo, _search_data())
    discovery = discover_sources(manifest_path, _discover_payload())["data"]
    discovery["leads"].append(discovery["leads"][0])
    discovery["usage"]["leads"] += 1

    with pytest.raises(EvidenceError, match="duplicates"):
        capture_sources(
            manifest_path,
            {
                "schema_version": "hound.source.capture.input.v2",
                "discovery": discovery,
                "owner_input": {"captures": []},
            },
        )


def test_capture_rejects_a_lead_reference_absent_from_discovery(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    _configure(repo, _search_data())
    discovery = discover_sources(manifest_path, _discover_payload())["data"]
    _configure(repo, _extract_data())

    with pytest.raises(EvidenceError, match="absent from discovery"):
        capture_sources(
            manifest_path,
            {
                "schema_version": "hound.source.capture.input.v2",
                "discovery": discovery,
                "owner_input": {
                    "captures": [
                        {
                            "search_record_id": "0" * 64,
                            "lead_id": discovery["leads"][0]["lead_id"],
                            "adapter": "extract",
                        }
                    ]
                },
            },
        )


def test_inspection_rejects_tampered_extract_records(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    _configure(repo, _search_data())
    discovery = discover_sources(manifest_path, _discover_payload())["data"]
    selected = discovery["leads"][0]
    _configure(repo, _extract_data())
    captured = capture_sources(
        manifest_path,
        {
            "schema_version": "hound.source.capture.input.v2",
            "discovery": discovery,
            "owner_input": {
                "captures": [
                    {
                        "search_record_id": selected["record_id"],
                        "lead_id": selected["lead_id"],
                        "adapter": "extract",
                    }
                ]
            },
        },
    )["data"]
    extract_id = captured["captures"][0]["extract_record_id"]
    (repo / ".hound" / "web" / extract_id / "raw.bin").write_bytes(b"tampered")

    with pytest.raises(EvidenceError, match="record is invalid"):
        inspect_sources(manifest_path, {"capture_set": captured})


def test_source_limits_fail_closed_before_adapter_execution(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    payload = _discover_payload()
    payload["limits"]["max_requests"] = 33

    with pytest.raises(EvidenceError, match="max_requests"):
        discover_sources(manifest_path, payload)
