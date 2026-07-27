from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hound_research.evidence import (
    EvidenceError,
    enforce_budget,
    make_lead,
    store_capture,
    verify_capture,
)


def _capture(root: Path, body: bytes = b"durable evidence") -> dict[str, object]:
    return store_capture(
        root,
        provider="example-search",
        source_url="https://example.test/report",
        body=body,
        media_type="text/plain",
        retrieved_at="2026-07-17T12:00:00Z",
        metadata={"query_rank": 1},
    )


def test_discovery_lead_is_explicitly_not_evidence() -> None:
    lead = make_lead(
        "example-search",
        "caregiving market",
        "https://example.test/result",
        title="A result",
        metadata={"rank": 1},
    )

    assert lead == {
        "schema_version": "hound.lead.v1",
        "evidence_status": "not-evidence",
        "provider": "example-search",
        "query": "caregiving market",
        "url": "https://example.test/result",
        "title": "A result",
        "metadata": {"rank": 1},
    }
    assert "capture_id" not in lead


@pytest.mark.parametrize(
    "url",
    [
        "relative/path",
        "file:///etc/passwd",
        "ftp://example.test/report",
        "https:///missing-host",
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
def test_leads_require_public_http_urls(url: str) -> None:
    with pytest.raises(EvidenceError, match="URL"):
        make_lead("search", "query", url)


def test_capture_requires_timezone_aware_retrieval_time(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="retrieved_at"):
        store_capture(
            tmp_path,
            provider="direct",
            source_url="https://example.test/report",
            body=b"body",
            media_type="text/plain",
            retrieved_at="yesterday",
        )


def test_source_urls_reject_secret_fragments_without_echoing_them() -> None:
    secret = "fragment-secret-value"

    with pytest.raises(EvidenceError) as caught:
        make_lead(
            "search",
            "query",
            f"https://example.test/report#access_token={secret}",
        )

    assert secret not in str(caught.value)


def test_source_urls_reject_ambiguous_semicolon_query_separators() -> None:
    with pytest.raises(EvidenceError):
        make_lead(
            "search",
            "query",
            "https://example.test/report?safe=1;access_token=must-not-land",
        )


@pytest.mark.parametrize(
    "parameter",
    ["X-Amz-Credential", "X-Amz-Signature", "access_key", "private_key", "sig"],
)
def test_source_urls_reject_signed_credential_parameters(parameter: str) -> None:
    secret = "presigned-secret-value"

    with pytest.raises(EvidenceError) as caught:
        make_lead(
            "search",
            "query",
            f"https://example.test/report?{parameter}={secret}",
        )

    assert secret not in str(caught.value)


def test_capture_is_content_addressed_and_idempotent(tmp_path: Path) -> None:
    body = b"same bytes, same identity\n"
    first = _capture(tmp_path, body)
    second = _capture(tmp_path, body)
    digest = hashlib.sha256(body).hexdigest()

    assert first == second
    assert first["schema_version"] == "hound.capture.v1"
    assert len(str(first["capture_id"])) == 64
    assert first["sha256"] == digest
    assert first["byte_length"] == len(body)
    assert first["blob"] == f"blobs/{digest}"
    assert (tmp_path / "blobs" / digest).read_bytes() == body
    assert json.loads(
        (tmp_path / "manifests" / f"{first['capture_id']}.json").read_text(encoding="utf-8")
    ) == first
    assert verify_capture(tmp_path, str(first["capture_id"])) is True


def test_same_bytes_from_distinct_retrievals_keep_distinct_provenance(tmp_path: Path) -> None:
    body = b"shared source body"
    first = _capture(tmp_path, body)
    second = store_capture(
        tmp_path,
        provider="second-provider",
        source_url="https://mirror.example.test/report",
        body=body,
        media_type="text/plain",
        retrieved_at="2026-07-18T12:00:00Z",
    )

    assert first["capture_id"] != second["capture_id"]
    assert first["sha256"] == second["sha256"]
    assert len(list((tmp_path / "blobs").iterdir())) == 1
    assert len(list((tmp_path / "manifests").iterdir())) == 2
    assert verify_capture(tmp_path, str(first["capture_id"])) is True
    assert verify_capture(tmp_path, str(second["capture_id"])) is True


def test_capture_manifest_is_create_only(tmp_path: Path) -> None:
    body = b"one immutable observation"
    original = _capture(tmp_path, body)
    digest = str(original["capture_id"])
    manifest_path = tmp_path / "manifests" / f"{digest}.json"
    manifest_path.write_bytes(b'{"tampered":true}\n')
    tampered_manifest = manifest_path.read_bytes()

    with pytest.raises(EvidenceError, match="manifest"):
        _capture(tmp_path, body)

    assert manifest_path.read_bytes() == tampered_manifest
    assert (tmp_path / "blobs" / str(original["sha256"])).read_bytes() == body


def test_capture_publication_failure_leaves_no_partial_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    def fail_link(_source: Path, _destination: Path) -> None:
        raise OSError("synthetic publication failure")

    monkeypatch.setattr(runtime.os, "link", fail_link)

    with pytest.raises(EvidenceError, match="blob cannot be created"):
        _capture(tmp_path)

    assert list((tmp_path / "blobs").iterdir()) == []
    assert list((tmp_path / "manifests").iterdir()) == []


def test_existing_wrong_blob_is_never_overwritten(tmp_path: Path) -> None:
    intended = b"intended evidence"
    digest = hashlib.sha256(intended).hexdigest()
    blob_path = tmp_path / "blobs" / digest
    blob_path.parent.mkdir(parents=True)
    blob_path.write_bytes(b"unexpected pre-existing bytes")

    with pytest.raises(EvidenceError, match="blob"):
        _capture(tmp_path, intended)

    assert blob_path.read_bytes() == b"unexpected pre-existing bytes"
    assert not (tmp_path / "manifests").exists() or not list((tmp_path / "manifests").iterdir())


def test_capture_store_rejects_symlinked_storage_paths(tmp_path: Path) -> None:
    root = tmp_path / "captures"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "blobs").symlink_to(outside, target_is_directory=True)

    with pytest.raises(EvidenceError, match="symlink"):
        _capture(root, b"must stay contained")

    assert not list(outside.iterdir())


def test_verify_capture_detects_body_tampering(tmp_path: Path) -> None:
    manifest = _capture(tmp_path)
    capture_id = str(manifest["capture_id"])
    (tmp_path / "blobs" / str(manifest["sha256"])).write_bytes(b"tampered")

    assert verify_capture(tmp_path, capture_id) is False
    assert verify_capture(tmp_path, "not-a-capture-id") is False
    assert verify_capture(tmp_path, "0" * 64) is False


@pytest.mark.parametrize("mutation", ["missing-provenance", "unknown-field"])
def test_verify_capture_rejects_self_hashed_malformed_manifest(
    tmp_path: Path, mutation: str
) -> None:
    stored = _capture(tmp_path)
    body = {key: value for key, value in stored.items() if key != "capture_id"}
    if mutation == "missing-provenance":
        for key in ("provider", "source_url", "media_type", "retrieved_at"):
            body.pop(key)
    else:
        body["unexpected"] = True
    encoded_body = (
        json.dumps(body, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    capture_id = hashlib.sha256(encoded_body).hexdigest()
    malformed = {**body, "capture_id": capture_id}
    (tmp_path / "manifests" / f"{capture_id}.json").write_text(
        json.dumps(malformed, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert verify_capture(tmp_path, capture_id) is False


@pytest.mark.parametrize(
    "metadata",
    [
        {"api_key": "should-never-land"},
        {"Authorization": "Bearer should-never-land"},
        {"nested": {"access-token": "should-never-land"}},
        {"items": [{"token": "should-never-land"}]},
        {"credentials": "should-never-land"},
        {"X-Amz-Signature": "should-never-land"},
        {"private_key": "should-never-land"},
    ],
)
def test_secret_bearing_metadata_is_rejected_without_leaking_value(
    tmp_path: Path, metadata: dict[str, object]
) -> None:
    with pytest.raises(EvidenceError) as lead_error:
        make_lead(
            "example-search",
            "query",
            "https://example.test/result",
            metadata=metadata,
        )
    assert "should-never-land" not in str(lead_error.value)

    with pytest.raises(EvidenceError) as capture_error:
        store_capture(
            tmp_path,
            provider="example-search",
            source_url="https://example.test/report",
            body=b"body",
            media_type="text/plain",
            retrieved_at="2026-07-17T12:00:00Z",
            metadata=metadata,
        )
    assert "should-never-land" not in str(capture_error.value)
    assert not tmp_path.exists() or list(tmp_path.iterdir()) == []


def test_enforce_budget_reports_usage_within_limits() -> None:
    usage = enforce_budget(
        [
            {"url": "https://example.test/one", "estimated_bytes": 7},
            {
                "urls": [
                    "https://example.test/two",
                    "https://example.test/three",
                ],
                "estimated_bytes": 4,
            },
        ],
        {"max_requests": 2, "max_urls": 3, "max_bytes": 11},
    )

    assert usage == {"requests": 2, "urls": 3, "estimated_bytes": 11}


@pytest.mark.parametrize(
    ("limits", "message"),
    [
        ({"max_requests": 1, "max_urls": 3}, "max_requests"),
        ({"max_requests": 2, "max_urls": 2}, "max_urls"),
        (
            {"max_requests": 2, "max_urls": 3, "max_bytes": 10},
            "max_bytes",
        ),
    ],
)
def test_enforce_budget_rejects_limit_overruns(
    limits: dict[str, int], message: str
) -> None:
    requests = [
        {"url": "https://example.test/one", "estimated_bytes": 7},
        {
            "urls": [
                "https://example.test/two",
                "https://example.test/three",
            ],
            "estimated_bytes": 4,
        },
    ]

    with pytest.raises(EvidenceError, match=message):
        enforce_budget(requests, limits)
