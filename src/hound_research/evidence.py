"""Evidence boundaries and immutable capture storage for Hound."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from datetime import datetime
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from hound_cli.runtime import RuntimeErrorHound, write_bytes_create_or_confirm
from hound_cli.safety import public_hostname, secret_key, url_text_safe


LEAD_SCHEMA = "hound.lead.v1"
CAPTURE_SCHEMA = "hound.capture.v1"
_CAPTURE_ID = re.compile(r"[0-9a-f]{64}")


class EvidenceError(ValueError):
    """Raised when evidence would be unsafe, ambiguous, or mutable."""


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a non-empty string")
    return value


def _clean_json(value: object, path: str) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvidenceError(f"{path} keys must be strings")
            if secret_key(key):
                raise EvidenceError(f"{path} contains prohibited secret key {key!r}")
            cleaned[key] = _clean_json(item, f"{path}.{key}")
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_clean_json(item, f"{path}[]") for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise EvidenceError(f"{path} must contain only finite JSON values")


def _clean_metadata(metadata: Mapping[str, object] | None) -> dict[str, Any] | None:
    if metadata is None:
        return None
    if not isinstance(metadata, Mapping):
        raise EvidenceError("metadata must be a mapping")
    return _clean_json(metadata, "metadata")


def _safe_url(value: object, field: str) -> str:
    url = _required_text(value, field)
    if not url_text_safe(url):
        raise EvidenceError(f"{field} is not a valid URL")
    try:
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        fragment = parse_qsl(parsed.fragment, keep_blank_values=True)
        username = parsed.username
        password = parsed.password
        parsed.port
    except ValueError as error:
        raise EvidenceError(f"{field} is not a valid URL") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or not public_hostname(parsed.hostname)
    ):
        raise EvidenceError(f"{field} must be a public HTTP URL")
    if username is not None or password is not None:
        raise EvidenceError(f"{field} must not contain credentials")
    if ";" in parsed.query or ";" in parsed.fragment:
        raise EvidenceError(f"{field} contains ambiguous URL parameters")
    for key, _ in [*query, *fragment]:
        if secret_key(key):
            raise EvidenceError(f"{field} contains a prohibited secret parameter")
    return url


def _retrieval_time(value: object) -> str:
    text = _required_text(value, "retrieved_at")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("retrieved_at must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise EvidenceError("retrieved_at must include a timezone")
    return text


def validate_public_url(value: object, field: str = "url") -> str:
    """Validate and return one public HTTP(S) URL."""

    return _safe_url(value, field)


def make_lead(
    provider: str,
    query: str,
    url: str,
    title: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Create a discovery lead that is explicitly not admissible evidence."""

    lead: dict[str, Any] = {
        "schema_version": LEAD_SCHEMA,
        "evidence_status": "not-evidence",
        "provider": _required_text(provider, "provider"),
        "query": _required_text(query, "query"),
        "url": _safe_url(url, "url"),
    }
    if title is not None:
        if not isinstance(title, str):
            raise EvidenceError("title must be a string")
        lead["title"] = title
    clean_metadata = _clean_metadata(metadata)
    if clean_metadata is not None:
        lead["metadata"] = clean_metadata
    return lead


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _create_or_confirm(path: Path, expected: bytes, kind: str) -> None:
    """Create *path* exclusively, or confirm that its bytes already match."""

    if path.is_symlink():
        raise EvidenceError(f"existing {kind} is a symlink; refusing to follow it")
    try:
        write_bytes_create_or_confirm(path, expected)
    except RuntimeErrorHound as error:
        if path.is_symlink():
            raise EvidenceError(f"existing {kind} is a symlink; refusing to follow it") from error
        if not path.exists():
            raise EvidenceError(f"{kind} cannot be created") from error
        raise EvidenceError(f"existing {kind} differs; refusing to overwrite") from error


def store_capture(
    root: str | os.PathLike[str],
    *,
    provider: str,
    source_url: str,
    body: bytes,
    media_type: str,
    retrieved_at: str,
    metadata: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Store raw response bytes and a create-only capture manifest."""

    if not isinstance(body, bytes):
        raise EvidenceError("body must be bytes")

    clean_metadata = _clean_metadata(metadata)
    digest = hashlib.sha256(body).hexdigest()
    manifest_body: dict[str, Any] = {
        "schema_version": CAPTURE_SCHEMA,
        "sha256": digest,
        "byte_length": len(body),
        "blob": f"blobs/{digest}",
        "provider": _required_text(provider, "provider"),
        "source_url": _safe_url(source_url, "source_url"),
        "media_type": _required_text(media_type, "media_type"),
        "retrieved_at": _retrieval_time(retrieved_at),
    }
    if clean_metadata is not None:
        manifest_body["metadata"] = clean_metadata
    capture_id = hashlib.sha256(_canonical_json(manifest_body)).hexdigest()
    manifest = {**manifest_body, "capture_id": capture_id}

    storage_root = Path(root)
    if storage_root.is_symlink():
        raise EvidenceError("capture storage root must not be a symlink")
    try:
        storage_root.mkdir(parents=True, exist_ok=True)
        storage_root = storage_root.resolve(strict=True)
    except OSError as error:
        raise EvidenceError("capture storage cannot be created") from error
    blob_directory = storage_root / "blobs"
    manifest_directory = storage_root / "manifests"
    if blob_directory.is_symlink() or manifest_directory.is_symlink():
        raise EvidenceError("capture storage directories must not be symlinks")
    try:
        blob_directory.mkdir(parents=True, exist_ok=True)
        manifest_directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise EvidenceError("capture storage cannot be created") from error

    _create_or_confirm(blob_directory / digest, body, "blob")
    _create_or_confirm(
        manifest_directory / f"{capture_id}.json",
        _canonical_json(manifest),
        "manifest",
    )
    return manifest


def verify_capture(root: str | os.PathLike[str], capture_id: str) -> bool:
    """Return whether a capture manifest and its addressed bytes are intact."""

    if not isinstance(capture_id, str) or _CAPTURE_ID.fullmatch(capture_id) is None:
        return False
    storage_root = Path(root)
    manifest_path = storage_root / "manifests" / f"{capture_id}.json"
    if (
        storage_root.is_symlink()
        or (storage_root / "manifests").is_symlink()
        or (storage_root / "blobs").is_symlink()
        or manifest_path.is_symlink()
    ):
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict):
        return False
    required = {
        "schema_version",
        "capture_id",
        "sha256",
        "byte_length",
        "blob",
        "provider",
        "source_url",
        "media_type",
        "retrieved_at",
    }
    optional = {"metadata"}
    if required - manifest.keys() or set(manifest) - required - optional:
        return False
    if manifest.get("schema_version") != CAPTURE_SCHEMA:
        return False
    if manifest.get("capture_id") != capture_id:
        return False
    try:
        _required_text(manifest["provider"], "provider")
        _safe_url(manifest["source_url"], "source_url")
        _required_text(manifest["media_type"], "media_type")
        _retrieval_time(manifest["retrieved_at"])
        if "metadata" in manifest:
            cleaned_metadata = _clean_metadata(manifest["metadata"])
            if cleaned_metadata != manifest["metadata"]:
                return False
    except EvidenceError:
        return False
    manifest_body = {key: value for key, value in manifest.items() if key != "capture_id"}
    if hashlib.sha256(_canonical_json(manifest_body)).hexdigest() != capture_id:
        return False
    blob_digest = manifest.get("sha256")
    if not isinstance(blob_digest, str) or _CAPTURE_ID.fullmatch(blob_digest) is None:
        return False
    if manifest.get("blob") != f"blobs/{blob_digest}":
        return False
    blob_path = storage_root / "blobs" / blob_digest
    if blob_path.is_symlink():
        return False
    try:
        body = blob_path.read_bytes()
    except OSError:
        return False
    byte_length = manifest.get("byte_length")
    if isinstance(byte_length, bool) or not isinstance(byte_length, int):
        return False
    if byte_length != len(body):
        return False
    return hashlib.sha256(body).hexdigest() == blob_digest


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{field} must be a non-negative integer")
    return value


def enforce_budget(
    requests: Iterable[Mapping[str, object]], limits: Mapping[str, object]
) -> dict[str, int]:
    """Validate a request batch against request, URL, and byte ceilings."""

    if isinstance(requests, (str, bytes)):
        raise EvidenceError("requests must be an iterable of mappings")
    try:
        batch = list(requests)
    except TypeError as error:
        raise EvidenceError("requests must be an iterable of mappings") from error
    if not isinstance(limits, Mapping):
        raise EvidenceError("limits must be a mapping")

    url_count = 0
    estimated_bytes = 0
    for request in batch:
        if not isinstance(request, Mapping):
            raise EvidenceError("each request must be a mapping")
        if "url" in request:
            _safe_url(request["url"], "request.url")
            url_count += 1
        if "urls" in request:
            urls = request["urls"]
            if not isinstance(urls, Sequence) or isinstance(urls, (str, bytes)):
                raise EvidenceError("request.urls must be a sequence")
            for url in urls:
                _safe_url(url, "request.urls[]")
                url_count += 1
        if "estimated_bytes" in request:
            estimated_bytes += _nonnegative_integer(
                request["estimated_bytes"], "request.estimated_bytes"
            )

    usage = {
        "requests": len(batch),
        "urls": url_count,
        "estimated_bytes": estimated_bytes,
    }
    for limit_name, usage_name in (
        ("max_requests", "requests"),
        ("max_urls", "urls"),
        ("max_bytes", "estimated_bytes"),
    ):
        if limit_name not in limits:
            continue
        ceiling = _nonnegative_integer(limits[limit_name], limit_name)
        if usage[usage_name] > ceiling:
            raise EvidenceError(f"{limit_name} exceeded: {usage[usage_name]} > {ceiling}")
    return usage


__all__ = [
    "EvidenceError",
    "enforce_budget",
    "make_lead",
    "store_capture",
    "verify_capture",
]
