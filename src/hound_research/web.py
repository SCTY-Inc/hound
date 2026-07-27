"""Provider-neutral web operations with immutable provenance records."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hound_cli.contracts import canonical_hash, canonical_json, load_manifest
from hound_cli.orchestrator import HoundError, invoke_read_with_receipt
from hound_cli.runtime import kernel_identity, write_bytes_create_or_confirm

from .evidence import EvidenceError, make_lead, validate_public_url

try:
    import fcntl
except ImportError:  # pragma: no cover - Hound web budgets require POSIX
    fcntl = None


ADAPTER_SCHEMA = "hound.web.adapter.v1"
SEARCH_SCHEMA = "hound.web.search.v1"
SEARCH_RECORD_SCHEMA = "hound.web.search.v2"
EXTRACT_SCHEMA = "hound.web.extract.v1"
INTERACT_SCHEMA = "hound.web.interact.v1"
REQUEST_SCHEMA = "hound.web.request.v1"
RECORD_SCHEMA = "hound.web.record.v1"
INDEX_SCHEMA = "hound.web.run.index.v1"
MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_SEARCH_LEADS = 50
MAX_SEARCH_OPTIONS_BYTES = 64 * 1024
MAX_EXTRACT_PAGES = 20
MAX_PROVIDER_REQUESTS = 64
MAX_INTERACT_TEXT = 10_000
MAX_INTERACT_ACTIONS = 30
MAX_INTERACT_SECONDS = 5 * 60
MAX_CONTEXT_TEXT = 12_000
MAX_CONTEXT_LINKS = 100
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class WebError(HoundError):
    """A web capability or provenance record is invalid."""


def _strict(value: object, required: set[str], optional: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebError(f"{label} must be an object", exit_code=2)
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing fields {sorted(missing)!r}")
        if unknown:
            details.append(f"unknown fields {sorted(unknown)!r}")
        raise WebError(f"{label} has {' and '.join(details)}", exit_code=2)
    return value


def _text(value: object, label: str, *, maximum: int = 10_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WebError(f"{label} must be a non-empty string", exit_code=2)
    if len(value) > maximum or any(ord(char) < 32 and char not in "\n\r\t" for char in value):
        raise WebError(f"{label} is invalid or too long", exit_code=2)
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise WebError(f"{label} must be an identifier", exit_code=2)
    return value


def _integer(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise WebError(f"{label} must be an integer from {minimum} through {maximum}", exit_code=2)
    return value


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, maximum=128)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise WebError(f"{label} must be an ISO 8601 timestamp", exit_code=2) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WebError(f"{label} must include a timezone", exit_code=2)
    return text


def _canonical_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _lineage(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise WebError("extract input.lineage must be an object", exit_code=2)
    kind = value.get("kind")
    if kind == "direct":
        _strict(value, {"kind"}, set(), "extract direct lineage")
        return {"kind": "direct"}
    lineage = _strict(
        value,
        {"kind", "record_id", "lead_id"},
        set(),
        "extract search lineage",
    )
    if lineage["kind"] != "search":
        raise WebError("extract input.lineage kind must be direct or search", exit_code=2)
    for field in ("record_id", "lead_id"):
        if not isinstance(lineage[field], str) or _SHA256.fullmatch(lineage[field]) is None:
            raise WebError(f"extract input.lineage {field} is invalid", exit_code=2)
    return dict(lineage)


def validate_web_input(verb: str, payload: object) -> dict[str, Any]:
    if verb == "search":
        value = _strict(payload, {"query"}, {"limit", "options"}, "search input")
        normalized = {
            "query": _text(value["query"], "search input.query"),
            "limit": _integer(value.get("limit", 10), "search input.limit", minimum=1, maximum=50),
        }
        if "options" in value:
            options = value["options"]
            if not isinstance(options, dict):
                raise WebError("search input.options must be an object", exit_code=2)
            if len(canonical_json(options).encode("utf-8")) > MAX_SEARCH_OPTIONS_BYTES:
                raise WebError("search input.options is too large", exit_code=2)
            normalized["options"] = deepcopy(options)
        return normalized
    if verb == "extract":
        value = _strict(payload, {"url", "lineage"}, {"max_pages"}, "extract input")
        normalized: dict[str, Any] = {
            "url": validate_public_url(value["url"], "extract input.url"),
            "lineage": _lineage(value["lineage"]),
        }
        if "max_pages" in value:
            normalized["max_pages"] = _integer(
                value["max_pages"], "extract input.max_pages", minimum=2, maximum=MAX_EXTRACT_PAGES
            )
        return normalized
    if verb != "interact":
        raise WebError("web verb must be search, extract, or interact", exit_code=2)

    if not isinstance(payload, dict):
        raise WebError("interact input must be an object", exit_code=2)
    action = payload.get("action")
    common = {"action", "session_id", "tab_id"}
    if action == "open":
        value = _strict(payload, {"action", "url"}, set(), "interact open input")
        return {
            "action": "open",
            "url": validate_public_url(value["url"], "interact input.url"),
        }
    if action == "snapshot":
        value = _strict(
            payload,
            common,
            {"offset", "include_screenshot"},
            "interact snapshot input",
        )
        normalized = {
            "action": "snapshot",
            "session_id": _identifier(value["session_id"], "interact input.session_id"),
            "tab_id": _identifier(value["tab_id"], "interact input.tab_id"),
            "include_screenshot": value.get("include_screenshot", False),
        }
        if not isinstance(normalized["include_screenshot"], bool):
            raise WebError("interact input.include_screenshot must be a boolean", exit_code=2)
        if "offset" in value:
            normalized["offset"] = _integer(
                value["offset"], "interact input.offset", minimum=0, maximum=1_000_000
            )
        return normalized
    if action == "click":
        value = _strict(payload, common | {"ref"}, set(), "interact click input")
        return {
            "action": "click",
            "session_id": _identifier(value["session_id"], "interact input.session_id"),
            "tab_id": _identifier(value["tab_id"], "interact input.tab_id"),
            "ref": _identifier(value["ref"], "interact input.ref"),
        }
    if action == "type":
        value = _strict(payload, common | {"ref", "text"}, set(), "interact type input")
        return {
            "action": "type",
            "session_id": _identifier(value["session_id"], "interact input.session_id"),
            "tab_id": _identifier(value["tab_id"], "interact input.tab_id"),
            "ref": _identifier(value["ref"], "interact input.ref"),
            "text": _text(value["text"], "interact input.text", maximum=MAX_INTERACT_TEXT),
        }
    if action == "scroll":
        value = _strict(payload, common, {"direction", "amount"}, "interact scroll input")
        direction = value.get("direction", "down")
        if direction not in {"up", "down"}:
            raise WebError("interact input.direction must be up or down", exit_code=2)
        return {
            "action": "scroll",
            "session_id": _identifier(value["session_id"], "interact input.session_id"),
            "tab_id": _identifier(value["tab_id"], "interact input.tab_id"),
            "direction": direction,
            "amount": _integer(
                value.get("amount", 500), "interact input.amount", minimum=1, maximum=5_000
            ),
        }
    if action == "close":
        value = _strict(payload, {"action", "session_id"}, set(), "interact close input")
        return {
            "action": "close",
            "session_id": _identifier(value["session_id"], "interact input.session_id"),
        }
    raise WebError("interact input.action is unsupported", exit_code=2)


def _search_text_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 50:
        raise WebError(f"{label} must be an array of at most 50 strings", exit_code=2)
    return [_text(item, f"{label} item", maximum=1_000) for item in value]


def _validate_search_routing(value: object) -> dict[str, Any]:
    routing = _strict(
        value,
        {
            "completed_pages",
            "config_sha256",
            "corrections",
            "requested_categories",
            "requested_engines",
            "suggestions",
            "unresponsive_engines",
        },
        set(),
        "search output.routing",
    )
    if (
        not isinstance(routing["config_sha256"], str)
        or _SHA256.fullmatch(routing["config_sha256"]) is None
    ):
        raise WebError("search output.routing config_sha256 is invalid", exit_code=2)
    failures = routing["unresponsive_engines"]
    if not isinstance(failures, list) or len(failures) > 50:
        raise WebError("search output.routing unresponsive_engines is invalid", exit_code=2)
    normalized_failures: list[dict[str, str]] = []
    for item in failures:
        failure = _strict(item, {"engine", "error"}, set(), "unresponsive engine")
        normalized_failures.append(
            {
                "engine": _text(failure["engine"], "unresponsive engine name", maximum=200),
                "error": _text(failure["error"], "unresponsive engine error", maximum=1_000),
            }
        )
    return {
        "completed_pages": _integer(
            routing["completed_pages"],
            "search output.routing completed_pages",
            minimum=1,
            maximum=64,
        ),
        "config_sha256": routing["config_sha256"],
        "corrections": _search_text_list(
            routing["corrections"], "search output.routing corrections"
        ),
        "requested_categories": _search_text_list(
            routing["requested_categories"], "search output.routing requested_categories"
        ),
        "requested_engines": _search_text_list(
            routing["requested_engines"], "search output.routing requested_engines"
        ),
        "suggestions": _search_text_list(
            routing["suggestions"], "search output.routing suggestions"
        ),
        "unresponsive_engines": normalized_failures,
    }


def _validate_search_output(output: object, request: dict[str, Any]) -> dict[str, Any]:
    value = _strict(
        output,
        {"schema_version", "trust", "evidence_status", "leads"},
        {"routing"},
        "search output",
    )
    if (
        value["schema_version"] != SEARCH_SCHEMA
        or value["trust"] != "untrusted"
        or value["evidence_status"] != "not-evidence"
    ):
        raise WebError("search output has invalid schema or trust classification", exit_code=2)
    leads = value["leads"]
    if not isinstance(leads, list) or len(leads) > request["limit"]:
        raise WebError("search output exceeds the requested lead limit", exit_code=2)
    validated: list[dict[str, Any]] = []
    for rank, lead in enumerate(leads, start=1):
        if not isinstance(lead, dict):
            raise WebError("search output lead must be an object", exit_code=2)
        try:
            expected = make_lead(
                lead.get("provider"),
                lead.get("query"),
                lead.get("url"),
                title=lead.get("title"),
                metadata=lead.get("metadata"),
            )
        except EvidenceError as error:
            raise WebError(str(error), exit_code=2) from error
        if lead != expected or lead.get("query") != request["query"]:
            raise WebError("search output lead does not match its request", exit_code=2)
        validated.append(
            {
                **expected,
                "schema_version": "hound.lead.v2",
                "lead_id": canonical_hash({"request": request, "rank": rank, "lead": expected}),
            }
        )
    normalized = {**value, "schema_version": SEARCH_RECORD_SCHEMA, "leads": validated}
    if "routing" in value:
        normalized["routing"] = _validate_search_routing(value["routing"])
    return normalized


def _validate_extract_output(output: object, request: dict[str, Any]) -> dict[str, Any]:
    value = _strict(
        output,
        {"schema_version", "trust", "evidence_class", "documents"},
        set(),
        "extract output",
    )
    if (
        value["schema_version"] != EXTRACT_SCHEMA
        or value["trust"] != "untrusted"
        or value["evidence_class"] != "provider-derived"
    ):
        raise WebError("extract output has invalid schema or evidence class", exit_code=2)
    documents = value["documents"]
    ceiling = request.get("max_pages", 1)
    if not isinstance(documents, list) or len(documents) > ceiling:
        raise WebError("extract output exceeds the requested page limit", exit_code=2)
    validated: list[dict[str, Any]] = []
    for raw in documents:
        document = _strict(
            raw,
            {"url", "markdown", "markdown_sha256", "links", "metadata"},
            set(),
            "extract document",
        )
        url = validate_public_url(document["url"], "extract document.url")
        markdown = _text(document["markdown"], "extract document.markdown", maximum=MAX_RAW_BYTES)
        if _sha256(markdown.encode("utf-8")) != document["markdown_sha256"]:
            raise WebError("extract document markdown sha256 does not match", exit_code=2)
        links = document["links"]
        if not isinstance(links, list):
            raise WebError("extract document.links must be a list", exit_code=2)
        safe_links = [validate_public_url(link, "extract document link") for link in links]
        if not isinstance(document["metadata"], dict):
            raise WebError("extract document.metadata must be an object", exit_code=2)
        canonical_json(document["metadata"])
        validated.append({**document, "url": url, "links": safe_links})
    return {**value, "documents": validated}


def _validate_interact_output(output: object, request: dict[str, Any]) -> dict[str, Any]:
    value = _strict(
        output,
        {"schema_version", "trust", "evidence_class", "action", "session_id", "result"},
        set(),
        "interact output",
    )
    if (
        value["schema_version"] != INTERACT_SCHEMA
        or value["trust"] != "untrusted"
        or value["evidence_class"] != "provider-derived"
        or value["action"] != request["action"]
    ):
        raise WebError("interact output has invalid schema, action, or evidence class", exit_code=2)
    session_id = _identifier(value["session_id"], "interact output.session_id")
    if request["action"] != "open" and session_id != request["session_id"]:
        raise WebError("interact output session does not match its request", exit_code=2)
    if not isinstance(value["result"], dict):
        raise WebError("interact output.result must be an object", exit_code=2)
    canonical_json(value["result"])
    return {**value, "session_id": session_id}


def _validate_adapter_data(
    data: object, verb: str, request: dict[str, Any]
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    value = _strict(
        data,
        {"schema_version", "retrieved_at", "raw", "output", "usage"},
        set(),
        "adapter data",
    )
    if value["schema_version"] != ADAPTER_SCHEMA:
        raise WebError(f"adapter data schema must be {ADAPTER_SCHEMA}", exit_code=2)
    retrieved_at = _timestamp(value["retrieved_at"], "adapter data.retrieved_at")
    raw = _strict(
        value["raw"],
        {"media_type", "body_base64", "sha256"},
        set(),
        "adapter data.raw",
    )
    media_type = _text(raw["media_type"], "adapter data.raw.media_type", maximum=256)
    if not isinstance(raw["body_base64"], str):
        raise WebError("adapter data.raw.body_base64 must be a string", exit_code=2)
    try:
        raw_bytes = base64.b64decode(raw["body_base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise WebError("adapter data.raw.body_base64 is malformed", exit_code=2) from error
    if len(raw_bytes) > MAX_RAW_BYTES:
        raise WebError("adapter raw body exceeds the byte ceiling", exit_code=2)
    if not isinstance(raw["sha256"], str) or _SHA256.fullmatch(raw["sha256"]) is None:
        raise WebError("adapter raw sha256 is malformed", exit_code=2)
    if _sha256(raw_bytes) != raw["sha256"]:
        raise WebError("adapter raw sha256 does not match its body", exit_code=2)
    usage = _strict(value["usage"], {"requests", "bytes"}, set(), "adapter data.usage")
    requests = _integer(
        usage["requests"], "adapter data.usage.requests", minimum=1, maximum=MAX_PROVIDER_REQUESTS
    )
    if usage["bytes"] != len(raw_bytes):
        raise WebError("adapter usage bytes do not match its raw body", exit_code=2)
    if verb == "search":
        output = _validate_search_output(value["output"], request)
    elif verb == "extract":
        output = _validate_extract_output(value["output"], request)
    else:
        output = _validate_interact_output(value["output"], request)
    return (
        raw_bytes,
        output,
        {
            "retrieved_at": retrieved_at,
            "media_type": media_type,
            "usage": {"requests": requests, "bytes": len(raw_bytes)},
        },
    )


def _recover_adapter_raw(data: object) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("raw"), dict):
        return b"", {
            "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "media_type": "application/octet-stream",
            "usage": {"requests": 0, "bytes": 0},
        }
    raw = data["raw"]
    encoded = raw.get("body_base64")
    if not isinstance(encoded, str):
        raise WebError("adapter raw body is unavailable", exit_code=2)
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise WebError("adapter raw body is malformed", exit_code=2) from error
    if len(payload) > MAX_RAW_BYTES:
        raise WebError("adapter raw body exceeds the byte ceiling", exit_code=2)
    usage = data.get("usage", {})
    requests = usage.get("requests", 0) if isinstance(usage, dict) else 0
    if (
        isinstance(requests, bool)
        or not isinstance(requests, int)
        or not 0 <= requests <= MAX_PROVIDER_REQUESTS
    ):
        requests = 0
    retrieved = data.get("retrieved_at")
    try:
        retrieved_at = _timestamp(retrieved, "adapter retrieved_at")
    except WebError:
        retrieved_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    media_type = raw.get("media_type")
    if not isinstance(media_type, str) or not media_type:
        media_type = "application/octet-stream"
    return payload, {
        "retrieved_at": retrieved_at,
        "media_type": media_type,
        "usage": {"requests": requests, "bytes": len(payload)},
    }


def _validate_failure_adapter_data(
    data: object,
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    value = _strict(
        data,
        {"schema_version", "retrieved_at", "raw", "output", "usage"},
        set(),
        "failed adapter data",
    )
    if value["schema_version"] != ADAPTER_SCHEMA:
        raise WebError("failed adapter data has an invalid schema", exit_code=2)
    raw = _strict(
        value["raw"],
        {"media_type", "body_base64", "sha256"},
        set(),
        "failed adapter raw",
    )
    if not isinstance(raw["body_base64"], str):
        raise WebError("failed adapter raw body must be base64", exit_code=2)
    try:
        raw_bytes = base64.b64decode(raw["body_base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise WebError("failed adapter raw body is malformed", exit_code=2) from error
    if len(raw_bytes) > MAX_RAW_BYTES or _sha256(raw_bytes) != raw["sha256"]:
        raise WebError("failed adapter raw body hash does not match", exit_code=2)
    output = _strict(
        value["output"],
        {"schema_version", "trust", "error"},
        set(),
        "failed adapter output",
    )
    if output["schema_version"] != "hound.web.failure.v1" or output["trust"] != "untrusted":
        raise WebError("failed adapter output has an invalid schema", exit_code=2)
    _text(output["error"], "failed adapter output.error")
    usage = _strict(value["usage"], {"requests", "bytes"}, set(), "failed adapter usage")
    requests = _integer(
        usage["requests"], "failed adapter usage.requests", minimum=0, maximum=MAX_PROVIDER_REQUESTS
    )
    if usage["bytes"] != len(raw_bytes):
        raise WebError("failed adapter usage bytes do not match", exit_code=2)
    return (
        raw_bytes,
        output,
        {
            "retrieved_at": _timestamp(value["retrieved_at"], "failed adapter retrieved_at"),
            "media_type": _text(raw["media_type"], "failed adapter raw.media_type", maximum=256),
            "usage": {"requests": requests, "bytes": len(raw_bytes)},
        },
    )


def _decoded_adapter_outputs(response: dict[str, Any]) -> list[bytes]:
    decoded: list[bytes] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and key.endswith("_base64") and isinstance(item, str):
                    try:
                        payload = base64.b64decode(item, validate=True)
                    except (binascii.Error, ValueError):
                        pass
                    else:
                        decoded.append(payload)
                        try:
                            visit(json.loads(payload))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            pass
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(response)
    return decoded


def _adapter_state(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "hound.web.adapter-state.v2",
        "manifest_sha256": receipt["manifest_sha256"],
        "repository": receipt["repository"],
        "environment_sha256": receipt["environment_sha256"],
        "kernel": receipt["kernel"],
    }


def _failed_adapter_state(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "hound.web.adapter-state.v2",
        "manifest_sha256": canonical_hash(manifest),
        "repository": None,
        "environment_sha256": None,
        "kernel": kernel_identity(),
    }


def _persist_record(
    root: Path,
    *,
    verb: str,
    manifest: dict[str, Any],
    state: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    raw: bytes,
    output: dict[str, Any],
    outcome: str,
    retrieved_at: str,
    recorded_at: str,
    media_type: str,
    usage: dict[str, int],
    error: str | None,
) -> tuple[str, Path]:
    if root.is_symlink():
        raise WebError("web record root must not be a symlink", exit_code=2)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    if root.is_symlink():
        raise WebError("web record root must not be a symlink", exit_code=2)

    files = {
        "adapter-manifest.json": _canonical_bytes(manifest),
        "adapter-state.json": _canonical_bytes(state),
        "request.json": _canonical_bytes(request),
        "adapter-response.json": _canonical_bytes(response),
        "raw.bin": raw,
        "output.json": _canonical_bytes(output),
    }
    evidence_status = (
        "not-evidence"
        if verb == "search" and outcome == "completed"
        else ("provider-derived" if outcome == "completed" else "none")
    )
    body: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA,
        "operation": verb,
        "outcome": outcome,
        "adapter_id": manifest["id"],
        "retrieved_at": retrieved_at,
        "recorded_at": recorded_at,
        "evidence_status": evidence_status,
        "media_type": media_type,
        "usage": usage,
        "files": {name: _sha256(payload) for name, payload in sorted(files.items())},
    }
    if error is not None:
        body["error"] = error
    record_id = canonical_hash(body)
    record = {**body, "record_id": record_id}
    files["record.json"] = _canonical_bytes(record)
    index = {
        "schema_version": INDEX_SCHEMA,
        "record_id": record_id,
        "files": {name: _sha256(payload) for name, payload in sorted(files.items())},
    }

    temporary = Path(tempfile.mkdtemp(prefix=".hound-web-", dir=root))
    final = root / record_id
    try:
        for name, payload in files.items():
            write_bytes_create_or_confirm(temporary / name, payload)
        write_bytes_create_or_confirm(temporary / "index.json", _canonical_bytes(index))
        try:
            os.rename(temporary, final)
        except FileExistsError:
            shutil.rmtree(temporary)
            verified = verify_web_run(final)
            if not verified["valid"]:
                raise WebError("existing web record is invalid", exit_code=2)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return record_id, final


@contextmanager
def _record_lock(root: Path) -> Iterator[Path]:
    if fcntl is None:
        raise WebError("web record locking is unavailable", exit_code=2)
    if root.is_symlink():
        raise WebError("web record root must not be a symlink", exit_code=2)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    lock_path = root / ".hound-web.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield root
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _interaction_budget(root: Path, request: dict[str, Any], recorded_at: str) -> None:
    if request["action"] in {"open", "close"}:
        return
    session_id = request["session_id"]
    count = 0
    opened_at: datetime | None = None
    for child in root.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        try:
            stored_request = json.loads((child / "request.json").read_text(encoding="utf-8"))
            if stored_request.get("operation") != "interact":
                continue
            stored_input = stored_request["input"]
            record = json.loads((child / "record.json").read_text(encoding="utf-8"))
            if stored_input.get("action") == "open":
                output = json.loads((child / "output.json").read_text(encoding="utf-8"))
                stored_session = output.get("session_id")
            else:
                stored_session = stored_input.get("session_id")
            if stored_session != session_id:
                continue
            count += 1
            timestamp = datetime.fromisoformat(record["recorded_at"].replace("Z", "+00:00"))
            opened_at = timestamp if opened_at is None else min(opened_at, timestamp)
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            raise WebError(
                "cannot establish browser action budget from existing records", exit_code=2
            )
    if opened_at is None:
        raise WebError("browser session has no open provenance record", exit_code=2)
    if count >= MAX_INTERACT_ACTIONS:
        raise WebError("browser session action budget exhausted", exit_code=2)
    now = datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
    if (now - opened_at).total_seconds() > MAX_INTERACT_SECONDS:
        raise WebError("browser session time budget exhausted", exit_code=2)


def _validate_extract_lineage(root: Path, request: dict[str, Any]) -> None:
    lineage = request["lineage"]
    if lineage["kind"] == "direct":
        return
    parent = root / lineage["record_id"]
    verification = verify_web_run(parent)
    if not verification["valid"]:
        raise WebError("extract search lineage record is invalid", exit_code=2)
    try:
        record = json.loads((parent / "record.json").read_text(encoding="utf-8"))
        output = json.loads((parent / "output.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise WebError("extract search lineage record is unreadable", exit_code=2) from None
    if record.get("operation") != "search":
        raise WebError("extract lineage parent is not a search record", exit_code=2)
    matches = [
        lead
        for lead in output.get("leads", [])
        if isinstance(lead, dict) and lead.get("lead_id") == lineage["lead_id"]
    ]
    if len(matches) != 1 or matches[0].get("url") != request["url"]:
        raise WebError("extract search lineage lead does not match its URL", exit_code=2)


def _context_view(
    verb: str, output: dict[str, Any], *, record_id: str | None = None
) -> dict[str, Any]:
    view = deepcopy(output)
    if verb == "search" and record_id is not None:
        for lead in view.get("leads", []):
            lead["search_record_id"] = record_id
    elif verb == "extract":
        for document in view.get("documents", []):
            markdown = document.get("markdown")
            if isinstance(markdown, str) and len(markdown) > MAX_CONTEXT_TEXT:
                document["markdown"] = markdown[:MAX_CONTEXT_TEXT]
                document["markdown_truncated"] = True
                document["markdown_total_chars"] = len(markdown)
            links = document.get("links")
            if isinstance(links, list) and len(links) > MAX_CONTEXT_LINKS:
                document["links"] = links[:MAX_CONTEXT_LINKS]
                document["links_truncated"] = True
                document["links_total"] = len(links)
    elif verb == "interact":
        result = view.get("result", {})
        snapshot = result.get("snapshot") if isinstance(result, dict) else None
        if isinstance(snapshot, str) and len(snapshot) > MAX_CONTEXT_TEXT:
            result["snapshot"] = snapshot[:MAX_CONTEXT_TEXT]
            result["snapshot_truncated_by_hound"] = True
            result["snapshot_total_chars"] = len(snapshot)
        if isinstance(result, dict) and "screenshot_base64" in result:
            result.pop("screenshot_base64")
            result["screenshot_omitted_from_context"] = True
    return view


def _run_web_locked(
    path: Path,
    manifest: dict[str, Any],
    verb: str,
    normalized: dict[str, Any],
    root: Path,
    as_of: str | None,
) -> dict[str, Any]:
    operation = f"web.{verb}"
    state = _failed_adapter_state(manifest)
    request: dict[str, Any] = {
        "schema_version": REQUEST_SCHEMA,
        "operation": verb,
        "input": normalized,
    }
    if as_of is not None:
        request["as_of"] = as_of
    recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if verb == "extract":
        _validate_extract_lineage(root, normalized)
    elif verb == "interact":
        _interaction_budget(root, normalized, recorded_at)

    response: dict[str, Any]
    error: str | None = None
    try:
        response, receipt = invoke_read_with_receipt(
            path,
            operation,
            normalized,
            as_of=as_of,
            decoded_outputs=_decoded_adapter_outputs,
        )
        manifest = receipt["manifest"]
        state = _adapter_state(receipt)
    except Exception as caught:
        error = str(caught)
        response = {"schema_version": "hound.web.adapter-error.v1", "error": error}

    raw = b""
    output: dict[str, Any] = {
        "schema_version": "hound.web.failure.v1",
        "trust": "untrusted",
    }
    retrieved_at = recorded_at
    media_type = "application/octet-stream"
    usage = {"requests": 0, "bytes": 0}
    if error is None:
        if not response.get("ok") or response.get("outcome") != "completed":
            error = f"adapter reported failure: {canonical_json(response.get('diagnostics', []))}"
            if response.get("data_schema") == ADAPTER_SCHEMA:
                try:
                    raw, output, metadata = _validate_failure_adapter_data(response.get("data"))
                    retrieved_at = metadata["retrieved_at"]
                    media_type = metadata["media_type"]
                    usage = metadata["usage"]
                except Exception as caught:
                    error = f"{error}; invalid failure provenance: {caught}"
        elif response.get("data_schema") != ADAPTER_SCHEMA:
            error = f"adapter response data_schema must be {ADAPTER_SCHEMA}"
        else:
            try:
                raw, output, metadata = _validate_adapter_data(
                    response.get("data"), verb, normalized
                )
                retrieved_at = metadata["retrieved_at"]
                media_type = metadata["media_type"]
                usage = metadata["usage"]
            except Exception as caught:
                error = str(caught)
                try:
                    raw, metadata = _recover_adapter_raw(response.get("data"))
                    retrieved_at = metadata["retrieved_at"]
                    media_type = metadata["media_type"]
                    usage = metadata["usage"]
                except WebError as recovery_error:
                    error = f"{error}; raw recovery failed: {recovery_error}"
                output = {
                    "schema_version": "hound.web.failure.v1",
                    "trust": "untrusted",
                    "error": error,
                }

    outcome = "completed" if error is None else "failed"
    record_id, run_dir = _persist_record(
        root,
        verb=verb,
        manifest=manifest,
        state=state,
        request=request,
        response=response,
        raw=raw,
        output=output,
        outcome=outcome,
        retrieved_at=retrieved_at,
        recorded_at=recorded_at,
        media_type=media_type,
        usage=usage,
        error=error,
    )
    result: dict[str, Any] = {
        "schema_version": "hound.web.invocation.v1",
        "ok": error is None,
        "outcome": outcome,
        "operation": verb,
        "record_id": record_id,
        "run_dir": str(run_dir),
        "evidence_status": (
            "not-evidence"
            if verb == "search" and error is None
            else ("provider-derived" if error is None else "none")
        ),
        "data": _context_view(verb, output, record_id=record_id),
        "output_path": str(run_dir / "output.json"),
    }
    if error is not None:
        result["error"] = error
    return result


def run_web(
    manifest_path: str | Path,
    verb: str,
    payload: object,
    *,
    record_root: str | Path = ".hound/web",
    as_of: str | None = None,
) -> dict[str, Any]:
    normalized = validate_web_input(verb, payload)
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    with _record_lock(Path(record_root)) as root:
        return _run_web_locked(path, manifest, verb, normalized, root, as_of)


def verify_web_run(run_dir: str | Path) -> dict[str, Any]:
    supplied_root = Path(run_dir)
    root = supplied_root.resolve()
    failures: list[str] = []

    def fail(label: str) -> None:
        if label not in failures:
            failures.append(label)

    if supplied_root.is_symlink():
        fail("run_dir")
    if (root / "index.json").is_symlink():
        fail("index.json")
    try:
        index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        index = {}
        fail("index.json")
    expected = {
        "adapter-manifest.json",
        "adapter-state.json",
        "request.json",
        "adapter-response.json",
        "raw.bin",
        "output.json",
        "record.json",
    }
    if index.get("schema_version") != INDEX_SCHEMA or set(index.get("files", {})) != expected:
        fail("index.files")
    try:
        actual = {entry.name for entry in root.iterdir()}
    except OSError:
        actual = set()
        fail("run_dir")
    if actual != expected | {"index.json"}:
        fail("index.files")
    indexed = index.get("files", {}) if isinstance(index.get("files"), dict) else {}
    for name in expected:
        path = root / name
        if path.is_symlink():
            fail(name)
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            fail(name)
            continue
        if indexed.get(name) != _sha256(payload):
            fail(name)

    record: dict[str, Any] = {}
    try:
        record = json.loads((root / "record.json").read_text(encoding="utf-8"))
        record_id = record.pop("record_id")
        if (
            record.get("schema_version") != RECORD_SCHEMA
            or canonical_hash(record) != record_id
            or index.get("record_id") != record_id
            or root.name != record_id
        ):
            fail("record.json")
        file_hashes = record.get("files", {})
        for name in expected - {"record.json"}:
            if file_hashes.get(name) != indexed.get(name):
                fail("record.files")
    except (OSError, json.JSONDecodeError, AttributeError, KeyError):
        record_id = index.get("record_id")
        fail("record.json")

    try:
        manifest = load_manifest(root / "adapter-manifest.json")
        state = json.loads((root / "adapter-state.json").read_text(encoding="utf-8"))
        if state.get("manifest_sha256") != canonical_hash(manifest):
            fail("adapter-state.json")
        if record.get("adapter_id") != manifest["id"]:
            fail("record.adapter_id")
    except (OSError, json.JSONDecodeError, AttributeError, KeyError, ValueError):
        fail("adapter-manifest.json")

    try:
        request = json.loads((root / "request.json").read_text(encoding="utf-8"))
        operation = request["operation"]
        normalized = validate_web_input(operation, request["input"])
        if normalized != request["input"] or record.get("operation") != operation:
            fail("request.json")
        if operation == "extract":
            _validate_extract_lineage(root.parent, normalized)
    except (OSError, json.JSONDecodeError, KeyError, WebError):
        fail("request.json")

    try:
        raw = (root / "raw.bin").read_bytes()
        output = json.loads((root / "output.json").read_text(encoding="utf-8"))
        response = json.loads((root / "adapter-response.json").read_text(encoding="utf-8"))
        if record.get("outcome") == "completed":
            validated_raw, validated_output, metadata = _validate_adapter_data(
                response["data"], operation, normalized
            )
            if validated_raw != raw or validated_output != output:
                fail("adapter-response.json")
            if (
                metadata["retrieved_at"] != record.get("retrieved_at")
                or metadata["media_type"] != record.get("media_type")
                or metadata["usage"] != record.get("usage")
            ):
                fail("record.json")
        elif output.get("schema_version") != "hound.web.failure.v1":
            fail("output.json")
        elif response.get("data_schema") == ADAPTER_SCHEMA and response.get("ok") is False:
            failed_raw, failed_output, metadata = _validate_failure_adapter_data(response["data"])
            if failed_raw != raw or failed_output != output:
                fail("adapter-response.json")
            if (
                metadata["retrieved_at"] != record.get("retrieved_at")
                or metadata["media_type"] != record.get("media_type")
                or metadata["usage"] != record.get("usage")
            ):
                fail("record.json")
        elif response.get("data_schema") == ADAPTER_SCHEMA:
            recovered_raw, metadata = _recover_adapter_raw(response["data"])
            if recovered_raw != raw:
                fail("raw.bin")
            if (
                metadata["retrieved_at"] != record.get("retrieved_at")
                or metadata["media_type"] != record.get("media_type")
                or metadata["usage"] != record.get("usage")
            ):
                fail("record.json")
    except (OSError, json.JSONDecodeError, KeyError, WebError):
        fail("adapter-response.json")

    return {
        "schema_version": "hound.run.verification.v1",
        "valid": not failures,
        "plan_id": record_id,
        "failures": sorted(failures),
    }


__all__ = ["WebError", "run_web", "validate_web_input", "verify_web_run"]
