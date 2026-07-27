"""Camofox disposable browser interaction adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

from hound_research.evidence import EvidenceError, validate_public_url
from hound_research.web import ADAPTER_SCHEMA, INTERACT_SCHEMA, validate_web_input
from ._http import AdapterError, Transport, json_object, request, service_url


SessionFactory = Callable[[], str]


def _retrieved_at(value: str | None) -> str:
    return value or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _session_id() -> str:
    return f"hound-{uuid.uuid4().hex}"


def _headers(access_key: str) -> dict[str, str]:
    if not access_key:
        raise AdapterError("CAMOFOX_ACCESS_KEY is required")
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_key}",
        "Content-Type": "application/json",
    }


def _json_body(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_result_url(value: object, label: str) -> str:
    try:
        return validate_public_url(value, label)
    except EvidenceError as error:
        raise AdapterError(str(error)) from error


def _snapshot_result(response: dict[str, Any]) -> dict[str, Any]:
    snapshot = response.get("snapshot")
    if not isinstance(snapshot, str):
        raise AdapterError("Camofox snapshot response has no snapshot text")
    result: dict[str, Any] = {
        "url": _safe_result_url(response.get("url"), "Camofox snapshot URL"),
        "snapshot": snapshot,
        "snapshot_sha256": hashlib.sha256(snapshot.encode("utf-8")).hexdigest(),
        "refs_count": response.get("refsCount", 0),
        "truncated": response.get("truncated", False),
        "has_more": response.get("hasMore", False),
    }
    if not isinstance(result["refs_count"], int) or isinstance(result["refs_count"], bool):
        raise AdapterError("Camofox snapshot refsCount is invalid")
    if not isinstance(result["truncated"], bool) or not isinstance(result["has_more"], bool):
        raise AdapterError("Camofox snapshot pagination flags are invalid")
    next_offset = response.get("nextOffset")
    if next_offset is not None:
        if not isinstance(next_offset, int) or isinstance(next_offset, bool):
            raise AdapterError("Camofox snapshot nextOffset is invalid")
        result["next_offset"] = next_offset
    screenshot = response.get("screenshot")
    if isinstance(screenshot, str):
        try:
            screenshot_bytes = base64.b64decode(screenshot, validate=True)
        except ValueError as error:
            raise AdapterError("Camofox screenshot is malformed") from error
        result["screenshot_base64"] = screenshot
        result["screenshot_sha256"] = hashlib.sha256(screenshot_bytes).hexdigest()
    return result


def _action_result(response: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": response.get("ok", True)}
    if not isinstance(result["ok"], bool):
        raise AdapterError("Camofox action response has invalid ok flag")
    url = response.get("url")
    if url is not None:
        result["url"] = _safe_result_url(url, "Camofox action URL")
    snapshot = response.get("snapshot")
    if isinstance(snapshot, str):
        result["snapshot"] = snapshot
        result["snapshot_sha256"] = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
    return result


def interact(
    payload: object,
    *,
    env: Mapping[str, str],
    transport: Transport = request,
    session_factory: SessionFactory = _session_id,
    retrieved_at: str | None = None,
) -> dict[str, Any]:
    interaction = validate_web_input("interact", payload)
    base = service_url(env.get("CAMOFOX_ENDPOINT"), "CAMOFOX_ENDPOINT")
    headers = _headers(env.get("CAMOFOX_ACCESS_KEY", ""))
    action = interaction["action"]

    if action == "open":
        session_id = session_factory()
        url = f"{base}/tabs"
        method = "POST"
        body = _json_body(
            {
                "userId": session_id,
                "sessionKey": session_id,
                "url": interaction["url"],
                "trace": False,
            }
        )
    elif action == "snapshot":
        session_id = interaction["session_id"]
        query = {
            "userId": session_id,
            "format": "text",
            "includeScreenshot": str(interaction["include_screenshot"]).lower(),
        }
        if "offset" in interaction:
            query["offset"] = str(interaction["offset"])
        url = f"{base}/tabs/{quote(interaction['tab_id'], safe='')}/snapshot?{urlencode(query)}"
        method = "GET"
        body = b""
    elif action in {"click", "type", "scroll"}:
        session_id = interaction["session_id"]
        url = f"{base}/tabs/{quote(interaction['tab_id'], safe='')}/{action}"
        method = "POST"
        request_body: dict[str, Any] = {"userId": session_id}
        if action == "click":
            request_body["ref"] = interaction["ref"]
        elif action == "type":
            request_body.update(
                {
                    "ref": interaction["ref"],
                    "text": interaction["text"],
                    "clear": True,
                    "submit": False,
                }
            )
        else:
            request_body.update(
                {"direction": interaction["direction"], "amount": interaction["amount"]}
            )
        body = _json_body(request_body)
    else:
        session_id = interaction["session_id"]
        url = f"{base}/sessions/{quote(session_id, safe='')}"
        method = "DELETE"
        body = b""

    status, raw = transport(
        method=method,
        url=url,
        headers=headers,
        body=body,
        timeout=30,
    )
    response = json_object(status, raw, f"Camofox {action}")
    try:
        if action == "open":
            tab_id = response.get("tabId")
            if not isinstance(tab_id, str) or not tab_id:
                raise AdapterError("Camofox open response has no tabId")
            result = {
                "tab_id": tab_id,
                "url": _safe_result_url(response.get("url"), "Camofox open URL"),
            }
        elif action == "snapshot":
            result = _snapshot_result(response)
        elif action == "close":
            ok = response.get("ok")
            closed = response.get("closed")
            if not isinstance(ok, bool) or (
                closed is not None and (isinstance(closed, bool) or not isinstance(closed, int))
            ):
                raise AdapterError("Camofox close response is invalid")
            result = {"ok": ok}
            if closed is not None:
                result["closed"] = closed
        else:
            result = _action_result(response)
    except AdapterError as error:
        raise error.with_raw(raw) from error

    return {
        "schema_version": ADAPTER_SCHEMA,
        "retrieved_at": _retrieved_at(retrieved_at),
        "raw": {
            "media_type": "application/json",
            "body_base64": base64.b64encode(raw).decode("ascii"),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "output": {
            "schema_version": INTERACT_SCHEMA,
            "trust": "untrusted",
            "evidence_class": "provider-derived",
            "action": action,
            "session_id": session_id,
            "result": result,
        },
        "usage": {"requests": 1, "bytes": len(raw)},
    }
