"""Executable boundary for Hound's first-party web adapters."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from hound_cli.contracts import canonical_json
from hound_research.web import WebError

from . import camofox, exa, firecrawl, searxng
from ._http import AdapterError


Adapter = Callable[..., dict[str, Any]]
_ADAPTERS: dict[str, tuple[str, Adapter]] = {
    "searxng": ("web.search", searxng.search),
    "exa": ("web.search", exa.search),
    "firecrawl": ("web.extract", firecrawl.extract),
    "camofox": ("web.interact", camofox.interact),
}


def run(adapter_name: str, request: object, env: Mapping[str, str]) -> dict[str, Any]:
    if adapter_name not in _ADAPTERS:
        raise AdapterError(f"unknown first-party adapter {adapter_name!r}")
    if not isinstance(request, dict):
        raise AdapterError("adapter request must be an object")
    mode = request.get("mode")
    if mode == "check":
        return {
            "schema_version": "hound.driver.response.v1",
            "ok": True,
            "outcome": "completed",
            "data_schema": "hound.web.adapter-check.v1",
            "data": {
                "protocol": "hound.protocol.v1",
                "adapter": adapter_name,
                "operation": _ADAPTERS[adapter_name][0],
            },
            "artifacts": [],
            "proofs": [],
            "diagnostics": [],
        }
    operation, adapter = _ADAPTERS[adapter_name]
    if mode != "read" or request.get("operation") != operation:
        raise AdapterError(f"adapter {adapter_name!r} accepts only {operation} read requests")
    data = adapter(request.get("input", {}), env=env)
    return {
        "schema_version": "hound.driver.response.v1",
        "ok": True,
        "outcome": "completed",
        "data_schema": "hound.web.adapter.v1",
        "data": data,
        "artifacts": [],
        "proofs": [],
        "diagnostics": [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    response: dict[str, Any]
    try:
        if len(arguments) != 1:
            raise AdapterError("usage: hound-web-adapter searxng|exa|firecrawl|camofox")
        request = json.load(sys.stdin)
        response = run(arguments[0], request, os.environ)
    except (AdapterError, WebError, ValueError, json.JSONDecodeError) as error:
        raw = error.raw if isinstance(error, AdapterError) else b""
        media_type = (
            error.media_type if isinstance(error, AdapterError) else "application/octet-stream"
        )
        requests = error.requests if isinstance(error, AdapterError) else 0
        response = {
            "schema_version": "hound.driver.response.v1",
            "ok": False,
            "outcome": "failed",
            "data_schema": "hound.web.adapter.v1",
            "data": {
                "schema_version": "hound.web.adapter.v1",
                "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "raw": {
                    "media_type": media_type,
                    "body_base64": base64.b64encode(raw).decode("ascii"),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                },
                "output": {
                    "schema_version": "hound.web.failure.v1",
                    "trust": "untrusted",
                    "error": str(error),
                },
                "usage": {"requests": requests, "bytes": len(raw)},
            },
            "artifacts": [],
            "proofs": [],
            "diagnostics": [str(error)],
        }
    sys.stdout.write(canonical_json(response) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
