"""Bounded HTTP transport shared by first-party web adapters."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_RESPONSE_BYTES = 16 * 1024 * 1024
Transport = Callable[..., tuple[int, bytes]]


class AdapterError(ValueError):
    """A provider request failed or returned an invalid response."""

    def __init__(
        self,
        message: str,
        *,
        raw: bytes = b"",
        media_type: str = "application/octet-stream",
        requests: int = 0,
    ) -> None:
        super().__init__(message)
        self.raw = raw
        self.media_type = media_type
        self.requests = requests

    def with_raw(
        self,
        raw: bytes,
        *,
        media_type: str = "application/json",
        requests: int = 1,
    ) -> "AdapterError":
        return AdapterError(str(self), raw=raw, media_type=media_type, requests=requests)


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def service_url(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdapterError(f"{label} is required")
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise AdapterError(f"{label} is invalid") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterError(f"{label} must be an HTTP service URL without credentials or parameters")
    return value.rstrip("/")


def request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float = 30,
) -> tuple[int, bytes]:
    req = Request(
        url,
        data=body if method != "GET" else None,
        headers=dict(headers),
        method=method,
    )
    opener = build_opener(_NoRedirects())
    try:
        with opener.open(req, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            status = int(response.getcode())
    except HTTPError as error:
        payload = error.read(MAX_RESPONSE_BYTES + 1)
        status = error.code
        error.close()
    except Exception as error:
        raise AdapterError("provider transport failed") from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise AdapterError("provider response exceeded the byte ceiling")
    return status, payload


def json_object(status: object, body: object, label: str) -> dict[str, Any]:
    if isinstance(status, bool) or not isinstance(status, int):
        raise AdapterError(f"{label} returned an invalid status")
    if status < 200 or status >= 300:
        raise AdapterError(
            f"{label} returned HTTP status {status}",
            raw=body if isinstance(body, bytes) else b"",
            media_type="application/octet-stream",
            requests=1,
        )
    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        raise AdapterError(f"{label} returned an invalid or oversized body")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AdapterError(
            f"{label} did not return JSON",
            raw=body,
            media_type="application/octet-stream",
            requests=1,
        ) from error
    if not isinstance(value, dict):
        raise AdapterError(
            f"{label} returned non-object JSON",
            raw=body,
            media_type="application/json",
            requests=1,
        )
    return value
