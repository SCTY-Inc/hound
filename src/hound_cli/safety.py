"""Shared safety classifiers used at external-data boundaries."""

from __future__ import annotations

import base64
import ipaddress
import re
from urllib.parse import quote


_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def secret_key(key: str) -> bool:
    normalized = normalized_key(key)
    compact = normalized.replace("_", "")
    if compact in {
        "apikey",
        "authorization",
        "token",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "password",
        "passwd",
        "secret",
        "clientsecret",
        "credential",
        "credentials",
        "sig",
        "signature",
        "accesskey",
        "secretaccesskey",
        "privatekey",
        "signingkey",
        "cookie",
        "setcookie",
    }:
        return True
    return normalized.endswith(
        (
            "_api_key",
            "_apikey",
            "_authorization",
            "_token",
            "_password",
            "_secret",
            "_credential",
            "_credentials",
            "_sig",
            "_signature",
            "_access_key",
            "_private_key",
            "_signing_key",
            "_cookie",
        )
    )


def public_hostname(hostname: str) -> bool:
    if not isinstance(hostname, str) or not url_text_safe(hostname):
        return False
    candidate = hostname.casefold().rstrip(".")
    if not candidate:
        return False
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            candidate = candidate.encode("idna").decode("ascii").casefold()
        except (UnicodeError, UnicodeDecodeError):
            return False
        labels = candidate.split(".")
        if (
            len(candidate) > 253
            or any(_HOST_LABEL.fullmatch(label) is None for label in labels)
        ):
            return False
        if ":" in candidate or candidate.replace(".", "").isdigit():
            return False
        if "." not in candidate:
            return False
        return not candidate.endswith((".localhost", ".local", ".internal"))
    return address.is_global


def url_text_safe(value: str) -> bool:
    """Reject URL text parsed differently by RFC-oriented and browser parsers."""

    return bool(value) and "\\" not in value and all(
        ord(character) > 0x20 and ord(character) != 0x7F and not character.isspace()
        for character in value
    )


def credential_forms(value: str) -> tuple[str, ...]:
    forms = {
        value,
        quote(value, safe=""),
        base64.b64encode(value.encode("utf-8")).decode("ascii"),
    }
    return tuple(item for item in forms if item)


def contains_credential(value: object, forms: tuple[str, ...]) -> bool:
    if not forms or value is None:
        return False
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return any(form in value for form in forms)
    if isinstance(value, (list, tuple)):
        return any(contains_credential(item, forms) for item in value)
    if isinstance(value, dict):
        return any(
            contains_credential(key, forms) or contains_credential(item, forms)
            for key, item in value.items()
        )
    return False


__all__ = [
    "contains_credential",
    "credential_forms",
    "normalized_key",
    "public_hostname",
    "secret_key",
    "url_text_safe",
]
