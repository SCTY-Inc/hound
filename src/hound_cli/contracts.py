"""Versioned wire contracts for Hound drivers."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


MANIFEST_SCHEMA = "hound.driver.v1"
PROTOCOL = "hound.protocol.v1"
RESPONSE_SCHEMA = "hound.driver.response.v1"

_MANIFEST_REQUIRED = {
    "schema_version",
    "id",
    "protocol",
    "owner",
    "exec",
    "capabilities",
}
_MANIFEST_OPTIONAL = {
    "run_root",
    "write_scopes",
    "ignored_snapshot_excludes",
    "timeouts_seconds",
    "env_allowlist",
    "extensions",
    "source",
}
_RESPONSE_REQUIRED = {"schema_version", "ok", "outcome"}
_RESPONSE_OPTIONAL = {
    "data_schema",
    "data",
    "artifacts",
    "proofs",
    "diagnostics",
}
_OUTCOMES = {"planned", "completed", "no-change", "no-op", "no-edition", "held", "failed"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class ContractError(ValueError):
    """A manifest or driver response violates the Hound wire contract."""


def canonical_json(obj: Any) -> str:
    """Return deterministic, compact JSON that is valid UTF-8."""

    try:
        _validate_json_value(obj, "value")
        encoded = json.dumps(
            obj,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        encoded.encode("utf-8")
    except (
        ContractError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError(f"value is not canonical JSON: {error}") from error
    return encoded


def canonical_hash(obj: Any) -> str:
    """Return the SHA-256 digest of an object's canonical UTF-8 JSON."""

    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load and validate a UTF-8 JSON driver manifest."""

    try:
        raw = Path(path).read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot load manifest {path!s}: {error}") from error
    return validate_manifest(value)


def validate_manifest(obj: Any) -> dict[str, Any]:
    """Validate and return a ``hound.driver.v1`` manifest."""

    _require_object(obj, "manifest")
    _require_fields(obj, _MANIFEST_REQUIRED, _MANIFEST_OPTIONAL, "manifest")

    if obj["schema_version"] != MANIFEST_SCHEMA:
        raise ContractError(f"manifest.schema_version must be {MANIFEST_SCHEMA!r}")
    _require_identifier(obj["id"], "manifest.id")
    if obj["protocol"] != PROTOCOL:
        raise ContractError(f"manifest.protocol must be {PROTOCOL!r}")

    owner = obj["owner"]
    _require_object(owner, "manifest.owner")
    _require_fields(owner, {"repo"}, set(), "manifest.owner")
    _require_repo_locator(owner["repo"], "manifest.owner.repo")

    argv = obj["exec"]
    if not isinstance(argv, list) or not argv:
        raise ContractError("manifest.exec must be a non-empty argv list")
    for index, argument in enumerate(argv):
        _require_safe_string(argument, f"manifest.exec[{index}]", allow_empty=index > 0)

    capabilities = obj["capabilities"]
    if not isinstance(capabilities, dict) or not capabilities:
        raise ContractError("manifest.capabilities must be a non-empty object")
    for operation, capability in capabilities.items():
        _require_identifier(operation, "manifest.capabilities operation")
        _require_object(capability, f"manifest.capabilities.{operation}")
        _require_fields(
            capability,
            {"effect", "gate"},
            {"env_allowlist"},
            f"manifest.capabilities.{operation}",
        )
        if not isinstance(capability["effect"], str) or capability["effect"] not in {
            "read",
            "write",
        }:
            raise ContractError(
                f"manifest.capabilities.{operation}.effect must be 'read' or 'write'"
            )
        if not isinstance(capability["gate"], str) or capability["gate"] not in {
            "none",
            "human",
        }:
            raise ContractError(f"manifest.capabilities.{operation}.gate must be 'none' or 'human'")
        if capability["effect"] == "read" and capability["gate"] != "none":
            raise ContractError(
                f"manifest.capabilities.{operation} read effects must use gate 'none'"
            )
        if "env_allowlist" in capability:
            _require_environment_names(
                capability["env_allowlist"],
                f"manifest.capabilities.{operation}.env_allowlist",
            )
    if "extensions" in obj:
        extensions = obj["extensions"]
        _require_object(extensions, "manifest.extensions")
        for name, value in extensions.items():
            _require_identifier(name, "manifest.extensions name")
            _require_object(value, f"manifest.extensions.{name}")
    if "source" in obj:
        _require_object(obj["source"], "manifest.source")

    if "run_root" in obj:
        _require_relative_path(obj["run_root"], "manifest.run_root")
    if "write_scopes" in obj:
        _require_path_list(obj["write_scopes"], "manifest.write_scopes")
    if "ignored_snapshot_excludes" in obj:
        excludes = obj["ignored_snapshot_excludes"]
        _require_path_list(excludes, "manifest.ignored_snapshot_excludes")
        if any(PurePosixPath(value.replace("\\", "/")).as_posix() == "." for value in excludes):
            raise ContractError("manifest.ignored_snapshot_excludes must not contain '.'")

    if "timeouts_seconds" in obj:
        timeouts = obj["timeouts_seconds"]
        if not isinstance(timeouts, dict):
            raise ContractError("manifest.timeouts_seconds must be an object")
        for operation, seconds in timeouts.items():
            _require_identifier(operation, "manifest.timeouts_seconds operation")
            if (
                isinstance(seconds, bool)
                or not isinstance(seconds, (int, float))
                or not math.isfinite(seconds)
                or seconds <= 0
            ):
                raise ContractError(
                    f"manifest.timeouts_seconds.{operation} must be a positive finite number"
                )

    if "env_allowlist" in obj:
        _require_environment_names(obj["env_allowlist"], "manifest.env_allowlist")

    canonical_json(obj)
    return obj


def validate_response(obj: Any) -> dict[str, Any]:
    """Validate and return a ``hound.driver.response.v1`` response."""

    _require_object(obj, "response")
    _require_fields(obj, _RESPONSE_REQUIRED, _RESPONSE_OPTIONAL, "response")
    if obj["schema_version"] != RESPONSE_SCHEMA:
        raise ContractError(f"response.schema_version must be {RESPONSE_SCHEMA!r}")
    if not isinstance(obj["ok"], bool):
        raise ContractError("response.ok must be a boolean")
    if not isinstance(obj["outcome"], str) or obj["outcome"] not in _OUTCOMES:
        raise ContractError(f"response.outcome must be one of {sorted(_OUTCOMES)!r}")
    if obj["ok"] != (obj["outcome"] not in {"held", "failed"}):
        raise ContractError("response.ok contradicts response.outcome")
    if "data_schema" in obj:
        _require_safe_string(obj["data_schema"], "response.data_schema")
    for field in ("artifacts", "proofs", "diagnostics"):
        if field in obj and not isinstance(obj[field], list):
            raise ContractError(f"response.{field} must be a list")
    canonical_json(obj)
    return obj


def _require_object(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")


def _require_fields(
    value: dict[str, Any], required: set[str], optional: set[str], label: str
) -> None:
    if any(not isinstance(key, str) for key in value):
        raise ContractError(f"{label} field names must be strings")
    missing = required - value.keys()
    if missing:
        raise ContractError(f"{label} missing required fields: {sorted(missing)!r}")
    unknown = value.keys() - required - optional
    if unknown:
        raise ContractError(f"{label} has unknown fields: {sorted(unknown)!r}")


def _require_safe_string(value: Any, label: str, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ContractError(f"{label} must be {'a' if allow_empty else 'a non-empty'} string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ContractError(f"{label} contains control characters")


def _require_identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ContractError(f"{label} must be an identifier")


def _require_relative_path(value: Any, label: str) -> None:
    _require_safe_string(value, label)
    normalized = value.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(value)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise ContractError(f"{label} must be relative")
    if ".." in posix_path.parts:
        raise ContractError(f"{label} must not traverse outside its root")


def _require_repo_locator(value: Any, label: str) -> None:
    _require_safe_string(value, label)
    normalized = value.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(value)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise ContractError(f"{label} must be relative")


def _require_path_list(value: Any, label: str) -> None:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be a list")
    for index, path in enumerate(value):
        _require_relative_path(path, f"{label}[{index}]")
    if len(value) != len(set(value)):
        raise ContractError(f"{label} contains duplicate paths")


def _require_environment_names(value: Any, label: str) -> None:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be a list")
    for index, name in enumerate(value):
        if not isinstance(name, str) or not _ENVIRONMENT_NAME.fullmatch(name):
            raise ContractError(f"{label}[{index}] is not an environment name")
        if name == "PATH":
            raise ContractError(f"{label} must not override PATH")
    if len(value) != len(set(value)):
        raise ContractError(f"{label} contains duplicate names")


def _validate_json_value(value: Any, label: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if math.isfinite(value):
            return
        raise ContractError(f"{label} contains a non-finite number")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{label} contains a non-string object key")
            _validate_json_value(item, f"{label}.{key}")
        return
    raise ContractError(f"{label} contains a non-JSON value")
