"""Frozen, local, exact-digest PHI-clear certification for Slice 3C1."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .commit import (
    MAX_SOURCE_BYTES,
    MAX_WIRE_BODY_BYTES,
    SUPPORTED_SOURCE_ENCODING,
    SUPPORTED_SOURCE_MEDIA_TYPE,
    SourceError,
    _HeldPath,
    _close_held_path,
    _open_absolute_nofollow,
    _same_file,
    _validate_held_path,
)


PHI_MANIFEST_SCHEMA = "houndd.phi-clear.v1"
PHI_MANIFEST_FILENAME = "phi-clear.json"
_MAX_MANIFEST_BYTES = MAX_WIRE_BODY_BYTES


class PhiManifestError(ValueError):
    """The operator-provisioned clear manifest is unavailable or invalid."""


class PhiInputError(ValueError):
    """A scanner input is outside the supported Slice 3C1 representation."""


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhiManifestError("manifest contains duplicate keys")
        result[key] = value
    return result


def _exact_str(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise PhiManifestError(f"{label} must be a non-empty string")
    return value


def _digest(value: Any) -> str:
    value = _exact_str(value, "manifest.sha256")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise PhiManifestError("manifest digest is not a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True, order=True)
class PhiClearEntry:
    sha256: str
    media_type: str = SUPPORTED_SOURCE_MEDIA_TYPE
    encoding: str = SUPPORTED_SOURCE_ENCODING

    def __post_init__(self) -> None:
        if type(self.sha256) is not str or type(self.media_type) is not str or type(self.encoding) is not str:
            raise TypeError("manifest entry fields must have exact runtime types")
        if len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256):
            raise ValueError("manifest entry digest is invalid")
        if self.media_type != SUPPORTED_SOURCE_MEDIA_TYPE or self.encoding != SUPPORTED_SOURCE_ENCODING:
            raise ValueError("manifest entry representation is unsupported")

    def to_dict(self) -> dict[str, str]:
        return {"sha256": self.sha256, "media_type": self.media_type, "encoding": self.encoding}


@dataclass(frozen=True, slots=True)
class PhiManifest:
    entries: tuple[PhiClearEntry, ...]

    @classmethod
    def from_path(cls, path: str | os.PathLike[str]) -> "PhiManifest":
        return load_phi_manifest(path)

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(type(entry) is not PhiClearEntry for entry in self.entries):
            raise TypeError("manifest entries must be an exact tuple of PhiClearEntry")
        if tuple(sorted(self.entries)) != self.entries or len(set(self.entries)) != len(self.entries):
            raise ValueError("manifest entries must be unique and sorted")

    @property
    def schema_version(self) -> str:
        return PHI_MANIFEST_SCHEMA

    def contains(self, digest: str, media_type: str, encoding: str) -> bool:
        return PhiClearEntry(digest, media_type, encoding) in self.entries

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": PHI_MANIFEST_SCHEMA, "entries": [entry.to_dict() for entry in self.entries]}


PhiClearManifest = PhiManifest


def phi_manifest_path(state: str | os.PathLike[str]) -> Path:
    if type(state) not in {str, Path} and not isinstance(state, os.PathLike):
        raise TypeError("state must be a path")
    return Path(state) / "service" / PHI_MANIFEST_FILENAME


def _reject_symlink_ancestry(path: Path) -> None:
    if not path.is_absolute():
        raise PhiManifestError("manifest path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except OSError as error:
            raise PhiManifestError("manifest path is unavailable") from error
        if stat.S_ISLNK(info.st_mode):
            raise PhiManifestError("manifest path follows a symlink")


def _manifest_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size


def _validate_manifest_parent(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise PhiManifestError("manifest service directory is not private")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PhiManifestError("clear manifest ownership is invalid")


def _validate_manifest_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise PhiManifestError("clear manifest mode is not 0600")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PhiManifestError("clear manifest ownership is invalid")
    if info.st_size < 0 or info.st_size > _MAX_MANIFEST_BYTES:
        raise PhiManifestError("clear manifest is too large")


def _read_held_manifest(path: Path) -> bytes:
    """Read exactly one held, no-follow manifest snapshot."""

    descriptor: int | None = None
    held: _HeldPath | None = None
    try:
        descriptor, held = _open_absolute_nofollow(str(path))
        owner_pid = os.getpid()
        _validate_held_path(held, descriptor)
        parent_before = os.fstat(held.parents[-1])
        before = os.fstat(descriptor)
        _validate_manifest_parent(parent_before)
        _validate_manifest_file(before)
        chunks: list[bytes] = []
        total = 0
        while total <= before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if os.getpid() != owner_pid:
            raise PhiManifestError("clear manifest descriptor cannot be used after fork")
        raw = b"".join(chunks)
        parent_after = os.fstat(held.parents[-1])
        after = os.fstat(descriptor)
        _validate_manifest_parent(parent_after)
        _validate_manifest_file(after)
        if _manifest_signature(before) != _manifest_signature(after) or len(raw) != before.st_size or not _same_file(parent_before, parent_after):
            raise PhiManifestError("clear manifest changed during read")
        _validate_held_path(held, descriptor)
        return raw
    except (OSError, SourceError) as error:
        raise PhiManifestError("clear manifest is unavailable") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if held is not None:
            _close_held_path(held)


def load_phi_manifest(path: str | os.PathLike[str]) -> PhiManifest:
    """Load and fully validate one canonical 0600 manifest."""

    manifest_path = Path(path)
    try:
        raw = _read_held_manifest(manifest_path)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_rejector)
    except (OSError, UnicodeError, json.JSONDecodeError, PhiManifestError) as error:
        raise PhiManifestError("clear manifest is malformed") from error
    if type(value) is not dict or set(value) != {"schema_version", "entries"} or value["schema_version"] != PHI_MANIFEST_SCHEMA:
        raise PhiManifestError("clear manifest fields are invalid")
    entries_value = value["entries"]
    if type(entries_value) is not list:
        raise PhiManifestError("clear manifest entries must be an array")
    entries: list[PhiClearEntry] = []
    try:
        for item in entries_value:
            if type(item) is not dict or set(item) != {"sha256", "media_type", "encoding"}:
                raise PhiManifestError("clear manifest entry fields are invalid")
            entries.append(PhiClearEntry(_digest(item["sha256"]), _exact_str(item["media_type"], "manifest.media_type"), _exact_str(item["encoding"], "manifest.encoding")))
        manifest = PhiManifest(tuple(entries))
    except (TypeError, ValueError, PhiManifestError) as error:
        raise PhiManifestError("clear manifest entries are invalid") from error
    try:
        canonical = json.dumps(manifest.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as error:
        raise PhiManifestError("clear manifest cannot be canonicalized") from error
    if raw != canonical:
        raise PhiManifestError("clear manifest is not canonical JSON")
    return manifest


load_clear_manifest = load_phi_manifest


class PhiScanner:
    """A deterministic scanner bound to one immutable manifest snapshot."""

    __slots__ = ("_digests",)

    def __init__(self, manifest: PhiManifest) -> None:
        if type(manifest) is not PhiManifest:
            raise TypeError("scanner manifest must be a PhiManifest")
        # Copy the tuple into an immutable set so later filesystem changes or
        # mutations of caller-owned objects cannot change this scanner.
        self._digests = frozenset((entry.sha256, entry.media_type, entry.encoding) for entry in manifest.entries)

    @classmethod
    def from_path(cls, path: str | os.PathLike[str]) -> "PhiScanner":
        return cls(load_phi_manifest(path))

    @property
    def manifest_entries(self) -> frozenset[tuple[str, str, str]]:
        return self._digests

    def scan(self, data: bytes, media_type: str, encoding: str, operation: str) -> str:
        if type(data) is not bytes or len(data) > MAX_SOURCE_BYTES:
            raise PhiInputError("scanner data is outside the bounded byte representation")
        if type(media_type) is not str or type(encoding) is not str or type(operation) is not str:
            raise PhiInputError("scanner inputs have invalid runtime types")
        if media_type != SUPPORTED_SOURCE_MEDIA_TYPE or encoding != SUPPORTED_SOURCE_ENCODING:
            raise PhiInputError("scanner representation is unsupported")
        if operation not in {"ingest.file", "import.record"}:
            raise PhiInputError("scanner operation is unsupported")
        digest = hashlib.sha256(data).hexdigest()
        return "clear" if (digest, media_type, encoding) in self._digests else "suspected"


def scan_phi(data: bytes, media_type: str, encoding: str, operation: str, manifest: PhiManifest) -> str:
    return PhiScanner(manifest).scan(data, media_type, encoding, operation)


__all__ = [
    "PHI_MANIFEST_FILENAME",
    "PHI_MANIFEST_SCHEMA",
    "PhiClearEntry",
    "PhiClearManifest",
    "PhiInputError",
    "PhiManifest",
    "PhiManifestError",
    "PhiScanner",
    "load_clear_manifest",
    "load_phi_manifest",
    "phi_manifest_path",
    "scan_phi",
]
