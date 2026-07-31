"""HSP-07: immutable content-addressed records and shared exact blobs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import canonical_bytes


class StoreError(RuntimeError):
    """The store cannot safely read or write immutable data."""


class UnsafeStoreError(StoreError):
    """The store has unsafe ownership, permissions, or symlink structure."""


class ImmutableConflict(StoreError):
    """An immutable path already contains different bytes."""


_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


@dataclass(frozen=True)
class RecordRef:
    record_id: str
    content_sha256: str
    byte_length: int
    path: Path
    legacy: bool = False


def _validate_id(value: str, label: str = "record_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 255 or any(char not in _ID_CHARS for char in value):
        raise StoreError(f"{label} is not a safe immutable identifier")
    return value


def _check_owner_mode(path: Path, *, directory: bool) -> None:
    try:
        info = path.stat()
    except OSError as error:
        raise UnsafeStoreError(f"cannot inspect {path}") from error
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise UnsafeStoreError(f"{path} is not owned by the current user")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise UnsafeStoreError(f"{path} has group/world permissions")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise UnsafeStoreError(f"{path} is not a directory")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise UnsafeStoreError(f"{path} is not a regular file")


def _mkdir_private(path: Path) -> None:
    if path.is_symlink():
        raise UnsafeStoreError(f"{path} must not be a symlink")
    existed = path.exists()
    try:
        path.mkdir(exist_ok=existed)
    except OSError as error:
        raise StoreError(f"cannot create {path}") from error
    if not existed:
        path.chmod(0o700)
    _check_owner_mode(path, directory=True)


def _create_or_confirm(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise UnsafeStoreError(f"{path} must not be a symlink")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        if path.is_symlink():
            raise UnsafeStoreError(f"{path} must not be a symlink")
        try:
            existing = path.read_bytes()
        except OSError as error:
            raise StoreError(f"cannot read immutable {path}") from error
        _check_owner_mode(path, directory=False)
        if existing != data:
            raise ImmutableConflict(f"immutable bytes differ at {path}")
        return
    except OSError as error:
        raise StoreError(f"cannot create immutable {path}") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise StoreError(f"cannot persist immutable {path}") from error


class BlobStore:
    """A create-only SHA-256 blob store."""

    def __init__(self, root: Path) -> None:
        self.root = root
        _mkdir_private(root)
        _mkdir_private(root / "blobs")

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise StoreError("blob digest must be lowercase SHA-256")
        return self.root / "blobs" / digest

    def put(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise StoreError("blob data must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        _create_or_confirm(self.path_for(digest), data)
        return digest

    def get(self, digest: str) -> bytes:
        path = self.path_for(digest)
        if path.is_symlink():
            raise UnsafeStoreError(f"{path} must not be a symlink")
        _check_owner_mode(path, directory=False)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise StoreError(f"cannot read blob {digest}") from error
        if hashlib.sha256(data).hexdigest() != digest:
            raise StoreError(f"blob {digest} failed verification")
        return data

    def digests(self) -> list[str]:
        result = []
        for path in sorted((self.root / "blobs").iterdir()):
            if path.is_symlink() or not path.is_file():
                raise UnsafeStoreError(f"unexpected blob path {path}")
            result.append(path.name)
        return result


class RecordStore:
    """Create-only record bytes with a verbatim legacy mirror primitive."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        _mkdir_private(self.root)
        self.records = self.root / "records"
        self.legacy = self.root / "legacy"
        _mkdir_private(self.records)
        _mkdir_private(self.legacy)
        self.blobs = BlobStore(self.root)

    def record_path(self, record_id: str) -> Path:
        return self.records / f"{_validate_id(record_id)}.bin"

    def put_json(self, value: Any) -> RecordRef:
        data = canonical_bytes(value)
        record_id = hashlib.sha256(data).hexdigest()
        path = self.record_path(record_id)
        _create_or_confirm(path, data)
        return RecordRef(record_id, record_id, len(data), path)

    def put_bytes(self, record_id: str, data: bytes, *, expected_sha256: str | None = None) -> RecordRef:
        """Mirror legacy bytes without changing their ID, bytes, or hash."""

        _validate_id(record_id)
        if not isinstance(data, bytes):
            raise StoreError("record data must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and expected_sha256 != digest:
            raise StoreError("legacy record hash does not match its bytes")
        path = self.record_path(record_id)
        _create_or_confirm(path, data)
        manifest = self.legacy / f"{record_id}.json"
        manifest_body = {
            "record_id": record_id,
            "sha256": digest,
            "byte_length": len(data),
        }
        _create_or_confirm(manifest, canonical_bytes(manifest_body))
        return RecordRef(record_id, digest, len(data), path, legacy=True)

    def read(self, record_id: str) -> bytes:
        path = self.record_path(record_id)
        if path.is_symlink():
            raise UnsafeStoreError(f"{path} must not be a symlink")
        _check_owner_mode(path, directory=False)
        try:
            return path.read_bytes()
        except OSError as error:
            raise StoreError(f"cannot read record {record_id}") from error

    def read_json(self, record_id: str) -> Any:
        try:
            value = json.loads(self.read(record_id).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise StoreError(f"record {record_id} is not canonical JSON") from error
        if canonical_bytes(value) != self.read(record_id):
            raise StoreError(f"record {record_id} is not canonical JSON")
        return value

    def has(self, record_id: str) -> bool:
        path = self.record_path(record_id)
        return path.is_file() and not path.is_symlink()

    def record_ids(self) -> list[str]:
        result = []
        for path in sorted(self.records.iterdir()):
            if path.is_symlink() or path.suffix != ".bin" or not path.is_file():
                raise UnsafeStoreError(f"unexpected record path {path}")
            result.append(path.stem)
        return result

    def blob(self, data: bytes) -> str:
        return self.blobs.put(data)

    def verify_record(self, record_id: str, expected_sha256: str | None = None) -> bool:
        try:
            data = self.read(record_id)
        except StoreError:
            return False
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and expected_sha256 != digest:
            return False
        manifest_path = self.legacy / f"{_validate_id(record_id)}.json"
        if manifest_path.is_symlink():
            return False
        if manifest_path.exists():
            try:
                _check_owner_mode(manifest_path, directory=False)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                return False
            return (
                isinstance(manifest, dict)
                and manifest == {"record_id": record_id, "sha256": digest, "byte_length": len(data)}
            )
        return record_id == digest

    def is_legacy(self, record_id: str) -> bool:
        return (self.legacy / f"{_validate_id(record_id)}.json").is_file()


__all__ = [
    "BlobStore",
    "ImmutableConflict",
    "RecordRef",
    "RecordStore",
    "StoreError",
    "UnsafeStoreError",
]
