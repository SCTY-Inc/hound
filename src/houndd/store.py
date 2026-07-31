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
from ._safety import AnchoredRoot, check_private_stat


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
    check_private_stat(info, path, directory=directory, error_type=UnsafeStoreError)


def _mkdir_private(path: Path, *, create: bool = True) -> None:
    if path.is_symlink():
        raise UnsafeStoreError(f"{path} must not be a symlink")
    existed = path.exists()
    if create:
        try:
            path.mkdir(exist_ok=existed)
        except OSError as error:
            raise StoreError(f"cannot create {path}") from error
        if not existed:
            path.chmod(0o700)
    elif not existed:
        raise UnsafeStoreError(f"{path} is missing")
    _check_owner_mode(path, directory=True)


def _create_or_confirm(anchor: AnchoredRoot, *parts: str, data: bytes) -> None:
    try:
        parent_fd = anchor.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(anchor.fd)
        try:
            descriptor = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)
    except FileExistsError:
        try:
            existing = anchor.read_bytes(*parts)
        except OSError as error:
            raise StoreError(f"cannot read immutable {anchor.path.joinpath(*parts)}") from error
        _check_owner_mode(anchor.path.joinpath(*parts), directory=False)
        if existing != data:
            raise ImmutableConflict(f"immutable bytes differ at {anchor.path.joinpath(*parts)}")
        return
    except OSError as error:
        raise StoreError(f"cannot create immutable {anchor.path.joinpath(*parts)}") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = anchor.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(anchor.fd)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise StoreError(f"cannot persist immutable {anchor.path.joinpath(*parts)}") from error


class BlobStore:
    """A create-only SHA-256 blob store."""

    def __init__(self, root: Path, *, create: bool = True) -> None:
        self.root = Path(root).resolve(strict=False)
        _mkdir_private(self.root, create=create)
        _mkdir_private(self.root / "blobs", create=create)
        self.anchor = AnchoredRoot(self.root, error_type=UnsafeStoreError)

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise StoreError("blob digest must be lowercase SHA-256")
        return self.root / "blobs" / digest

    def put(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise StoreError("blob data must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        _create_or_confirm(self.anchor, "blobs", digest, data=data)
        return digest

    def get(self, digest: str) -> bytes:
        path = self.path_for(digest)
        check_private_stat(self.anchor.stat("blobs", digest), path, directory=False, error_type=UnsafeStoreError)
        try:
            data = self.anchor.read_bytes("blobs", digest)
        except OSError as error:
            raise StoreError(f"cannot read blob {digest}") from error
        if hashlib.sha256(data).hexdigest() != digest:
            raise StoreError(f"blob {digest} failed verification")
        return data

    def digests(self) -> list[str]:
        names = self.anchor.listdir("blobs")
        for name in names:
            if len(name) != 64 or any(char not in "0123456789abcdef" for char in name):
                raise UnsafeStoreError(f"unexpected blob path {self.root / 'blobs' / name}")
        return names


class RecordStore:
    """Create-only record bytes with a verbatim legacy mirror primitive."""

    def __init__(self, root: str | os.PathLike[str], *, create: bool = True) -> None:
        root_path = Path(root)
        if root_path.is_symlink():
            raise UnsafeStoreError(f"{root_path} must not be a symlink")
        self.root = root_path.resolve(strict=False)
        _mkdir_private(self.root, create=create)
        self.records = self.root / "records"
        self.legacy = self.root / "legacy"
        _mkdir_private(self.records, create=create)
        _mkdir_private(self.legacy, create=create)
        self.blobs = BlobStore(self.root, create=create)
        self.anchor = AnchoredRoot(self.root, error_type=UnsafeStoreError)

    def record_path(self, record_id: str) -> Path:
        return self.records / f"{_validate_id(record_id)}.bin"

    def put_json(self, value: Any) -> RecordRef:
        data = canonical_bytes(value)
        record_id = hashlib.sha256(data).hexdigest()
        path = self.record_path(record_id)
        _create_or_confirm(self.anchor, "records", f"{record_id}.bin", data=data)
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
        _create_or_confirm(self.anchor, "records", f"{record_id}.bin", data=data)
        manifest = self.legacy / f"{record_id}.json"
        _create_or_confirm(self.anchor, "legacy", f"{record_id}.json", data=canonical_bytes({
            "record_id": record_id,
            "sha256": digest,
            "byte_length": len(data),
        }))
        manifest_body = {
            "record_id": record_id,
            "sha256": digest,
            "byte_length": len(data),
        }
        return RecordRef(record_id, digest, len(data), path, legacy=True)

    def read(self, record_id: str) -> bytes:
        path = self.record_path(record_id)
        check_private_stat(self.anchor.stat("records", f"{_validate_id(record_id)}.bin"), path, directory=False, error_type=UnsafeStoreError)
        try:
            return self.anchor.read_bytes("records", f"{_validate_id(record_id)}.bin")
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
        try:
            self.anchor.stat("records", f"{_validate_id(record_id)}.bin")
        except (UnsafeStoreError, OSError, ValueError):
            return False
        return True

    def record_ids(self) -> list[str]:
        names = self.anchor.listdir("records")
        result = []
        for name in names:
            if not name.endswith(".bin") or len(name) <= 4:
                raise UnsafeStoreError(f"unexpected record path {self.records / name}")
            result.append(name[:-4])
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
        try:
            manifest_bytes = self.anchor.read_bytes("legacy", f"{_validate_id(record_id)}.json")
        except (UnsafeStoreError, StoreError, OSError):
            manifest_bytes = None
        if manifest_bytes is not None:
            try:
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                return False
            return (
                isinstance(manifest, dict)
                and manifest == {"record_id": record_id, "sha256": digest, "byte_length": len(data)}
            )
        return record_id == digest

    def is_legacy(self, record_id: str) -> bool:
        try:
            self.anchor.stat("legacy", f"{_validate_id(record_id)}.json")
        except (UnsafeStoreError, OSError, ValueError):
            return False
        return True


__all__ = [
    "BlobStore",
    "ImmutableConflict",
    "RecordRef",
    "RecordStore",
    "StoreError",
    "UnsafeStoreError",
]
