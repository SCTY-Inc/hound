"""HSP-20: one durable service generation and cursor-key identity."""

from __future__ import annotations

import base64
import binascii
import errno
import json
import os
import re
import secrets
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from ._safety import AnchoredRoot, check_private_stat
from .contracts import canonical_bytes
from .cursor import CursorKeyring
from .store import StoreError

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


IdentityFaultHook = Callable[[str], None]


class ServiceIdentityError(StoreError):
    """The service identity cannot be loaded or changed safely."""


class ServiceIdentityLocked(ServiceIdentityError):
    """Another process owns the service identity lifetime lock."""


class ServiceIdentityConflict(ServiceIdentityError):
    """An identity transition conflicts with current durable state."""


_SCHEMA_VERSION = "houndd.service-identity.v1"
_IDENTITY_FIELDS = {"schema_version", "generation", "active_kid", "keys"}
_GENERATION_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_KID_PATTERN = re.compile(r"k-[0-9a-f]{24}", re.ASCII)
_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
_TEMP_PREFIX = ".identity.json.tmp."
_TEMP_PATTERN = re.compile(r"\.identity\.json\.tmp\.[A-Za-z0-9._-]+", re.ASCII)


@dataclass(frozen=True, slots=True)
class ServiceIdentityState:
    generation: str
    keyring: CursorKeyring

    def __post_init__(self) -> None:
        if type(self.generation) is not str or _GENERATION_PATTERN.fullmatch(self.generation) is None:
            raise ServiceIdentityError("service generation must be 32 random bytes in lowercase hex")
        if type(self.keyring) is not CursorKeyring:
            raise ServiceIdentityError("service identity requires a cursor keyring")

    @property
    def active_kid(self) -> str:
        return self.keyring.active_kid


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _bound_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _private_file(value: os.stat_result, label: str) -> None:
    check_private_stat(value, label, directory=False, error_type=ServiceIdentityError)
    if value.st_nlink != 1:
        raise ServiceIdentityError(f"{label} must have exactly one link")


def _read_descriptor(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(size - offset, 1024 * 1024), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    if offset != size or os.pread(descriptor, 1, size):
        raise ServiceIdentityError("service identity changed while it was read")
    return b"".join(chunks)


def _decode_secret(value: object) -> bytes:
    if type(value) is not str or _SECRET_PATTERN.fullmatch(value) is None:
        raise ServiceIdentityError("cursor key secret is not canonical base64url")
    try:
        decoded = base64.b64decode(f"{value}=", altchars=b"-_", validate=True)
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise ServiceIdentityError("cursor key secret is not canonical base64url") from error
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ServiceIdentityError("cursor key secret must encode exactly 32 bytes")
    return decoded


def _decode_state(raw: bytes) -> ServiceIdentityState:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise ServiceIdentityError("service identity is malformed") from error
    if not isinstance(value, dict) or set(value) != _IDENTITY_FIELDS:
        raise ServiceIdentityError("service identity has missing or unknown fields")
    try:
        canonical = canonical_bytes(value)
    except ValueError as error:
        raise ServiceIdentityError("service identity is not canonical JSON") from error
    if canonical != raw:
        raise ServiceIdentityError("service identity is not canonical JSON")
    if value["schema_version"] != _SCHEMA_VERSION:
        raise ServiceIdentityError("service identity schema version is unsupported")
    generation = value["generation"]
    active_kid = value["active_kid"]
    keys_value = value["keys"]
    if type(generation) is not str or _GENERATION_PATTERN.fullmatch(generation) is None:
        raise ServiceIdentityError("service generation is invalid")
    if type(active_kid) is not str or _KID_PATTERN.fullmatch(active_kid) is None:
        raise ServiceIdentityError("active cursor key ID is invalid")
    if type(keys_value) is not dict or not keys_value:
        raise ServiceIdentityError("cursor keyring must be a nonempty object")
    keys: dict[str, bytes] = {}
    for kid, encoded in keys_value.items():
        if type(kid) is not str or _KID_PATTERN.fullmatch(kid) is None:
            raise ServiceIdentityError("cursor key ID is invalid")
        keys[kid] = _decode_secret(encoded)
    try:
        keyring = CursorKeyring(active_kid, keys)
    except ValueError as error:
        raise ServiceIdentityError("cursor keyring is invalid") from error
    return ServiceIdentityState(generation, keyring)


def _encode_state(state: ServiceIdentityState) -> bytes:
    if type(state) is not ServiceIdentityState:
        raise ServiceIdentityError("service identity transition is invalid")
    keys: dict[str, str] = {}
    for kid, secret in state.keyring.keys.items():
        if _KID_PATTERN.fullmatch(kid) is None or type(secret) is not bytes or len(secret) != 32:
            raise ServiceIdentityError("service identity cursor keyring is invalid")
        keys[kid] = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
    raw = canonical_bytes(
        {
            "schema_version": _SCHEMA_VERSION,
            "generation": state.generation,
            "active_kid": state.active_kid,
            "keys": keys,
        }
    )
    if _decode_state(raw) != state:
        raise ServiceIdentityError("service identity transition failed canonical validation")
    return raw


class ServiceIdentity:
    """A process-lifetime lock over one atomically replaced identity file."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        create: bool = False,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        fault_hook: IdentityFaultHook | None = None,
    ) -> None:
        if not callable(random_bytes):
            raise ServiceIdentityError("service identity random source must be callable")
        if fault_hook is not None and not callable(fault_hook):
            raise ServiceIdentityError("service identity fault hook must be callable")
        self._mutex = threading.RLock()
        self._random_bytes = random_bytes
        self._fault_hook = fault_hook
        self._poisoned = False
        self._closed = False
        self.anchor: AnchoredRoot | None = None
        self.root = None
        self._service_fd: int | None = None
        self._lock_fd: int | None = None
        self._lock_signature: tuple[int, ...] | None = None
        self._identity_fd: int | None = None
        self._identity_signature: tuple[int, ...] | None = None
        self._identity_bytes: bytes | None = None
        self._state: ServiceIdentityState | None = None
        try:
            self.anchor = AnchoredRoot(root, error_type=ServiceIdentityError, create=create)
            self.root = self.anchor.path
            with self.anchor.operation():
                self.anchor.mkdir("service", create=create)
                self._service_fd = self.anchor.dirfd("service")
                self._validate_service_binding()
                self._open_lifetime_lock(create=create)
                self._reclaim_stale_temps()
                if self._leaf_exists("identity.json"):
                    self._load_identity()
                elif create:
                    self._persist(self._new_identity(), expect_absent=True)
                else:
                    raise ServiceIdentityError("service identity is missing")
        except Exception:
            self.close()
            raise

    def __enter__(self) -> "ServiceIdentity":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_anchor(self) -> AnchoredRoot:
        if self.anchor is None or self._service_fd is None:
            raise ServiceIdentityError("service identity is closed")
        return self.anchor

    def _ensure_usable(self) -> None:
        if self._closed or self.anchor is None or self._service_fd is None or self._lock_fd is None:
            raise ServiceIdentityError("service identity is closed")
        if self._poisoned:
            raise ServiceIdentityError("service identity must be reopened after an uncertain persistence outcome")

    def _visible_root_child(self, name: str) -> os.stat_result:
        anchor = self._require_anchor()
        assert anchor.fd is not None
        return os.stat(name, dir_fd=anchor.fd, follow_symlinks=False)

    def _visible_service_child(self, name: str) -> os.stat_result:
        if self._service_fd is None:
            raise ServiceIdentityError("service identity is closed")
        return os.stat(name, dir_fd=self._service_fd, follow_symlinks=False)

    def _validate_service_binding(self) -> None:
        anchor = self._require_anchor()
        assert self._service_fd is not None
        held = os.fstat(self._service_fd)
        visible = self._visible_root_child("service")
        check_private_stat(held, anchor.path / "service", directory=True, error_type=ServiceIdentityError)
        check_private_stat(visible, anchor.path / "service", directory=True, error_type=ServiceIdentityError)
        if not _same_file(held, visible):
            raise ServiceIdentityConflict("service identity directory binding changed")

    def _leaf_exists(self, name: str) -> bool:
        try:
            self._visible_service_child(name)
        except FileNotFoundError:
            return False
        return True

    def _open_lifetime_lock(self, *, create: bool) -> None:
        if fcntl is None:
            raise ServiceIdentityError("service identity locking is unavailable")
        assert self._service_fd is not None
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            if create:
                try:
                    descriptor = os.open("lock", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self._service_fd)
                except FileExistsError:
                    descriptor = os.open("lock", flags, dir_fd=self._service_fd)
            else:
                descriptor = os.open("lock", flags, dir_fd=self._service_fd)
            info = os.fstat(descriptor)
            _private_file(info, "service/lock")
            visible = self._visible_service_child("lock")
            _private_file(visible, "service/lock")
            if not _same_file(info, visible) or info.st_ctime_ns != visible.st_ctime_ns:
                raise ServiceIdentityConflict("service identity lock binding changed")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise ServiceIdentityLocked("service identity is locked by another process") from None
                raise
            self._lock_fd = descriptor
            self._lock_signature = _bound_signature(os.fstat(descriptor))
            descriptor = None
            self._validate_lock_binding()
        except ServiceIdentityError:
            raise
        except OSError as error:
            raise ServiceIdentityError("service identity lock is missing or unsafe") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _validate_lock_binding(self) -> None:
        self._validate_service_binding()
        if self._lock_fd is None or self._lock_signature is None:
            raise ServiceIdentityError("service identity lock is closed")
        held = os.fstat(self._lock_fd)
        _private_file(held, "service/lock")
        visible = self._visible_service_child("lock")
        _private_file(visible, "service/lock")
        if (
            _bound_signature(held) != self._lock_signature
            or not _same_file(held, visible)
            or held.st_ctime_ns != visible.st_ctime_ns
        ):
            raise ServiceIdentityConflict("service identity lock binding changed")

    def _open_validated_leaf(self, name: str) -> tuple[int, os.stat_result, bytes]:
        assert self._service_fd is not None
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._service_fd,
            )
            opened = os.fstat(descriptor)
            _private_file(opened, f"service/{name}")
            visible = self._visible_service_child(name)
            _private_file(visible, f"service/{name}")
            if not _same_file(opened, visible) or opened.st_ctime_ns != visible.st_ctime_ns:
                raise ServiceIdentityConflict(f"service/{name} changed while it was opened")
            raw = _read_descriptor(descriptor, opened.st_size)
            held_after = os.fstat(descriptor)
            visible_after = self._visible_service_child(name)
            if (
                _bound_signature(held_after) != _bound_signature(opened)
                or not _same_file(held_after, visible_after)
                or held_after.st_ctime_ns != visible_after.st_ctime_ns
            ):
                raise ServiceIdentityConflict(f"service/{name} changed while it was read")
            result = (descriptor, held_after, raw)
            descriptor = None
            return result
        except ServiceIdentityError:
            raise
        except OSError as error:
            raise ServiceIdentityError(f"service/{name} is missing or unsafe") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _load_identity(self) -> None:
        descriptor: int | None = None
        try:
            descriptor, info, raw = self._open_validated_leaf("identity.json")
            state = _decode_state(raw)
            self._identity_fd = descriptor
            self._identity_signature = _bound_signature(info)
            self._identity_bytes = raw
            self._state = state
            descriptor = None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _validate_identity_binding(self) -> None:
        self._validate_lock_binding()
        if (
            self._identity_fd is None
            or self._identity_signature is None
            or self._identity_bytes is None
            or self._state is None
        ):
            raise ServiceIdentityError("service identity is not loaded")
        held = os.fstat(self._identity_fd)
        _private_file(held, "service/identity.json")
        visible = self._visible_service_child("identity.json")
        _private_file(visible, "service/identity.json")
        if (
            _bound_signature(held) != self._identity_signature
            or not _same_file(held, visible)
            or held.st_ctime_ns != visible.st_ctime_ns
        ):
            raise ServiceIdentityConflict("service identity binding changed")
        raw = _read_descriptor(self._identity_fd, held.st_size)
        held_after = os.fstat(self._identity_fd)
        visible_after = self._visible_service_child("identity.json")
        if (
            raw != self._identity_bytes
            or _bound_signature(held_after) != self._identity_signature
            or not _same_file(held_after, visible_after)
            or held_after.st_ctime_ns != visible_after.st_ctime_ns
        ):
            raise ServiceIdentityConflict("service identity changed while it was verified")

    def _validate_identity_absent(self) -> None:
        self._validate_lock_binding()
        for _ in range(2):
            try:
                self._visible_service_child("identity.json")
            except FileNotFoundError:
                continue
            raise ServiceIdentityConflict("service identity unexpectedly exists")

    def _reclaim_stale_temps(self) -> None:
        self._validate_lock_binding()
        assert self._service_fd is not None
        try:
            names = sorted(name for name in os.listdir(self._service_fd) if name.startswith(_TEMP_PREFIX))
        except OSError as error:
            raise ServiceIdentityError("service identity directory cannot be inventoried") from error
        for name in names:
            if _TEMP_PATTERN.fullmatch(name) is None:
                raise ServiceIdentityError("service identity contains an unrecognized temporary path")
            descriptor: int | None = None
            try:
                descriptor, opened, _ = self._open_validated_leaf(name)
                visible = self._visible_service_child(name)
                if not _same_file(opened, visible) or opened.st_ctime_ns != visible.st_ctime_ns:
                    raise ServiceIdentityConflict("service identity temporary path changed")
                os.unlink(name, dir_fd=self._service_fd)
                os.fsync(self._service_fd)
                if os.fstat(descriptor).st_nlink != 0:
                    raise ServiceIdentityConflict("service identity temporary path was not reclaimed")
                try:
                    self._visible_service_child(name)
                except FileNotFoundError:
                    pass
                else:
                    raise ServiceIdentityConflict("service identity temporary path was replaced")
            except ServiceIdentityError:
                raise
            except OSError as error:
                raise ServiceIdentityError("service identity temporary path is unsafe") from error
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    def _random(self, size: int, label: str) -> bytes:
        try:
            value = self._random_bytes(size)
        except Exception as error:
            raise ServiceIdentityError(f"service identity random source failed for {label}") from error
        if type(value) is not bytes or len(value) != size:
            raise ServiceIdentityError(f"service identity random source must return exactly {size} bytes for {label}")
        return value

    def _new_identity(self) -> ServiceIdentityState:
        generation = self._random(32, "generation").hex()
        kid = f"k-{self._random(12, 'cursor key ID').hex()}"
        secret = self._random(32, "cursor key")
        return ServiceIdentityState(generation, CursorKeyring(kid, {kid: secret}))

    def _hook(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover
                raise OSError("service identity temporary write made no progress")
            view = view[written:]

    def _validate_temp(self, descriptor: int, name: str, data: bytes) -> os.stat_result:
        opened = os.fstat(descriptor)
        _private_file(opened, f"service/{name}")
        visible = self._visible_service_child(name)
        _private_file(visible, f"service/{name}")
        if (
            opened.st_size != len(data)
            or not _same_file(opened, visible)
            or opened.st_ctime_ns != visible.st_ctime_ns
            or _read_descriptor(descriptor, opened.st_size) != data
        ):
            raise ServiceIdentityConflict("service identity temporary bytes changed")
        return opened

    def _persist(self, state: ServiceIdentityState, *, expect_absent: bool = False) -> ServiceIdentityState:
        self._require_anchor()
        raw = _encode_state(state)
        assert self._service_fd is not None
        temp_name = f"{_TEMP_PREFIX}{os.getpid()}.{secrets.token_hex(16)}"
        temp_fd: int | None = None
        old_identity_fd = self._identity_fd
        renamed = False
        try:
            if expect_absent:
                self._validate_identity_absent()
            else:
                self._validate_identity_binding()
            temp_fd = os.open(
                temp_name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._service_fd,
            )
            self._hook("before_identity_temp_write")
            self._write_all(temp_fd, raw)
            self._hook("after_identity_temp_write")
            os.fsync(temp_fd)
            self._hook("after_identity_temp_fsync")
            self._validate_temp(temp_fd, temp_name, raw)
            if expect_absent:
                self._validate_identity_absent()
            else:
                self._validate_identity_binding()
            os.replace(
                temp_name,
                "identity.json",
                src_dir_fd=self._service_fd,
                dst_dir_fd=self._service_fd,
            )
            renamed = True
            if old_identity_fd is not None and os.fstat(old_identity_fd).st_nlink != 0:
                raise ServiceIdentityConflict("service identity destination changed before replacement")
            self._hook("after_identity_rename")
            os.fsync(self._service_fd)
            self._hook("after_identity_directory_fsync")
            published = os.fstat(temp_fd)
            _private_file(published, "service/identity.json")
            visible = self._visible_service_child("identity.json")
            _private_file(visible, "service/identity.json")
            if (
                not _same_file(published, visible)
                or published.st_ctime_ns != visible.st_ctime_ns
                or _read_descriptor(temp_fd, published.st_size) != raw
            ):
                raise ServiceIdentityConflict("published service identity changed")
            self._validate_lock_binding()
            if self._identity_fd is not None:
                os.close(self._identity_fd)
            self._identity_fd = temp_fd
            self._identity_signature = _bound_signature(published)
            self._identity_bytes = raw
            self._state = state
            temp_fd = None
            return state
        except Exception as error:
            self._poisoned = True
            if isinstance(error, (ServiceIdentityError, RuntimeError)):
                raise
            raise ServiceIdentityError("service identity atomic replacement failed") from error
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if not renamed:
                # A private stale temp is intentionally retained. Reopen owns
                # the only safe reclamation path under the lifetime lock.
                pass

    @property
    def state(self) -> ServiceIdentityState:
        with self.lease() as state:
            return state

    @contextmanager
    def lease(self) -> Iterator[ServiceIdentityState]:
        with self._mutex:
            self._ensure_usable()
            anchor = self._require_anchor()
            with anchor.operation():
                self._validate_identity_binding()
                assert self._state is not None
                try:
                    yield self._state
                except Exception:
                    raise
                else:
                    self._validate_identity_binding()

    def rotate_cursor_key(self) -> ServiceIdentityState:
        with self._mutex:
            self._ensure_usable()
            anchor = self._require_anchor()
            with anchor.operation():
                self._validate_identity_binding()
                assert self._state is not None
                kid = f"k-{self._random(12, 'cursor key ID').hex()}"
                if kid in self._state.keyring.keys:
                    raise ServiceIdentityConflict("new cursor key ID collides with the current keyring")
                secret = self._random(32, "cursor key")
                keys = dict(self._state.keyring.keys)
                keys[kid] = secret
                return self._persist(
                    ServiceIdentityState(self._state.generation, CursorKeyring(kid, keys))
                )

    def retire_cursor_key(self, kid: str) -> ServiceIdentityState:
        with self._mutex:
            self._ensure_usable()
            anchor = self._require_anchor()
            with anchor.operation():
                self._validate_identity_binding()
                assert self._state is not None
                if type(kid) is not str or kid not in self._state.keyring.keys:
                    raise ServiceIdentityConflict("cursor key cannot be retired")
                if kid == self._state.active_kid:
                    raise ServiceIdentityConflict("the active cursor key cannot be retired")
                keys = dict(self._state.keyring.keys)
                del keys[kid]
                return self._persist(
                    ServiceIdentityState(
                        self._state.generation,
                        CursorKeyring(self._state.active_kid, keys),
                    )
                )

    def roll_generation(self) -> ServiceIdentityState:
        with self._mutex:
            self._ensure_usable()
            anchor = self._require_anchor()
            with anchor.operation():
                self._validate_identity_binding()
                assert self._state is not None
                generation = self._random(32, "generation").hex()
                if generation == self._state.generation:
                    raise ServiceIdentityConflict("new service generation must differ from the current generation")
                return self._persist(ServiceIdentityState(generation, self._state.keyring))

    def close(self) -> None:
        mutex = getattr(self, "_mutex", None)
        if mutex is None:
            return
        with mutex:
            if self._closed:
                return
            self._closed = True
            lock_fd, self._lock_fd = self._lock_fd, None
            identity_fd, self._identity_fd = self._identity_fd, None
            service_fd, self._service_fd = self._service_fd, None
            if lock_fd is not None and fcntl is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            for descriptor in (identity_fd, lock_fd, service_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            anchor, self.anchor = self.anchor, None
            if anchor is not None:
                anchor.close()


__all__ = [
    "IdentityFaultHook",
    "ServiceIdentity",
    "ServiceIdentityConflict",
    "ServiceIdentityError",
    "ServiceIdentityLocked",
    "ServiceIdentityState",
]
