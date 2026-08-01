"""HSP-20: one durable service generation and cursor-key identity."""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import hashlib
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
_TXN_SCHEMA_VERSION = "houndd.service-identity-transaction.v1"
_TXID_PATTERN = re.compile(r"[0-9a-f]{32}", re.ASCII)
_TXN_PREFIX = ".identity.txn."
_UNTRUSTED_PREFIX = ".identity.untrusted."
_AT_FDCWD = -100
_AT_EMPTY_PATH = 0x1000
_AT_SYMLINK_FOLLOW = 0x400
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2


def _renameat2(
    source: str,
    destination: str,
    *,
    source_dir_fd: int,
    destination_dir_fd: int,
    flags: int,
) -> None:
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:  # pragma: no cover - current Linux/glibc exposes renameat2
        raise ServiceIdentityError("atomic identity path operations are unavailable") from error
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(
        source_dir_fd,
        os.fsencode(source),
        destination_dir_fd,
        os.fsencode(destination),
        flags,
    ) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), source, destination)


def _exchange_identity_paths(source: str, destination: str, *, dir_fd: int) -> None:
    try:
        _renameat2(
            source,
            destination,
            source_dir_fd=dir_fd,
            destination_dir_fd=dir_fd,
            flags=_RENAME_EXCHANGE,
        )
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ELOOP, errno.ENOTDIR, errno.EISDIR}:
            raise ServiceIdentityConflict("service identity exchange paths changed") from error
        if error.errno in {
            errno.ENOSYS,
            errno.EINVAL,
            errno.EOPNOTSUPP,
            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        }:
            raise ServiceIdentityError("atomic identity path operations are unavailable") from error
        raise


def _rename_identity_noreplace(source: str, destination: str, *, dir_fd: int) -> None:
    try:
        _renameat2(
            source,
            destination,
            source_dir_fd=dir_fd,
            destination_dir_fd=dir_fd,
            flags=_RENAME_NOREPLACE,
        )
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise ServiceIdentityConflict("service identity quarantine destination already exists") from error
        if error.errno in {errno.ENOENT, errno.ELOOP, errno.ENOTDIR, errno.EISDIR}:
            raise ServiceIdentityConflict("service identity quarantine paths changed") from error
        if error.errno in {
            errno.ENOSYS,
            errno.EINVAL,
            errno.EOPNOTSUPP,
            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        }:
            raise ServiceIdentityError("atomic identity path operations are unavailable") from error
        raise


def _linkat(
    source_dir_fd: int,
    source: str,
    destination_dir_fd: int,
    destination: str,
    flags: int,
) -> None:
    try:
        function = ctypes.CDLL(None, use_errno=True).linkat
    except AttributeError as error:  # pragma: no cover - Linux/glibc contract
        raise ServiceIdentityError("exact-FD identity linking is unavailable") from error
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    function.restype = ctypes.c_int
    if function(
        source_dir_fd,
        os.fsencode(source),
        destination_dir_fd,
        os.fsencode(destination),
        flags,
    ) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), source, destination)


def _open_proc_self_fd() -> int:
    """Hold the kernel procfs descriptor directory for one fallback link."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            "/proc/self/fd",
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ServiceIdentityError("exact-FD identity linking is unavailable")
        result = descriptor
        descriptor = None
        return result
    except OSError as error:
        raise ServiceIdentityError("exact-FD identity linking is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_link_source_flags(source_fd: int, *, require_otmpfile: bool) -> None:
    if fcntl is None:
        raise ServiceIdentityError("exact-FD identity linking is unavailable")
    try:
        flags = fcntl.fcntl(source_fd, fcntl.F_GETFL)
    except OSError as error:
        raise ServiceIdentityError("exact-FD identity source is unavailable") from error
    otmpfile = getattr(os, "O_TMPFILE", 0)
    if require_otmpfile and (not otmpfile or flags & otmpfile != otmpfile):
        raise ServiceIdentityError("service identity source is not O_TMPFILE")
    if require_otmpfile and flags & os.O_EXCL:
        raise ServiceIdentityError("service identity O_TMPFILE must not use O_EXCL")


def _link_identity_fd(
    source_fd: int,
    destination: str,
    *,
    dir_fd: int,
    owner_pid: int,
    expected_fingerprint: dict[str, object],
    require_otmpfile: bool,
) -> None:
    """Give one exact held inode a relative, non-overwriting name."""

    if owner_pid != os.getpid():
        raise ServiceIdentityError("service identity cannot link inherited descriptors after fork")
    if type(destination) is not str or not destination or "/" in destination:
        raise ServiceIdentityError("service identity destination name is unsafe")
    _validate_link_source_flags(source_fd, require_otmpfile=require_otmpfile)
    before_fingerprint, _, before = _descriptor_fingerprint(source_fd)
    if before_fingerprint != expected_fingerprint:
        raise ServiceIdentityConflict("exact-FD identity source changed before link")
    try:
        _linkat(source_fd, "", dir_fd, destination, _AT_EMPTY_PATH)
        return
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise ServiceIdentityConflict("service identity destination already exists") from error
        if error.errno not in {errno.ENOENT, errno.EPERM}:
            if error.errno in {
                errno.EACCES,
                errno.EISDIR,
                errno.ELOOP,
                errno.EMLINK,
                errno.ENOSYS,
                errno.EINVAL,
                errno.EOPNOTSUPP,
                errno.EXDEV,
                errno.ENOTDIR,
                getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
            }:
                raise ServiceIdentityError("exact-FD identity linking is unavailable") from error
            raise

    # Unprivileged Linux commonly rejects AT_EMPTY_PATH.  Follow only the
    # numeric entry beneath a held kernel procfs directory descriptor; the
    # destination remains relative to the already-held service directory.
    if owner_pid != os.getpid():
        raise ServiceIdentityError("service identity cannot link inherited descriptors after fork")
    proc_fd: int | None = None
    try:
        try:
            proc_fd = _open_proc_self_fd()
        except ServiceIdentityError:
            raise
        except OSError as error:
            raise ServiceIdentityError("exact-FD identity linking is unavailable") from error
        if owner_pid != os.getpid():
            raise ServiceIdentityError("service identity cannot link inherited descriptors after fork")
        current_fingerprint, _, current = _descriptor_fingerprint(source_fd)
        if (
            current_fingerprint != expected_fingerprint
            or _bound_signature(current) != _bound_signature(before)
        ):
            raise ServiceIdentityConflict("exact-FD identity source changed before procfs link")
        source_name = str(source_fd)
        proc_entry = os.stat(source_name, dir_fd=proc_fd, follow_symlinks=True)
        if not _same_file(current, proc_entry):
            raise ServiceIdentityConflict("procfs does not name the held identity inode")
        _linkat(proc_fd, source_name, dir_fd, destination, _AT_SYMLINK_FOLLOW)
    except ServiceIdentityError:
        raise
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise ServiceIdentityConflict("service identity destination already exists") from error
        if error.errno == errno.ENOENT:
            raise ServiceIdentityError(
                "exact-FD identity source is unlinkable (O_EXCL or unavailable)"
            ) from error
        if error.errno in {
            errno.EACCES,
            errno.EBADF,
            errno.ELOOP,
            errno.EMLINK,
            errno.ENOSYS,
            errno.EINVAL,
            errno.EISDIR,
            errno.EPERM,
            errno.EOPNOTSUPP,
            errno.EXDEV,
            errno.ENOTDIR,
            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        }:
            raise ServiceIdentityError("exact-FD identity linking is unavailable") from error
        raise
    finally:
        if proc_fd is not None:
            os.close(proc_fd)


def _transaction_names(txid: str) -> dict[str, str]:
    if _TXID_PATTERN.fullmatch(txid) is None:
        raise ServiceIdentityError("service identity transaction ID is invalid")
    prefix = f"{_TXN_PREFIX}{txid}"
    return {
        "marker": f"{prefix}.json",
        "old": f"{prefix}.old",
        "new": f"{prefix}.new",
        "swap": f"{prefix}.swap",
        "trash_marker": f"{prefix}.trash.marker",
        "trash_old": f"{prefix}.trash.old",
        "trash_new": f"{prefix}.trash.new",
        "trash_swap": f"{prefix}.trash.swap",
    }


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


_FINGERPRINT_FIELDS = {"st_dev", "st_ino", "uid", "gid", "mode", "size", "sha256"}
_MARKER_SIGNATURE_FIELDS = {"st_dev", "st_ino", "uid", "gid", "mode"}


def _marker_signature(value: os.stat_result) -> dict[str, int]:
    return {
        "st_dev": value.st_dev,
        "st_ino": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
    }


def _descriptor_fingerprint(descriptor: int) -> tuple[dict[str, object], bytes, os.stat_result]:
    before = os.fstat(descriptor)
    check_private_stat(before, "service identity transaction file", directory=False, error_type=ServiceIdentityError)
    raw = _read_descriptor(descriptor, before.st_size)
    after = os.fstat(descriptor)
    if _bound_signature(before) != _bound_signature(after):
        raise ServiceIdentityConflict("service identity transaction file changed while read")
    return (
        {
            "st_dev": after.st_dev,
            "st_ino": after.st_ino,
            "uid": after.st_uid,
            "gid": after.st_gid,
            "mode": stat.S_IMODE(after.st_mode),
            "size": after.st_size,
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        raw,
        after,
    )


def _validate_fingerprint(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != _FINGERPRINT_FIELDS:
        raise ServiceIdentityError(f"{label} fingerprint has invalid fields")
    integers = ("st_dev", "st_ino", "uid", "gid", "mode", "size")
    if any(type(value[field]) is not int or value[field] < 0 for field in integers):
        raise ServiceIdentityError(f"{label} fingerprint is invalid")
    if value["mode"] != 0o600:
        raise ServiceIdentityError(f"{label} fingerprint mode is unsafe")
    digest = value["sha256"]
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest, re.ASCII) is None:
        raise ServiceIdentityError(f"{label} fingerprint hash is invalid")
    return dict(value)


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
        self._owner_pid = os.getpid()
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
                self._recover_identity_namespace()
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
        self._require_process_owner()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_anchor(self) -> AnchoredRoot:
        if self.anchor is None or self._service_fd is None:
            raise ServiceIdentityError("service identity is closed")
        return self.anchor

    def _require_process_owner(self) -> None:
        if getattr(self, "_owner_pid", None) != os.getpid():
            raise ServiceIdentityError("service identity cannot be used after fork")

    def _ensure_usable(self) -> None:
        self._require_process_owner()
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
        anchor._check_root_identity()
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
        self._require_process_owner()
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
        self._require_anchor()._check_root_identity()

    def _open_validated_leaf(self, name: str) -> tuple[int, os.stat_result, bytes]:
        self._validate_lock_binding()
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
            self._validate_lock_binding()
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

    def _open_auxiliary(self, name: str) -> tuple[int, dict[str, object], bytes]:
        """Open and fingerprint one transaction-owned regular file."""

        if type(name) is not str or not name or "/" in name or name in {".", ".."}:
            raise ServiceIdentityError("service identity transaction name is unsafe")
        self._validate_lock_binding()
        assert self._service_fd is not None
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._service_fd,
            )
            opened = os.fstat(descriptor)
            check_private_stat(opened, f"service/{name}", directory=False, error_type=ServiceIdentityError)
            visible = self._visible_service_child(name)
            check_private_stat(visible, f"service/{name}", directory=False, error_type=ServiceIdentityError)
            if not _same_file(opened, visible):
                raise ServiceIdentityConflict(f"service/{name} changed while opened")
            fingerprint, raw, after = _descriptor_fingerprint(descriptor)
            visible_after = self._visible_service_child(name)
            if not _same_file(after, visible_after):
                raise ServiceIdentityConflict(f"service/{name} changed while fingerprinted")
            result = descriptor, fingerprint, raw
            self._validate_lock_binding()
            descriptor = None
            return result
        except ServiceIdentityError:
            raise
        except OSError as error:
            raise ServiceIdentityError(f"service/{name} is missing or unsafe") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _path_fingerprint(self, name: str, *, canonical_identity: bool = False) -> dict[str, object]:
        descriptor: int | None = None
        try:
            descriptor, fingerprint, raw = self._open_auxiliary(name)
            if canonical_identity:
                _decode_state(raw)
            return fingerprint
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _link_exact_identity_fd(
        self,
        source_fd: int,
        destination: str,
        expected_fingerprint: dict[str, object],
        expected_raw: bytes,
        *,
        require_otmpfile: bool,
        after_link_hook: str | None = None,
        after_fsync_hook: str | None = None,
    ) -> None:
        """Link, verify, and durably bind one exact held source descriptor."""

        self._require_process_owner()
        self._validate_lock_binding()
        assert self._service_fd is not None
        source_before_fingerprint, source_before_raw, source_before = _descriptor_fingerprint(source_fd)
        if source_before_fingerprint != expected_fingerprint or source_before_raw != expected_raw:
            raise ServiceIdentityConflict("exact-FD identity source changed before publication")
        before_links = source_before.st_nlink
        _link_identity_fd(
            source_fd,
            destination,
            dir_fd=self._service_fd,
            owner_pid=self._owner_pid,
            expected_fingerprint=expected_fingerprint,
            require_otmpfile=require_otmpfile,
        )
        if after_link_hook is not None:
            self._hook(after_link_hook)

        def validate_link() -> None:
            source_fingerprint, source_raw, source_info = _descriptor_fingerprint(source_fd)
            destination_fd: int | None = None
            try:
                destination_fd, destination_fingerprint, destination_raw = self._open_auxiliary(destination)
                destination_info = os.fstat(destination_fd)
                if (
                    source_fingerprint != expected_fingerprint
                    or destination_fingerprint != expected_fingerprint
                    or source_raw != expected_raw
                    or destination_raw != expected_raw
                    or not _same_file(source_info, destination_info)
                    or source_info.st_nlink != before_links + 1
                    or destination_info.st_nlink != before_links + 1
                    or stat.S_IMODE(source_info.st_mode) != 0o600
                    or stat.S_IMODE(destination_info.st_mode) != 0o600
                ):
                    raise ServiceIdentityConflict("exact-FD identity destination binding changed")
            finally:
                if destination_fd is not None:
                    os.close(destination_fd)

        validate_link()
        self._validate_lock_binding()
        os.fsync(self._service_fd)
        if after_fsync_hook is not None:
            self._hook(after_fsync_hook)
        self._validate_lock_binding()
        validate_link()

    @staticmethod
    def _expected_roles(
        marker: dict[str, object],
        canonical: dict[str, object] | None,
    ) -> dict[str, dict[str, object]]:
        new = _validate_fingerprint(marker["new"], "new identity")
        if marker["kind"] == "create":
            return {"new": new}
        old = _validate_fingerprint(marker["old"], "old identity")
        return {"old": old, "new": new, "swap": old if canonical == new else new}

    def _read_transaction_marker(
        self,
        marker_name: str,
        txid: str,
    ) -> tuple[dict[str, object], dict[str, object]]:
        descriptor: int | None = None
        try:
            descriptor, fingerprint, raw = self._open_auxiliary(marker_name)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise ServiceIdentityError("service identity transaction marker is malformed") from error
            if canonical_bytes(value) != raw:
                raise ServiceIdentityError("service identity transaction marker is not canonical JSON")
            fields = {"schema_version", "txid", "kind", "marker", "old", "new", "roles"}
            if type(value) is not dict or set(value) != fields:
                raise ServiceIdentityError("service identity transaction marker has invalid fields")
            if value["schema_version"] != _TXN_SCHEMA_VERSION or value["txid"] != txid:
                raise ServiceIdentityError("service identity transaction marker identity is invalid")
            if value["kind"] not in {"create", "replace"}:
                raise ServiceIdentityError("service identity transaction kind is invalid")
            marker_signature = value["marker"]
            if (
                type(marker_signature) is not dict
                or set(marker_signature) != _MARKER_SIGNATURE_FIELDS
                or marker_signature != _marker_signature(os.fstat(descriptor))
            ):
                raise ServiceIdentityConflict("service identity transaction marker inode changed")
            expected_names = _transaction_names(txid)
            if type(value["roles"]) is not dict or value["roles"] != expected_names:
                raise ServiceIdentityError("service identity transaction role names are invalid")
            _validate_fingerprint(value["new"], "new identity")
            if value["kind"] == "create":
                if value["old"] is not None:
                    raise ServiceIdentityError("create transaction records an old identity")
            else:
                _validate_fingerprint(value["old"], "old identity")
            return value, fingerprint
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _validate_transaction_artifacts(
        self,
        marker: dict[str, object],
        marker_fingerprint: dict[str, object],
        canonical: dict[str, object] | None,
    ) -> None:
        self._validate_lock_binding()
        names = marker["roles"]
        assert type(names) is dict and self._service_fd is not None
        expected_roles = self._expected_roles(marker, canonical)
        present = set(os.listdir(self._service_fd))
        allowed = set(names.values())
        tx_prefix = f"{_TXN_PREFIX}{marker['txid']}."
        unexpected = {name for name in present if name.startswith(tx_prefix)} - allowed
        if unexpected:
            raise ServiceIdentityConflict("service identity transaction has unknown paths")
        marker_paths = [
            name
            for name in (names["marker"], names["trash_marker"])
            if name in present
        ]
        if len(marker_paths) != 1:
            raise ServiceIdentityConflict("service identity transaction marker path changed")
        if self._path_fingerprint(marker_paths[0]) != marker_fingerprint:
            raise ServiceIdentityConflict("service identity transaction marker changed")
        role_presence: set[str] = set()
        for role, expected in expected_roles.items():
            source = names[role]
            trash = names[f"trash_{role}"]
            if source in present and trash in present:
                raise ServiceIdentityConflict(f"service identity transaction has duplicate {role} paths")
            candidate = source if source in present else trash if trash in present else None
            if candidate is not None:
                role_presence.add(role)
                if self._path_fingerprint(candidate) != expected:
                    raise ServiceIdentityConflict(f"service identity transaction {role} witness changed")
        if marker["kind"] == "create":
            if any(names[role] in present or names[f"trash_{role}"] in present for role in ("old", "swap")):
                raise ServiceIdentityConflict("create transaction contains replacement witnesses")
            allowed_role_sets = {frozenset(), frozenset({"new"})}
        elif canonical == marker["old"]:
            allowed_role_sets = {
                frozenset(),
                frozenset({"new"}),
                frozenset({"new", "old"}),
                frozenset({"new", "old", "swap"}),
            }
        else:
            allowed_role_sets = {
                frozenset(),
                frozenset({"swap"}),
                frozenset({"new", "swap"}),
                frozenset({"old", "new", "swap"}),
            }
        if frozenset(role_presence) not in allowed_role_sets:
            raise ServiceIdentityConflict("service identity transaction witness order is impossible")
        if names["trash_marker"] in present and role_presence:
            raise ServiceIdentityConflict("cleaned transaction marker still has role paths")
        self._validate_lock_binding()

    def _validate_transaction_canonical(
        self,
        expected: dict[str, object] | None,
    ) -> None:
        self._validate_lock_binding()
        if expected is None:
            if self._leaf_exists("identity.json"):
                raise ServiceIdentityConflict("service identity appeared during transaction cleanup")
        elif self._path_fingerprint("identity.json", canonical_identity=True) != expected:
            raise ServiceIdentityConflict("canonical identity changed during transaction cleanup")
        self._validate_lock_binding()

    def _restore_old_identity_witness(
        self,
        old_name: str,
        old_fingerprint: dict[str, object],
    ) -> None:
        """Exchange exact old truth back while preserving an anomalous canonical path."""

        self._validate_lock_binding()
        if self._path_fingerprint(old_name) != old_fingerprint:
            raise ServiceIdentityConflict("service identity old witness changed before rollback")
        if not self._leaf_exists("identity.json"):
            raise ServiceIdentityConflict("service identity disappeared before rollback")
        assert self._service_fd is not None
        _exchange_identity_paths(old_name, "identity.json", dir_fd=self._service_fd)
        self._validate_lock_binding()
        os.fsync(self._service_fd)
        self._validate_lock_binding()
        if self._path_fingerprint("identity.json", canonical_identity=True) != old_fingerprint:
            raise ServiceIdentityConflict("service identity rollback could not restore old truth")

    def _cleanup_transaction_file(
        self,
        source: str,
        trash: str,
        expected: dict[str, object],
        canonical: dict[str, object] | None,
    ) -> None:
        """Quarantine, validate, and unlink one marker-bound exact inode.

        The last validation-to-unlink gap is inside Hound's documented
        cooperative-same-UID boundary; there is no Linux unlink-by-FD.
        """

        self._validate_transaction_canonical(canonical)
        assert self._service_fd is not None
        source_exists = self._leaf_exists(source)
        trash_exists = self._leaf_exists(trash)
        if source_exists and trash_exists:
            raise ServiceIdentityConflict("service identity cleanup paths are ambiguous")
        if not source_exists and not trash_exists:
            return
        candidate = source if source_exists else trash
        descriptor: int | None = None
        try:
            descriptor, fingerprint, _ = self._open_auxiliary(candidate)
            if fingerprint != expected:
                raise ServiceIdentityConflict("service identity cleanup candidate changed")
            if source_exists:
                _rename_identity_noreplace(source, trash, dir_fd=self._service_fd)
                self._validate_lock_binding()
                self._hook("after_identity_quarantine_move")
                self._validate_transaction_canonical(canonical)
                os.fsync(self._service_fd)
                self._validate_transaction_canonical(canonical)
                self._hook("after_identity_quarantine_fsync")
                self._validate_transaction_canonical(canonical)
            moved = self._path_fingerprint(trash)
            held, _, _ = _descriptor_fingerprint(descriptor)
            if moved != expected or held != expected:
                raise ServiceIdentityConflict("service identity quarantine does not name the held inode")
            self._validate_transaction_canonical(canonical)
            before_links = os.fstat(descriptor).st_nlink
            os.unlink(trash, dir_fd=self._service_fd)
            self._validate_transaction_canonical(canonical)
            self._hook("after_identity_quarantine_unlink")
            os.fsync(self._service_fd)
            self._validate_transaction_canonical(canonical)
            if self._leaf_exists(trash) or os.fstat(descriptor).st_nlink != before_links - 1:
                raise ServiceIdentityConflict("service identity quarantine cleanup is uncertain")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _finish_transaction_cleanup(
        self,
        marker: dict[str, object],
        marker_fingerprint: dict[str, object],
        canonical: dict[str, object] | None,
    ) -> None:
        names = marker["roles"]
        assert type(names) is dict
        for role, expected in self._expected_roles(marker, canonical).items():
            self._cleanup_transaction_file(names[role], names[f"trash_{role}"], expected, canonical)
        self._cleanup_transaction_file(
            names["marker"],
            names["trash_marker"],
            marker_fingerprint,
            canonical,
        )
        self._hook("after_identity_marker_cleanup")

    def _recover_transaction(self, marker_name: str, txid: str) -> None:
        marker, marker_fingerprint = self._read_transaction_marker(marker_name, txid)
        names = marker["roles"]
        assert type(names) is dict
        canonical: dict[str, object] | None
        if self._leaf_exists("identity.json"):
            try:
                canonical = self._path_fingerprint("identity.json", canonical_identity=True)
            except ServiceIdentityError as error:
                if marker["kind"] == "replace":
                    for old_name in (names["old"], names["trash_old"]):
                        if self._leaf_exists(old_name) and self._path_fingerprint(old_name) == marker["old"]:
                            self._restore_old_identity_witness(old_name, marker["old"])
                            raise ServiceIdentityConflict(
                                "malformed service identity replacement was preserved during rollback"
                            ) from error
                raise
        else:
            canonical = None
        old = marker["old"]
        new = marker["new"]
        normal = canonical == new or (marker["kind"] == "create" and canonical is None) or canonical == old
        if not normal:
            if marker["kind"] == "replace" and canonical is not None:
                for old_name in (names["old"], names["trash_old"]):
                    if self._leaf_exists(old_name) and self._path_fingerprint(old_name) == old:
                        self._restore_old_identity_witness(old_name, old)
                        raise ServiceIdentityConflict("service identity replacement was preserved during rollback")
            raise ServiceIdentityConflict("service identity transaction canonical path is anomalous")
        self._validate_transaction_artifacts(marker, marker_fingerprint, canonical)
        self._finish_transaction_cleanup(marker, marker_fingerprint, canonical)

    def _preserve_unknown_temp(self, name: str) -> None:
        assert self._service_fd is not None
        destination = f"{_UNTRUSTED_PREFIX}{secrets.token_hex(16)}"
        self._validate_lock_binding()
        _rename_identity_noreplace(name, destination, dir_fd=self._service_fd)
        self._validate_lock_binding()
        os.fsync(self._service_fd)
        self._validate_lock_binding()
        raise ServiceIdentityConflict("unmarked service identity temporary path was preserved")

    def _recover_identity_namespace(self) -> None:
        """Recover only exact marker-bound transaction topology."""

        self._validate_lock_binding()
        assert self._service_fd is not None
        try:
            names = sorted(os.listdir(self._service_fd))
        except OSError as error:
            raise ServiceIdentityError("service identity directory cannot be inventoried") from error
        untrusted = [name for name in names if name.startswith(_UNTRUSTED_PREFIX)]
        if untrusted:
            raise ServiceIdentityConflict("service identity has preserved untrusted paths")
        legacy = [name for name in names if name.startswith(_TEMP_PREFIX)]
        if legacy:
            self._preserve_unknown_temp(legacy[0])
        transaction_paths = [name for name in names if name.startswith(_TXN_PREFIX)]
        if not transaction_paths:
            return
        txids: set[str] = set()
        for name in transaction_paths:
            match = re.match(r"\.identity\.txn\.([0-9a-f]{32})\.", name, re.ASCII)
            if match is None:
                raise ServiceIdentityConflict("service identity has malformed transaction paths")
            txids.add(match.group(1))
        if len(txids) != 1:
            raise ServiceIdentityConflict("service identity has multiple transactions")
        txid = next(iter(txids))
        txn_names = _transaction_names(txid)
        marker_candidates = [
            name for name in (txn_names["marker"], txn_names["trash_marker"]) if name in transaction_paths
        ]
        if len(marker_candidates) != 1:
            raise ServiceIdentityConflict("service identity transaction marker is missing or ambiguous")
        self._recover_transaction(marker_candidates[0], txid)
        self._validate_lock_binding()

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

    @staticmethod
    def _validate_unnamed_identity(
        descriptor: int,
        data: bytes,
        state: ServiceIdentityState,
    ) -> dict[str, object]:
        fingerprint, observed, info = _descriptor_fingerprint(descriptor)
        if info.st_nlink != 0 or observed != data or _decode_state(observed) != state:
            raise ServiceIdentityConflict("unnamed service identity bytes are invalid")
        return fingerprint

    def _persist(self, state: ServiceIdentityState, *, expect_absent: bool = False) -> ServiceIdentityState:
        self._require_anchor()
        raw = _encode_state(state)
        assert self._service_fd is not None
        new_fd: int | None = None
        marker_fd: int | None = None
        old_identity_fd = self._identity_fd
        try:
            if expect_absent:
                self._validate_identity_absent()
            else:
                self._validate_identity_binding()
            try:
                new_fd = os.open(
                    ".",
                    getattr(os, "O_TMPFILE", 0)
                    | os.O_RDWR
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=self._service_fd,
                )
            except OSError as error:
                raise ServiceIdentityError("unnamed service identity files are unavailable") from error
            _validate_link_source_flags(new_fd, require_otmpfile=True)
            os.fchmod(new_fd, 0o600)
            self._hook("before_identity_temp_write")
            self._write_all(new_fd, raw)
            self._hook("after_identity_temp_write")
            os.fsync(new_fd)
            self._hook("after_identity_temp_fsync")
            new_fingerprint = self._validate_unnamed_identity(new_fd, raw, state)
            old_fingerprint = None
            old_raw: bytes | None = None
            if not expect_absent:
                assert old_identity_fd is not None
                old_fingerprint, old_raw, _ = _descriptor_fingerprint(old_identity_fd)
                if old_raw != self._identity_bytes:
                    raise ServiceIdentityConflict("held old identity bytes changed")

            def validate_canonical_before_publication() -> dict[str, object] | None:
                self._validate_lock_binding()
                if expect_absent:
                    self._validate_identity_absent()
                    return None
                assert old_fingerprint is not None and old_identity_fd is not None and old_raw is not None
                held_fingerprint, held_raw, held_info = _descriptor_fingerprint(old_identity_fd)
                visible = self._path_fingerprint("identity.json", canonical_identity=True)
                if (
                    held_fingerprint != old_fingerprint
                    or held_raw != old_raw
                    or visible != old_fingerprint
                    or held_info.st_dev != old_fingerprint["st_dev"]
                    or held_info.st_ino != old_fingerprint["st_ino"]
                ):
                    raise ServiceIdentityConflict("canonical identity changed during transaction preparation")
                return old_fingerprint

            txid = secrets.token_hex(16)
            names = _transaction_names(txid)
            validate_canonical_before_publication()
            marker_fd = os.open(
                names["marker"],
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._service_fd,
            )
            marker = {
                "schema_version": _TXN_SCHEMA_VERSION,
                "txid": txid,
                "kind": "create" if expect_absent else "replace",
                "marker": _marker_signature(os.fstat(marker_fd)),
                "old": old_fingerprint,
                "new": new_fingerprint,
                "roles": names,
            }
            marker_raw = canonical_bytes(marker)
            self._write_all(marker_fd, marker_raw)
            os.fsync(marker_fd)
            os.fsync(self._service_fd)
            marker_fingerprint, observed_marker, _ = _descriptor_fingerprint(marker_fd)
            if observed_marker != marker_raw or self._path_fingerprint(names["marker"]) != marker_fingerprint:
                raise ServiceIdentityConflict("service identity transaction marker changed")
            self._hook("after_identity_marker_fsync")
            canonical_before = validate_canonical_before_publication()
            self._validate_transaction_artifacts(marker, marker_fingerprint, canonical_before)

            self._link_exact_identity_fd(
                new_fd,
                names["new"],
                new_fingerprint,
                raw,
                require_otmpfile=True,
            )
            self._hook("after_identity_new_witness_link")
            canonical_before = validate_canonical_before_publication()
            self._validate_transaction_artifacts(marker, marker_fingerprint, canonical_before)

            if not expect_absent:
                assert old_fingerprint is not None and old_identity_fd is not None and old_raw is not None
                self._link_exact_identity_fd(
                    old_identity_fd,
                    names["old"],
                    old_fingerprint,
                    old_raw,
                    require_otmpfile=False,
                )
                self._hook("after_identity_old_witness_link")
                canonical_before = validate_canonical_before_publication()
                self._validate_transaction_artifacts(marker, marker_fingerprint, canonical_before)
                self._link_exact_identity_fd(
                    new_fd,
                    names["swap"],
                    new_fingerprint,
                    raw,
                    require_otmpfile=True,
                )
                self._hook("after_identity_swap_witness_link")
                canonical_before = validate_canonical_before_publication()
                self._validate_transaction_artifacts(marker, marker_fingerprint, canonical_before)

            os.fsync(self._service_fd)
            self._hook("after_identity_prepared_directory_fsync")
            canonical_before = validate_canonical_before_publication()
            self._validate_transaction_artifacts(marker, marker_fingerprint, canonical_before)
            self._hook("before_identity_publication")
            canonical_before = validate_canonical_before_publication()
            self._validate_transaction_artifacts(marker, marker_fingerprint, canonical_before)

            if expect_absent:
                self._link_exact_identity_fd(
                    new_fd,
                    "identity.json",
                    new_fingerprint,
                    raw,
                    require_otmpfile=True,
                    after_link_hook="after_identity_rename",
                    after_fsync_hook="after_identity_directory_fsync",
                )
            else:
                _exchange_identity_paths(names["swap"], "identity.json", dir_fd=self._service_fd)
                self._hook("after_identity_rename")

            self._validate_lock_binding()
            try:
                published_fingerprint = self._path_fingerprint("identity.json", canonical_identity=True)
            except ServiceIdentityError as error:
                if not expect_absent:
                    assert old_fingerprint is not None
                    self._restore_old_identity_witness(names["old"], old_fingerprint)
                    raise ServiceIdentityConflict(
                        "malformed canonical replacement was preserved during rollback"
                    ) from error
                raise
            if published_fingerprint != new_fingerprint:
                if not expect_absent:
                    assert old_fingerprint is not None
                    self._restore_old_identity_witness(names["old"], old_fingerprint)
                raise ServiceIdentityConflict("published identity does not name the exact new inode")
            if not expect_absent and self._path_fingerprint(names["swap"]) != old_fingerprint:
                assert old_fingerprint is not None
                self._restore_old_identity_witness(names["old"], old_fingerprint)
                raise ServiceIdentityConflict("displaced identity was preserved after an anomalous exchange")

            self._validate_transaction_artifacts(marker, marker_fingerprint, new_fingerprint)
            if not expect_absent:
                os.fsync(self._service_fd)
                self._hook("after_identity_directory_fsync")
            self._finish_transaction_cleanup(marker, marker_fingerprint, new_fingerprint)
            self._validate_lock_binding()
            published = os.fstat(new_fd)
            _private_file(published, "service/identity.json")
            if published.st_nlink != 1 or self._path_fingerprint("identity.json", canonical_identity=True) != new_fingerprint:
                raise ServiceIdentityConflict("published identity cleanup is incomplete")
            if self._identity_fd is not None:
                os.close(self._identity_fd)
            self._identity_fd = new_fd
            self._identity_signature = _bound_signature(published)
            self._identity_bytes = raw
            self._state = state
            new_fd = None
            return state
        except Exception as error:
            self._poisoned = True
            if isinstance(error, (ServiceIdentityError, RuntimeError)):
                raise
            raise ServiceIdentityError("service identity atomic replacement failed") from error
        finally:
            if marker_fd is not None:
                try:
                    os.close(marker_fd)
                except OSError:
                    pass
            if new_fd is not None:
                try:
                    os.close(new_fd)
                except OSError:
                    pass

    @property
    def state(self) -> ServiceIdentityState:
        with self.lease() as state:
            return state

    @contextmanager
    def lease(self) -> Iterator[ServiceIdentityState]:
        self._require_process_owner()
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
        self._require_process_owner()
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
        self._require_process_owner()
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
        self._require_process_owner()
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
        if getattr(self, "_owner_pid", None) != os.getpid():
            self._close_owned_descriptors(unlock=False)
            return
        with mutex:
            self._close_owned_descriptors(unlock=True)

    def _close_owned_descriptors(self, *, unlock: bool) -> None:
        if self._closed:
            return
        self._closed = True
        lock_fd, self._lock_fd = self._lock_fd, None
        identity_fd, self._identity_fd = self._identity_fd, None
        service_fd, self._service_fd = self._service_fd, None
        if unlock and lock_fd is not None and fcntl is not None:
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
