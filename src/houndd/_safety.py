"""Anchored directory/file helpers for fail-closed store access."""

from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Type


def _raise(error_type: Type[BaseException], path: Path | str, reason: str) -> None:
    raise error_type(f"{path} {reason}")


def check_private_stat(st: os.stat_result, path: Path | str, *, directory: bool, error_type: Type[BaseException]) -> None:
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        _raise(error_type, path, "is not owned by the current user")
    if stat.S_IMODE(st.st_mode) & 0o077:
        _raise(error_type, path, "has group/world permissions")
    if directory and not stat.S_ISDIR(st.st_mode):
        _raise(error_type, path, "is not a directory")
    if not directory and not stat.S_ISREG(st.st_mode):
        _raise(error_type, path, "is not a regular file")


@dataclass
class _AncestryLink:
    parent_fd: int
    child_fd: int
    name: str


class AnchoredRoot:
    """Openat-style access to one initialized root directory.

    ``operation()`` is the linearization boundary for a public store action.
    It walks the *supplied lexical path* from ``/`` with ``O_NOFOLLOW`` and
    holds every ancestor descriptor until completion. At completion it
    re-walks the lexical spelling and requires every name-to-inode link to
    still match, without treating unrelated sibling churn as unsafe.

    A successful return is linearized at the final validation.  This is not an
    OS sandbox: a same-UID process with raw filesystem access can still race a
    name after that validation or alter durable bytes by other means. A swap
    restored to the same inode before that validation leaves no portable
    observable evidence and is outside this guard's claim.
    """

    def __init__(self, root: Path | str | os.PathLike[str], *, error_type: Type[BaseException], create: bool = False) -> None:
        raw = os.fspath(root)
        if not raw:
            _raise(error_type, root, "must not be empty")
        # Do not let normpath/resolve erase a caller-supplied component before
        # it has been opened with O_NOFOLLOW.  Dot traversal is not a stable
        # supplied ancestry, so reject it rather than silently canonicalizing.
        supplied = [part for part in raw.split(os.sep) if part]
        if any(part in {".", ".."} for part in supplied):
            _raise(error_type, root, "must not contain dot traversal")
        self.path = Path(os.path.abspath(raw))
        self.error_type = error_type
        self._parts = self.path.parts[1:]
        if not self._parts:
            _raise(self.error_type, self.path, "must have a parent directory")
        self.fd: int | None = None
        self._root_stat: os.stat_result | None = None
        self._binding: list[_AncestryLink] | None = None
        # A facade can be shared by callers.  An operation guard is not
        # transferable across threads, so serialize its descriptor lifetime.
        self._operation_lock = threading.RLock()
        try:
            links = self._walk(create=create)
            self.fd = links[-1].child_fd
            self._root_stat = os.fstat(self.fd)
            check_private_stat(self._root_stat, self.path, directory=True, error_type=self.error_type)
            # Ownership of the root fd transfers to us; close only ancestors.
            self._close_links(links, keep={self.fd})
        except Exception:
            self.close()
            raise

    @staticmethod
    def _directory_flags() -> int:
        return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    @staticmethod
    def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino

    def _walk(self, *, create: bool) -> list[_AncestryLink]:
        """Open every supplied component without following a symlink."""

        current = os.open(os.sep, self._directory_flags())
        links: list[_AncestryLink] = []
        try:
            for index, name in enumerate(self._parts):
                try:
                    child = os.open(name, self._directory_flags(), dir_fd=current)
                except FileNotFoundError:
                    if not create or index != len(self._parts) - 1:
                        raise
                    os.mkdir(name, 0o700, dir_fd=current)
                    child = os.open(name, self._directory_flags(), dir_fd=current)
                links.append(_AncestryLink(current, child, name))
                current = child
            return links
        except OSError as error:
            self._close_links(links)
            # ``current`` is either owned by the final link or is the initial
            # slash descriptor.  The former was closed above.
            if not links:
                os.close(current)
            raise self.error_type(f"{self.path} cannot be anchored without following a symlink") from error

    def _require_open(self) -> None:
        if self.fd is None or self._root_stat is None:
            _raise(self.error_type, self.path, "has been closed")

    def _validate_binding(self) -> None:
        self._require_open()
        assert self._binding is not None
        try:
            for link in self._binding:
                visible = os.stat(link.name, dir_fd=link.parent_fd, follow_symlinks=False)
                child_now = os.fstat(link.child_fd)
                if not stat.S_ISDIR(visible.st_mode) or not self._same_file(visible, child_now):
                    _raise(self.error_type, self.path, "supplied ancestry changed during this operation")
            rebound = self._walk(create=False)
            try:
                if len(rebound) != len(self._binding) or any(
                    not self._same_file(os.fstat(now.child_fd), os.fstat(held.child_fd))
                    for now, held in zip(rebound, self._binding)
                ):
                    _raise(self.error_type, self.path, "supplied ancestry no longer names the anchored root")
            finally:
                self._close_links(rebound)
            root_now = os.fstat(self.fd)
            if not self._same_file(root_now, self._root_stat):
                _raise(self.error_type, self.path, "is no longer the anchored root directory")
            check_private_stat(root_now, self.path, directory=True, error_type=self.error_type)
        except OSError as error:
            raise self.error_type(f"{self.path} supplied ancestry is no longer safe") from error

    def _close_binding(self) -> None:
        binding, self._binding = self._binding, None
        if binding is not None:
            self._close_links(binding)

    @staticmethod
    def _close_links(links: list[_AncestryLink], *, keep: set[int] | None = None) -> None:
        for descriptor in {fd for link in links for fd in (link.parent_fd, link.child_fd)} - (keep or set()):
            os.close(descriptor)

    @contextmanager
    def operation(self) -> Iterator["AnchoredRoot"]:
        """Bind and validate the complete original ancestry for one action."""

        with self._operation_lock:
            if self._binding is not None:
                yield self
                return
            self._require_open()
            binding = self._walk(create=False)
            try:
                root_now = os.fstat(binding[-1].child_fd)
                assert self._root_stat is not None
                if not self._same_file(root_now, self._root_stat):
                    _raise(self.error_type, self.path, "is no longer the anchored root directory")
                self._binding = binding
                self._validate_binding()
                try:
                    yield self
                except Exception:
                    raise
                else:
                    self._validate_binding()
            finally:
                self._close_binding()

    def _check_root_identity(self) -> None:
        if self._binding is not None:
            self._validate_binding()
            return
        # Internal callers remain safe when used directly, while public
        # callers keep one binding around their complete operation.
        with self.operation():
            pass

    def close(self) -> None:
        self._close_binding()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self._root_stat = None

    def __enter__(self) -> "AnchoredRoot":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _validate_part(part: str) -> None:
        if not isinstance(part, str) or not part or "/" in part or part in {".", ".."}:
            raise ValueError("path components must be safe relative names")

    def mkdir(self, *parts: str, create: bool = True) -> None:
        if not parts:
            raise ValueError("a directory path is required")
        self._check_root_identity()
        parent_fd = self.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(self.fd)
        try:
            leaf = parts[-1]
            self._validate_part(leaf)
            if create:
                try:
                    os.mkdir(leaf, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                except OSError as error:
                    raise self.error_type(f"{self.path.joinpath(*parts)} cannot be created") from error
            try:
                child_fd = os.open(leaf, self._directory_flags(), dir_fd=parent_fd)
            except OSError as error:
                raise self.error_type(f"{self.path.joinpath(*parts)} is missing or unsafe") from error
            try:
                check_private_stat(os.fstat(child_fd), self.path.joinpath(*parts), directory=True, error_type=self.error_type)
            finally:
                os.close(child_fd)
            self._check_root_identity()
        finally:
            os.close(parent_fd)

    def dirfd(self, *parts: str) -> int:
        self._check_root_identity()
        fd = os.dup(self.fd)
        try:
            for part in parts:
                self._validate_part(part)
                try:
                    next_fd = os.open(part, self._directory_flags(), dir_fd=fd)
                except OSError as error:
                    raise self.error_type(f"{self.path.joinpath(*parts)} is not a safe directory") from error
                os.close(fd)
                fd = next_fd
            self._check_root_identity()
            return fd
        except Exception:
            os.close(fd)
            raise

    def open_file(self, *parts: str, flags: int, mode: int = 0o600) -> int:
        if not parts:
            raise ValueError("a file path is required")
        self._check_root_identity()
        parent_fd = self.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(self.fd)
        fd: int | None = None
        try:
            leaf = parts[-1]
            self._validate_part(leaf)
            try:
                fd = os.open(leaf, flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=parent_fd)
            except OSError as error:
                raise self.error_type(f"{self.path.joinpath(*parts)} is not a safe file") from error
            self._check_root_identity()
            return fd
        except Exception:
            if fd is not None:
                os.close(fd)
            raise
        finally:
            os.close(parent_fd)

    def read_bytes(self, *parts: str) -> bytes:
        self._check_root_identity()
        fd = self.open_file(*parts, flags=os.O_RDONLY)
        try:
            check_private_stat(os.fstat(fd), self.path.joinpath(*parts), directory=False, error_type=self.error_type)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read()
            self._check_root_identity()
            return data
        except OSError as error:
            raise self.error_type(f"{self.path.joinpath(*parts)} cannot be read") from error

    def write_bytes_atomic(self, *parts: str, data: bytes, mode: int = 0o600) -> None:
        if not parts:
            raise ValueError("a file path is required")
        self._check_root_identity()
        parent_fd = self.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(self.fd)
        leaf = parts[-1]
        self._validate_part(leaf)
        temp_name = f".{leaf}.tmp.{os.getpid()}.{os.urandom(8).hex()}"
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=parent_fd)
        try:
            with os.fdopen(temp_fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
            self._check_root_identity()
        except OSError as error:
            raise self.error_type(f"{self.path.joinpath(*parts)} cannot be written") from error
        finally:
            os.close(parent_fd)

    def append_bytes(self, *parts: str, data: bytes) -> None:
        if not parts:
            raise ValueError("a file path is required")
        self._check_root_identity()
        parent_fd = self.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(self.fd)
        leaf = parts[-1]
        self._validate_part(leaf)
        try:
            fd = os.open(leaf, os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            check_private_stat(os.fstat(fd), self.path.joinpath(*parts), directory=False, error_type=self.error_type)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent_fd)
            self._check_root_identity()
        except OSError as error:
            raise self.error_type(f"{self.path.joinpath(*parts)} cannot be written") from error
        finally:
            os.close(parent_fd)

    def listdir(self, *parts: str) -> list[str]:
        self._check_root_identity()
        fd = self.dirfd(*parts)
        try:
            entries = sorted(os.listdir(fd))
        finally:
            os.close(fd)
        self._check_root_identity()
        return entries

    def stat(self, *parts: str) -> os.stat_result:
        self._check_root_identity()
        if not parts:
            info = os.fstat(self.fd)
            self._check_root_identity()
            return info
        fd = self.open_file(*parts, flags=os.O_RDONLY)
        try:
            info = os.fstat(fd)
        finally:
            os.close(fd)
        self._check_root_identity()
        return info

    def lstat(self, *parts: str) -> os.stat_result:
        """Return a no-follow visible stat relative to this bound root."""

        if not parts:
            return self.stat()
        self._check_root_identity()
        parent_fd = self.dirfd(*parts[:-1]) if len(parts) > 1 else os.dup(self.fd)
        try:
            leaf = parts[-1]
            self._validate_part(leaf)
            info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
        self._check_root_identity()
        return info

    def exists(self, *parts: str) -> bool:
        try:
            self.lstat(*parts)
        except FileNotFoundError:
            return False
        return True
