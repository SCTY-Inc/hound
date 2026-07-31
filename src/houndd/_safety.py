"""Anchored directory/file helpers for fail-closed store access."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Type


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


class AnchoredRoot:
    """Openat-style access to one initialized root directory."""

    def __init__(self, root: Path, *, error_type: Type[BaseException]) -> None:
        self.path = Path(root)
        self.error_type = error_type
        if self.path.is_symlink():
            _raise(self.error_type, self.path, "must not be a symlink")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(self.path, flags)
        except OSError as error:
            _raise(self.error_type, self.path, "cannot be anchored")
            raise error  # pragma: no cover
        self._root_stat = os.fstat(self.fd)
        check_private_stat(self._root_stat, self.path, directory=True, error_type=self.error_type)

    def _require_open(self) -> None:
        if self.fd is None:
            _raise(self.error_type, self.path, "has been closed")

    def _check_root_identity(self) -> None:
        self._require_open()
        try:
            current = os.lstat(self.path)
        except OSError as error:
            raise self.error_type(f"{self.path} is no longer the anchored root directory") from error
        if not stat.S_ISDIR(current.st_mode):
            _raise(self.error_type, self.path, "is no longer the anchored root directory")
        if (
            current.st_dev != self._root_stat.st_dev
            or current.st_ino != self._root_stat.st_ino
            or current.st_uid != self._root_stat.st_uid
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(self._root_stat.st_mode)
        ):
            _raise(self.error_type, self.path, "is no longer the anchored root directory")

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self) -> "AnchoredRoot":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _validate_part(part: str) -> None:
        if not isinstance(part, str) or not part or "/" in part or part in {".", ".."}:
            raise ValueError("path components must be safe relative names")

    def dirfd(self, *parts: str) -> int:
        self._check_root_identity()
        fd = os.dup(self.fd)
        try:
            for part in parts:
                self._validate_part(part)
                try:
                    next_fd = os.open(
                        part,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=fd,
                    )
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
                fd = os.open(
                    leaf,
                    flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                    dir_fd=parent_fd,
                )
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
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent_fd,
        )
        try:
            with os.fdopen(temp_fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            directory_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0), dir_fd=parent_fd)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
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
            fd = os.open(
                leaf,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            check_private_stat(os.fstat(fd), self.path.joinpath(*parts), directory=False, error_type=self.error_type)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            directory_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0), dir_fd=parent_fd)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
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
