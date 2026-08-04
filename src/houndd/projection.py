"""HSP-20: disposable SQLite projection rebuilt only from journal truth."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

from ._safety import AnchoredRoot, check_private_stat
from .journal import Journal
from .store import RecordStore, StoreError, UnsafeStoreError


class ProjectionError(StoreError):
    """The disposable projection cannot be rebuilt safely."""


_ENTRIES_SCHEMA = """CREATE TABLE entries (
    sequence INTEGER NOT NULL,
    entry_id TEXT PRIMARY KEY,
    appended_at TEXT NOT NULL,
    record_id TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    object_key TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    access TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    run_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    canonical_url TEXT NOT NULL
)"""
_BLOBS_SCHEMA = """CREATE TABLE blobs (
    content_sha256 TEXT PRIMARY KEY,
    byte_length INTEGER NOT NULL
)"""
_INSERT_ENTRY = "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
_INSERT_BLOB = "INSERT OR IGNORE INTO blobs VALUES (?, ?)"
# Rows the blobs table must hold, derived from the entries table alone.  Only a
# completed, non-legacy outcome stages a blob (see ``_derive_rows``).
_DERIVED_BLOB_KEYS = "SELECT content_sha256 FROM entries WHERE outcome = 'completed' AND substr(object_key, 1, 7) <> 'legacy:'"


def _create_schema(connection: sqlite3.Connection) -> None:
    """Create the one projection schema both drivers write."""

    connection.execute(_ENTRIES_SCHEMA)
    connection.execute(_BLOBS_SCHEMA)


def _derive_rows(event: Mapping[str, Any], records: RecordStore) -> tuple[tuple[Any, ...], tuple[str, int] | None]:
    """Derive one committed event's ``entries`` row and its optional ``blobs`` row.

    This is the sole row derivation in the projection: the full rebuild and
    the incremental append both drive it, so an incrementally maintained
    projection cannot diverge from a from-scratch rebuild.  Each call verifies
    exactly one record and reads at most one staged object, so it is the unit
    both drivers are measured in.
    """

    record_id = event["artifact"]["record_id"]
    if not records.verify_record(record_id, event["artifact"]["hash"]):
        raise ProjectionError(f"record {record_id} failed before projection")
    content_sha256 = event["dedupe"]["content_sha256"]
    object_key = event["dedupe"]["object_key"]
    # Only a completed outcome commits dereferenceable content: a completed
    # import preserves exact bytes under its legacy record ID, every other
    # completed artifact stages a blob, and non-completed outcomes carry a
    # commitment with no object.
    blob_row: tuple[str, int] | None = None
    if event["classification"]["outcome"] == "completed":
        if object_key.startswith("legacy:"):
            legacy_body = records.read(object_key[len("legacy:"):])
            if hashlib.sha256(legacy_body).hexdigest() != content_sha256:
                raise ProjectionError(f"legacy content {object_key} does not match its digest")
        else:
            blob_row = (content_sha256, len(records.blobs.get(content_sha256)))
    producer = event["producer"]
    source = event["source"]
    classification = event["classification"]
    entry_row = (
        event["sequence"],
        event["entry_id"],
        event["appended_at"],
        record_id,
        event["artifact"]["hash"],
        object_key,
        content_sha256,
        event["access"],
        event["policy_id"],
        classification["outcome"],
        classification["evidence_status"],
        producer["owner_id"],
        producer["capability"],
        producer["run_id"],
        source["provider"],
        source["canonical_url"],
    )
    return entry_row, blob_row


class Projection:
    """A query aid whose rows are never used as canonical truth."""

    _TEMP_PREFIX = ".index.sqlite.tmp."

    @staticmethod
    def _supplied_path_has_symlink(path: Path) -> bool:
        """Detect a dangling symlink in any lexical root component."""

        current = Path(os.sep)
        for part in path.parts[1:]:
            current /= part
            if current.is_symlink():
                return True
        return False

    def __init__(self, root: str | os.PathLike[str], *, create: bool = False) -> None:
        raw = os.fspath(root)
        supplied_parts = [part for part in raw.split(os.sep) if part]
        self._unsafe_supplied_spelling = not raw or any(part in {".", ".."} for part in supplied_parts)
        self.root = Path(os.path.abspath(raw))
        self.path = self.root / "index.sqlite"
        self.anchor: AnchoredRoot | None = None
        try:
            self.anchor = AnchoredRoot(root, error_type=UnsafeStoreError, create=create)
            self.root = self.anchor.path
            self.path = self.root / "index.sqlite"
            if self.anchor is not None:
                with self.anchor.operation():
                    if "index.sqlite" in self.anchor.listdir():
                        check_private_stat(self.anchor.stat("index.sqlite"), self.path, directory=False, error_type=UnsafeStoreError)
        except UnsafeStoreError:
            # A dangling root symlink reports false from ``Path.exists()``,
            # but it is still an unsafe supplied component, not a missing
            # optional projection directory.
            if create or self._unsafe_supplied_spelling or os.path.lexists(self.root) or self._supplied_path_has_symlink(self.root):
                self.close()
                raise
        except Exception:
            self.close()
            raise

    def _ensure_anchor(self, *, create: bool = False) -> AnchoredRoot:
        if self.anchor is not None:
            return self.anchor
        self.anchor = AnchoredRoot(self.root, error_type=UnsafeStoreError, create=create)
        self.root = self.anchor.path
        self.path = self.root / "index.sqlite"
        return self.anchor

    def close(self) -> None:
        anchor = getattr(self, "anchor", None)
        if anchor is not None:
            anchor.close()

    def __enter__(self) -> "Projection":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _open_index(self, anchor: AnchoredRoot) -> tuple[int, os.stat_result]:
        """Open the projection leaf once, without ever handing SQLite its name.

        SQLite canonicalizes ``/proc/self/fd/<fd>`` before opening it, which
        reintroduces a leaf-name race.  We therefore copy bytes between this
        held descriptor and an in-memory SQLite connection instead.
        """

        # This helper is intentionally read-only.  Publication never opens
        # the visible leaf for writing, so a failed rebuild cannot corrupt a
        # prior usable projection.
        directory_before = anchor.stat()
        visible = self._visible_index_stat(anchor)
        descriptor = anchor.open_file("index.sqlite", flags=os.O_RDONLY)
        try:
            info = os.fstat(descriptor)
            self._check_private_index(info)
            directory_after = anchor.stat()
            if (
                not self._same_file(visible, info)
                or visible.st_ctime_ns != info.st_ctime_ns
                or not self._same_directory_generation(directory_before, directory_after)
            ):
                raise UnsafeStoreError(f"{self.path} changed while it was opened")
            return descriptor, info
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino

    @staticmethod
    def _same_directory_generation(left: os.stat_result, right: os.stat_result) -> bool:
        """Return whether an anchored directory was untouched between checks."""

        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_ctime_ns == right.st_ctime_ns
            and left.st_mtime_ns == right.st_mtime_ns
        )

    def _check_private_index(self, info: os.stat_result) -> None:
        check_private_stat(info, self.path, directory=False, error_type=UnsafeStoreError)
        if info.st_nlink != 1:
            raise UnsafeStoreError(f"{self.path} must have exactly one link")

    def _visible_stat(self, anchor: AnchoredRoot, leaf: str) -> os.stat_result:
        """lstat one direct child through a duplicate of the anchored fd."""

        directory_fd = anchor.dirfd()
        try:
            return os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        finally:
            os.close(directory_fd)

    def _visible_index_stat(self, anchor: AnchoredRoot) -> os.stat_result:
        """lstat the visible leaf from the anchored directory, never following it."""

        info = self._visible_stat(anchor, "index.sqlite")
        self._check_private_index(info)
        return info

    def _assert_index_absent(self, anchor: AnchoredRoot) -> None:
        directory_before = anchor.stat()
        try:
            self._visible_index_stat(anchor)
        except FileNotFoundError:
            directory_after = anchor.stat()
            if not self._same_directory_generation(directory_before, directory_after):
                raise UnsafeStoreError(f"{self.path} changed while its absence was checked")
        else:
            raise UnsafeStoreError(f"{self.path} unexpectedly exists")
        # Filesystem directory timestamps can have coarser granularity than
        # this operation.  Recheck the no-follow name once so a replacement
        # created after the first absent lstat cannot be acknowledged absent.
        try:
            self._visible_index_stat(anchor)
        except FileNotFoundError:
            return
        raise UnsafeStoreError(f"{self.path} unexpectedly exists")

    def _check_private_temp(self, info: os.stat_result, name: str) -> None:
        path = self.root / name
        check_private_stat(info, path, directory=False, error_type=UnsafeStoreError)
        if info.st_nlink != 1:
            raise UnsafeStoreError(f"{path} must have exactly one link")

    def _reclaim_stale_temps(self, anchor: AnchoredRoot) -> None:
        """Remove prior private publication temps before a new rebuild.

        Temp names are never followed.  A candidate must remain the exact
        private inode opened through the anchored root before it is removed;
        anything else fails closed rather than being treated as recoverable.
        """

        names = [name for name in anchor.listdir() if name.startswith(self._TEMP_PREFIX)]
        directory_fd = anchor.dirfd()
        try:
            for name in names:
                descriptor = anchor.open_file(name, flags=os.O_RDONLY)
                try:
                    held = os.fstat(descriptor)
                    self._check_private_temp(held, name)
                    visible = self._visible_stat(anchor, name)
                    self._check_private_temp(visible, name)
                    visible_after_open = self._visible_stat(anchor, name)
                    if (
                        not self._same_file(visible, held)
                        or visible.st_ctime_ns != held.st_ctime_ns
                        or not self._same_file(visible_after_open, held)
                        or visible_after_open.st_ctime_ns != held.st_ctime_ns
                    ):
                        raise UnsafeStoreError(f"{self.root / name} changed while stale state was reclaimed")
                    os.unlink(name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    if os.fstat(descriptor).st_nlink != 0:
                        raise UnsafeStoreError(f"{self.root / name} was not reclaimed")
                    try:
                        self._visible_stat(anchor, name)
                    except FileNotFoundError:
                        continue
                    raise UnsafeStoreError(f"{self.root / name} was replaced while stale state was reclaimed")
                finally:
                    os.close(descriptor)
        finally:
            os.close(directory_fd)

    def _validate_bound_index(self, anchor: AnchoredRoot, descriptor: int, opened: os.stat_result) -> None:
        """Reject replacement, symlink, or swap-back races before acknowledging work."""

        directory_before = anchor.stat()
        held = os.fstat(descriptor)
        self._check_private_index(held)
        # A rename-away/rename-back changes ctime even if dev/ino are restored.
        if (
            not self._same_file(held, opened)
            or held.st_ctime_ns != opened.st_ctime_ns
            or held.st_nlink != opened.st_nlink
        ):
            raise UnsafeStoreError(f"{self.path} changed while it was in use")
        visible = self._visible_index_stat(anchor)
        held_after_visible = os.fstat(descriptor)
        self._check_private_index(held_after_visible)
        if (
            not self._same_file(visible, held_after_visible)
            or visible.st_ctime_ns != held_after_visible.st_ctime_ns
            or held_after_visible.st_nlink != opened.st_nlink
        ):
            raise UnsafeStoreError(f"{self.path} is no longer the opened projection")
        directory_after = anchor.stat()
        if not self._same_directory_generation(directory_before, directory_after):
            raise UnsafeStoreError(f"{self.path} changed while it was validated")

    @staticmethod
    def _read_descriptor(descriptor: int, size: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining:
            raise ProjectionError("projection changed while it was being read")
        return b"".join(chunks)

    @staticmethod
    def _write_descriptor(descriptor: int, data: bytes) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write either writes or raises
                raise OSError("could not write projection")
            view = view[written:]
        os.fsync(descriptor)

    def _cleanup_temp(self, anchor: AnchoredRoot, directory_fd: int, name: str, descriptor: int | None) -> None:
        """Remove only the temp leaf we still hold; never delete a replacement."""

        if descriptor is None:
            return
        try:
            held = os.fstat(descriptor)
            visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if self._same_file(held, visible) and held.st_ctime_ns == visible.st_ctime_ns:
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            # A surviving private temp cannot be read as the projection.  Do
            # not risk unlinking a same-UID replacement while handling the
            # original failure.
            pass

    def _validate_published_index(self, anchor: AnchoredRoot, descriptor: int, data: bytes) -> None:
        """Prove the visible leaf is the just-serialized, held temp file."""

        directory_before = anchor.stat()
        visible = self._visible_index_stat(anchor)
        held = os.fstat(descriptor)
        self._check_private_index(held)
        if not self._same_file(visible, held) or visible.st_ctime_ns != held.st_ctime_ns:
            raise UnsafeStoreError(f"{self.path} is no longer the published projection")
        read_fd = anchor.open_file("index.sqlite", flags=os.O_RDONLY)
        try:
            read_info = os.fstat(read_fd)
            self._check_private_index(read_info)
            if (
                not self._same_file(read_info, held)
                or read_info.st_ctime_ns != held.st_ctime_ns
                or self._read_descriptor(read_fd, read_info.st_size) != data
            ):
                raise UnsafeStoreError(f"{self.path} does not match the published projection")
        finally:
            os.close(read_fd)
        # This final fstat and generation check catch a replacement after the
        # no-follow visible lstat, including a rename-away/rename-back.
        held_after_read = os.fstat(descriptor)
        self._check_private_index(held_after_read)
        directory_after = anchor.stat()
        if (
            not self._same_file(held_after_read, held)
            or held_after_read.st_ctime_ns != held.st_ctime_ns
            or held_after_read.st_nlink != 1
            or not self._same_directory_generation(directory_before, directory_after)
        ):
            raise UnsafeStoreError(f"{self.path} changed while publication was validated")

    def _publish(self, anchor: AnchoredRoot, data: bytes) -> None:
        """Atomically replace the visible projection from a private temp leaf."""

        directory_fd = anchor.dirfd()
        temp_name = f"{self._TEMP_PREFIX}{os.urandom(16).hex()}"
        temp_fd: int | None = None
        replaced = False
        try:
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            self._write_descriptor(temp_fd, data)
            temp_info = os.fstat(temp_fd)
            self._check_private_index(temp_info)
            if temp_info.st_size != len(data):
                raise ProjectionError("temporary projection has an unexpected size")

            # Validate complete bytes through a second no-follow descriptor;
            # SQLite never receives either pathname.
            checked_fd = anchor.open_file(temp_name, flags=os.O_RDONLY)
            try:
                checked = os.fstat(checked_fd)
                self._check_private_index(checked)
                if (
                    not self._same_file(temp_info, checked)
                    or temp_info.st_ctime_ns != checked.st_ctime_ns
                    or checked.st_nlink != 1
                    or self._read_descriptor(checked_fd, checked.st_size) != data
                ):
                    raise UnsafeStoreError(f"{self.path} temporary projection changed while it was validated")
            finally:
                os.close(checked_fd)

            os.replace(temp_name, "index.sqlite", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            replaced = True
            os.fsync(directory_fd)
            self._validate_published_index(anchor, temp_fd, data)
        finally:
            if not replaced:
                self._cleanup_temp(anchor, directory_fd, temp_name, temp_fd)
            if temp_fd is not None:
                os.close(temp_fd)
            os.close(directory_fd)

    def _connect(self, descriptor: int, opened: os.stat_result, *, read_only: bool) -> sqlite3.Connection:
        """Use SQLite in memory, with the store database held by ``descriptor``.

        The descriptor remains open until its connection is closed by the
        caller.  This avoids SQLite's pathname canonicalization and also
        prevents on-disk journal/WAL sidecars from being created through a
        mutable leaf name.
        """

        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(self._read_descriptor(descriptor, opened.st_size))
            connection.execute("PRAGMA secure_delete=ON")
            if read_only:
                connection.execute("PRAGMA query_only=ON")
            connection.row_factory = sqlite3.Row
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _insert_rows(
        connection: sqlite3.Connection,
        events: Sequence[Mapping[str, Any]],
        records: RecordStore,
        *,
        fault: Callable[[str], None] | None,
        phase: str,
    ) -> None:
        """Insert the derived rows for ``events`` into an open transaction."""

        for event in events:
            if fault is not None:
                fault(phase)
            entry_row, blob_row = _derive_rows(event, records)
            connection.execute(_INSERT_ENTRY, entry_row)
            if blob_row is not None:
                connection.execute(_INSERT_BLOB, blob_row)

    def rebuild(
        self,
        journal: Journal,
        records: RecordStore,
        *,
        fault: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Replace all rows in one SQLite transaction from committed events."""

        anchor = self._ensure_anchor(create=True)
        with anchor.operation():
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            self._reclaim_stale_temps(anchor)
            events = journal.entries()
            directory_before_build = anchor.stat()
            connection: sqlite3.Connection | None = None
            # Build the whole database in memory before touching the visible
            # leaf.  A failed build or temp write therefore leaves the prior
            # projection byte-for-byte usable.
            connection = sqlite3.connect(":memory:")
            connection.execute("PRAGMA secure_delete=ON")
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            _create_schema(connection)
            self._insert_rows(connection, events, records, fault=fault, phase="during_projection_rebuild")
            connection.commit()
            directory_before_publish = anchor.stat()
            if not self._same_directory_generation(directory_before_build, directory_before_publish):
                raise UnsafeStoreError(f"{self.path} changed while the projection was rebuilt")
            self._publish(anchor, connection.serialize())
            # _validate_published_index checks root identity and the final
            # directory generation.  Keep this explicit final identity check
            # so success is never returned through a renamed-away root.
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            result = {"valid": True, "entries": len(events), "database": "index.sqlite"}
            if connection is not None:
                connection.close()
            return result

    @staticmethod
    def _assert_appends_onto(connection: sqlite3.Connection, events: Sequence[Mapping[str, Any]]) -> None:
        """Prove the loaded projection is the full rebuild of the prefix before ``events``.

        The proof is structural and reads no record or blob: the schema is the
        one ``_create_schema`` writes, the entries hold exactly the contiguous
        journal prefix ``0..events[0].sequence - 1``, the blobs hold exactly
        the keys that prefix derives, and ``events`` themselves are the next
        contiguous run.  Anything else is unproven, so it raises and the caller
        rebuilds instead.
        """

        schema = {row["name"]: row["sql"] for row in connection.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")}
        if schema != {"entries": _ENTRIES_SCHEMA, "blobs": _BLOBS_SCHEMA}:
            raise ProjectionError("projection schema is not the rebuild schema")
        counts = connection.execute("SELECT COUNT(*) AS rows, COUNT(DISTINCT sequence) AS sequences, MIN(sequence) AS lowest, MAX(sequence) AS highest FROM entries").fetchone()
        rows = counts["rows"]
        if rows and (counts["lowest"] != 0 or counts["highest"] != rows - 1 or counts["sequences"] != rows):
            raise ProjectionError("projection is not a contiguous journal prefix")
        expected = 0 if not rows else counts["highest"] + 1
        for offset, event in enumerate(events):
            if event["sequence"] != expected + offset:
                raise ProjectionError("appended events do not continue the projection")
        orphans = connection.execute(f"SELECT COUNT(*) AS orphans FROM blobs WHERE content_sha256 NOT IN ({_DERIVED_BLOB_KEYS})").fetchone()["orphans"]
        derived = connection.execute(f"SELECT COUNT(*) AS derived FROM (SELECT DISTINCT content_sha256 FROM ({_DERIVED_BLOB_KEYS}))").fetchone()["derived"]
        held = connection.execute("SELECT COUNT(*) AS held FROM blobs").fetchone()["held"]
        if orphans or held != derived:
            raise ProjectionError("projection blobs do not match its entries")

    def append(
        self,
        events: Sequence[Mapping[str, Any]],
        records: RecordStore,
        *,
        fault: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Add rows for newly committed ``events`` to the published projection.

        This is the O(1)-per-event driver of the same ``_derive_rows``
        derivation the full rebuild uses, so its result is the rebuild's
        result: identical schema and identical row set.  It applies only where
        it can prove that (see ``_assert_appends_onto``) and raises
        ``ProjectionError`` otherwise; a caller that cannot tolerate a refusal
        must fall back to ``rebuild``, which is unconditional.  Publication is
        the rebuild's: the new database is built in memory and replaces the
        visible leaf atomically, so a failure anywhere leaves the prior
        projection byte-for-byte usable.
        """

        if not events:
            raise ProjectionError("incremental append requires at least one event")
        anchor = self._ensure_anchor()
        with anchor.operation():
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            self._reclaim_stale_temps(anchor)
            if "index.sqlite" not in anchor.listdir():
                self._assert_index_absent(anchor)
                raise ProjectionError("no published projection to append to")
            descriptor, opened = self._open_index(anchor)
            directory_before_build = anchor.stat()
            connection: sqlite3.Connection | None = None
            try:
                try:
                    connection = self._connect(descriptor, opened, read_only=False)
                    self._assert_appends_onto(connection, events)
                    connection.execute("BEGIN IMMEDIATE")
                    self._insert_rows(connection, events, records, fault=fault, phase="during_projection_append")
                    connection.commit()
                    entries = connection.execute("SELECT COUNT(*) AS rows FROM entries").fetchone()["rows"]
                except sqlite3.Error as error:
                    raise ProjectionError("projection cannot be appended to") from error
                # The rows were derived from the database this descriptor still
                # names, so prove that is still the published projection before
                # replacing it with them.
                self._validate_bound_index(anchor, descriptor, opened)
                directory_before_publish = anchor.stat()
                if not self._same_directory_generation(directory_before_build, directory_before_publish):
                    raise UnsafeStoreError(f"{self.path} changed while the projection was appended to")
                self._publish(anchor, connection.serialize())
                check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
                return {"valid": True, "entries": entries, "database": "index.sqlite"}
            finally:
                if connection is not None:
                    connection.close()
                os.close(descriptor)

    def rows(self) -> list[dict[str, Any]]:
        if self.anchor is None and not self.root.exists():
            return []
        anchor = self._ensure_anchor()
        with anchor.operation():
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            if "index.sqlite" not in anchor.listdir():
                self._assert_index_absent(anchor)
                return []
            descriptor, opened = self._open_index(anchor)
            connection: sqlite3.Connection | None = None
            try:
                connection = self._connect(descriptor, opened, read_only=True)
                rows = [dict(row) for row in connection.execute("SELECT * FROM entries ORDER BY sequence, entry_id")]
                self._validate_bound_index(anchor, descriptor, opened)
                return rows
            except sqlite3.Error as error:
                raise ProjectionError("projection is unreadable") from error
            finally:
                if connection is not None:
                    connection.close()
                os.close(descriptor)

    def delete(self) -> None:
        if self.anchor is None and not self.root.exists():
            return
        anchor = self._ensure_anchor()
        with anchor.operation():
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            if "index.sqlite" not in anchor.listdir():
                self._assert_index_absent(anchor)
                return
            descriptor, opened = self._open_index(anchor)
            directory_fd = anchor.dirfd()
            try:
                self._validate_bound_index(anchor, descriptor, opened)
                os.unlink("index.sqlite", dir_fd=directory_fd)
                # Successful unlink plus this sync is the delete linearization
                # point.  Everything below is validation, not a retry loop.
                os.fsync(directory_fd)
                held = os.fstat(descriptor)
                if held.st_nlink != 0:
                    raise UnsafeStoreError(f"{self.path} was not unlinked")
                self._assert_index_absent(anchor)
            finally:
                os.close(directory_fd)
                os.close(descriptor)


__all__ = ["Projection", "ProjectionError"]
