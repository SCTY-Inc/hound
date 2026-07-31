"""HSP-20: disposable SQLite projection rebuilt only from journal truth."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable

from .journal import Journal
from .store import RecordStore, StoreError, UnsafeStoreError


class ProjectionError(StoreError):
    """The disposable projection cannot be rebuilt safely."""


class Projection:
    """A query aid whose rows are never used as canonical truth."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        if self.root.is_symlink():
            raise UnsafeStoreError(f"{self.root} must not be a symlink")
        existed = self.root.exists()
        self.root.mkdir(exist_ok=existed)
        if not existed:
            self.root.chmod(0o700)
        info = self.root.stat()
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise UnsafeStoreError(f"{self.root} is not owned by the current user")
        if info.st_mode & 0o077:
            raise UnsafeStoreError(f"{self.root} has group/world permissions")
        self.path = self.root / "index.sqlite"
        if self.path.exists():
            if self.path.is_symlink() or stat.S_IMODE(self.path.stat().st_mode) & 0o077:
                raise UnsafeStoreError(f"{self.path} has unsafe permissions")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        self.path.chmod(0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    def rebuild(
        self,
        journal: Journal,
        records: RecordStore,
        *,
        fault: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Replace all rows in one SQLite transaction from committed events."""

        events = journal.entries()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP TABLE IF EXISTS entries")
            connection.execute("DROP TABLE IF EXISTS blobs")
            connection.execute(
                """CREATE TABLE entries (
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
            )
            connection.execute(
                """CREATE TABLE blobs (
                    content_sha256 TEXT PRIMARY KEY,
                    byte_length INTEGER NOT NULL
                )"""
            )
            for event in events:
                if fault is not None:
                    fault("during_projection_rebuild")
                record_id = event["artifact"]["record_id"]
                if not records.verify_record(record_id, event["artifact"]["hash"]):
                    raise ProjectionError(f"record {record_id} failed before projection")
                content_sha256 = event["dedupe"]["content_sha256"]
                blob = records.blobs.get(content_sha256)
                producer = event["producer"]
                source = event["source"]
                classification = event["classification"]
                connection.execute(
                    "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event["sequence"],
                        event["entry_id"],
                        event["appended_at"],
                        record_id,
                        event["artifact"]["hash"],
                        event["dedupe"]["object_key"],
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
                    ),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO blobs VALUES (?, ?)",
                    (content_sha256, len(blob)),
                )
            connection.commit()
            return {"valid": True, "entries": len(events), "database": str(self.path)}
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def rows(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        connection = self._connect()
        try:
            return [dict(row) for row in connection.execute("SELECT * FROM entries ORDER BY sequence, entry_id")]
        except sqlite3.Error as error:
            raise ProjectionError("projection is unreadable") from error
        finally:
            connection.close()

    def delete(self) -> None:
        if self.path.exists():
            if self.path.is_symlink():
                raise UnsafeStoreError(f"{self.path} must not be a symlink")
            self.path.unlink()


__all__ = ["Projection", "ProjectionError"]
