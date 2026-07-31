"""HSP-20: independent verification of records, blobs, journal, idempotency, and projection."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .journal import Journal
from .projection import Projection
from .store import RecordStore, StoreError


def _safe_metadata_file(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    info = path.stat()
    return (
        (not hasattr(os, "getuid") or info.st_uid == os.getuid())
        and not stat.S_IMODE(info.st_mode) & 0o077
    )


def _expected_projection(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in events:
        producer = event["producer"]
        source = event["source"]
        classification = event["classification"]
        rows.append(
            {
                "sequence": event["sequence"],
                "entry_id": event["entry_id"],
                "appended_at": event["appended_at"],
                "record_id": event["artifact"]["record_id"],
                "record_hash": event["artifact"]["hash"],
                "object_key": event["dedupe"]["object_key"],
                "content_sha256": event["dedupe"]["content_sha256"],
                "access": event["access"],
                "policy_id": event["policy_id"],
                "outcome": classification["outcome"],
                "evidence_status": classification["evidence_status"],
                "owner_id": producer["owner_id"],
                "capability": producer["capability"],
                "run_id": producer["run_id"],
                "provider": source["provider"],
                "canonical_url": source["canonical_url"],
            }
        )
    return rows


def verify_store(root: str | Path, *, projection: bool = True) -> dict[str, Any]:
    """Return a non-throwing integrity report whose truth source is the journal."""

    failures: list[str] = []
    report: dict[str, Any] = {"valid": False, "failures": failures}
    try:
        records = RecordStore(root)
        journal = Journal(root)
    except Exception as error:
        failures.append(f"store initialization: {error}")
        return report

    try:
        record_ids = records.record_ids()
        for record_id in record_ids:
            if not records.verify_record(record_id):
                failures.append(f"record verification failed: {record_id}")
    except Exception as error:
        failures.append(f"record inventory: {error}")
        record_ids = []

    try:
        events = journal.entries()
    except Exception as error:
        failures.append(f"journal verification: {error}")
        events = []

    referenced_records: set[str] = set()
    referenced_blobs: set[str] = set()
    for event in events:
        record_id = event["artifact"]["record_id"]
        digest = event["dedupe"]["content_sha256"]
        referenced_records.add(record_id)
        referenced_blobs.add(digest)
        if record_id not in record_ids:
            failures.append(f"orphan journal record: {record_id}")
        elif not records.verify_record(record_id, event["artifact"]["hash"]):
            failures.append(f"journal record hash mismatch: {record_id}")
        try:
            blob = records.blobs.get(digest)
            if len(blob) < 0:  # pragma: no cover - keeps the check visibly byte-based
                failures.append(f"invalid blob length: {digest}")
        except Exception as error:
            failures.append(f"journal blob failure {digest}: {error}")

    for record_id in sorted(set(record_ids) - referenced_records):
        failures.append(f"orphan record: {record_id}")
    try:
        for digest in records.blobs.digests():
            if digest not in referenced_blobs:
                failures.append(f"orphan blob: {digest}")
    except Exception as error:
        failures.append(f"blob inventory: {error}")

    idempotency = Path(root) / "transactions" / "idempotency"
    idempotency_values: dict[str, dict[str, Any]] = {}
    if idempotency.is_dir():
        for path in sorted(idempotency.glob("*.json")):
            if not _safe_metadata_file(path):
                failures.append(f"unsafe idempotency metadata: {path.name}")
                continue
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                idempotency_values[path.stem] = value if isinstance(value, dict) else {}
                if not isinstance(value, dict) or value.get("status") not in {"open", "complete"}:
                    failures.append(f"invalid idempotency metadata: {path.name}")
                if isinstance(value, dict) and value.get("status") == "complete":
                    response = value.get("response", {})
                    event_by_id = {event["entry_id"]: event for event in events}
                    response_entries = response.get("entry_ids", []) if isinstance(response, dict) else []
                    response_records = response.get("record_ids", []) if isinstance(response, dict) else []
                    if (
                        not isinstance(response, dict)
                        or not isinstance(response_entries, list)
                        or not isinstance(response_records, list)
                        or not set(response_entries) <= set(event_by_id)
                        or len(response_entries) != len(response_records)
                        or any(
                            event_by_id[entry_id]["artifact"]["record_id"] != record_id
                            for entry_id, record_id in zip(response_entries, response_records, strict=False)
                        )
                    ):
                        failures.append(f"idempotency response is not journaled: {path.name}")
            except (OSError, UnicodeError, json.JSONDecodeError):
                failures.append(f"unreadable idempotency metadata: {path.name}")

    stages = Path(root) / "transactions" / "stages"
    if stages.is_dir():
        for path in sorted(stages.glob("*.json")):
            if not _safe_metadata_file(path):
                failures.append(f"unsafe transaction stage: {path.name}")
                continue
            try:
                stage = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(stage, dict) or stage.get("status") not in {"open", "prepared", "published", "complete"}:
                    failures.append(f"invalid transaction stage: {path.name}")
                    continue
                if stage.get("transaction_id") != path.stem:
                    failures.append(f"transaction stage identity drift: {path.name}")
                scope_id = stage.get("scope_id")
                if not isinstance(scope_id, str) or scope_id not in idempotency_values:
                    failures.append(f"transaction stage has no idempotency reservation: {path.name}")
                if stage.get("status") == "complete" and idempotency_values.get(scope_id, {}).get("status") != "complete":
                    failures.append(f"completed transaction stage is not idempotent: {path.name}")
                envelope = stage.get("envelope")
                if isinstance(envelope, dict) and envelope.get("entry_id") not in {event["entry_id"] for event in events}:
                    failures.append(f"transaction stage event is not journaled: {path.name}")
            except (OSError, UnicodeError, json.JSONDecodeError):
                failures.append(f"unreadable transaction stage: {path.name}")

    expected_rows = _expected_projection(events)
    if projection:
        try:
            actual_rows = Projection(root).rows()
            if actual_rows != expected_rows:
                failures.append("projection drift")
        except Exception as error:
            failures.append(f"projection verification: {error}")

    report.update(
        {
            "valid": not failures,
            "records": len(record_ids),
            "entries": len(events),
            "blobs": len(referenced_blobs),
            "expected_projection_rows": len(expected_rows),
        }
    )
    return report


__all__ = ["verify_store"]
