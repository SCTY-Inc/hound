"""HSP-20: independent verification of records, blobs, journal, idempotency, and projection."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .contracts import canonical_request_hash, validate_request
from .journal import Journal
from .projection import Projection
from .store import RecordStore, StoreError
from .transactions import TransactionCoordinator


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
    root_path = Path(root)
    if root_path.is_symlink() or not root_path.exists():
        failures.append(f"store root missing or unsafe: {root_path}")
        return report
    try:
        with ExitStack() as stack:
            records = stack.enter_context(RecordStore(root_path, create=False))
            journal = stack.enter_context(Journal(root_path, create=False))
            transactions = stack.enter_context(TransactionCoordinator(root_path, create=False))
            projection_store = stack.enter_context(Projection(root_path)) if projection else None

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

            try:
                stage_names = [name for name in transactions.anchor.listdir("transactions", "stages") if name.endswith(".json")]
                idempotency_names = [name for name in transactions.anchor.listdir("transactions", "idempotency") if name.endswith(".json")]
            except Exception as error:
                failures.append(f"transaction inventory: {error}")
                stage_names = []
                idempotency_names = []

            observed_scope_ids: set[str] = set()

            for name in stage_names:
                try:
                    stage = transactions._load_metadata("transactions", "stages", name)
                    if stage.get("transaction_id") != Path(name).stem:
                        raise ValueError("transaction stage identity drifted")
                    request = validate_request(stage["request"])
                    scope_id = transactions._scope_id(stage["principal"], stage["capability"], request["idempotency_key"])
                    request_hash = canonical_request_hash(request)
                    idempotency = transactions._load_metadata("transactions", "idempotency", f"{scope_id}.json")
                    transactions._validate_reservation(
                        stage,
                        idempotency,
                        request=request,
                        principal=stage["principal"],
                        capability=stage["capability"],
                        request_hash=request_hash,
                        scope_id=scope_id,
                        transaction_id=stage["transaction_id"],
                        require_complete=False,
                    )
                    observed_scope_ids.add(scope_id)
                except Exception as error:
                    failures.append(f"transaction stage verification {name}: {error}")

            for name in idempotency_names:
                try:
                    idempotency = transactions._load_metadata("transactions", "idempotency", name)
                    if idempotency.get("scope_id") != Path(name).stem:
                        raise ValueError("idempotency metadata identity drifted")
                    if idempotency["scope_id"] not in observed_scope_ids:
                        stage_name = f"{idempotency['transaction_id']}.json"
                        transactions._load_metadata("transactions", "stages", stage_name)
                        raise ValueError("idempotency metadata has no validated counterpart")
                except Exception as error:
                    failures.append(f"idempotency verification {name}: {error}")

            expected_rows = _expected_projection(events)
            if projection and projection_store is not None:
                try:
                    actual_rows = projection_store.rows()
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
    except Exception as error:
        failures.append(f"store initialization: {error}")
        return report


__all__ = ["verify_store"]
