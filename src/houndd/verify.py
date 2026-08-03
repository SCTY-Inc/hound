"""HSP-20: independent verification of records, blobs, journal, idempotency, and projection."""

from __future__ import annotations

import hashlib
import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .contracts import canonical_bytes, canonical_request_hash, validate_request
from .adapter_validation import AdapterOutcomeError, validate_adapter_outcome
from ._safety import AnchoredRoot
from .journal import Journal
from .projection import Projection
from .store import RecordStore, StoreError
from .transactions import TransactionCoordinator


_RECORD_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
_OUTCOME_SCHEMAS = frozenset({"houndd.import-outcome.v1", "houndd.file-record.v1", "houndd.search-record.v1", "houndd.url-record.v1", "houndd.quarantine-record.v1"})
_ADAPTER_SCHEMAS = frozenset({"houndd.search-record.v1", "houndd.url-record.v1", "houndd.quarantine-record.v1"})
def _verify_adapter_outcome(records: RecordStore, event: dict[str, Any], record: Any, schema: str, record_id: str, dedupe: Any, referenced_blobs: set[str]) -> None:
    """Bind one Slice 3C2 outcome record to its exact journal event."""

    if type(record) is not dict or record.get("schema_version") != schema:
        raise ValueError("adapter outcome record is malformed")
    try:
        outcome = validate_adapter_outcome(record, event, record_id=record_id)
    except AdapterOutcomeError as error:
        raise ValueError("adapter outcome does not bind the journal event") from error
    if not outcome.staged:
        return
    digest = record["content_sha256"]
    length = record["byte_length"]
    if len(records.blobs.get(digest)) != length:
        raise ValueError("adapter content blob length does not bind its record")
    referenced_blobs.add(digest)


def _safe_record_id(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 255
        and all(char in _RECORD_ID_CHARS for char in value)
    )


def _verify_legacy_manifests(
    records: RecordStore,
    record_ids: list[str],
    failures: list[str],
) -> set[str]:
    """Verify every persisted legacy witness, including unpaired witnesses."""

    try:
        names = records.anchor.listdir("legacy")
    except Exception as error:
        failures.append(f"legacy manifest inventory: {error}")
        return set()

    observed_ids: set[str] = set()
    for name in names:
        try:
            if type(name) is not str or not name.endswith(".json") or len(name) <= 5:
                raise ValueError("legacy manifest name is malformed")
            filename_id = name[:-5]
            if not _safe_record_id(filename_id):
                raise ValueError("legacy manifest name is malformed")
            if filename_id not in record_ids:
                # The filename alone is a durable claim about a legacy
                # record.  Classify the missing counterpart without opening
                # attacker-controlled manifest bytes.
                failures.append(f"orphan legacy manifest: {filename_id}")
                continue

            raw = records.anchor.read_bytes("legacy", name)
            try:
                manifest = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ValueError("legacy manifest is not canonical JSON") from error
            if type(manifest) is not dict or set(manifest) != {"record_id", "sha256", "byte_length"}:
                raise ValueError("legacy manifest schema is malformed")
            record_id = manifest["record_id"]
            digest = manifest["sha256"]
            byte_length = manifest["byte_length"]
            if (
                not _safe_record_id(record_id)
                or record_id != filename_id
                or type(digest) is not str
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or type(byte_length) is not int
                or byte_length < 0
                or canonical_bytes(manifest) != raw
            ):
                raise ValueError("legacy manifest values are malformed")
            data = records.read(record_id)
            if (
                len(data) != byte_length
                or hashlib.sha256(data).hexdigest() != digest
                or not records.verify_record(record_id, digest)
            ):
                raise ValueError("legacy manifest does not bind its record")
            if record_id in observed_ids:
                raise ValueError("duplicate legacy manifest identity")
            observed_ids.add(record_id)
        except Exception as error:
            failures.append(f"legacy manifest verification {name}: {error}")
    return observed_ids


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
    try:
        with ExitStack() as stack:
            root_anchor = stack.enter_context(AnchoredRoot(root, error_type=StoreError, create=False))
            stack.enter_context(root_anchor.operation())
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

            legacy_manifest_ids = _verify_legacy_manifests(records, record_ids, failures)

            try:
                events = journal.entries()
            except Exception as error:
                failures.append(f"journal verification: {error}")
                events = []

            referenced_records: set[str] = set()
            referenced_blobs: set[str] = set()
            outcome_event_counts: dict[str, int] = {}
            for event in events:
                """Verify public 3C1 import truth without inventing a blob.

                A legacy import intentionally preserves caller supplied record
                identity and raw bytes.  It therefore has an outcome record in
                the normal content-addressed store *and* a legacy raw record,
                but no canonical blob for the raw bytes.  Treating the latter
                as an orphan (or requiring a blob for it) would make a valid
                import fail after restart.  The exception is deliberately
                narrow and derives every additional reference from the
                journal-linked outcome record.
                """
                try:
                    artifact = event["artifact"]
                    dedupe = event["dedupe"]
                    record_id = artifact["record_id"]
                    digest = dedupe["content_sha256"]
                    if type(record_id) is not str or type(digest) is not str:
                        raise ValueError("event record identity is malformed")
                    referenced_records.add(record_id)
                    if record_id not in record_ids:
                        failures.append(f"orphan journal record: {record_id}")
                        continue
                    if not records.verify_record(record_id, artifact["hash"]):
                        failures.append(f"journal record hash mismatch: {record_id}")
                        continue
                    schema = artifact.get("schema")
                    try:
                        record = records.read_json(record_id)
                    except StoreError:
                        record = None
                    if (
                        type(record) is dict
                        and record.get("schema_version") in _OUTCOME_SCHEMAS
                        and schema != record["schema_version"]
                    ):
                        raise ValueError("outcome record schema does not bind the journal event")
                    if schema in _OUTCOME_SCHEMAS:
                        outcome_event_counts[record_id] = outcome_event_counts.get(record_id, 0) + 1
                    if schema == "houndd.import-outcome.v1":
                        outcome = record
                        if (
                            type(outcome) is not dict
                            or set(outcome) != {"schema_version", "attempt_id", "request_hash", "operation", "outcome", "evidence_status", "legacy", "lineage"}
                            or outcome.get("schema_version") != "houndd.import-outcome.v1"
                            or outcome.get("operation") != "import.record"
                            or type(outcome.get("legacy")) is not dict
                        ):
                            raise ValueError("import outcome record is malformed")
                        legacy = outcome["legacy"]
                        if set(legacy) != {"record_id", "sha256", "byte_length", "media_type", "encoding"}:
                            raise ValueError("import legacy reference is malformed")
                        legacy_id = legacy["record_id"]
                        legacy_digest = legacy["sha256"]
                        legacy_length = legacy["byte_length"]
                        if (
                            type(legacy_id) is not str
                            or type(legacy_digest) is not str
                            or type(legacy_length) is not int
                            or legacy_length < 0
                            or len(legacy_digest) != 64
                            or any(character not in "0123456789abcdef" for character in legacy_digest)
                            or legacy.get("media_type") != "application/octet-stream"
                            or legacy.get("encoding") != "identity"
                            or event.get("artifact") != {
                                "kind": "import",
                                "schema": "houndd.import-outcome.v1",
                                "record_id": record_id,
                                "hash": record_id,
                                "authorized_uri": f"houndd://record/{record_id}",
                            }
                            or event.get("source") != {"provider": "legacy", "native_id": legacy_id, "canonical_url": "none"}
                            or event.get("lineage") != outcome.get("lineage")
                            or type(outcome.get("lineage")) is not dict
                            or set(outcome["lineage"]) != {"relation", "record_id", "lead_id"}
                            or any(type(item) is not str for item in outcome["lineage"].values())
                            or event.get("usage") != {"requests": 0, "bytes": legacy_length, "cost": 0}
                        ):
                            raise ValueError("import outcome does not bind the journal event")
                        if outcome.get("outcome") == "completed":
                            if (
                                outcome.get("evidence_status") != "clear"
                                or event.get("classification") != {"outcome": "completed", "evidence_status": "clear"}
                                or legacy_digest != digest
                                or dedupe != {"object_key": f"legacy:{legacy_id}", "content_sha256": legacy_digest}
                            ):
                                raise ValueError("completed import event does not bind legacy truth")
                            referenced_records.add(legacy_id)
                            raw = records.read(legacy_id)
                            if (
                                legacy_id not in legacy_manifest_ids
                                or len(raw) != legacy_length
                                or not records.verify_record(legacy_id, legacy_digest)
                            ):
                                raise ValueError("legacy import bytes do not verify")
                        elif outcome.get("outcome") == "interrupted":
                            if (
                                outcome.get("evidence_status") != "interrupted"
                                or event.get("classification") != {"outcome": "interrupted", "evidence_status": "interrupted"}
                                or dedupe != {"object_key": f"import-outcome:{record_id}", "content_sha256": record_id}
                            ):
                                raise ValueError("interrupted import claims raw legacy truth")
                        else:
                            raise ValueError("import outcome is unsupported")
                    elif schema == "houndd.file-record.v1":
                        file_outcome = record
                        if (
                            type(file_outcome) is not dict
                            or set(file_outcome) != {"schema_version", "attempt_id", "request_hash", "operation", "outcome", "evidence_status", "source", "lineage"}
                            or file_outcome.get("schema_version") != "houndd.file-record.v1"
                            or file_outcome.get("operation") != "ingest.file"
                            or type(file_outcome.get("source")) is not dict
                        ):
                            raise ValueError("file outcome record is malformed")
                        source = file_outcome["source"]
                        source_digest = source.get("sha256")
                        source_length = source.get("byte_length")
                        if (
                            set(source) != {"sha256", "byte_length", "media_type", "encoding"}
                            or type(source_digest) is not str
                            or len(source_digest) != 64
                            or any(character not in "0123456789abcdef" for character in source_digest)
                            or type(source_length) is not int
                            or source_length < 0
                            or source.get("media_type") != "application/octet-stream"
                            or source.get("encoding") != "identity"
                            or file_outcome.get("lineage") != {"relation": "none", "record_id": "none", "lead_id": "none"}
                            or event.get("artifact") != {
                                "kind": "file",
                                "schema": "houndd.file-record.v1",
                                "record_id": record_id,
                                "hash": record_id,
                                "authorized_uri": f"houndd://record/{record_id}",
                            }
                            or event.get("source") != {"provider": "local", "native_id": source_digest, "canonical_url": "none"}
                            or event.get("lineage") != file_outcome["lineage"]
                            or event.get("classification") != {"outcome": file_outcome.get("outcome"), "evidence_status": file_outcome.get("evidence_status")}
                            or dedupe != {"object_key": f"file:{source_digest}", "content_sha256": source_digest}
                            or event.get("usage") != {"requests": 0, "bytes": source_length, "cost": 0}
                        ):
                            raise ValueError("file outcome does not bind the journal event")
                        if file_outcome.get("outcome") == "completed":
                            if file_outcome.get("evidence_status") != "clear":
                                raise ValueError("completed file outcome evidence is invalid")
                            blob = records.blobs.get(source_digest)
                            if len(blob) != source_length:
                                raise ValueError("file outcome blob length does not bind its source")
                            referenced_blobs.add(source_digest)
                        elif file_outcome.get("outcome") == "interrupted":
                            if file_outcome.get("evidence_status") != "interrupted":
                                raise ValueError("interrupted file outcome evidence is invalid")
                        else:
                            raise ValueError("file outcome is unsupported")
                    elif schema in _ADAPTER_SCHEMAS:
                        _verify_adapter_outcome(records, event, record, schema, record_id, dedupe, referenced_blobs)
                    else:
                        referenced_blobs.add(digest)
                        blob = records.blobs.get(digest)
                        if len(blob) < 0:  # pragma: no cover - visibly byte-based
                            failures.append(f"invalid blob length: {digest}")
                except Exception as error:
                    failures.append(f"journal artifact verification {event.get('entry_id', '<unknown>')}: {error}")

            for record_id, count in outcome_event_counts.items():
                if count != 1:
                    failures.append(f"Slice 3C1 outcome event cardinality is invalid: {record_id}")

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
