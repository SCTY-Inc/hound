"""Pure approval-seam validation for HSP-10/HSP-22 (E4).

This module intentionally has no Hound service imports and performs no writes or
network access.  It is usable from a copied Hound checkout, just like
``migration.consumer_inventory`` and ``migration.stage_ledger``.

Approval involves three facts that docs/approval-seams.md requires never be
conflated:

* **Gate receipt** (``hound.approval.gate-receipt.v1``) -- a gate existed,
  over exactly these contents. Content-addressed: a receipt's own hash
  (sha256 over its canonical JSON) is what a decision binds to.
* **Decision** (``hound.approval.decision.v1``) -- what the human said.
  Appended to a ``decisions.jsonl`` audit log that is hash-chained in the
  same shape as :mod:`migration.stage_ledger`'s stage ledger: each line's
  ``entry_hash`` binds sha256 over the prior line's ``entry_hash`` plus this
  line's body, reusing :func:`migration.stage_ledger.compute_entry_hash`
  directly so both logs share one hashing derivation.
* **Outcome** -- the lane's own artifact. For the HSP-22 per-lane cutover
  gate this is a stage-ledger ``migrated`` transition's ``approval_ref``,
  which must name a decision's ``entry_hash``.

A gate receipt without a decision is an open gate; an approved decision
without a stage-ledger outcome is an unexecuted approval. Both are legal
states this module reports rather than repairs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from migration.consumer_inventory import (
    InventoryError,
    _has_path_control,
    _json_graph_problem,
    _json_text_problem,
    _path_ok,
    _path_problem,
    _reject_duplicate_pairs,
)
from migration.stage_ledger import (
    GENESIS_HASH,
    LedgerError,
    _LANE_RE,
    _STAGE_REQUIRED_EVIDENCE,
    _STAGE_REQUIRES_APPROVAL,
    _TIMESTAMP_RE,
    _is_sha256,
    canonical_bytes,
    compute_entry_hash,
    load_ledger,
    validate_ledger,
)


class ApprovalError(ValueError):
    """Raised when a receipt, decision log, or annotation cannot be loaded."""


RECEIPT_SCHEMA_VERSION = "hound.approval.gate-receipt.v1"
DECISION_SCHEMA_VERSION = "hound.approval.decision.v1"
ANNOTATION_SCHEMA_VERSION = "hound.approval.annotation.v1"

DECISION_VALUES = frozenset({"approve", "reject"})
ANNOTATION_KINDS = frozenset({"plus", "amplify"})

RECEIPT_FIELDS = frozenset({"schema_version", "gate_id", "lane", "subject", "requested_at", "queue_ref"})
SUBJECT_FIELDS = frozenset({"plan_id", "artifacts"})
ARTIFACT_FIELDS = frozenset({"path", "hash"})
DECISION_BODY_FIELDS = frozenset(
    {"schema_version", "gate_id", "decision", "decided_by", "decided_at", "receipt_hash", "evidence_refs"}
)
DECISION_CHAIN_FIELDS = frozenset({"sequence", "previous_entry_hash", "entry_hash"})
DECISION_ENTRY_FIELDS = DECISION_BODY_FIELDS | DECISION_CHAIN_FIELDS
ANNOTATION_BODY_FIELDS = frozenset({"schema_version", "record_hash", "annotation", "author", "at"})
ANNOTATION_ENTRY_FIELDS = ANNOTATION_BODY_FIELDS | frozenset({"entry_hash"})

MAX_RECEIPT_BYTES = 65_536
MAX_ANNOTATION_BYTES = 65_536
MAX_DECISIONS_BYTES = 1_048_576
MAX_DECISION_ENTRIES = 10_000
MAX_DIRECTORY_ENTRIES = 10_000


def _exact(value: object, expected: type, label: str, errors: list[str]) -> bool:
    if type(value) is not expected:
        errors.append(f"{label} must be exact builtin type {expected.__name__}")
        return False
    return True


def _object(value: object, label: str, fields: frozenset[str], errors: list[str]) -> bool:
    if not _exact(value, dict, label, errors):
        return False
    actual: set[str] = set()
    keys_ok = True
    for key in value:
        if _exact(key, str, f"{label} key", errors):
            actual.add(key)
        else:
            keys_ok = False
    missing = fields - actual
    extra = actual - fields
    if missing:
        errors.append(f"{label} missing fields: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} field closure violated: {', '.join(sorted(extra))}")
    return keys_ok and not missing and not extra


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def receipt_hash(receipt: dict[str, Any]) -> str:
    """Content-address a gate receipt: sha256 over its canonical JSON."""

    return _sha256_hex(canonical_bytes(receipt))


def annotation_entry_hash(body: dict[str, Any]) -> str:
    """Content-address an annotation's append-time body (mirrors receipt_hash)."""

    return _sha256_hex(canonical_bytes(body))


def _validate_subject(value: object, label: str, errors: list[str]) -> None:
    if not _object(value, label, SUBJECT_FIELDS, errors):
        return
    plan_ok = _exact(value["plan_id"], str, f"{label}.plan_id", errors)
    if plan_ok and not value["plan_id"]:
        errors.append(f"{label}.plan_id must be non-empty")
    if not _exact(value["artifacts"], list, f"{label}.artifacts", errors):
        return
    if not value["artifacts"]:
        errors.append(f"{label}.artifacts must name at least one artifact")
    seen_paths: set[str] = set()
    for index, artifact in enumerate(value["artifacts"]):
        alabel = f"{label}.artifacts[{index}]"
        if not _object(artifact, alabel, ARTIFACT_FIELDS, errors):
            continue
        if _path_ok(artifact["path"], f"{alabel}.path", errors):
            if artifact["path"] in seen_paths:
                errors.append(f"{alabel}.path duplicates another artifact in this subject: {artifact['path']}")
            seen_paths.add(artifact["path"])
        hash_ok = _exact(artifact["hash"], str, f"{alabel}.hash", errors)
        if hash_ok and not _is_sha256(artifact["hash"]):
            errors.append(f"{alabel}.hash must be an exact lowercase SHA-256 string")


def validate_receipt(receipt: object) -> list[str]:
    """Return every gate-receipt error; nothing is suppressed as a baseline."""

    errors: list[str] = []
    if not _object(receipt, "receipt", RECEIPT_FIELDS, errors):
        return errors
    schema_ok = _exact(receipt["schema_version"], str, "receipt.schema_version", errors)
    if schema_ok and receipt["schema_version"] != RECEIPT_SCHEMA_VERSION:
        errors.append("receipt.schema_version is not the canonical gate-receipt version")
    gate_ok = _exact(receipt["gate_id"], str, "receipt.gate_id", errors)
    if gate_ok and (not receipt["gate_id"] or _has_path_control(receipt["gate_id"])):
        errors.append("receipt.gate_id must be a non-empty identifier")
    lane_ok = _exact(receipt["lane"], str, "receipt.lane", errors)
    if lane_ok and (not receipt["lane"] or _has_path_control(receipt["lane"]) or not _LANE_RE.match(receipt["lane"])):
        errors.append("receipt.lane must be a bounded lowercase identifier")
    _validate_subject(receipt["subject"], "receipt.subject", errors)
    if not _exact(receipt["requested_at"], str, "receipt.requested_at", errors):
        pass
    elif not _TIMESTAMP_RE.match(receipt["requested_at"]):
        errors.append("receipt.requested_at must be an exact RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")
    queue_ok = _exact(receipt["queue_ref"], str, "receipt.queue_ref", errors)
    if queue_ok and (not receipt["queue_ref"] or _has_path_control(receipt["queue_ref"])):
        errors.append("receipt.queue_ref must be a non-empty opaque reference")
    return errors


def validate_annotation(record: object) -> list[str]:
    """Return every annotation error, including a tampered entry_hash."""

    errors: list[str] = []
    if not _object(record, "annotation", ANNOTATION_ENTRY_FIELDS, errors):
        return errors
    schema_ok = _exact(record["schema_version"], str, "annotation.schema_version", errors)
    if schema_ok and record["schema_version"] != ANNOTATION_SCHEMA_VERSION:
        errors.append("annotation.schema_version is not the canonical annotation version")
    hash_ok = _exact(record["record_hash"], str, "annotation.record_hash", errors)
    if hash_ok and not _is_sha256(record["record_hash"]):
        errors.append("annotation.record_hash must be an exact lowercase SHA-256 string")
    kind_ok = _exact(record["annotation"], str, "annotation.annotation", errors)
    if kind_ok and record["annotation"] not in ANNOTATION_KINDS:
        errors.append("annotation.annotation must be plus or amplify")
    author_ok = _exact(record["author"], str, "annotation.author", errors)
    if author_ok and (not record["author"] or _has_path_control(record["author"])):
        errors.append("annotation.author must be a non-empty identifier")
    if not _exact(record["at"], str, "annotation.at", errors):
        pass
    elif not _TIMESTAMP_RE.match(record["at"]):
        errors.append("annotation.at must be an exact RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")
    entry_hash_ok = _exact(record["entry_hash"], str, "annotation.entry_hash", errors)
    if entry_hash_ok and not _is_sha256(record["entry_hash"]):
        errors.append("annotation.entry_hash must be an exact lowercase SHA-256 string")
    if not errors:
        body = {key: record[key] for key in ANNOTATION_BODY_FIELDS}
        if record["entry_hash"] != annotation_entry_hash(body):
            errors.append("annotation.entry_hash does not match its append-time body (annotation was edited)")
    return errors


def _validate_decision_fields(entry: dict[str, Any], label: str, errors: list[str]) -> None:
    schema_ok = _exact(entry["schema_version"], str, f"{label}.schema_version", errors)
    if schema_ok and entry["schema_version"] != DECISION_SCHEMA_VERSION:
        errors.append(f"{label}.schema_version is not the canonical decision version")
    gate_ok = _exact(entry["gate_id"], str, f"{label}.gate_id", errors)
    if gate_ok and (not entry["gate_id"] or _has_path_control(entry["gate_id"])):
        errors.append(f"{label}.gate_id must be a non-empty identifier")
    decision_ok = _exact(entry["decision"], str, f"{label}.decision", errors)
    if decision_ok and entry["decision"] not in DECISION_VALUES:
        errors.append(f"{label}.decision must be approve or reject")
    by_ok = _exact(entry["decided_by"], str, f"{label}.decided_by", errors)
    if by_ok and (not entry["decided_by"] or _has_path_control(entry["decided_by"])):
        errors.append(f"{label}.decided_by must be a non-empty identifier")
    if not _exact(entry["decided_at"], str, f"{label}.decided_at", errors):
        pass
    elif not _TIMESTAMP_RE.match(entry["decided_at"]):
        errors.append(f"{label}.decided_at must be an exact RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")
    hash_ok = _exact(entry["receipt_hash"], str, f"{label}.receipt_hash", errors)
    if hash_ok and not _is_sha256(entry["receipt_hash"]):
        errors.append(f"{label}.receipt_hash must be an exact lowercase SHA-256 string")
    if _exact(entry["evidence_refs"], list, f"{label}.evidence_refs", errors):
        seen: set[str] = set()
        for index, ref in enumerate(entry["evidence_refs"]):
            if _path_ok(ref, f"{label}.evidence_refs[{index}]", errors):
                if ref in seen:
                    errors.append(f"{label}.evidence_refs contains duplicate path: {ref}")
                seen.add(ref)


def _load_json_document(path: Path, max_bytes: int) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > max_bytes:
            raise ApprovalError(f"{path} exceeds {max_bytes} bytes")
        text = raw.decode("utf-8")
        if problem := _json_text_problem(text):
            raise ApprovalError(f"cannot load {path}: {problem}")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except RecursionError as exc:
        raise ApprovalError(f"cannot load {path}: JSON nesting exceeds maximum depth") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, InventoryError) as exc:
        raise ApprovalError(f"cannot load {path}: {exc}") from exc
    if problem := _json_graph_problem(value):
        raise ApprovalError(f"cannot load {path}: {problem}")
    if type(value) is not dict:
        raise ApprovalError(f"{path} JSON must be an object")
    return value


def _scan_json_files(directory: Path, label: str, errors: list[str]) -> list[Path]:
    if directory.is_symlink() or not directory.is_dir():
        errors.append(f"{label} is missing, not a directory, or a symlink: {directory}")
        return []
    entries = sorted(path for path in directory.iterdir() if path.suffix == ".json")
    if len(entries) > MAX_DIRECTORY_ENTRIES:
        errors.append(f"{label} exceeds {MAX_DIRECTORY_ENTRIES} entries: {directory}")
        return []
    ok: list[Path] = []
    for path in entries:
        if path.is_symlink():
            errors.append(f"{label} file uses a symlink: {path.name}")
            continue
        ok.append(path)
    return ok


def load_receipts(directory: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load every ``*.json`` receipt in *directory*, keyed by its content hash."""

    errors: list[str] = []
    receipts: dict[str, dict[str, Any]] = {}
    for path in _scan_json_files(directory, "receipts directory", errors):
        try:
            document = _load_json_document(path, MAX_RECEIPT_BYTES)
        except ApprovalError as exc:
            errors.append(str(exc))
            continue
        receipt_errors = validate_receipt(document)
        if receipt_errors:
            errors.extend(f"{path.name}: {message}" for message in receipt_errors)
            continue
        digest = receipt_hash(document)
        if digest in receipts:
            errors.append(f"{path.name}: duplicate receipt content (same hash as an existing receipt)")
            continue
        receipts[digest] = document
    return receipts, errors


def load_annotations(directory: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load every ``*.json`` annotation in *directory*."""

    errors: list[str] = []
    annotations: list[dict[str, Any]] = []
    for path in _scan_json_files(directory, "annotations directory", errors):
        try:
            document = _load_json_document(path, MAX_ANNOTATION_BYTES)
        except ApprovalError as exc:
            errors.append(str(exc))
            continue
        annotation_errors = validate_annotation(document)
        if annotation_errors:
            errors.extend(f"{path.name}: {message}" for message in annotation_errors)
            continue
        annotations.append(document)
    return annotations, errors


def load_decisions(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load and hash-chain-validate ``decisions.jsonl``. Returns (entries, errors).

    Mirrors :func:`migration.stage_ledger.validate_ledger`'s chain discipline
    line by line: each line's ``entry_hash`` binds sha256 over the prior
    line's ``entry_hash`` plus this line's body, computed with the exact same
    :func:`migration.stage_ledger.compute_entry_hash`.
    """

    errors: list[str] = []
    entries: list[dict[str, Any]] = []
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return entries, [f"cannot load {path}: {exc}"]
    if len(raw) > MAX_DECISIONS_BYTES:
        return entries, [f"{path} exceeds {MAX_DECISIONS_BYTES} bytes"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return entries, [f"cannot load {path}: {exc}"]
    lines = [line for line in text.split("\n") if line != ""]
    if len(lines) > MAX_DECISION_ENTRIES:
        return entries, [f"{path} exceeds {MAX_DECISION_ENTRIES} entries"]

    previous_hash = GENESIS_HASH
    for index, line in enumerate(lines):
        label = f"decisions.jsonl:{index}"
        if problem := _json_text_problem(line):
            errors.append(f"{label}: {problem}")
            previous_hash = GENESIS_HASH
            continue
        try:
            entry = json.loads(line, object_pairs_hook=_reject_duplicate_pairs)
        except (json.JSONDecodeError, InventoryError) as exc:
            errors.append(f"{label}: {exc}")
            previous_hash = GENESIS_HASH
            continue
        if problem := _json_graph_problem(entry):
            errors.append(f"{label}: {problem}")
            previous_hash = GENESIS_HASH
            continue
        if not _object(entry, label, DECISION_ENTRY_FIELDS, errors):
            previous_hash = GENESIS_HASH
            continue

        before = len(errors)
        sequence_ok = _exact(entry["sequence"], int, f"{label}.sequence", errors)
        if sequence_ok and entry["sequence"] != index:
            errors.append(f"{label}.sequence must equal its position ({index})")
        _validate_decision_fields(entry, label, errors)

        prev_ok = False
        if not _exact(entry["previous_entry_hash"], str, f"{label}.previous_entry_hash", errors) or not _is_sha256(
            entry["previous_entry_hash"]
        ):
            if type(entry["previous_entry_hash"]) is str:
                errors.append(f"{label}.previous_entry_hash must be an exact lowercase SHA-256 string")
        else:
            prev_ok = True
        hash_ok = False
        if not _exact(entry["entry_hash"], str, f"{label}.entry_hash", errors) or not _is_sha256(entry["entry_hash"]):
            if type(entry["entry_hash"]) is str:
                errors.append(f"{label}.entry_hash must be an exact lowercase SHA-256 string")
        else:
            hash_ok = True

        chain_checkable = sequence_ok and prev_ok and hash_ok and len(errors) == before
        if chain_checkable:
            if entry["previous_entry_hash"] != previous_hash:
                errors.append(f"{label} chain integrity broken: previous_entry_hash does not match the prior entry")
            body = {key: entry[key] for key in DECISION_BODY_FIELDS}
            expected_hash = compute_entry_hash(entry["sequence"], entry["previous_entry_hash"], body)
            if entry["entry_hash"] != expected_hash:
                errors.append(f"{label} chain integrity broken: entry_hash does not match its signed body")
            if len(errors) == before:
                previous_hash = entry["entry_hash"]
                entries.append(entry)
            else:
                previous_hash = GENESIS_HASH
        else:
            previous_hash = GENESIS_HASH
    return entries, errors


def _resolve_artifact(workspace: Path, relative_path: str, expected_hash: str) -> str | None:
    candidate = workspace / relative_path
    problem = _path_problem(candidate, workspace)
    if problem:
        return f"artifact {relative_path} {problem}"
    if not candidate.is_file():
        return f"artifact {relative_path} is not a file"
    try:
        actual = _sha256_hex(candidate.read_bytes())
    except OSError as exc:
        return f"artifact {relative_path} unreadable: {exc}"
    if actual != expected_hash:
        return f"artifact {relative_path} content hash does not match subject (expected {expected_hash}, got {actual})"
    return None


def _walk_stage_ledger(
    path: Path,
    decision_by_hash: dict[str, dict[str, Any]],
    receipts_by_hash: dict[str, dict[str, Any]],
    errors: list[str],
    legal_states: list[str],
) -> dict[str, Any]:
    """Walk stage-ledger approval_ref -> decision -> receipt -> subject hashes (HSP-22)."""

    try:
        ledger = load_ledger(path)
    except LedgerError as exc:
        errors.append(str(exc))
        return {"path": str(path), "lanes": []}
    ledger_errors = validate_ledger(ledger)
    if ledger_errors:
        errors.extend(ledger_errors)
        return {"path": str(path), "lanes": []}

    lanes: list[dict[str, Any]] = []
    referenced: set[str] = set()
    for index, entry in enumerate(ledger["entries"]):
        if entry["to_stage"] not in _STAGE_REQUIRES_APPROVAL:
            continue
        label = f"stage-ledger entries[{index}] lane {entry['lane']}"
        approval_ref = entry["approval_ref"]
        if approval_ref is None:
            # validate_ledger already rejects a null approval_ref reaching a
            # required stage; nothing new to walk for this entry.
            continue
        decision = decision_by_hash.get(approval_ref)
        if decision is None:
            errors.append(f"{label}: approval_ref {approval_ref} names no decision in decisions.jsonl")
            continue
        referenced.add(approval_ref)
        if decision["decision"] != "approve":
            errors.append(f"{label}: approval_ref {approval_ref} names a rejecting decision")
            continue
        receipt = receipts_by_hash.get(decision["receipt_hash"])
        if receipt is None:
            # Already reported while validating decisions; avoid double-counting.
            continue
        evidence = entry["evidence"] if type(entry["evidence"]) is dict else {}
        subject_paths = {artifact["path"] for artifact in receipt["subject"]["artifacts"]}
        for key in _STAGE_REQUIRED_EVIDENCE["migrated"]:
            pointer = evidence.get(key)
            if type(pointer) is not str:
                continue  # already reported by validate_ledger
            if pointer not in subject_paths:
                errors.append(f"{label}: receipt subject does not cover migrated evidence.{key} ({pointer})")
        lanes.append({"lane": entry["lane"], "approval_ref": approval_ref, "receipt_gate_id": receipt["gate_id"]})

    for digest, decision in decision_by_hash.items():
        if decision["decision"] == "approve" and digest not in referenced:
            legal_states.append(f"unexecuted approval: decision {digest} (gate {decision['gate_id']}) has no stage-ledger outcome")

    return {"path": str(path), "lanes": lanes}


def check(
    *,
    receipts_dir: Path,
    decisions_path: Path,
    workspace: Path,
    annotations_dir: Path | None = None,
    stage_ledger_path: Path | None = None,
) -> dict[str, Any]:
    """Validate the full approval seam and return a structured report.

    Fails closed: any structural error in receipts, decisions, annotations,
    or the optional stage-ledger walk makes the report invalid. Open gates
    (a receipt with no decision) and unexecuted approvals (an approved
    decision with no stage-ledger outcome) are legal states per
    docs/approval-seams.md and are reported, never treated as errors.
    """

    errors: list[str] = []
    legal_states: list[str] = []

    receipts_by_hash, receipt_errors = load_receipts(receipts_dir)
    errors.extend(receipt_errors)

    decisions, decision_errors = load_decisions(decisions_path)
    errors.extend(decision_errors)

    annotations: list[dict[str, Any]] = []
    if annotations_dir is not None:
        annotations, annotation_errors = load_annotations(annotations_dir)
        errors.extend(annotation_errors)

    workspace = workspace.resolve()
    for digest, receipt in receipts_by_hash.items():
        for artifact in receipt["subject"]["artifacts"]:
            problem = _resolve_artifact(workspace, artifact["path"], artifact["hash"])
            if problem:
                errors.append(f"receipt {receipt['gate_id']} ({digest}): {problem}")

    decision_by_hash: dict[str, dict[str, Any]] = {}
    matched_receipt_hashes: set[str] = set()
    for entry in decisions:
        decision_by_hash[entry["entry_hash"]] = entry
        if entry["receipt_hash"] not in receipts_by_hash:
            errors.append(f"decision {entry['entry_hash']} names a receipt_hash with no matching receipt: {entry['receipt_hash']}")
        else:
            matched_receipt_hashes.add(entry["receipt_hash"])

    for digest, receipt in receipts_by_hash.items():
        if digest not in matched_receipt_hashes:
            legal_states.append(f"open gate: receipt {receipt['gate_id']} ({digest}) has no decision")

    stage_ledger_report = None
    if stage_ledger_path is not None:
        stage_ledger_report = _walk_stage_ledger(stage_ledger_path, decision_by_hash, receipts_by_hash, errors, legal_states)

    return {
        "schema_version": "hound.migration.approvals-report.v1",
        "valid": not errors,
        "errors": errors,
        "legal_states": legal_states,
        "receipts": len(receipts_by_hash),
        "decisions": len(decisions),
        "annotations": len(annotations),
        "stage_ledger": stage_ledger_report,
    }
