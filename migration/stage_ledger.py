"""Pure stage-ledger validation for HSP-15.

This module intentionally has no Hound service imports and performs no writes or
network access.  It is usable from a copied Hound checkout.

A stage ledger is a single append-only, hash-chained JSON document recording
every migration-lane stage transition (freeze_contracts -> import_mirror ->
shadow -> migrated -> retired, per ``migration.consumer_inventory.STAGES``).
Each entry binds a sha256 over the canonical prior-entry hash plus the entry
body, giving the same tamper-evident chain shape as ``journal/chain.jsonl``
in the houndd state layout, without any external key infrastructure.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from migration.consumer_inventory import (
    EVIDENCE_FIELDS,
    STAGES,
    InventoryError,
    _has_path_control,
    _json_graph_problem,
    _json_text_problem,
    _path_ok,
    _reject_duplicate_pairs,
)


class LedgerError(ValueError):
    """Raised when a stage ledger document cannot be loaded."""


SCHEMA_VERSION = "hound.migration.stage-ledger.v1"
GENESIS_HASH = "0" * 64
_SHA256_CHARACTERS = frozenset("0123456789abcdef")

# HSP-15: shadow is limited to Pulse and Benefits radar, and both must pass
# through it before cutover -- mirrors the identical restriction already
# enforced on the frozen manifest by consumer_inventory.validate_inventory.
SHADOW_REQUIRED_LANES = frozenset({"pulse", "benefits-radar"})

TOP_FIELDS = frozenset({"schema_version", "entries"})
ENTRY_FIELDS = frozenset(
    {
        "sequence",
        "lane",
        "from_stage",
        "to_stage",
        "timestamp",
        "evidence",
        "approval_ref",
        "previous_entry_hash",
        "entry_hash",
    }
)
BODY_FIELDS = frozenset({"lane", "from_stage", "to_stage", "timestamp", "evidence", "approval_ref"})

MAX_LEDGER_BYTES = 1_048_576
MAX_ENTRIES = 10_000

_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_LANE_RE = re.compile(r"^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$")

# Evidence required to enter each stage. Mirrors consumer_inventory's
# per-stage evidence gating on the frozen manifest, extended to ledger
# transitions: shadow needs parity; migrated needs the full no-bypass/
# recovery evidence set; retired additionally needs legacy_absent (the two
# HSP-15 deletion gates: recovery drill and one full scheduled cycle).
_STAGE_REQUIRED_EVIDENCE: dict[str, tuple[str, ...]] = {
    "import_mirror": (),
    "shadow": ("parity",),
    "migrated": ("static_no_direct_provider", "credential_unset", "unix_socket", "recovery_drill", "full_cycle"),
    "retired": (
        "static_no_direct_provider",
        "credential_unset",
        "unix_socket",
        "recovery_drill",
        "full_cycle",
        "legacy_absent",
    ),
}
# HSP-22: a lane becomes canonical only on an explicit Ali cutover approval;
# that is exactly the migrated transition.
_STAGE_REQUIRES_APPROVAL = frozenset({"migrated"})


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


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in _SHA256_CHARACTERS for c in value)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _entry_body(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: entry[key] for key in BODY_FIELDS}


def compute_entry_hash(sequence: int, previous_entry_hash: str, body: dict[str, Any]) -> str:
    """Sha256 over the canonical prior-entry hash and entry body (the "signature" binding)."""

    payload = {"sequence": sequence, "previous_entry_hash": previous_entry_hash, "body": body}
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _validate_evidence(value: object, label: str, errors: list[str]) -> None:
    if not _object(value, label, EVIDENCE_FIELDS, errors):
        return
    pointers: dict[str, str] = {}
    for key, pointer in value.items():
        if pointer is not None and not _exact(pointer, str, f"{label}.{key}", errors):
            continue
        if type(pointer) is str:
            _path_ok(pointer, f"{label}.{key}", errors)
            if pointer in pointers:
                errors.append(f"{label} contains duplicate evidence path: {pointer}")
            pointers[pointer] = key


def _next_allowed_stages(from_stage: str, lane: str) -> frozenset[str]:
    if from_stage == "freeze_contracts":
        return frozenset({"import_mirror"})
    if from_stage == "import_mirror":
        return frozenset({"shadow"}) if lane in SHADOW_REQUIRED_LANES else frozenset({"migrated"})
    if from_stage == "shadow":
        return frozenset({"migrated"})
    if from_stage == "migrated":
        return frozenset({"retired"})
    return frozenset()  # retired is terminal


def validate_ledger(ledger: object) -> list[str]:
    """Return every ledger error; nothing is suppressed as a baseline."""

    errors: list[str] = []
    if not _object(ledger, "ledger", TOP_FIELDS, errors):
        return errors
    schema_ok = _exact(ledger["schema_version"], str, "ledger.schema_version", errors)
    if schema_ok and ledger["schema_version"] != SCHEMA_VERSION:
        errors.append("ledger.schema_version is not the canonical version")
    if not _exact(ledger["entries"], list, "ledger.entries", errors):
        return errors

    entries = ledger["entries"]
    if len(entries) > MAX_ENTRIES:
        errors.append(f"ledger.entries exceeds maximum size {MAX_ENTRIES}")
        return errors

    lane_stage: dict[str, str] = {}
    previous_hash = GENESIS_HASH
    for index, entry in enumerate(entries):
        label = f"entries[{index}]"
        if not _object(entry, label, ENTRY_FIELDS, errors):
            # Structural failure: cannot safely chain past this entry.
            previous_hash = GENESIS_HASH
            continue

        sequence_ok = _exact(entry["sequence"], int, f"{label}.sequence", errors)
        if sequence_ok and entry["sequence"] != index:
            errors.append(f"{label}.sequence must equal its position ({index})")

        lane_ok = _exact(entry["lane"], str, f"{label}.lane", errors)
        if lane_ok:
            if not entry["lane"] or _has_path_control(entry["lane"]) or not _LANE_RE.match(entry["lane"]):
                errors.append(f"{label}.lane must be a bounded lowercase identifier")

        stage_fields_ok = True
        for key in ("from_stage", "to_stage"):
            if not _exact(entry[key], str, f"{label}.{key}", errors):
                stage_fields_ok = False
            elif entry[key] not in STAGES:
                errors.append(f"{label}.{key} is not an allowed stage")
                stage_fields_ok = False

        if not _exact(entry["timestamp"], str, f"{label}.timestamp", errors):
            pass
        elif not _TIMESTAMP_RE.match(entry["timestamp"]):
            errors.append(f"{label}.timestamp must be an exact RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)")

        _validate_evidence(entry["evidence"], f"{label}.evidence", errors)

        approval_ok = entry["approval_ref"] is None or _exact(entry["approval_ref"], str, f"{label}.approval_ref", errors)
        if type(entry["approval_ref"]) is str:
            if not entry["approval_ref"]:
                errors.append(f"{label}.approval_ref must be non-empty when present")
            elif _has_path_control(entry["approval_ref"]):
                errors.append(f"{label}.approval_ref contains control characters")

        # Hash-chain integrity: recompute both the body hash link and this
        # entry's own binding; either being tampered fails closed.
        if not _exact(entry["previous_entry_hash"], str, f"{label}.previous_entry_hash", errors) or not _is_sha256(
            entry["previous_entry_hash"]
        ):
            if type(entry["previous_entry_hash"]) is str:
                errors.append(f"{label}.previous_entry_hash must be an exact lowercase SHA-256 string")
        if not _exact(entry["entry_hash"], str, f"{label}.entry_hash", errors) or not _is_sha256(entry["entry_hash"]):
            if type(entry["entry_hash"]) is str:
                errors.append(f"{label}.entry_hash must be an exact lowercase SHA-256 string")

        chain_checkable = (
            _is_sha256(entry.get("previous_entry_hash"))
            and _is_sha256(entry.get("entry_hash"))
            and sequence_ok
            and lane_ok
            and stage_fields_ok
        )
        if chain_checkable:
            if entry["previous_entry_hash"] != previous_hash:
                errors.append(f"{label} chain integrity broken: previous_entry_hash does not match the prior entry")
            body = _entry_body(entry)
            expected_hash = compute_entry_hash(entry["sequence"], entry["previous_entry_hash"], body)
            if entry["entry_hash"] != expected_hash:
                errors.append(f"{label} chain integrity broken: entry_hash does not match its signed body")
            previous_hash = entry["entry_hash"]
        else:
            previous_hash = GENESIS_HASH

        if not (lane_ok and stage_fields_ok):
            continue

        lane = entry["lane"]
        from_stage = entry["from_stage"]
        to_stage = entry["to_stage"]
        current = lane_stage.get(lane, STAGES[0])
        if from_stage != current:
            errors.append(f"{label} lane {lane} from_stage {from_stage!r} does not match its current stage {current!r}")
            continue

        allowed = _next_allowed_stages(from_stage, lane)
        if to_stage not in allowed:
            from_index = STAGES.index(from_stage)
            to_index = STAGES.index(to_stage)
            if to_index <= from_index:
                errors.append(f"{label} lane {lane} regresses stage order: {from_stage} -> {to_stage} moves backward")
            else:
                errors.append(f"{label} lane {lane} skips stage order: {from_stage} -> {to_stage} is not the next stage")
            continue

        lane_stage[lane] = to_stage

        evidence = entry["evidence"] if type(entry["evidence"]) is dict else {}
        for key in _STAGE_REQUIRED_EVIDENCE.get(to_stage, ()):
            if type(evidence.get(key)) is not str:
                errors.append(f"{label}.evidence.{key} is required to reach {to_stage}")
        if to_stage in _STAGE_REQUIRES_APPROVAL and entry["approval_ref"] is None:
            errors.append(f"{label} entering {to_stage} requires a non-null approval_ref (HSP-22 cutover approval)")

    return errors


def lane_stage(ledger: dict[str, Any], lane: str) -> str:
    """Replay a validated ledger and return *lane*'s current stage.

    Callers must validate the ledger with :func:`validate_ledger` first; this
    function trusts the shape it is given.
    """

    stage = STAGES[0]
    for entry in ledger.get("entries", []):
        if type(entry) is dict and entry.get("lane") == lane and type(entry.get("to_stage")) is str:
            stage = entry["to_stage"]
    return stage


def validate_deletion(ledger: dict[str, Any], lane: str) -> list[str]:
    """Reject deleting *lane*'s legacy paths unless the ledger shows it retired."""

    stage = lane_stage(ledger, lane)
    if stage != "retired":
        return [f"lane {lane} has not reached retired stage (currently {stage}); deletion is rejected"]
    return []


def load_ledger(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_LEDGER_BYTES:
            raise LedgerError(f"stage ledger exceeds {MAX_LEDGER_BYTES} bytes")
        text = raw.decode("utf-8")
        if problem := _json_text_problem(text):
            raise LedgerError(f"cannot load stage ledger {path}: {problem}")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except RecursionError as exc:
        raise LedgerError(f"cannot load stage ledger {path}: JSON nesting exceeds maximum depth") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, InventoryError) as exc:
        raise LedgerError(f"cannot load stage ledger {path}: {exc}") from exc
    if problem := _json_graph_problem(value):
        raise LedgerError(f"cannot load stage ledger {path}: {problem}")
    if type(value) is not dict:
        raise LedgerError("stage ledger JSON must be an object")
    return value
