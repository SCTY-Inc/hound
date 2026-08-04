from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from migration.consumer_inventory import EVIDENCE_FIELDS
from migration.stage_ledger import GENESIS_HASH, SCHEMA_VERSION as LEDGER_SCHEMA_VERSION, compute_entry_hash
from migration.approvals import (
    ANNOTATION_SCHEMA_VERSION,
    DECISION_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION,
    annotation_entry_hash,
    check,
    load_annotations,
    load_decisions,
    load_receipts,
    receipt_hash,
    validate_annotation,
    validate_receipt,
)


ROOT = Path(__file__).parents[1]
MIGRATED_EVIDENCE_KEYS = ("static_no_direct_provider", "credential_unset", "unix_socket", "recovery_drill", "full_cycle")


def _no_evidence() -> dict[str, None]:
    return {key: None for key in EVIDENCE_FIELDS}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_artifact(workspace: Path, relative: str, content: bytes = b"{}") -> tuple[str, str]:
    path = workspace / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return relative, _sha256(content)


def make_receipt(
    workspace: Path,
    *,
    gate_id: str = "gate-1",
    lane: str = "wiki-refresh",
    plan_id: str = "plan-1",
    artifact_names: tuple[str, ...] = ("e/a.json",),
    requested_at: str = "2026-08-04T00:00:00Z",
    queue_ref: str = "https://queue.example/gate-1",
) -> dict[str, Any]:
    artifacts = []
    for index, name in enumerate(artifact_names):
        relative, digest = _write_artifact(workspace, name, content=f'{{"n":{index}}}'.encode())
        artifacts.append({"path": relative, "hash": digest})
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "gate_id": gate_id,
        "lane": lane,
        "subject": {"plan_id": plan_id, "artifacts": artifacts},
        "requested_at": requested_at,
        "queue_ref": queue_ref,
    }


def write_receipt(receipts_dir: Path, receipt: dict[str, Any], *, filename: str | None = None) -> None:
    receipts_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"{receipt['gate_id']}.json"
    (receipts_dir / name).write_text(json.dumps(receipt))


class DecisionChainBuilder:
    """Test-only helper that appends correctly hash-chained decisions.jsonl lines."""

    def __init__(self) -> None:
        self.lines: list[dict[str, Any]] = []
        self._previous = GENESIS_HASH

    def add(
        self,
        *,
        gate_id: str,
        receipt_hash_value: str,
        decision: str = "approve",
        decided_by: str = "ali",
        decided_at: str = "2026-08-04T00:05:00Z",
        evidence_refs: list[str] | None = None,
    ) -> "DecisionChainBuilder":
        sequence = len(self.lines)
        body = {
            "schema_version": DECISION_SCHEMA_VERSION,
            "gate_id": gate_id,
            "decision": decision,
            "decided_by": decided_by,
            "decided_at": decided_at,
            "receipt_hash": receipt_hash_value,
            "evidence_refs": evidence_refs if evidence_refs is not None else [],
        }
        entry_hash = compute_entry_hash(sequence, self._previous, body)
        entry = {"sequence": sequence, "previous_entry_hash": self._previous, "entry_hash": entry_hash, **body}
        self.lines.append(entry)
        self._previous = entry_hash
        return self

    def write(self, path: Path) -> None:
        path.write_text("".join(json.dumps(line) + "\n" for line in self.lines))

    def last_hash(self) -> str:
        return self.lines[-1]["entry_hash"]


class StageLedgerBuilder:
    """Minimal stage-ledger builder scoped to what these tests need."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self._previous = GENESIS_HASH

    def add(
        self,
        lane: str,
        from_stage: str,
        to_stage: str,
        *,
        timestamp: str = "2026-08-04T00:00:00Z",
        evidence: dict[str, Any] | None = None,
        approval_ref: str | None = None,
    ) -> "StageLedgerBuilder":
        sequence = len(self.entries)
        body = {
            "lane": lane,
            "from_stage": from_stage,
            "to_stage": to_stage,
            "timestamp": timestamp,
            "evidence": evidence if evidence is not None else _no_evidence(),
            "approval_ref": approval_ref,
        }
        entry_hash = compute_entry_hash(sequence, self._previous, body)
        entry = {"sequence": sequence, "previous_entry_hash": self._previous, "entry_hash": entry_hash, **body}
        self.entries.append(entry)
        self._previous = entry_hash
        return self

    def build(self) -> dict[str, Any]:
        return {"schema_version": LEDGER_SCHEMA_VERSION, "entries": self.entries}

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(self.build()))


def make_annotation(
    *,
    record_hash: str = "a" * 64,
    annotation: str = "plus",
    author: str = "ali",
    at: str = "2026-08-04T00:00:00Z",
) -> dict[str, Any]:
    body = {"schema_version": ANNOTATION_SCHEMA_VERSION, "record_hash": record_hash, "annotation": annotation, "author": author, "at": at}
    return {**body, "entry_hash": annotation_entry_hash(body)}


def migrated_evidence(workspace: Path, receipt_artifact_names: tuple[str, ...] = ()) -> dict[str, Any]:
    """Build a full evidence dict for a migrated transition, reusing *receipt_artifact_names* as pointers."""

    evidence = _no_evidence()
    names = receipt_artifact_names or tuple(f"e/{key}.json" for key in MIGRATED_EVIDENCE_KEYS)
    for key, name in zip(MIGRATED_EVIDENCE_KEYS, names):
        evidence[key] = name
    return evidence


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "migration/check_approvals.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


# --- happy path ---------------------------------------------------------------


def test_receipt_and_decision_alone_validate(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace)
    assert report["valid"] is True
    assert report["errors"] == []
    assert report["receipts"] == 1
    assert report["decisions"] == 1


def test_full_walk_through_stage_ledger_validates(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    names = tuple(f"e/{key}.json" for key in MIGRATED_EVIDENCE_KEYS)
    receipt = make_receipt(workspace, artifact_names=names)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    ledger = (
        StageLedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=migrated_evidence(workspace, names),
            approval_ref=decisions.last_hash(),
        )
    )
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, stage_ledger_path=ledger_path)
    assert report["valid"] is True, report["errors"]
    assert report["errors"] == []
    assert report["legal_states"] == []
    assert report["stage_ledger"]["lanes"] == [
        {"lane": "wiki-refresh", "approval_ref": decisions.last_hash(), "receipt_gate_id": receipt["gate_id"]}
    ]


# --- legal states (reported, not failed) --------------------------------------


def test_receipt_without_decision_is_open_gate(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace)
    assert report["valid"] is True
    assert report["errors"] == []
    assert any("open gate" in state for state in report["legal_states"])


def test_approved_decision_without_stage_ledger_outcome_is_unexecuted(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    ledger = StageLedgerBuilder().add("wiki-refresh", "freeze_contracts", "import_mirror")
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, stage_ledger_path=ledger_path)
    assert report["valid"] is True
    assert report["errors"] == []
    assert any("unexecuted approval" in state for state in report["legal_states"])


def test_rejected_decision_is_not_flagged_unexecuted(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest, decision="reject")
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    ledger = StageLedgerBuilder().add("wiki-refresh", "freeze_contracts", "import_mirror")
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, stage_ledger_path=ledger_path)
    assert report["valid"] is True
    assert not any("unexecuted approval" in state for state in report["legal_states"])


# --- rejection: decision naming a missing receipt -----------------------------


def test_decision_naming_missing_receipt_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    decisions = DecisionChainBuilder().add(gate_id="gate-1", receipt_hash_value="c" * 64)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace)
    assert report["valid"] is False
    assert any("no matching receipt" in error for error in report["errors"])


# --- rejection: receipt subject hashes not resolving --------------------------


def test_receipt_artifact_missing_file_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    # Point at an artifact that was never written to the workspace.
    receipt["subject"]["artifacts"][0]["path"] = "e/never-written.json"
    write_receipt(receipts_dir, receipt)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace)
    assert report["valid"] is False
    assert any("missing or unreadable" in error for error in report["errors"])


def test_receipt_artifact_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    receipt["subject"]["artifacts"][0]["hash"] = "f" * 64
    write_receipt(receipts_dir, receipt)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace)
    assert report["valid"] is False
    assert any("content hash does not match subject" in error for error in report["errors"])


def test_receipt_artifact_pointing_at_directory_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    (workspace / "e").mkdir(parents=True, exist_ok=True)
    receipt["subject"]["artifacts"][0]["path"] = "e"
    write_receipt(receipts_dir, receipt)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace)
    assert report["valid"] is False
    assert any("is not a file" in error for error in report["errors"])


def test_receipt_artifact_path_must_be_workspace_relative(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipt = make_receipt(workspace)
    receipt["subject"]["artifacts"][0]["path"] = "../escape.json"
    errors = validate_receipt(receipt)
    assert any("workspace-relative" in error or "broad" in error for error in errors)


# --- rejection: stage-ledger approval_ref binding ------------------------------


def test_stage_ledger_approval_ref_naming_missing_decision_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    names = tuple(f"e/{key}.json" for key in MIGRATED_EVIDENCE_KEYS)
    receipt = make_receipt(workspace, artifact_names=names)
    write_receipt(receipts_dir, receipt)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")

    ledger = (
        StageLedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=migrated_evidence(workspace, names),
            approval_ref="d" * 64,
        )
    )
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, stage_ledger_path=ledger_path)
    assert report["valid"] is False
    assert any("names no decision" in error for error in report["errors"])


def test_stage_ledger_approval_ref_naming_rejecting_decision_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    names = tuple(f"e/{key}.json" for key in MIGRATED_EVIDENCE_KEYS)
    receipt = make_receipt(workspace, artifact_names=names)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest, decision="reject")
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    ledger = (
        StageLedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=migrated_evidence(workspace, names),
            approval_ref=decisions.last_hash(),
        )
    )
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, stage_ledger_path=ledger_path)
    assert report["valid"] is False
    assert any("names a rejecting decision" in error for error in report["errors"])


def test_stage_ledger_receipt_subject_missing_migrated_evidence_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    # Receipt only covers one of the five required migrated-stage evidence pointers.
    receipt = make_receipt(workspace, artifact_names=("e/static_no_direct_provider.json",))
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    full_names = tuple(f"e/{key}.json" for key in MIGRATED_EVIDENCE_KEYS)
    for name in full_names:
        _write_artifact(workspace, name)
    ledger = (
        StageLedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=migrated_evidence(workspace, full_names),
            approval_ref=decisions.last_hash(),
        )
    )
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, stage_ledger_path=ledger_path)
    assert report["valid"] is False
    assert any("does not cover migrated evidence" in error for error in report["errors"])


# --- rejection: edited annotation ----------------------------------------------


def test_valid_annotation_passes() -> None:
    annotation = make_annotation()
    assert validate_annotation(annotation) == []


def test_edited_annotation_hash_mismatch_is_rejected() -> None:
    annotation = make_annotation()
    annotation["author"] = "someone-else"
    errors = validate_annotation(annotation)
    assert any("annotation was edited" in error for error in errors)


def test_annotation_unknown_kind_is_rejected() -> None:
    body = {"schema_version": ANNOTATION_SCHEMA_VERSION, "record_hash": "a" * 64, "annotation": "downvote", "author": "ali", "at": "2026-08-04T00:00:00Z"}
    annotation = {**body, "entry_hash": annotation_entry_hash(body)}
    errors = validate_annotation(annotation)
    assert any("plus or amplify" in error for error in errors)


def test_annotation_field_closure_violated() -> None:
    annotation = make_annotation()
    annotation["extra"] = True
    errors = validate_annotation(annotation)
    assert any("field closure violated" in error for error in errors)


def test_annotation_directory_flows_through_check(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    annotations_dir = tmp_path / "annotations"
    annotations_dir.mkdir()
    good = make_annotation(record_hash=digest)
    (annotations_dir / "one.json").write_text(json.dumps(good))
    tampered = make_annotation(record_hash=digest, author="tampered-after-write")
    tampered["entry_hash"] = good["entry_hash"]  # stale hash from a different body
    (annotations_dir / "two.json").write_text(json.dumps(tampered))

    report = check(receipts_dir=receipts_dir, decisions_path=decisions_path, workspace=workspace, annotations_dir=annotations_dir)
    assert report["valid"] is False
    assert report["annotations"] == 1
    assert any("annotation was edited" in error for error in report["errors"])


# --- decisions.jsonl hash-chain adversarial cases ------------------------------


def test_tampered_decision_body_breaks_entry_hash(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    lines = decisions_path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["decided_by"] = "someone-else"
    decisions_path.write_text(json.dumps(entry) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert entries == []
    assert any("entry_hash does not match its signed body" in error for error in errors)


def test_tampered_previous_entry_hash_breaks_chain(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest).add(
        gate_id=receipt["gate_id"], receipt_hash_value=digest, decided_at="2026-08-04T00:06:00Z"
    )
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    lines = decisions_path.read_text().splitlines()
    second = json.loads(lines[1])
    second["previous_entry_hash"] = "a" * 64
    decisions_path.write_text(lines[0] + "\n" + json.dumps(second) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert any("chain integrity broken" in error for error in errors)


def test_spliced_decision_entry_from_another_chain_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)

    first = DecisionChainBuilder().add(gate_id="gate-a", receipt_hash_value=digest)
    second = DecisionChainBuilder().add(gate_id="gate-b", receipt_hash_value=digest)
    spliced_line = dict(second.lines[0])
    spliced_line["sequence"] = 1
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text(json.dumps(first.lines[0]) + "\n" + json.dumps(spliced_line) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert any("chain integrity broken" in error for error in errors)
    assert len(entries) <= 1


def test_forged_entry_hash_without_recompute_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    entry = json.loads(decisions_path.read_text())
    entry["entry_hash"] = "b" * 64
    decisions_path.write_text(json.dumps(entry) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert any("entry_hash does not match its signed body" in error for error in errors)


def test_truncated_decision_line_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    raw = decisions_path.read_text()
    decisions_path.write_text(raw[: len(raw) // 2])

    entries, errors = load_decisions(decisions_path)
    assert entries == []
    assert errors != []


def test_decisions_field_closure_violated(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    entry = dict(decisions.lines[0])
    entry["unexpected"] = True
    decisions_path.write_text(json.dumps(entry) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert entries == []
    assert any("field closure violated" in error for error in errors)


def test_decisions_sequence_mismatch_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    entry = dict(decisions.lines[0])
    entry["sequence"] = 5
    decisions_path.write_text(json.dumps(entry) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert any("sequence must equal its position" in error for error in errors)


def test_decisions_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text('{"sequence": 0, "sequence": 1}\n')
    entries, errors = load_decisions(decisions_path)
    assert entries == []
    assert errors != []


def test_decisions_unknown_decision_value_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    entry = dict(decisions.lines[0])
    entry["decision"] = "maybe"
    # Recompute entry_hash so this fails on shape, not on chain tamper, to isolate the assertion.
    body = {key: entry[key] for key in ("schema_version", "gate_id", "decision", "decided_by", "decided_at", "receipt_hash", "evidence_refs")}
    entry["entry_hash"] = compute_entry_hash(entry["sequence"], entry["previous_entry_hash"], body)
    decisions_path.write_text(json.dumps(entry) + "\n")

    entries, errors = load_decisions(decisions_path)
    assert any("decision must be approve or reject" in error for error in errors)


def test_decisions_bad_receipt_hash_format_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value="not-a-hash")
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    entries, errors = load_decisions(decisions_path)
    assert any("receipt_hash must be an exact lowercase SHA-256 string" in error for error in errors)


# --- receipt / annotation closed-shape adversarial cases -----------------------


def test_hostile_receipt_scalar_returns_errors() -> None:
    assert validate_receipt(True) != []
    assert validate_receipt({}) != []


def test_receipt_field_closure_violated(tmp_path: Path) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["unexpected"] = True
    errors = validate_receipt(receipt)
    assert any("field closure violated" in error for error in errors)


def test_receipt_missing_field_reported(tmp_path: Path) -> None:
    receipt = make_receipt(tmp_path / "ws")
    del receipt["queue_ref"]
    errors = validate_receipt(receipt)
    assert any("missing fields" in error and "queue_ref" in error for error in errors)


def test_receipt_schema_version_mismatch_is_rejected(tmp_path: Path) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["schema_version"] = "hound.approval.gate-receipt.v0"
    errors = validate_receipt(receipt)
    assert any("not the canonical gate-receipt version" in error for error in errors)


@pytest.mark.parametrize("lane", ["", "Wiki-Refresh", "wiki_refresh", "-wiki", "wiki-"])
def test_receipt_lane_identifier_bounds_are_enforced(tmp_path: Path, lane: str) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["lane"] = lane
    errors = validate_receipt(receipt)
    assert any("bounded lowercase identifier" in error for error in errors)


@pytest.mark.parametrize("timestamp", ["2026-08-04", "2026-08-04T00:00:00", "not-a-time", "2026-08-04T00:00:00+00:00"])
def test_receipt_timestamp_format_is_strict(tmp_path: Path, timestamp: str) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["requested_at"] = timestamp
    errors = validate_receipt(receipt)
    assert any("RFC3339" in error for error in errors)


def test_receipt_duplicate_subject_artifact_path_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipt = make_receipt(workspace, artifact_names=("e/a.json",))
    receipt["subject"]["artifacts"].append(dict(receipt["subject"]["artifacts"][0]))
    errors = validate_receipt(receipt)
    assert any("duplicates another artifact" in error for error in errors)


def test_receipt_subject_requires_at_least_one_artifact(tmp_path: Path) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["subject"]["artifacts"] = []
    errors = validate_receipt(receipt)
    assert any("at least one artifact" in error for error in errors)


def test_receipt_artifact_hash_must_be_sha256(tmp_path: Path) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["subject"]["artifacts"][0]["hash"] = "xyz"
    errors = validate_receipt(receipt)
    assert any("SHA-256" in error for error in errors)


def test_receipt_empty_gate_id_is_rejected(tmp_path: Path) -> None:
    receipt = make_receipt(tmp_path / "ws")
    receipt["gate_id"] = ""
    errors = validate_receipt(receipt)
    assert any("gate_id must be a non-empty identifier" in error for error in errors)


def test_annotation_missing_field_reported() -> None:
    annotation = make_annotation()
    del annotation["author"]
    errors = validate_annotation(annotation)
    assert any("missing fields" in error and "author" in error for error in errors)


# --- directory loaders ----------------------------------------------------------


def test_load_receipts_missing_directory_reports_error(tmp_path: Path) -> None:
    receipts, errors = load_receipts(tmp_path / "does-not-exist")
    assert receipts == {}
    assert any("missing, not a directory" in error for error in errors)


def test_load_receipts_rejects_duplicate_content(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt, filename="one.json")
    write_receipt(receipts_dir, receipt, filename="two.json")

    receipts, errors = load_receipts(receipts_dir)
    assert len(receipts) == 1
    assert any("duplicate receipt content" in error for error in errors)


def test_load_receipts_rejects_oversize(tmp_path: Path) -> None:
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    (receipts_dir / "big.json").write_text(json.dumps({"pad": "x" * 100_000}))

    receipts, errors = load_receipts(receipts_dir)
    assert receipts == {}
    assert any("exceeds" in error and "bytes" in error for error in errors)


def test_load_receipts_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    (receipts_dir / "dup.json").write_text('{"gate_id": "a", "gate_id": "b"}')

    receipts, errors = load_receipts(receipts_dir)
    assert receipts == {}
    assert errors != []


def test_load_receipts_rejects_non_object_json(tmp_path: Path) -> None:
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    (receipts_dir / "list.json").write_text("[]")

    receipts, errors = load_receipts(receipts_dir)
    assert receipts == {}
    assert any("must be an object" in error for error in errors)


def test_load_receipts_rejects_symlinked_directory(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)

    receipts, errors = load_receipts(link)
    assert receipts == {}
    assert any("symlink" in error for error in errors)


def test_load_annotations_missing_directory_reports_error(tmp_path: Path) -> None:
    annotations, errors = load_annotations(tmp_path / "does-not-exist")
    assert annotations == []
    assert any("missing, not a directory" in error for error in errors)


# --- CLI --------------------------------------------------------------------


def test_cli_valid_inputs_pass(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    result = _cli(
        "--receipts", str(receipts_dir), "--decisions", str(decisions_path), "--workspace", str(workspace), "--json"
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["valid"] is True


def test_cli_invalid_inputs_report_errors(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    decisions = DecisionChainBuilder().add(gate_id="gate-1", receipt_hash_value="c" * 64)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    result = _cli("--receipts", str(receipts_dir), "--decisions", str(decisions_path), "--workspace", str(workspace))
    assert result.returncode == 1
    assert "invalid" in result.stdout
    assert "ERROR:" in result.stderr


def test_cli_reports_legal_states_on_stdout(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    receipt = make_receipt(workspace)
    write_receipt(receipts_dir, receipt)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")

    result = _cli("--receipts", str(receipts_dir), "--decisions", str(decisions_path), "--workspace", str(workspace))
    assert result.returncode == 0
    assert "STATE: open gate" in result.stdout


def test_cli_missing_receipts_dir_fails_closed(tmp_path: Path) -> None:
    decisions_path = tmp_path / "decisions.jsonl"
    decisions_path.write_text("")
    result = _cli(
        "--receipts", str(tmp_path / "nope"), "--decisions", str(decisions_path), "--workspace", str(tmp_path)
    )
    assert result.returncode == 1


def test_cli_malformed_arguments_return_error_without_traceback() -> None:
    result = _cli("--receipts")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_cli_with_stage_ledger_and_annotations_flags(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    receipts_dir = tmp_path / "receipts"
    names = tuple(f"e/{key}.json" for key in MIGRATED_EVIDENCE_KEYS)
    receipt = make_receipt(workspace, artifact_names=names)
    write_receipt(receipts_dir, receipt)
    digest = receipt_hash(receipt)
    decisions = DecisionChainBuilder().add(gate_id=receipt["gate_id"], receipt_hash_value=digest)
    decisions_path = tmp_path / "decisions.jsonl"
    decisions.write(decisions_path)

    ledger = (
        StageLedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=migrated_evidence(workspace, names),
            approval_ref=decisions.last_hash(),
        )
    )
    ledger_path = tmp_path / "ledger.json"
    ledger.write(ledger_path)

    annotations_dir = tmp_path / "annotations"
    annotations_dir.mkdir()
    annotation = make_annotation(record_hash=digest)
    (annotations_dir / "one.json").write_text(json.dumps(annotation))

    result = _cli(
        "--receipts",
        str(receipts_dir),
        "--decisions",
        str(decisions_path),
        "--workspace",
        str(workspace),
        "--stage-ledger",
        str(ledger_path),
        "--annotations",
        str(annotations_dir),
        "--json",
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["valid"] is True
    assert report["annotations"] == 1
    assert report["stage_ledger"]["lanes"][0]["lane"] == "wiki-refresh"
