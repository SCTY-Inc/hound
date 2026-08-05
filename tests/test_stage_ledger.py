from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from migration.consumer_inventory import EVIDENCE_FIELDS
from migration.stage_ledger import (
    GENESIS_HASH,
    LedgerError,
    compute_entry_hash,
    lane_stage,
    load_ledger,
    validate_anchor,
    validate_deletion,
    validate_ledger,
)


ROOT = Path(__file__).parents[1]


def _no_evidence() -> dict[str, None]:
    return {key: None for key in EVIDENCE_FIELDS}


def _evidence(**pointers: str) -> dict[str, str | None]:
    value = _no_evidence()
    value.update(pointers)
    return value


class LedgerBuilder:
    """Test-only helper that appends correctly hash-chained entries."""

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
    ) -> "LedgerBuilder":
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
        entry = {
            "sequence": sequence,
            "previous_entry_hash": self._previous,
            "entry_hash": entry_hash,
            **body,
        }
        self.entries.append(entry)
        self._previous = entry_hash
        return self

    def build(self) -> dict[str, Any]:
        return {"schema_version": "hound.migration.stage-ledger.v1", "entries": self.entries}


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "migration/check_stage_ledger.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _write(tmp_path: Path, value: dict[str, Any]) -> Path:
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(value))
    return path


# --- happy paths -----------------------------------------------------------


def test_single_valid_transition_validates() -> None:
    ledger = LedgerBuilder().add("wiki-refresh", "freeze_contracts", "import_mirror").build()
    assert validate_ledger(ledger) == []


def test_non_shadow_lane_full_progression_validates() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/wiki-refresh.json",
        )
        .add(
            "wiki-refresh",
            "migrated",
            "retired",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
                legacy_absent="e/f.json",
            ),
        )
        .build()
    )
    assert validate_ledger(ledger) == []
    assert lane_stage(ledger, "wiki-refresh") == "retired"
    assert validate_deletion(ledger, "wiki-refresh") == []


def test_shadow_lane_full_progression_validates() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .add(
            "pulse",
            "shadow",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/pulse.json",
        )
        .build()
    )
    assert validate_ledger(ledger) == []
    assert lane_stage(ledger, "pulse") == "migrated"


def test_multi_lane_interleaved_ledger_validates() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    assert validate_ledger(ledger) == []
    assert lane_stage(ledger, "pulse") == "shadow"
    assert lane_stage(ledger, "wiki-refresh") == "import_mirror"
    assert lane_stage(ledger, "never-appeared") == "freeze_contracts"


# --- stage-order adversarial cases -----------------------------------------


def test_skipped_stage_is_rejected() -> None:
    ledger = LedgerBuilder().add("wiki-refresh", "freeze_contracts", "migrated").build()
    errors = validate_ledger(ledger)
    assert any("skips stage order" in error for error in errors)


def test_shadow_required_lane_cannot_skip_shadow() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add(
            "pulse",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/pulse.json",
        )
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("skips stage order" in error for error in errors)


def test_non_shadow_lane_cannot_enter_shadow() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add("wiki-refresh", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("skips stage order" in error for error in errors)


def test_regressed_stage_is_rejected() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .add("pulse", "shadow", "import_mirror")
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("regresses stage order" in error for error in errors)


def test_from_stage_mismatch_with_lane_history_is_rejected() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add(
            "pulse",
            "shadow",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/pulse.json",
        )
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("does not match its current stage" in error for error in errors)


def test_retired_is_terminal() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/wiki-refresh.json",
        )
        .add(
            "wiki-refresh",
            "migrated",
            "retired",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
                legacy_absent="e/f.json",
            ),
        )
        .add("wiki-refresh", "retired", "import_mirror")
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("does not match its current stage" in error or "regresses" in error or "skips" in error for error in errors)


# --- deletion gate -----------------------------------------------------------


def test_deletion_before_retired_is_rejected() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    errors = validate_deletion(ledger, "pulse")
    assert any("has not reached retired stage" in error for error in errors)


def test_deletion_of_lane_never_started_is_rejected() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    errors = validate_deletion(ledger, "wiki-refresh")
    assert any("has not reached retired stage" in error for error in errors)


def test_deletion_after_retired_is_allowed() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/wiki-refresh.json",
        )
        .add(
            "wiki-refresh",
            "migrated",
            "retired",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
                legacy_absent="e/f.json",
            ),
        )
        .build()
    )
    assert validate_deletion(ledger, "wiki-refresh") == []


# --- evidence / approval gating ---------------------------------------------


def test_missing_evidence_for_migrated_is_rejected() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(static_no_direct_provider="e/a.json"),
            approval_ref="approvals/wiki-refresh.json",
        )
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("evidence.credential_unset is required" in error for error in errors)
    assert any("evidence.recovery_drill is required" in error for error in errors)
    assert any("evidence.full_cycle is required" in error for error in errors)
    assert any("evidence.unix_socket is required" in error for error in errors)


def test_missing_legacy_absent_for_retired_is_rejected() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/wiki-refresh.json",
        )
        .add(
            "wiki-refresh",
            "migrated",
            "retired",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
        )
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("evidence.legacy_absent is required" in error for error in errors)


def test_missing_approval_ref_for_migrated_is_rejected() -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
        )
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("requires a non-null approval_ref" in error for error in errors)


def test_shadow_requires_parity_evidence() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").add("pulse", "import_mirror", "shadow").build()
    errors = validate_ledger(ledger)
    assert any("evidence.parity is required" in error for error in errors)


def test_duplicate_evidence_pointer_is_rejected() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/dup.json", baseline_scan="e/dup.json"))
        .build()
    )
    errors = validate_ledger(ledger)
    assert any("duplicate evidence path" in error for error in errors)


# --- hash-chain / signature adversarial cases --------------------------------


def test_tampered_body_breaks_entry_hash() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    ledger["entries"][0]["timestamp"] = "2099-01-01T00:00:00Z"
    errors = validate_ledger(ledger)
    assert any("entry_hash does not match its signed body" in error for error in errors)


def test_tampered_previous_entry_hash_breaks_chain() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    ledger["entries"][1]["previous_entry_hash"] = "a" * 64
    errors = validate_ledger(ledger)
    assert any("chain integrity broken" in error for error in errors)


def test_reordered_entries_break_chain_even_if_stage_order_would_be_valid() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    entries = ledger["entries"]
    entries[0], entries[1] = entries[1], entries[0]
    entries[0]["sequence"], entries[1]["sequence"] = 0, 1
    errors = validate_ledger(ledger)
    assert any("chain integrity broken" in error for error in errors)


def test_spliced_entry_from_another_chain_is_rejected() -> None:
    first = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    second = LedgerBuilder().add("wiki-refresh", "freeze_contracts", "import_mirror").build()
    spliced = {"schema_version": first["schema_version"], "entries": [first["entries"][0], second["entries"][0]]}
    spliced["entries"][1]["sequence"] = 1
    errors = validate_ledger(spliced)
    assert any("chain integrity broken" in error for error in errors)


def test_forged_entry_hash_without_recompute_is_rejected() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    ledger["entries"][0]["entry_hash"] = "b" * 64
    errors = validate_ledger(ledger)
    assert any("entry_hash does not match its signed body" in error for error in errors)


# --- closed-shape / type adversarial cases -----------------------------------


def test_hostile_top_level_scalar_returns_errors() -> None:
    assert validate_ledger(True) != []
    assert validate_ledger({"schema_version": "hound.migration.stage-ledger.v1", "entries": {}}) != []


def test_entry_field_closure_violated() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    ledger["entries"][0]["unexpected"] = True
    errors = validate_ledger(ledger)
    assert any("field closure" in error for error in errors)


def test_entry_missing_field_reported() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    del ledger["entries"][0]["approval_ref"]
    errors = validate_ledger(ledger)
    assert any("missing fields" in error and "approval_ref" in error for error in errors)


def test_sequence_must_equal_position() -> None:
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    ledger["entries"][1]["sequence"] = 5
    errors = validate_ledger(ledger)
    assert any("sequence must equal its position" in error for error in errors)


@pytest.mark.parametrize("lane", ["", "Pulse", "pulse_radar", "pulse!", " pulse", "pulse "])
def test_lane_identifier_bounds_are_enforced(lane: str) -> None:
    ledger = LedgerBuilder().add("placeholder", "freeze_contracts", "import_mirror").build()
    ledger["entries"][0]["lane"] = lane
    errors = validate_ledger(ledger)
    assert any("bounded lowercase identifier" in error for error in errors)


@pytest.mark.parametrize(
    "timestamp",
    ["2026-08-04", "2026-08-04 00:00:00Z", "2026-08-04T00:00:00", "2026-08-04T00:00:00+00:00", "not-a-timestamp"],
)
def test_timestamp_format_is_strict(timestamp: str) -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror", timestamp=timestamp).build()
    errors = validate_ledger(ledger)
    assert any("RFC3339" in error for error in errors)


def test_unknown_stage_value_is_rejected() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    ledger["entries"][0]["to_stage"] = "cutover"
    errors = validate_ledger(ledger)
    assert any("not an allowed stage" in error for error in errors)


def test_hostile_evidence_container_type_is_reported() -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    ledger["entries"][0]["evidence"] = []
    errors = validate_ledger(ledger)
    assert any("evidence" in error for error in errors)


def test_entries_exceeding_max_size_is_rejected() -> None:
    builder = LedgerBuilder()
    ledger = {"schema_version": "hound.migration.stage-ledger.v1", "entries": [builder.add("pulse", "freeze_contracts", "import_mirror").entries[0]] * 10_001}
    errors = validate_ledger(ledger)
    assert any("exceeds maximum size" in error for error in errors)


# --- loader ------------------------------------------------------------------


def test_load_ledger_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    path.write_text('{"schema_version":"x","schema_version":"y","entries":[]}')
    with pytest.raises(LedgerError, match="duplicate JSON object key"):
        load_ledger(path)


def test_load_ledger_rejects_oversize(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    path.write_bytes(b"{" + b" " * 1_048_576)
    with pytest.raises(LedgerError, match="exceeds"):
        load_ledger(path)


def test_load_ledger_rejects_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    path.write_text("[]")
    with pytest.raises(LedgerError, match="must be an object"):
        load_ledger(path)


# --- git anchor ---------------------------------------------------------
#
# Fixture git repos live under tmp_path so these tests never depend on (or
# risk tripping over) the real hound repo's own working-tree state.


def _init_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Stage Ledger Test"], cwd=repo, check=True)
    return repo


def _commit_ledger(repo: Path, ledger: dict[str, Any], relpath: str = "stage-ledger.v1.json") -> Path:
    path = repo / relpath
    path.write_text(json.dumps(ledger))
    subprocess.run(["git", "add", relpath], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "commit ledger"], cwd=repo, check=True)
    return path


def _rehash_chain(entries: list[dict[str, Any]]) -> None:
    """Re-derive every entry_hash/previous_entry_hash in order, as a tamperer would."""

    previous = GENESIS_HASH
    for entry in entries:
        body = {key: entry[key] for key in ("lane", "from_stage", "to_stage", "timestamp", "evidence", "approval_ref")}
        entry["previous_entry_hash"] = previous
        entry["entry_hash"] = compute_entry_hash(entry["sequence"], previous, body)
        previous = entry["entry_hash"]


def test_anchor_rejects_in_place_mutation_even_with_consistent_rehash(tmp_path: Path) -> None:
    """THE live gap: an uncommitted rewrite of a historical entry with every
    downstream hash re-derived passes chain verification cleanly, but must
    still be rejected by the anchor check against the committed copy."""

    repo = _init_git_repo(tmp_path)
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .add(
            "pulse",
            "shadow",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/pulse.json",
        )
        .build()
    )
    path = _commit_ledger(repo, ledger)

    ledger["entries"][0]["evidence"]["baseline_scan"] = "mutated/path.json"
    _rehash_chain(ledger["entries"])
    path.write_text(json.dumps(ledger))

    assert validate_ledger(ledger) == [], "chain verification alone must stay green -- that is the gap"

    report = validate_anchor(path, ledger)
    assert report["status"] == "violation"
    assert any("entries[0]" in error and "mutated entry" in error for error in report["errors"])


def test_anchor_rejects_truncation(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    path = _commit_ledger(repo, ledger)

    truncated = {"schema_version": ledger["schema_version"], "entries": ledger["entries"][:1]}
    path.write_text(json.dumps(truncated))

    report = validate_anchor(path, truncated)
    assert report["status"] == "violation"
    assert any("entries[1]" in error and "truncation" in error for error in report["errors"])


def test_anchor_classifies_reorder(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .build()
    )
    path = _commit_ledger(repo, ledger)

    reordered = {"schema_version": ledger["schema_version"], "entries": [ledger["entries"][1], ledger["entries"][0]]}
    path.write_text(json.dumps(reordered))

    report = validate_anchor(path, reordered)
    assert report["status"] == "violation"
    assert any("entries[0]" in error and "reorder" in error for error in report["errors"])


def test_anchor_allows_pure_append(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    builder = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror")
    path = _commit_ledger(repo, builder.build())

    appended = builder.add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json")).build()
    path.write_text(json.dumps(appended))

    report = validate_anchor(path, appended)
    assert report == {"status": "ok", "ref": "HEAD", "reason": None, "errors": []}


def test_anchor_unmodified_committed_ledger_is_ok(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = _commit_ledger(repo, ledger)

    report = validate_anchor(path, ledger)
    assert report == {"status": "ok", "ref": "HEAD", "reason": None, "errors": []}


def test_anchor_unavailable_outside_git_checkout(tmp_path: Path) -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(ledger))

    report = validate_anchor(path, ledger)
    assert report["status"] == "unavailable"
    assert report["errors"] == []


def test_anchor_unavailable_when_file_untracked_at_ref(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    subprocess.run(["git", "commit", "--allow-empty", "-q", "-m", "empty"], cwd=repo, check=True)
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = repo / "stage-ledger.v1.json"
    path.write_text(json.dumps(ledger))

    report = validate_anchor(path, ledger)
    assert report["status"] == "unavailable"
    assert report["errors"] == []


def test_anchor_unavailable_for_unknown_ref(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = _commit_ledger(repo, ledger)

    report = validate_anchor(path, ledger, ref="does-not-exist")
    assert report["status"] == "unavailable"
    assert report["errors"] == []


# --- CLI -----------------------------------------------------------------


def test_cli_valid_ledger_passes(tmp_path: Path) -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = _write(tmp_path, ledger)
    completed = _cli("--ledger", str(path), "--json")
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["valid"] is True


def test_cli_invalid_ledger_reports_errors(tmp_path: Path) -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "migrated").build()
    path = _write(tmp_path, ledger)
    completed = _cli("--ledger", str(path), "--json")
    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["valid"] is False
    assert any("skips stage order" in error for error in report["errors"])


def test_cli_check_deletion_before_retired_fails(tmp_path: Path) -> None:
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = _write(tmp_path, ledger)
    completed = _cli("--ledger", str(path), "--check-deletion", "pulse", "--json")
    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert any("has not reached retired stage" in error for error in report["errors"])
    assert report["deletion_check"] == {"lane": "pulse", "stage": "import_mirror"}


def test_cli_check_deletion_after_retired_passes(tmp_path: Path) -> None:
    ledger = (
        LedgerBuilder()
        .add("wiki-refresh", "freeze_contracts", "import_mirror")
        .add(
            "wiki-refresh",
            "import_mirror",
            "migrated",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
            ),
            approval_ref="approvals/wiki-refresh.json",
        )
        .add(
            "wiki-refresh",
            "migrated",
            "retired",
            evidence=_evidence(
                static_no_direct_provider="e/a.json",
                credential_unset="e/b.json",
                unix_socket="e/c.json",
                recovery_drill="e/d.json",
                full_cycle="e/e.json",
                legacy_absent="e/f.json",
            ),
        )
        .build()
    )
    path = _write(tmp_path, ledger)
    completed = _cli("--ledger", str(path), "--check-deletion", "wiki-refresh", "--json")
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["valid"] is True
    assert report["deletion_check"] == {"lane": "wiki-refresh", "stage": "retired"}


def test_cli_malformed_arguments_return_error_without_traceback() -> None:
    completed = _cli("--ledger")
    assert completed.returncode == 2
    assert "Traceback" not in completed.stderr


def test_cli_missing_ledger_file_fails_closed(tmp_path: Path) -> None:
    completed = _cli("--ledger", str(tmp_path / "missing.json"), "--json")
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    report = json.loads(completed.stdout)
    assert report["valid"] is False


def test_cli_anchor_check_runs_without_flag_outside_git_repo(tmp_path: Path) -> None:
    """No git repo backs tmp_path, so the anchor check must degrade
    non-fatally rather than failing a ledger that is otherwise valid."""

    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = _write(tmp_path, ledger)
    completed = _cli("--ledger", str(path), "--json")
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["valid"] is True
    assert report["anchor_check"]["status"] == "unavailable"


def test_cli_anchor_violation_fails_even_though_chain_verifies(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Stage Ledger Test"], cwd=repo, check=True)

    ledger = (
        LedgerBuilder()
        .add("pulse", "freeze_contracts", "import_mirror")
        .add("pulse", "import_mirror", "shadow", evidence=_evidence(parity="e/parity.json"))
        .build()
    )
    path = repo / "ledger.json"
    path.write_text(json.dumps(ledger))
    subprocess.run(["git", "add", "ledger.json"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "ledger"], cwd=repo, check=True)

    ledger["entries"][0]["evidence"]["baseline_scan"] = "changed.json"
    previous = ledger["entries"][0]["previous_entry_hash"]
    for entry in ledger["entries"]:
        body = {key: entry[key] for key in ("lane", "from_stage", "to_stage", "timestamp", "evidence", "approval_ref")}
        entry["previous_entry_hash"] = previous
        entry["entry_hash"] = compute_entry_hash(entry["sequence"], previous, body)
        previous = entry["entry_hash"]
    path.write_text(json.dumps(ledger))

    completed = _cli("--ledger", str(path), "--json")
    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["valid"] is False
    assert report["anchor_check"]["status"] == "violation"
    assert any("mutated entry" in error for error in report["anchor_check"]["errors"])


def test_cli_anchor_ref_flag_selects_ref(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Stage Ledger Test"], cwd=repo, check=True)
    ledger = LedgerBuilder().add("pulse", "freeze_contracts", "import_mirror").build()
    path = repo / "ledger.json"
    path.write_text(json.dumps(ledger))
    subprocess.run(["git", "add", "ledger.json"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "ledger"], cwd=repo, check=True)

    completed = _cli("--ledger", str(path), "--anchor-ref", "does-not-exist", "--json")
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["anchor_check"]["status"] == "unavailable"
    assert report["anchor_check"]["ref"] == "does-not-exist"
