"""Adversarial tests for the HSP-21 acceptance gate.

The manifest is only worth something if the checker refuses to bless a
document that claims more than the repository proves. These tests attack it
from the four directions that matter: an orphan artifact no row claims, a row
claiming completion it has not earned, an artifact that is not on disk, and a
manifest tampered with in shape.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migration.check_acceptance import MANIFEST_PATH, ROOT, ROW_IDS, check, load_manifest, main

VISION_LINES = {identifier: 1243 + index for index, identifier in enumerate(ROW_IDS, start=1)}


def _row(identifier: str, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": identifier,
        "vision_line": VISION_LINES[identifier],
        "status": "open",
        "claim": f"synthetic claim for {identifier}",
        "tests": [],
        "evidence": [],
        "commands": [],
        "supporting": [],
        "assertions": [],
        "missing": ["nothing is proven in this fixture"],
        "deviations": [],
    }
    row.update(overrides)
    return row


def _workspace(tmp_path: Path, **first_row: object) -> tuple[Path, Path]:
    """A minimal repository whose declared scope is exactly two proof files."""
    proof = tmp_path / "proof"
    proof.mkdir()
    (proof / "test_one.py").write_text("def test_one() -> None:\n    assert True\n", encoding="utf-8")
    (proof / "test_two.py").write_text("def test_two() -> None:\n    assert True\n", encoding="utf-8")

    rows = [_row(identifier) for identifier in ROW_IDS]
    rows[0] = _row(
        ROW_IDS[0],
        status="complete",
        tests=["proof/test_one.py", "proof/test_two.py"],
        assertions=["both synthetic proofs hold"],
        missing=[],
        **first_row,
    )
    manifest = {
        "schema_version": "hound.migration.acceptance.v1",
        "goal": "synthetic fixture",
        "acceptance_command": "uv run python migration/check_acceptance.py --run-tests",
        "test_command": "python -m pytest -q",
        "traceability_scope": {
            "note": "synthetic",
            "globs": ["proof/*.py"],
            "excluded": [],
            "src_exclusion_reason": "synthetic",
        },
        "summary": {"total": 22, "complete": 1, "partial": 0, "open": 21},
        "rows": rows,
    }
    path = tmp_path / "acceptance.v1.json"
    path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return path, tmp_path


def _errors(path: Path, root: Path) -> list[str]:
    return check(manifest_path=path, root=root)["errors"]


def _rewrite(path: Path, mutate) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutate(manifest)
    path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")


# --- the fixture itself is honest -------------------------------------------------


def test_the_synthetic_workspace_validates(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    assert _errors(path, root) == []


# --- orphan artifact --------------------------------------------------------------


def test_an_in_scope_file_no_row_claims_is_an_orphan(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    (root / "proof" / "test_three.py").write_text("def test_three() -> None:\n    assert True\n", encoding="utf-8")
    assert any("orphan artifact proof/test_three.py" in error for error in _errors(path, root))


def test_dropping_an_artifact_from_its_row_orphans_it(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("tests", ["proof/test_one.py"]))
    assert any("orphan artifact proof/test_two.py" in error for error in _errors(path, root))


def test_the_same_artifact_owned_by_two_rows_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["rows"][1]["tests"] = ["proof/test_two.py"]

    _rewrite(path, mutate)
    errors = _errors(path, root)
    assert any("owned by both HSP-01 and HSP-02" in error for error in errors)


def test_a_supporting_citation_must_name_another_rows_artifact(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][1].__setitem__("supporting", ["proof/test_absent.py"]))
    assert any("supporting artifact proof/test_absent.py is owned by no row" in error for error in _errors(path, root))


def test_a_row_may_not_cite_its_own_artifact_as_supporting(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("supporting", ["proof/test_one.py"]))
    assert any("supporting artifact proof/test_one.py is its own" in error for error in _errors(path, root))


# --- unproven claim ---------------------------------------------------------------


def test_complete_with_no_proving_test_is_an_unproven_claim(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["rows"][1] |= {"status": "complete", "missing": [], "assertions": ["asserted"], "tests": []}
        manifest["summary"] |= {"complete": 2, "open": 20}

    _rewrite(path, mutate)
    assert any("status 'complete' with no proving test file" in error for error in _errors(path, root))


def test_complete_that_still_names_missing_work_must_be_partial(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("missing", ["a lane that never migrated"]))
    assert any("names 1 missing item(s); use 'partial'" in error for error in _errors(path, root))


def test_complete_with_no_asserted_behavior_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("assertions", []))
    assert any("status 'complete' with no asserted behavior" in error for error in _errors(path, root))


@pytest.mark.parametrize("status", ["partial", "open"])
def test_partial_or_open_must_say_what_is_missing(tmp_path: Path, status: str) -> None:
    path, root = _workspace(tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["rows"][1] |= {"status": status, "missing": []}
        manifest["summary"] |= {status: 1, "open": 20}

    _rewrite(path, mutate)
    assert any(f"status {status!r} must say what is missing" in error for error in _errors(path, root))


def test_summary_counts_must_match_the_rows(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["summary"].__setitem__("complete", 7))
    assert any("summary.complete says 7, the rows count 1" in error for error in _errors(path, root))


def test_a_row_command_may_not_run_a_test_it_does_not_own(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["rows"][1]["commands"] = [{"command": "python -m pytest tests/test_runtime.py", "ci": True}]

    _rewrite(path, mutate)
    assert any("its command runs tests/test_runtime.py, which the row does not own" in error for error in _errors(path, root))


# --- missing artifact -------------------------------------------------------------


def test_a_named_artifact_that_is_not_on_disk_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    (root / "proof" / "test_two.py").unlink()
    assert any("artifact proof/test_two.py does not exist" in error for error in _errors(path, root))


def test_a_named_evidence_directory_that_is_not_on_disk_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][1].__setitem__("evidence", ["evidence/never/"]))
    assert any("evidence directory evidence/never/ does not exist" in error for error in _errors(path, root))


def test_an_empty_evidence_directory_proves_nothing(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    (root / "evidence" / "hollow").mkdir(parents=True)
    _rewrite(path, lambda m: m["rows"][1].__setitem__("evidence", ["evidence/hollow/"]))
    assert any("evidence directory evidence/hollow/ is empty" in error for error in _errors(path, root))


def test_a_missing_manifest_file_is_reported_not_raised(tmp_path: Path) -> None:
    report = check(manifest_path=tmp_path / "absent.json", root=tmp_path)
    assert report["valid"] is False
    assert any("cannot read" in error for error in report["errors"])


# --- tampered manifest ------------------------------------------------------------


def test_an_unknown_top_level_field_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m.__setitem__("waivers", ["HSP-16"]))
    assert any("manifest: unknown field 'waivers'" in error for error in _errors(path, root))


def test_an_unknown_row_field_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("waived", True))
    assert any("unknown field 'waived'" in error for error in _errors(path, root))


def test_a_dropped_row_field_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].pop("missing"))
    assert any("missing field 'missing'" in error for error in _errors(path, root))


def test_a_deleted_row_breaks_the_ordered_twenty_two(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"].pop(15))
    assert any("exactly 22 entries ordered HSP-01..HSP-22" in error for error in _errors(path, root))


def test_reordered_rows_are_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["rows"][3], manifest["rows"][4] = manifest["rows"][4], manifest["rows"][3]

    _rewrite(path, mutate)
    assert any("ordered HSP-01..HSP-22" in error for error in _errors(path, root))


def test_a_duplicated_row_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"].__setitem__(2, copy.deepcopy(m["rows"][1])))
    assert any("ordered HSP-01..HSP-22" in error for error in _errors(path, root))


def test_a_wrong_schema_version_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m.__setitem__("schema_version", "hound.migration.acceptance.v2"))
    assert any("schema_version must be" in error for error in _errors(path, root))


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    body = path.read_text(encoding="utf-8")
    path.write_text(body.replace('"summary":', '"summary": {"total": 0, "complete": 0, "partial": 0, "open": 0},\n "summary":', 1), encoding="utf-8")
    assert any("duplicate JSON key 'summary'" in error for error in _errors(path, root))


def test_a_non_ci_command_must_explain_itself(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][1].__setitem__("commands", [{"command": "echo hi", "ci": False}]))
    assert any("non-CI command must carry ci_reason" in error for error in _errors(path, root))


def test_a_ci_command_may_not_carry_an_excuse(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][1].__setitem__("commands", [{"command": "echo hi", "ci": True, "ci_reason": "because"}]))
    assert any("CI command must not carry ci_reason" in error for error in _errors(path, root))


def test_a_vision_line_pointing_at_the_wrong_row_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("vision_line", VISION_LINES["HSP-02"]))
    assert any("VISION.md:1245 does not begin the HSP-01 acceptance row" in error for error in _errors(path, root))


def test_a_vision_line_outside_the_document_is_rejected(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"][0].__setitem__("vision_line", 10**6))
    assert any("is outside VISION.md" in error for error in _errors(path, root))


def test_run_tests_refuses_to_run_against_an_invalid_manifest(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m.__setitem__("waivers", []))
    report = check(manifest_path=path, root=root, run_tests=True)
    assert report["runs"] == []
    assert any("refusing to run the suites" in error for error in report["errors"])


def test_run_tests_reports_a_failing_command(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)

    def mutate(manifest: dict) -> None:
        manifest["test_command"] = "python -c 'raise SystemExit(3)'"

    _rewrite(path, mutate)
    report = check(manifest_path=path, root=root, run_tests=True)
    assert report["valid"] is False
    assert any("command failed (exit 3)" in error for error in report["errors"])


# --- the real manifest ------------------------------------------------------------


def test_the_checked_in_manifest_validates() -> None:
    report = check()
    assert report["errors"] == []
    assert report["valid"] is True


def test_the_checked_in_manifest_claims_every_hsp_row_exactly_once() -> None:
    rows = load_manifest(MANIFEST_PATH)["rows"]
    assert [row["id"] for row in rows] == list(ROW_IDS)


def test_every_row_that_is_not_complete_names_what_blocks_it() -> None:
    for row in load_manifest(MANIFEST_PATH)["rows"]:
        if row["status"] != "complete":
            assert row["missing"], f"{row['id']} is {row['status']} but names nothing missing"


def _status(identifier: str) -> str:
    return next(row["status"] for row in load_manifest(MANIFEST_PATH)["rows"] if row["id"] == identifier)


def _ledger() -> list[dict]:
    return json.loads((ROOT / "migration" / "stage-ledger.v1.json").read_text(encoding="utf-8"))["entries"]


def test_hsp15_may_not_be_claimed_until_every_lane_is_retired_with_full_evidence() -> None:
    """HSP-15's gate is deletion after the drill and a full cycle, not merely a populated ledger."""
    entries = _ledger()
    retired = [entry for entry in entries if entry["to_stage"] == "retired"]
    complete = bool(entries) and len(retired) == len({entry["lane"] for entry in entries}) and all(value is not None for entry in retired for value in entry["evidence"].values())
    assert complete == (_status("HSP-15") == "complete"), "HSP-15's status must track whether every lane reached retired with all nine evidence slots filled"


def test_hsp22_may_not_be_claimed_while_a_migrated_lane_has_no_approval() -> None:
    """Every lane that became canonical must name the decision that let it."""
    migrated = [entry for entry in _ledger() if entry["to_stage"] == "migrated"]
    complete = bool(migrated) and all(entry["approval_ref"] for entry in migrated)
    assert complete or _status("HSP-22") != "complete", "a migrated lane with no approval_ref forbids claiming HSP-22"


def test_the_traceability_scope_actually_matches_the_evidence_trees() -> None:
    """A vacuous scope silently disables the orphan check.

    ``Path.glob`` treats ``**`` as directories only, so a ``migration/evidence/**``
    glob matches no files at all and every evidence bundle becomes invisible to
    the closure while the manifest still reports valid. The globs must reach the
    files, and every retained bundle must be inside the scope they define.
    """
    from migration.check_acceptance import _in_scope

    scope = load_manifest(MANIFEST_PATH)["traceability_scope"]
    covered = _in_scope(scope, ROOT)
    for tree in ("tests/evidence", "migration/evidence"):
        on_disk = {path.relative_to(ROOT).as_posix() for path in (ROOT / tree).rglob("*") if path.is_file()}
        assert on_disk, f"{tree} has no files; this guard would pass vacuously"
        assert on_disk <= covered, f"{tree} files outside the traceability scope: {sorted(on_disk - covered)[:5]}"


def test_the_cli_exits_nonzero_on_an_invalid_manifest(tmp_path: Path) -> None:
    path, root = _workspace(tmp_path)
    _rewrite(path, lambda m: m["rows"].pop())
    assert main(["--manifest", str(path), "--root", str(root)]) == 1


def test_the_cli_exits_zero_on_the_checked_in_manifest() -> None:
    assert main(["--json"]) == 0


def test_the_checker_runs_as_a_module_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "migration/check_acceptance.py", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["valid"] is True
