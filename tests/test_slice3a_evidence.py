"""Strict verifier for a staged or retained Slice 3A E2 seal.

It never runs tests or constructs observations.  The generator is the only
supported writer for a candidate; this verifier accepts only its closed leaf
set and values emitted by the proving pytest nodes.
"""

from __future__ import annotations

import hashlib
import errno
import json
import math
import os
import re
import signal
import stat
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree

import pytest


ROOT = Path(__file__).parents[1].resolve()
EVIDENCE = ROOT / "tests" / "evidence" / "slice3a"
SCHEMA = "houndd.slice3a.evidence-seal.v2"
REPORTS = {
    "canonical-query-matrix.json", "cursor-restart-hwm.json", "sqlite-independence.json",
    "journal-snapshot-matrix.json", "recovery-vs-verification.json", "identity-crash-matrix.json",
    "identity-transition-report.json", "identity-mode-lock-path-report.json", "restore-portability-manifest.json",
    "fd-failure-path-matrix.json", "read-state-before.json", "read-state-after.json",
}
JUNITS = {"slice3a-pytest.xml", "compatibility-pytest.xml"}
LEAVES = REPORTS | JUNITS | {"run-manifest.json", "bundle-source-digests.json"}
STALE_JUNIT_SHA256 = {
    "806f799cf947046b2799a322542c559cd795bbadbba5ebe9f1689a408156c9fc",
    "0a2e980f425cacbc41d8d5a4be48c253b5c8ab3189f38ae9241067e4a3422bc1",
}
SUITE_FILES = {
    "focused": (
        "tests/test_hsp05_transactions.py", "tests/test_hsp08_durable_query.py", "tests/test_hsp20_durable_state.py", "tests/test_hsp20_verification.py",
    ),
    "compatibility": (
        "tests/test_hsp04_contract.py", "tests/test_hsp05_transactions.py", "tests/test_hsp07_dedupe.py", "tests/test_hsp14_legacy_portability.py", "tests/test_hsp20_verification.py", "tests/test_hsp08_cursor.py", "tests/test_hsp08_query_contracts.py", "tests/test_hsp09_access.py", "tests/test_hsp08_query_engine.py", "tests/test_hsp09_query_authorization.py", "tests/test_hsp20_query_snapshot.py",
    ),
}

_REPORT_NODE_BASES = {
    "canonical-query-matrix.json": (
        "tests/test_hsp08_durable_query.py::test_durable_query_uses_exact_persisted_chain_and_all_canonical_filter_families",
        "tests/test_hsp08_durable_query.py::test_projection_filters_fail_explicitly_before_identity_or_journal_access",
    ),
    "sqlite-independence.json": (
        "tests/test_hsp08_durable_query.py::test_query_is_sqlite_independent_across_valid_corrupt_and_absent_indexes",
    ),
    "cursor-restart-hwm.json": (
        "tests/test_hsp08_durable_query.py::test_fixed_hwm_cursor_resumes_after_append_and_full_restart_with_limit_change",
    ),
    "read-state-before.json": (
        "tests/test_hsp08_durable_query.py::test_queries_and_replay_persist_no_server_read_state",
    ),
    "read-state-after.json": (
        "tests/test_hsp08_durable_query.py::test_queries_and_replay_persist_no_server_read_state",
    ),
    "journal-snapshot-matrix.json": (
        "tests/test_hsp20_durable_state.py::test_verified_snapshot_returns_exact_triplet_and_empty_read_creates_no_head",
        "tests/test_hsp20_durable_state.py::test_verified_snapshot_reads_triplet_once_under_one_lock",
        "tests/test_hsp20_durable_state.py::test_journal_operations_reject_noncanonical_sequence_scalars_without_changing_bytes",
    ),
    "recovery-vs-verification.json": (
        "tests/test_hsp20_durable_state.py::test_verified_snapshot_is_non_repairing_and_explicit_reconcile_repairs_only_suffix",
        "tests/test_hsp20_durable_state.py::test_verified_snapshot_tampering_fails_without_mutation",
    ),
    "fd-failure-path-matrix.json": (
        "tests/test_hsp20_durable_state.py::test_verified_snapshot_unsafe_mode_failures_are_fd_flat_and_nonmutating",
        "tests/test_hsp20_durable_state.py::test_journal_append_validation_failures_are_fd_flat_and_nonmutating",
        "tests/test_hsp20_durable_state.py::test_procfs_fstat_failures_after_empty_path_fallback_are_fd_flat_and_nonmutating",
        "tests/test_hsp20_verification.py::test_hsp20_anchored_leaf_validation_failures_are_fd_flat_and_nonmutating",
        "tests/test_hsp20_verification.py::test_hsp20_verify_store_closes_verifier_anchors_on_success_and_failure",
    ),
    "identity-mode-lock-path-report.json": (
        "tests/test_hsp20_durable_state.py::test_service_identity_lifetime_lock_survives_process_boundary_and_releases_on_kill",
        "tests/test_hsp20_durable_state.py::test_service_identity_exact_fd_procfs_fallback_uses_only_held_relative_dirfds",
    ),
    "identity-crash-matrix.json": (
        "tests/test_hsp20_durable_state.py::test_service_identity_real_process_death_matrix",
    ),
    "identity-transition-report.json": (
        "tests/test_hsp20_durable_state.py::test_service_identity_exact_fd_procfs_fallback_uses_only_held_relative_dirfds",
    ),
    "restore-portability-manifest.json": (
        "tests/test_hsp20_durable_state.py::test_service_identity_relocation_preserves_identity_without_absolute_paths",
    ),
}
assert set(_REPORT_NODE_BASES) == REPORTS


_REBOUND_SOURCE = "HOUND_SLICE3A_REBOUND_SOURCE"


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _copy_and_rebind_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    source = Path(os.environ.get(_REBOUND_SOURCE, EVIDENCE))
    if not source.is_dir() or {path.name for path in source.iterdir()} != LEAVES:
        pytest.skip("complete Slice 3A candidate or retained E2 is required")
    original_root = ROOT
    original_commit = _git("rev-parse", "HEAD")
    paths = source_paths(original_commit)
    repository = tmp_path / "repo"
    for relative in paths:
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original_root / relative, destination)
    candidate = repository / "tests" / "evidence" / "candidate"
    candidate.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, candidate)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "Slice 3A checker"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.email", "slice3a-checker@example.invalid"], cwd=repository, check=True)
    subprocess.run(["git", "add", "--", *paths], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "Bind checker regression source"], cwd=repository, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repository, text=True).strip()

    manifest = _load(candidate / "run-manifest.json")
    manifest["reviewed"] = {"commit": commit, "tree": tree}
    manifest["cwd"] = str(repository)
    for suite in manifest["suites"].values():
        suite["junit_command"]["argv"][5] = f"--junitxml={candidate / suite['junit_file']}"
    manifest["sources"] = {}
    for relative in paths:
        raw = (repository / relative).read_bytes()
        manifest["sources"][relative] = {
            "blob": subprocess.check_output(
                ["git", "rev-parse", f"{commit}:{relative}"], cwd=repository, text=True
            ).strip(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    for artifact in manifest["artifacts"].values():
        artifact["source_paths"] = list(paths)
    _write_json(candidate / "run-manifest.json", manifest)
    _reseal_bundle(candidate, repository)
    monkeypatch.setattr(sys.modules[__name__], "ROOT", repository)
    return candidate


def _reseal_bundle(candidate: Path, repository: Path) -> None:
    manifest = _load(candidate / "run-manifest.json")
    for suite in manifest["suites"].values():
        suite["junit_sha256"] = _sha(candidate / suite["junit_file"])
    for name, artifact in manifest["artifacts"].items():
        artifact["sha256"] = _sha(candidate / name)
    _write_json(candidate / "run-manifest.json", manifest)
    bundle = _load(candidate / "bundle-source-digests.json")
    for relative in tuple(bundle["files"]):
        path = candidate / Path(relative).name if relative.startswith("tests/evidence/") else repository / relative
        bundle["files"][relative] = _sha(path)
    _write_json(candidate / "bundle-source-digests.json", bundle)


def _tamper_report_nodes(candidate: Path, name: str, nodes: list[str], *, manifest_too: bool = True) -> None:
    report = _load(candidate / name)
    report["proving_node_ids"] = sorted(nodes)
    _write_json(candidate / name, report)
    if manifest_too:
        manifest = _load(candidate / "run-manifest.json")
        manifest["artifacts"][name]["proving_node_ids"] = sorted(nodes)
        _write_json(candidate / "run-manifest.json", manifest)


def _mutate_fd_report(candidate: Path, mutation: Callable[[dict[str, Any]], None]) -> None:
    report = _load(candidate / "fd-failure-path-matrix.json")
    mutation(report)
    _write_json(candidate / "fd-failure-path-matrix.json", report)


def _mutate_junit(candidate: Path, mutation: Callable[[ElementTree.Element], None]) -> None:
    path = candidate / "slice3a-pytest.xml"
    root = ElementTree.parse(path).getroot()
    mutation(root)
    ElementTree.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def source_paths(commit: str) -> tuple[str, ...]:
    tracked = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", commit], cwd=ROOT, text=True).splitlines()
    required = {"pyproject.toml", "uv.lock", "tests/acceptance_slice3a.json", "tests/generate_slice3a_evidence.py", "tests/test_slice3a_evidence.py", "tests/slice3a_evidence_capture.py", *SUITE_FILES["focused"], *SUITE_FILES["compatibility"]}
    required.update(path for path in tracked if path.startswith("src/") and path.endswith(".py"))
    required.update(path for path in tracked if path.startswith("tests/fixtures/"))
    return tuple(sorted(required))


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class EvidenceValidationError(AssertionError):
    """A retained evidence value violates its exact typed contract."""


def _fail(label: str, detail: str) -> None:
    raise EvidenceValidationError(f"{label}: {detail}")


def _check(condition: bool, label: str, detail: str) -> None:
    if type(condition) is not bool or not condition:
        _fail(label, detail)


def _object(value: object, label: str, keys: set[str] | frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(label, "must be an exact JSON object")
    if any(type(key) is not str for key in value):
        _fail(label, "keys must be exact strings")
    if set(value) != set(keys):
        _fail(label, f"fields must be exactly {sorted(keys)!r}")
    return value


def _list(value: object, label: str, *, length: int | None = None, nonempty: bool = False) -> list[Any]:
    if type(value) is not list:
        _fail(label, "must be an exact JSON array")
    if length is not None and len(value) != length:
        _fail(label, f"must contain exactly {length} items")
    if nonempty and not value:
        _fail(label, "must not be empty")
    return value


def _string(
    value: object,
    label: str,
    *,
    pattern: str | None = None,
    choices: set[str] | frozenset[str] | None = None,
    nonempty: bool = True,
) -> str:
    if type(value) is not str or nonempty and not value:
        _fail(label, "must be an exact non-empty string")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        _fail(label, f"does not match {pattern!r}")
    if choices is not None and value not in choices:
        _fail(label, f"must be one of {sorted(choices)!r}")
    return value


def _int(value: object, label: str, *, minimum: int | None = 0) -> int:
    if type(value) is not int:
        _fail(label, "must be an exact integer")
    if minimum is not None and value < minimum:
        _fail(label, f"must be >= {minimum}")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        _fail(label, "must be an exact boolean")
    return value


def _null(value: object, label: str) -> None:
    if value is not None:
        _fail(label, "must be null")
    return None


def _equal(left: object, right: object, label: str) -> None:
    if left != right:
        _fail(label, "values differ")


def _load(path: Path, *, canonical: bool = True) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceValidationError(f"{path}: invalid strict JSON") from exc
    if type(value) is not dict:
        _fail(str(path), "top-level JSON must be an exact object")
    if canonical:
        expected = (
            json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        ).encode("utf-8")
        if raw != expected:
            _fail(str(path), "JSON bytes are not canonical pretty JSON with final LF")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _node_ids(path: Path) -> tuple[list[str], dict[str, int]]:
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError as error:
        raise EvidenceValidationError(f"{path}: invalid JUnit XML") from error
    count_keys = ("tests", "failures", "errors", "skipped")
    if root.tag == "testsuite":
        suites = [root]
        aggregate = None
    else:
        _check(root.tag == "testsuites", str(path), "root must be testsuite or testsuites")
        suites = list(root)
        _check(bool(suites), str(path), "testsuites must not be empty")
        _check(all(suite.tag == "testsuite" for suite in suites), str(path), "unexpected root child")
        aggregate = root

    counts = {key: 0 for key in count_keys}
    nodes: list[str] = []
    for suite in suites:
        cases = list(suite)
        _check(all(case.tag == "testcase" for case in cases), str(path), "unexpected suite child")
        derived = {key: 0 for key in count_keys}
        derived["tests"] = len(cases)
        for case in cases:
            classname, name = case.attrib.get("classname"), case.attrib.get("name")
            _string(classname, f"{path}.testcase.classname")
            _string(name, f"{path}.testcase.name")
            nodes.append(f"{classname.replace('.', '/')}.py::{name}")
            outcomes = list(case)
            _check(len(outcomes) <= 1, str(path), "testcase has multiple outcomes")
            _check(all(outcome.tag in {"failure", "error", "skipped"} for outcome in outcomes), str(path), "unexpected testcase child")
            if outcomes:
                outcome_key = "skipped" if outcomes[0].tag == "skipped" else f"{outcomes[0].tag}s"
                derived[outcome_key] += 1
        for key in count_keys:
            declared = suite.attrib.get(key)
            _string(declared, f"{path}.testsuite.{key}", pattern=r"0|[1-9][0-9]*", nonempty=False)
            _check(int(declared) == derived[key], str(path), f"testsuite {key} count mismatch")
            counts[key] += derived[key]
    if aggregate is not None:
        for key in count_keys:
            if key in aggregate.attrib:
                declared = aggregate.attrib[key]
                _string(declared, f"{path}.testsuites.{key}", pattern=r"0|[1-9][0-9]*", nonempty=False)
                _check(int(declared) == counts[key], str(path), f"aggregate {key} count mismatch")
    _check(counts["tests"] == len(nodes), str(path), "derived testcase count mismatch")
    _check(bool(nodes), str(path), "JUnit must include tests")
    _check(len(nodes) == len(set(nodes)), str(path), "JUnit node IDs must be unique")
    return nodes, counts


def _exact_keys(value: object, keys: set[str]) -> dict[str, Any]:
    return _object(value, "object", keys)


def _integer(value: object) -> int:
    return _int(value, "integer", minimum=None)


def _sha256(value: object, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    return _string(value, "sha256", pattern=r"[0-9a-f]{64}")


def _canonical_uuid(value: object) -> str:
    text = _string(value, "uuid")
    try:
        parsed = uuid.UUID(text)
    except ValueError as error:
        raise EvidenceValidationError("uuid: invalid UUID") from error
    _check(str(parsed) == text, "uuid", "must use canonical lowercase text")
    return text


def _position(value: object, *, digest: bool = False) -> list[Any]:
    expected = 4 if digest else 3
    assert type(value) is list and len(value) == expected
    _integer(value[0])
    _sha256(value[1])
    assert type(value[2]) is str and value[2]
    if digest:
        _sha256(value[3])
    return value


def _pages(value: object) -> list[Any]:
    assert type(value) is list and value
    for page in value:
        assert type(page) is list and len(page) == 2
        rows, cursor = page
        assert type(rows) is list and rows
        _sha256(cursor, nullable=True)
        for row in rows:
            assert type(row) is list and len(row) == 7
            canonical_event_json, sequence, entry_id, appended_at, lane, topics, entities = row
            assert type(canonical_event_json) is str
            event = json.loads(canonical_event_json)
            assert type(event) is dict
            assert json.dumps(event, sort_keys=True, separators=(",", ":")) == canonical_event_json
            _integer(sequence)
            _sha256(entry_id)
            assert type(appended_at) is str and appended_at
            assert lane is None or type(lane) is str and lane
            assert type(topics) is list and all(type(topic) is str for topic in topics)
            assert type(entities) is list and all(type(entity) is str for entity in entities)
            event_sequence = event.get("sequence")
            _integer(event_sequence)
            assert event_sequence == sequence
            assert event.get("entry_id") == entry_id and event.get("appended_at") == appended_at
    return value


def _index_manifest(value: object) -> list[Any] | None:
    if value is None:
        return None
    assert type(value) is list and len(value) == 15
    assert type(value[0]) is str and value[0] in {"file", "directory", "symlink", "other"}
    assert value[1] is None or type(value[1]) is str
    for field in value[2:14]:
        _integer(field)
    _sha256(value[14])
    return value


def _sqlite_observations(value: object) -> None:
    observations = _exact_keys(value, {"proofs_equal", "sqlite_connect_calls", "states"})
    assert observations["proofs_equal"] is True
    _integer(observations["sqlite_connect_calls"])
    assert observations["sqlite_connect_calls"] == 0
    states = observations["states"]
    assert type(states) is dict and set(states) == {"valid", "corrupt", "absent"}
    proof: list[object] = []
    for state in states.values():
        _exact_keys(state, {"appended", "fresh_cursor_sha256", "fresh_high_watermark", "fresh_pages", "fresh_positions", "fresh_recoveries", "index_after", "index_before", "old_cursor_sha256", "old_high_watermark", "old_pages", "old_positions", "old_recoveries", "terminal_cursor"})
        old_pages, fresh_pages = _pages(state["old_pages"]), _pages(state["fresh_pages"])
        for prefix, pages in (("old", old_pages), ("fresh", fresh_pages)):
            cursor_hashes = state[f"{prefix}_cursor_sha256"]
            assert type(cursor_hashes) is list and len(cursor_hashes) == len(pages)
            assert all(_sha256(digest, nullable=True) == page[1] for digest, page in zip(cursor_hashes, pages, strict=True))
            positions = state[f"{prefix}_positions"]
            assert type(positions) is list and positions
            for position in positions:
                _position(position)
            recoveries = state[f"{prefix}_recoveries"]
            assert type(recoveries) is list and recoveries
            for recovery_item in recoveries:
                assert type(recovery_item) is list and len(recovery_item) == 3
                _sha256(recovery_item[0])
                assert recovery_item[0] in cursor_hashes
                _position(recovery_item[1], digest=True)
                _position(recovery_item[2], digest=True)
            _position(state[f"{prefix}_high_watermark"], digest=True)
            assert positions == [[row[1], row[2], row[3]] for page in pages for row in page[0]]
        assert state["terminal_cursor"] is None
        appended = _exact_keys(state["appended"], {"entry_id", "sequence"})
        _sha256(appended["entry_id"])
        _integer(appended["sequence"])
        old_rows = [row for page in old_pages for row in page[0]]
        fresh_rows = [row for page in fresh_pages for row in page[0]]
        assert appended["entry_id"] not in [row[2] for row in old_rows]
        assert [appended["sequence"], appended["entry_id"]] in [[row[1], row[2]] for row in fresh_rows]
        _index_manifest(state["index_before"])
        _index_manifest(state["index_after"])
        assert state["index_before"] == state["index_after"]
        proof.append([state[key] for key in ("appended", "old_pages", "old_cursor_sha256", "old_positions", "old_recoveries", "old_high_watermark", "fresh_pages", "fresh_cursor_sha256", "fresh_positions", "fresh_recoveries", "fresh_high_watermark", "terminal_cursor")])
    assert proof[0] == proof[1] == proof[2]


def _inventory(value: object) -> dict[str, Any]:
    result = _exact_keys(value, {"root", "entries"})
    assert type(result["root"]) is str and result["root"] and not result["root"].startswith("synthetic")
    entries = result["entries"]
    assert type(entries) is list and entries
    paths: list[str] = []
    required = {"path", "kind", "dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "blocks", "blksize", "mtime_ns", "ctime_ns"}
    for entry in entries:
        assert type(entry) is dict
        assert "atime" not in entry and "atime_ns" not in entry
        assert type(entry["path"]) is str and entry["path"]
        paths.append(entry["path"])
        assert type(entry["kind"]) is str and entry["kind"] in {"directory", "regular", "symlink", "other"}
        extras = {"sha256"} if entry["kind"] == "regular" else {"symlink_target"} if entry["kind"] == "symlink" else set()
        assert set(entry) == required | extras
        for key in required - {"path", "kind"}:
            _integer(entry[key])
        if entry["kind"] == "regular":
            assert type(entry.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        if entry["kind"] == "symlink":
            assert type(entry.get("symlink_target")) is str
    assert paths == sorted(paths) and len(paths) == len(set(paths)) and paths[0] == "."
    return result


def _read_state_inventory(value: object) -> dict[str, Any]:
    result = _inventory(value)
    assert len(result["entries"]) > 1
    return result


def _node_base(node: object) -> str:
    assert type(node) is str
    matched = re.fullmatch(r"(tests/[A-Za-z0-9_./-]+\.py::test_[A-Za-z0-9_]+)(?:\[.*\])?", node)
    assert matched is not None
    return matched.group(1)


def _expected_report_nodes(focused_nodes: list[str]) -> dict[str, list[str]]:
    expected: dict[str, list[str]] = {}
    for report, bases in _REPORT_NODE_BASES.items():
        selected = sorted(node for node in focused_nodes if _node_base(node) in bases)
        assert {_node_base(node) for node in selected} == set(bases)
        expected[report] = selected
    return expected


def _report(evidence: Path, name: str, expected_nodes: list[str]) -> dict[str, Any]:
    report = _load(evidence / name)
    _exact_keys(report, {"schema_version", "observations", "proving_node_ids"})
    assert report["schema_version"] == SCHEMA and type(report["observations"]) is dict
    proving = report["proving_node_ids"]
    assert type(proving) is list and proving == expected_nodes
    return report


def _identity_crash_observations(value: object, expected_nodes: list[str]) -> None:
    observations = _exact_keys(value, {"matrix"})
    matrix = observations["matrix"]
    assert type(matrix) is list and matrix
    node_prefix = _REPORT_NODE_BASES["identity-crash-matrix.json"][0]
    expected_cases: set[tuple[str, str]] = set()
    for node in expected_nodes:
        matched = re.fullmatch(
            rf"{re.escape(node_prefix)}\[([a-z]+)-([a-z0-9_]+)\]",
            node,
        )
        assert matched is not None
        expected_cases.add((matched.group(1), matched.group(2)))
    assert len(expected_cases) == len(expected_nodes)

    before_publication = {
        "before_identity_temp_write",
        "mid_identity_temp_write",
        "after_identity_temp_write",
        "after_identity_temp_fsync",
        "after_identity_marker_fsync",
        "after_identity_new_witness_link",
        "after_identity_old_witness_link",
        "after_identity_swap_witness_link",
        "after_identity_prepared_directory_fsync",
        "before_identity_publication",
    }
    actual_cases: list[tuple[str, str]] = []
    for row in matrix:
        row = _exact_keys(
            row,
            {
                "before_rename",
                "child_exit",
                "fault_point",
                "identity_sha256",
                "operation",
                "state",
            },
        )
        assert type(row["operation"]) is str and row["operation"]
        assert type(row["fault_point"]) is str and row["fault_point"]
        assert type(row["before_rename"]) is bool
        _integer(row["child_exit"])
        assert row["child_exit"] == 77
        identity_sha256 = _sha256(row["identity_sha256"])
        state = _inventory(row["state"])
        identity_entries = [
            entry
            for entry in state["entries"]
            if entry["path"] == "service/identity.json" and entry["kind"] == "regular"
        ]
        assert len(identity_entries) == 1
        assert identity_entries[0]["sha256"] == identity_sha256
        assert row["before_rename"] is (row["fault_point"] in before_publication)
        actual_cases.append((row["operation"], row["fault_point"]))
    assert len(actual_cases) == len(expected_cases)
    assert set(actual_cases) == expected_cases


def _fd_descriptors(value: object) -> list[dict[str, Any]]:
    assert type(value) is list and value
    descriptors: list[dict[str, Any]] = []
    for descriptor in value:
        descriptor = _exact_keys(descriptor, {"fd", "target"})
        _integer(descriptor["fd"])
        assert type(descriptor["target"]) is str and descriptor["target"]
        descriptors.append(descriptor)
    assert [item["fd"] for item in descriptors] == sorted({item["fd"] for item in descriptors})
    return descriptors


def _outside_paths(value: object) -> list[str]:
    assert type(value) is list and value
    assert all(type(path) is str and path for path in value)
    assert value == sorted(set(value))
    return value


def _outside_manifest(value: object) -> list[list[Any]]:
    assert type(value) is list and value
    paths: list[str] = []
    for entry in value:
        assert type(entry) is list and len(entry) == 12
        path, kind, target, dev, ino, uid, gid, mode, size, mtime_ns, ctime_ns, digest = entry
        assert type(path) is str and path
        assert type(kind) is str and kind in {"directory", "file", "symlink"}
        assert target is None if kind != "symlink" else type(target) is str
        for field in (dev, ino, uid, gid, mode, size, mtime_ns, ctime_ns):
            _integer(field)
        if kind == "file":
            _sha256(digest)
        else:
            assert digest is None
        paths.append(path)
    assert paths == sorted(set(paths)) and paths[0] == "."
    return value


_OUTSIDE_SENTINEL_SHA256 = "73606bdee62655425a943d2a1c1343cc1fdad5aee3c48873416a34d5cd060f69"


def _exact_outside_manifest(value: object) -> list[list[Any]]:
    result = _outside_manifest(value)
    assert len(result) == 2
    directory, sentinel = result
    assert directory[0] == "." and directory[1] == "directory"
    assert directory[2] is None and directory[11] is None
    assert sentinel[0] == "sentinel" and sentinel[1] == "file"
    assert sentinel[2] is None and sentinel[8] == 25
    assert sentinel[11] == _OUTSIDE_SENTINEL_SHA256
    return result


def _fd_observations(value: object) -> None:
    observations = _exact_keys(value, {"paths"})
    rows = observations["paths"]
    assert type(rows) is list and len(rows) == 6
    expected = {
        "anchored_read": (64, {"outside_before", "outside_after"}, "paths"),
        "anchored_append": (64, {"outside_before", "outside_after"}, "paths"),
        "verified_snapshot": (64, {"outside_before", "outside_after"}, "manifest"),
        "direct_journal_append": (64, {"outside_before", "outside_after"}, "manifest"),
        "procfs_fstat_eio": (64, {"outside_before", "outside_after"}, "manifest"),
        "public_verified_snapshot": (5, {"result"}, "public"),
    }
    common = {
        "path", "baseline", "after", "baseline_count", "after_count",
        "retry_count", "fd_delta", "before_state", "after_state",
    }
    assert {row.get("path") for row in rows if type(row) is dict} == set(expected)
    assert len({row["path"] for row in rows}) == len(rows)
    for row in rows:
        assert type(row) is dict and type(row.get("path")) is str
        retry_count, extras, outside_kind = expected[row["path"]]
        _exact_keys(row, common | extras)
        for key in ("baseline_count", "after_count", "retry_count", "fd_delta"):
            _integer(row[key])
        assert row["retry_count"] == retry_count
        baseline, after = _fd_descriptors(row["baseline"]), _fd_descriptors(row["after"])
        assert row["baseline_count"] - len(baseline) == row["after_count"] - len(after) == 1
        assert row["fd_delta"] == row["after_count"] - row["baseline_count"] == 0
        assert len(after) == len(baseline) and baseline == after
        assert row["before_state"] == row["after_state"]
        _inventory(row["before_state"])
        _inventory(row["after_state"])
        if outside_kind == "public":
            assert row["result"] == "invalid" and type(row["result"]) is str
            assert "outside_before" not in row and "outside_after" not in row
        else:
            outside_before, outside_after = row["outside_before"], row["outside_after"]
            assert type(outside_before) is list and type(outside_after) is list
            assert outside_before == outside_after
            if outside_kind == "paths":
                assert _outside_paths(outside_before) == ["sentinel"]
                assert _outside_paths(outside_after) == ["sentinel"]
            else:
                _exact_outside_manifest(outside_before)
                _exact_outside_manifest(outside_after)


def _utc(value: object, label: str) -> str:
    text = _string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceValidationError(f"{label}: invalid ISO-8601 timestamp") from error
    _check(parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed), label, "timestamp must be UTC")
    return text


def _relative_path(value: object, label: str) -> str:
    text = _string(value, label)
    path = Path(text)
    _check(not path.is_absolute(), label, "path must be relative")
    _check(text == "." or all(part not in {"", ".", ".."} for part in path.parts), label, "path must be lexical and normalized")
    return text


def _canonical_compact(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise EvidenceValidationError("canonical-json: value is not canonicalizable") from error


def _journal_envelope(value: object, label: str) -> dict[str, Any]:
    keys = {
        "schema_version", "entry_id", "sequence", "appended_at", "producer",
        "artifact", "classification", "access", "policy_id", "dedupe",
        "lineage", "source", "usage",
    }
    event = _object(value, label, keys)
    _check(_string(event["schema_version"], f"{label}.schema_version") == "houndd.journal.v1", label, "wrong journal schema")
    entry_id = _sha256(event["entry_id"])
    _int(event["sequence"], f"{label}.sequence")
    _utc(event["appended_at"], f"{label}.appended_at")
    producer = _object(event["producer"], f"{label}.producer", {"owner_id", "capability", "run_id"})
    for key in producer:
        _string(producer[key], f"{label}.producer.{key}")
    artifact = _object(event["artifact"], f"{label}.artifact", {"kind", "schema", "record_id", "hash", "authorized_uri"})
    for key in ("kind", "schema", "record_id", "authorized_uri"):
        _string(artifact[key], f"{label}.artifact.{key}")
    _sha256(artifact["hash"])
    classification = _object(event["classification"], f"{label}.classification", {"outcome", "evidence_status"})
    for key in classification:
        _string(classification[key], f"{label}.classification.{key}")
    _string(event["access"], f"{label}.access", choices={"public", "workspace", "restricted"})
    _string(event["policy_id"], f"{label}.policy_id")
    dedupe = _object(event["dedupe"], f"{label}.dedupe", {"object_key", "content_sha256"})
    _string(dedupe["object_key"], f"{label}.dedupe.object_key")
    _sha256(dedupe["content_sha256"])
    lineage = _object(event["lineage"], f"{label}.lineage", {"relation", "record_id", "lead_id"})
    for key in lineage:
        _string(lineage[key], f"{label}.lineage.{key}")
    source = _object(event["source"], f"{label}.source", {"provider", "native_id", "canonical_url"})
    for key in source:
        _string(source[key], f"{label}.source.{key}")
    usage = event["usage"]
    if type(usage) is not dict or any(type(key) is not str for key in usage) or not set(usage) <= {"requests", "bytes", "cost"}:
        _fail(f"{label}.usage", "invalid usage object")
    for key, item in usage.items():
        if type(item) not in {int, float} or not math.isfinite(item) or item < 0:
            _fail(f"{label}.usage.{key}", "must be a nonnegative finite exact number")
    expected_id = hashlib.sha256(_canonical_compact({key: item for key, item in event.items() if key != "entry_id"})).hexdigest()
    _check(entry_id == expected_id, label, "entry_id does not bind canonical envelope")
    return event


def _inventory_exact(value: object, label: str, *, count: int | None = None) -> dict[str, Any]:
    inventory = _object(value, label, {"root", "entries"})
    root = _string(inventory["root"], f"{label}.root")
    _check(not root.startswith("synthetic"), label, "synthetic inventory root is forbidden")
    entries = _list(inventory["entries"], f"{label}.entries", nonempty=True)
    if count is not None:
        _check(len(entries) == count, label, f"inventory must contain {count} entries")
    base = {"path", "kind", "dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "blocks", "blksize", "mtime_ns", "ctime_ns"}
    paths: list[str] = []
    for index, item in enumerate(entries):
        item_label = f"{label}.entries[{index}]"
        if type(item) is not dict:
            _fail(item_label, "entry must be object")
        kind = _string(item.get("kind"), f"{item_label}.kind", choices={"directory", "regular", "symlink", "other"})
        extras = {"sha256"} if kind == "regular" else {"symlink_target"} if kind == "symlink" else set()
        entry = _object(item, item_label, base | extras)
        paths.append(_relative_path(entry["path"], f"{item_label}.path"))
        for key in base - {"path", "kind"}:
            _int(entry[key], f"{item_label}.{key}")
        if kind == "regular":
            _sha256(entry["sha256"])
        elif kind == "symlink":
            _string(entry["symlink_target"], f"{item_label}.symlink_target", nonempty=False)
    _check(paths == sorted(set(paths)), label, "inventory paths must be sorted and unique")
    _check(paths[0] == ".", label, "inventory must begin at root")
    return inventory


def _clean_identity(value: object, label: str) -> dict[str, Any]:
    inventory = _inventory_exact(value, label, count=4)
    _check(Path(inventory["root"]).is_absolute(), label, "identity root must be absolute")
    expected = {
        ".": ("directory", 0o700),
        "service": ("directory", 0o700),
        "service/identity.json": ("regular", 0o600),
        "service/lock": ("regular", 0o600),
    }
    entries = {entry["path"]: entry for entry in inventory["entries"]}
    _check(set(entries) == set(expected), label, "identity inventory has unexpected paths")
    for path, (kind, mode) in expected.items():
        _check(entries[path]["kind"] == kind and entries[path]["mode"] == mode, label, f"wrong kind/mode for {path}")
    _check(entries["service/identity.json"]["size"] > 0, label, "identity must be nonempty")
    _check(entries["service/lock"]["size"] == 0, label, "lock must be empty")
    return inventory


def _file_manifest(value: object, label: str, *, count: int | None = None) -> list[list[Any]]:
    rows = _list(value, label, nonempty=True)
    if count is not None:
        _check(len(rows) == count, label, f"manifest must contain {count} rows")
    paths: list[str] = []
    for index, row_value in enumerate(rows):
        row = _list(row_value, f"{label}[{index}]", length=12)
        path, kind, target, dev, ino, uid, gid, mode, size, mtime_ns, ctime_ns, digest = row
        paths.append(_relative_path(path, f"{label}[{index}].path"))
        kind_text = _string(kind, f"{label}[{index}].kind", choices={"directory", "file", "symlink"})
        if kind_text == "symlink":
            _string(target, f"{label}[{index}].target", nonempty=False)
        else:
            _null(target, f"{label}[{index}].target")
        for field_index, field in enumerate((dev, ino, uid, gid, mode, size, mtime_ns, ctime_ns), start=3):
            _int(field, f"{label}[{index}][{field_index}]")
        if kind_text == "file":
            _sha256(digest)
        else:
            _null(digest, f"{label}[{index}].sha256")
    _check(paths == sorted(set(paths)), label, "manifest paths must be sorted and unique")
    _check(paths[0] == ".", label, "manifest must begin at root")
    return rows


def _index_manifest_exact(value: object, label: str) -> list[Any] | None:
    if value is None:
        return None
    row = _list(value, label, length=15)
    kind = _string(row[0], f"{label}.kind", choices={"file", "directory", "symlink", "other"})
    if kind == "symlink":
        _string(row[1], f"{label}.target", nonempty=False)
    else:
        _null(row[1], f"{label}.target")
    for index, field in enumerate(row[2:14], start=2):
        _int(field, f"{label}[{index}]")
    if kind == "file":
        _sha256(row[14])
    else:
        _null(row[14], f"{label}.sha256")
    return row


_CANONICAL_FILTERS = [
    {},
    {"time_range": {"from": "2026-07-31T02:00:00Z", "to": "2026-07-31T04:00:00Z"}},
    {"producer": {"capability": ["capture"], "owner_id": ["owner"], "run_id": ["run-b"]}},
    {"source": {"provider": ["firecrawl"]}},
    {"source": {"canonical_url": ["https://example.test/2"]}},
    {"entry_id": ["b0fd78ae1f23048fc07979abb17c5ca0f4141b3cf245b1b9a4465614cb5d2333"]},
    {"record_id": ["record-4"]},
    {"object_key": ["object-0"]},
    {"content_sha256": ["3460ebae1c45bfd069074b365281354cfdf41b82ffb05c7eedd6775446fcd3a4"]},
    {"classification": {"outcome": ["completed"]}},
    {"classification": {"evidence_status": ["failure"]}},
    {"access": ["workspace", "restricted"]},
    {"classification": {"outcome": ["completed", "failed"]}, "source": {"provider": ["exa", "firecrawl"]}, "time_range": {"from": "2026-07-31T01:30:00Z", "to": "2026-07-31T03:00:00Z"}},
]
_CANONICAL_RESULT_INDEXES = (
    (0, 1, 2, 3, 4), (1, 2, 3), (0,), (0, 2,), (1,), (2,), (4,),
    (3,), (1,), (1, 3, 4), (2,), (0, 1, 4), (1, 2),
)


def _validate_filter(value: object, expected: dict[str, Any], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(label, "filter must be object")
    allowed = {"time_range", "producer", "lane", "topic", "source", "entity", "entry_id", "record_id", "object_key", "content_sha256", "classification", "access"}
    _check(set(value) <= allowed, label, "unknown filter family")
    for key, item in value.items():
        if key == "time_range":
            item = _object(item, f"{label}.time_range", {"from", "to"})
            start, end = _utc(item["from"], f"{label}.time_range.from"), _utc(item["to"], f"{label}.time_range.to")
            _check(datetime.fromisoformat(start.replace("Z", "+00:00")) < datetime.fromisoformat(end.replace("Z", "+00:00")), label, "time range must increase")
        elif key in {"producer", "source", "classification"}:
            nested_allowed = {"owner_id", "capability", "run_id"} if key == "producer" else {"provider", "canonical_url"} if key == "source" else {"outcome", "evidence_status"}
            nested = item
            if type(nested) is not dict or not nested or not set(nested) <= nested_allowed:
                _fail(f"{label}.{key}", "invalid nested filter")
            for nested_key, values in nested.items():
                strings = _list(values, f"{label}.{key}.{nested_key}", nonempty=True)
                for index, text in enumerate(strings):
                    _string(text, f"{label}.{key}.{nested_key}[{index}]")
                _check(strings == list(dict.fromkeys(strings)), label, "filter values must be unique")
        else:
            values = _list(item, f"{label}.{key}", nonempty=True)
            for index, text in enumerate(values):
                if key in {"entry_id", "content_sha256"}:
                    _sha256(text)
                elif key == "access":
                    _string(text, f"{label}.{key}[{index}]", choices={"public", "workspace", "restricted"})
                else:
                    _string(text, f"{label}.{key}[{index}]")
            _check(values == list(dict.fromkeys(values)), label, "filter values must be unique")
    _equal(value, expected, label)
    return value


def _canonical_query_observations(value: object) -> list[str]:
    observations = _object(value, "canonical-query", {"requests", "unsupported"})
    requests = _list(observations["requests"], "canonical-query.requests", length=13)
    canonical_ids: list[str] = []
    for index, request_value in enumerate(requests):
        request = _object(request_value, f"canonical-query.requests[{index}]", {"filter", "ordered_entry_ids"})
        _validate_filter(request["filter"], _CANONICAL_FILTERS[index], f"canonical-query.requests[{index}].filter")
        ids = _list(request["ordered_entry_ids"], f"canonical-query.requests[{index}].ordered_entry_ids", nonempty=True)
        for item in ids:
            _sha256(item)
        _check(len(ids) == len(set(ids)), "canonical-query", "result IDs must be unique")
        if index == 0:
            _check(len(ids) == 5, "canonical-query", "base request must return five IDs")
            canonical_ids = list(ids)
        expected_ids = [canonical_ids[item_index] for item_index in _CANONICAL_RESULT_INDEXES[index]]
        _equal(ids, expected_ids, f"canonical-query.requests[{index}].ordered_entry_ids")
    entry_filter = requests[5]["filter"]["entry_id"]
    _equal(entry_filter, requests[5]["ordered_entry_ids"], "canonical-query.entry-filter")
    unsupported = _list(observations["unsupported"], "canonical-query.unsupported", length=4)
    expected_filters = [
        {"entity": ["entity"]},
        {"entity": ["entity"], "lane": ["pulse"], "topic": ["care"]},
        {"topic": ["care"]},
        {"lane": ["pulse"]},
    ]
    seen: set[str] = set()
    for index, item_value in enumerate(unsupported):
        item = _object(item_value, f"canonical-query.unsupported[{index}]", {"filter", "result_type", "filter_keys", "class_hook_calls"})
        _validate_filter(item["filter"], expected_filters[index], f"canonical-query.unsupported[{index}].filter")
        _check(_string(item["result_type"], f"canonical-query.unsupported[{index}].result_type") == "QueryFilterNotAvailable", "canonical-query", "wrong unsupported result type")
        keys = _list(item["filter_keys"], f"canonical-query.unsupported[{index}].filter_keys", nonempty=True)
        for key in keys:
            _string(key, "canonical-query.unsupported.filter-key")
        _equal(keys, sorted(item["filter"]), "canonical-query.unsupported.filter_keys")
        hooks = _object(item["class_hook_calls"], "canonical-query.unsupported.hooks", {"Journal.verified_snapshot", "ServiceIdentity.lease"})
        for key in hooks:
            _check(_int(hooks[key], f"canonical-query.unsupported.hooks.{key}") == 0, "canonical-query", "unsupported filter reached class hook")
        identity = json.dumps(item["filter"], sort_keys=True, separators=(",", ":"))
        _check(identity not in seen, "canonical-query", "duplicate unsupported row")
        seen.add(identity)
    return canonical_ids


def _cursor_observations(value: object, canonical_ids: list[str]) -> tuple[str, int]:
    observations = _object(value, "cursor", {"first_cursor_sha256", "resumed_ids", "fresh_first", "terminal_cursor"})
    _sha256(observations["first_cursor_sha256"])
    ids = _list(observations["resumed_ids"], "cursor.resumed_ids", length=5)
    for item in ids:
        _sha256(item)
    _check(len(ids) == len(set(ids)), "cursor", "resumed IDs must be unique")
    _equal(ids, canonical_ids, "cursor.resumed_ids")
    fresh = _object(observations["fresh_first"], "cursor.fresh_first", {"sequence", "entry_id"})
    sequence = _int(fresh["sequence"], "cursor.fresh_first.sequence")
    _check(sequence == 5, "cursor", "fresh sequence must be five")
    entry_id = _sha256(fresh["entry_id"])
    _check(entry_id not in canonical_ids, "cursor", "fresh ID must not be resumed")
    _null(observations["terminal_cursor"], "cursor.terminal_cursor")
    return entry_id, sequence


def _position_exact(value: object, label: str, *, chain: bool) -> list[Any]:
    row = _list(value, label, length=4 if chain else 3)
    _int(row[0], f"{label}.sequence")
    _sha256(row[1])
    _utc(row[2], f"{label}.appended_at")
    if chain:
        _sha256(row[3])
    return row


def _page_exact(value: object, label: str, *, row_count: int) -> tuple[list[list[Any]], str | None]:
    page = _list(value, label, length=2)
    rows = _list(page[0], f"{label}.rows", length=row_count)
    cursor = _sha256(page[1], nullable=True)
    parsed_rows: list[list[Any]] = []
    for index, row_value in enumerate(rows):
        row = _list(row_value, f"{label}.rows[{index}]", length=7)
        canonical_event_json, sequence, entry_id, appended_at, lane, topics, entities = row
        text = _string(canonical_event_json, f"{label}.rows[{index}].event")
        try:
            event = json.loads(text, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
        except ValueError as error:
            raise EvidenceValidationError(f"{label}.rows[{index}]: invalid embedded event") from error
        _check(type(event) is dict, label, "embedded event must be object")
        _check(_canonical_compact(event).decode("utf-8") == text, label, "embedded event is not compact canonical JSON")
        _journal_envelope(event, f"{label}.rows[{index}].event")
        sequence_value = _int(sequence, f"{label}.rows[{index}].sequence")
        entry_value = _sha256(entry_id)
        time_value = _utc(appended_at, f"{label}.rows[{index}].appended_at")
        if lane is not None:
            _string(lane, f"{label}.rows[{index}].lane")
        for facet_name, facet_value in (("topics", topics), ("entities", entities)):
            facets = _list(facet_value, f"{label}.rows[{index}].{facet_name}")
            for facet in facets:
                _string(facet, f"{label}.rows[{index}].{facet_name}[]")
            _check(facets == sorted(set(facets)), label, f"{facet_name} must be sorted and unique")
        _check(event["sequence"] == sequence_value and type(event["sequence"]) is int, label, "row sequence does not bind event")
        _check(event["entry_id"] == entry_value and type(event["entry_id"]) is str, label, "row ID does not bind event")
        _check(event["appended_at"] == time_value and type(event["appended_at"]) is str, label, "row time does not bind event")
        parsed_rows.append(row)
    return parsed_rows, cursor


def _chain_candidates(events: list[dict[str, Any]], label: str) -> dict[str, list[Any]]:
    ordered = sorted(events, key=lambda event: event["sequence"])
    _check([event["sequence"] for event in ordered] == list(range(len(ordered))), label, "event sequences must be contiguous")
    previous = "0" * 64
    result: dict[str, list[Any]] = {}
    for event in ordered:
        body = {
            "sequence": event["sequence"],
            "entry_id": event["entry_id"],
            "event_sha256": hashlib.sha256(_canonical_compact(event)).hexdigest(),
            "previous_chain_sha256": previous,
        }
        previous = hashlib.sha256(_canonical_compact(body)).hexdigest()
        result[event["entry_id"]] = [
            event["sequence"], event["entry_id"],
            datetime.fromisoformat(event["appended_at"].replace("Z", "+00:00")).isoformat(),
            previous,
        ]
    return result


def _sqlite_observations_exact(value: object, canonical_ids: list[str], fresh_id: str, fresh_sequence: int) -> None:
    observations = _object(value, "sqlite", {"proofs_equal", "sqlite_connect_calls", "states"})
    _check(_bool(observations["proofs_equal"], "sqlite.proofs_equal"), "sqlite", "proof witness must be true")
    _check(_int(observations["sqlite_connect_calls"], "sqlite.sqlite_connect_calls") == 0, "sqlite", "SQLite must not be opened")
    states = _object(observations["states"], "sqlite.states", {"valid", "corrupt", "absent"})
    proof_fields: list[object] = []
    for state_name in ("valid", "corrupt", "absent"):
        state = _object(states[state_name], f"sqlite.states.{state_name}", {
            "appended", "fresh_cursor_sha256", "fresh_high_watermark", "fresh_pages",
            "fresh_positions", "fresh_recoveries", "index_after", "index_before",
            "old_cursor_sha256", "old_high_watermark", "old_pages", "old_positions",
            "old_recoveries", "terminal_cursor",
        })
        appended = _object(state["appended"], f"sqlite.states.{state_name}.appended", {"entry_id", "sequence"})
        _check(_sha256(appended["entry_id"]) == fresh_id, "sqlite", "appended ID does not bind cursor report")
        _check(_int(appended["sequence"], "sqlite.appended.sequence") == fresh_sequence, "sqlite", "appended sequence does not bind cursor report")
        page_sets: dict[str, list[tuple[list[list[Any]], str | None]]] = {}
        events: dict[str, dict[str, Any]] = {}
        for prefix, counts in (("old", (2, 1, 1, 1)), ("fresh", (2, 2, 2))):
            page_values = _list(state[f"{prefix}_pages"], f"sqlite.{state_name}.{prefix}_pages", length=len(counts))
            pages = [_page_exact(page, f"sqlite.{state_name}.{prefix}_pages[{index}]", row_count=count) for index, (page, count) in enumerate(zip(page_values, counts, strict=True))]
            page_sets[prefix] = pages
            flattened = [row for rows, _ in pages for row in rows]
            sort_keys = [(datetime.fromisoformat(row[3].replace("Z", "+00:00")), row[1], row[2]) for row in flattened]
            _check(sort_keys == sorted(sort_keys), "sqlite", f"{prefix} pages are not chronological")
            ids = [row[2] for row in flattened]
            expected_ids = canonical_ids if prefix == "old" else [fresh_id, *canonical_ids]
            _equal(ids, expected_ids, f"sqlite.{state_name}.{prefix}.ids")
            for row in flattened:
                events[row[2]] = json.loads(row[0])
            cursors = _list(state[f"{prefix}_cursor_sha256"], f"sqlite.{state_name}.{prefix}_cursor_sha256", length=len(pages))
            for cursor_index, digest in enumerate(cursors):
                _sha256(digest, nullable=True)
                _equal(digest, pages[cursor_index][1], f"sqlite.{state_name}.{prefix}.cursor[{cursor_index}]")
            _check(cursors[-1] is None and all(item is not None for item in cursors[:-1]), "sqlite", f"{prefix} cursor terminal shape is wrong")
            positions = _list(state[f"{prefix}_positions"], f"sqlite.{state_name}.{prefix}_positions", length=len(flattened))
            for position_index, position in enumerate(positions):
                _position_exact(position, f"sqlite.{state_name}.{prefix}_positions[{position_index}]", chain=False)
            _equal(positions, [[row[1], row[2], row[3]] for row in flattened], f"sqlite.{state_name}.{prefix}.positions")
            recoveries = _list(state[f"{prefix}_recoveries"], f"sqlite.{state_name}.{prefix}_recoveries", length=2 * (len(pages) - 1))
            candidates = _chain_candidates(list(events.values()), f"sqlite.{state_name}.{prefix}.chain")
            hwm = _position_exact(state[f"{prefix}_high_watermark"], f"sqlite.{state_name}.{prefix}_high_watermark", chain=True)
            expected_hwm_id = canonical_ids[-1] if prefix == "old" else fresh_id
            _equal(hwm, candidates[expected_hwm_id], f"sqlite.{state_name}.{prefix}.high_watermark")
            for recovery_index, recovery_value in enumerate(recoveries):
                recovery = _list(recovery_value, f"sqlite.{state_name}.{prefix}_recoveries[{recovery_index}]", length=3)
                cursor_digest = _sha256(recovery[0])
                position = _position_exact(recovery[1], f"sqlite.{state_name}.{prefix}_recoveries[{recovery_index}].position", chain=True)
                recovered_hwm = _position_exact(recovery[2], f"sqlite.{state_name}.{prefix}_recoveries[{recovery_index}].hwm", chain=True)
                cursor_page = recovery_index // 2
                _equal(cursor_digest, cursors[cursor_page], "sqlite.recovery.cursor")
                last_row = pages[cursor_page][0][-1]
                _equal(position, candidates[last_row[2]], "sqlite.recovery.position")
                _equal(recovered_hwm, hwm, "sqlite.recovery.hwm")
        _null(state["terminal_cursor"], f"sqlite.states.{state_name}.terminal_cursor")
        old_ids = [row[2] for rows, _ in page_sets["old"] for row in rows]
        fresh_ids = [row[2] for rows, _ in page_sets["fresh"] for row in rows]
        _check(fresh_id not in old_ids and fresh_ids.count(fresh_id) == 1, "sqlite", "appended inclusion/exclusion failed")
        before = _index_manifest_exact(state["index_before"], f"sqlite.states.{state_name}.index_before")
        after = _index_manifest_exact(state["index_after"], f"sqlite.states.{state_name}.index_after")
        _equal(before, after, f"sqlite.states.{state_name}.index")
        if state_name == "absent":
            _check(before is None, "sqlite", "absent state must omit index")
        else:
            _check(before is not None and before[0] == "file", "sqlite", f"{state_name} state must retain file index")
        proof_fields.append([state[key] for key in (
            "appended", "old_pages", "old_cursor_sha256", "old_positions", "old_recoveries", "old_high_watermark",
            "fresh_pages", "fresh_cursor_sha256", "fresh_positions", "fresh_recoveries", "fresh_high_watermark", "terminal_cursor",
        )])
    _check(proof_fields[0] == proof_fields[1] == proof_fields[2], "sqlite", "query proof differs across index states")


def _hex_bytes(value: object, label: str, *, final_lf: bool | None) -> bytes:
    text = _string(value, label, pattern=r"(?:[0-9a-f]{2})+")
    raw = bytes.fromhex(text)
    if final_lf is True:
        _check(raw.endswith(b"\n") and not raw.endswith(b"\r\n"), label, "row must end in one exact LF")
    elif final_lf is False:
        _check(not raw.endswith((b"\n", b"\r")), label, "row must not end in a line ending")
    return raw


def _strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
    except (UnicodeError, ValueError) as error:
        raise EvidenceValidationError(f"{label}: invalid strict JSON") from error
    if type(value) is not dict:
        _fail(label, "JSON row must be object")
    _check(_canonical_compact(value) == raw, label, "JSON row is not compact canonical JSON")
    return value


def _journal_triplet(value: object, label: str) -> dict[str, Any]:
    triplet = _object(value, label, {"event_rows", "chain_rows", "head_bytes"})
    event_hex = _list(triplet["event_rows"], f"{label}.event_rows", length=2)
    chain_hex = _list(triplet["chain_rows"], f"{label}.chain_rows", length=2)
    event_rows = [_hex_bytes(item, f"{label}.event_rows[{index}]", final_lf=True) for index, item in enumerate(event_hex)]
    chain_rows = [_hex_bytes(item, f"{label}.chain_rows[{index}]", final_lf=True) for index, item in enumerate(chain_hex)]
    head_bytes = _hex_bytes(triplet["head_bytes"], f"{label}.head_bytes", final_lf=False)
    events: list[dict[str, Any]] = []
    chains: list[dict[str, Any]] = []
    previous = "0" * 64
    seen_ids: set[str] = set()
    seen_events: set[str] = set()
    seen_chains: set[str] = set()
    for index, (event_raw, chain_raw) in enumerate(zip(event_rows, chain_rows, strict=True)):
        event = _journal_envelope(_strict_json_bytes(event_raw[:-1], f"{label}.event[{index}]"), f"{label}.event[{index}]")
        _check(event["sequence"] == index and type(event["sequence"]) is int, label, "event sequence is not contiguous")
        event_digest = hashlib.sha256(event_raw[:-1]).hexdigest()
        _check(event["entry_id"] not in seen_ids and event_digest not in seen_events, label, "duplicate event identity")
        chain = _object(_strict_json_bytes(chain_raw[:-1], f"{label}.chain[{index}]"), f"{label}.chain[{index}]", {"sequence", "entry_id", "event_sha256", "previous_chain_sha256", "chain_sha256"})
        _check(_int(chain["sequence"], f"{label}.chain[{index}].sequence") == index, label, "chain sequence mismatch")
        for key in ("entry_id", "event_sha256", "previous_chain_sha256", "chain_sha256"):
            _sha256(chain[key])
        body = {key: chain[key] for key in ("sequence", "entry_id", "event_sha256", "previous_chain_sha256")}
        expected_chain = hashlib.sha256(_canonical_compact(body)).hexdigest()
        _check(chain["entry_id"] == event["entry_id"], label, "chain entry ID mismatch")
        _check(chain["event_sha256"] == event_digest, label, "chain event hash mismatch")
        _check(chain["previous_chain_sha256"] == previous, label, "chain previous hash mismatch")
        _check(chain["chain_sha256"] == expected_chain, label, "chain hash mismatch")
        _check(expected_chain not in seen_chains, label, "duplicate chain hash")
        seen_ids.add(event["entry_id"])
        seen_events.add(event_digest)
        seen_chains.add(expected_chain)
        previous = expected_chain
        events.append(event)
        chains.append(chain)
    head = _object(_strict_json_bytes(head_bytes, f"{label}.head"), f"{label}.head", {"sequence", "entry_id", "chain_sha256"})
    _check(_int(head["sequence"], f"{label}.head.sequence", minimum=-1) == 1, label, "head sequence mismatch")
    _sha256(head["entry_id"])
    _sha256(head["chain_sha256"])
    _check(head == {"sequence": 1, "entry_id": events[-1]["entry_id"], "chain_sha256": previous}, label, "head does not bind chain")
    return {
        "event_rows": event_rows, "chain_rows": chain_rows, "head_bytes": head_bytes,
        "events": events, "chains": chains, "head": head,
        "events_bytes": b"".join(event_rows), "chains_bytes": b"".join(chain_rows),
    }


def _manifest_map(rows: list[list[Any]]) -> dict[str, list[Any]]:
    return {row[0]: row for row in rows}


def _private_manifest_shape(
    rows: list[list[Any]],
    label: str,
    paths: set[str],
    *,
    allow_unsafe: set[str] | None = None,
) -> dict[str, list[Any]]:
    mapped = _manifest_map(rows)
    _check(set(mapped) == paths, label, "manifest path set mismatch")
    for path, row in mapped.items():
        if row[1] == "directory":
            _check(row[7] == 0o700, label, f"directory {path} must be 0700")
        elif row[1] == "file" and path not in (allow_unsafe or set()):
            _check(row[7] == 0o600, label, f"file {path} must be 0600")
    return mapped


def _bind_file(row: list[Any], raw: bytes, label: str) -> None:
    _check(row[1] == "file", label, "bound manifest row must be a file")
    _check(row[8] == len(raw), label, "file size mismatch")
    _check(row[11] == hashlib.sha256(raw).hexdigest(), label, "file digest mismatch")


def _journal_observations_exact(value: object) -> dict[str, Any]:
    observations = _object(value, "journal", {"snapshot", "lock_order", "scalars"})
    snapshot = _object(observations["snapshot"], "journal.snapshot", {"triplet", "before", "after", "empty_before", "empty_after"})
    triplet = _journal_triplet(snapshot["triplet"], "journal.snapshot.triplet")
    before = _file_manifest(snapshot["before"], "journal.snapshot.before", count=6)
    after = _file_manifest(snapshot["after"], "journal.snapshot.after", count=6)
    before_map = _private_manifest_shape(before, "journal.snapshot.before", {".", "journal", "journal/events.jsonl", "journal/chain.jsonl", "journal/head.json", "journal/lock"})
    _private_manifest_shape(after, "journal.snapshot.after", set(before_map))
    _bind_file(before_map["journal/events.jsonl"], triplet["events_bytes"], "journal.snapshot.events")
    _bind_file(before_map["journal/chain.jsonl"], triplet["chains_bytes"], "journal.snapshot.chain")
    _bind_file(before_map["journal/head.json"], triplet["head_bytes"], "journal.snapshot.head")
    _bind_file(before_map["journal/lock"], b"", "journal.snapshot.lock")
    _equal(before, after, "journal.snapshot.manifest")
    empty_before = _file_manifest(snapshot["empty_before"], "journal.snapshot.empty_before", count=5)
    empty_after = _file_manifest(snapshot["empty_after"], "journal.snapshot.empty_after", count=5)
    empty_map = _private_manifest_shape(empty_before, "journal.snapshot.empty_before", {".", "journal", "journal/events.jsonl", "journal/chain.jsonl", "journal/lock"})
    _private_manifest_shape(empty_after, "journal.snapshot.empty_after", set(empty_map))
    for path in ("journal/events.jsonl", "journal/chain.jsonl", "journal/lock"):
        _bind_file(empty_map[path], b"", f"journal.snapshot.empty.{path}")
    _equal(empty_before, empty_after, "journal.snapshot.empty-manifest")
    lock_order = _object(observations["lock_order"], "journal.lock_order", {"lock_entries", "reads", "snapshot_rows", "before", "after"})
    _check(_int(lock_order["lock_entries"], "journal.lock_order.lock_entries") == 1, "journal", "lock entry count mismatch")
    reads = _list(lock_order["reads"], "journal.lock_order.reads", length=3)
    expected_reads = [["journal", "events.jsonl"], ["journal", "chain.jsonl"], ["journal", "head.json"]]
    for index, read in enumerate(reads):
        parts = _list(read, f"journal.lock_order.reads[{index}]", length=2)
        for part in parts:
            _string(part, "journal.lock_order.read-part")
    _equal(reads, expected_reads, "journal.lock_order.reads")
    _check(_int(lock_order["snapshot_rows"], "journal.lock_order.snapshot_rows") == 3, "journal", "lock-order snapshot row count mismatch")
    lock_before = _file_manifest(lock_order["before"], "journal.lock_order.before", count=6)
    lock_after = _file_manifest(lock_order["after"], "journal.lock_order.after", count=6)
    _private_manifest_shape(lock_before, "journal.lock_order.before", set(before_map))
    _private_manifest_shape(lock_after, "journal.lock_order.after", set(before_map))
    _equal(lock_before, lock_after, "journal.lock_order.manifest")
    scalars = _list(observations["scalars"], "journal.scalars", length=24)
    expected_cases = {
        (operation, target, scalar_type, scalar)
        for operation in ("append", "reconcile", "verified_snapshot")
        for target in ("chain", "current_head")
        for scalar_type, scalar in (("bool", False), ("bool", True), ("float", 0.0), ("float", 1.0))
    }
    cases: set[tuple[str, str, str, object]] = set()
    for index, row_value in enumerate(scalars):
        row = _object(row_value, f"journal.scalars[{index}]", {"after", "before", "operation", "result", "scalar", "scalar_type", "sequence", "target"})
        operation = _string(row["operation"], f"journal.scalars[{index}].operation", choices={"append", "reconcile", "verified_snapshot"})
        target = _string(row["target"], f"journal.scalars[{index}].target", choices={"chain", "current_head"})
        scalar_type = _string(row["scalar_type"], f"journal.scalars[{index}].scalar_type", choices={"bool", "float"})
        scalar = row["scalar"]
        if scalar_type == "bool":
            _bool(scalar, f"journal.scalars[{index}].scalar")
        elif type(scalar) is not float or scalar not in {0.0, 1.0}:
            _fail(f"journal.scalars[{index}].scalar", "must be exact 0.0 or 1.0 float")
        sequence = _int(row["sequence"], f"journal.scalars[{index}].sequence")
        _check(sequence == int(scalar), "journal", "sequence must reflect forged scalar numeric value")
        _check(_string(row["result"], f"journal.scalars[{index}].result") == "JournalError", "journal", "scalar case must fail closed")
        row_before = _file_manifest(row["before"], f"journal.scalars[{index}].before", count=6)
        row_after = _file_manifest(row["after"], f"journal.scalars[{index}].after", count=6)
        _private_manifest_shape(row_before, f"journal.scalars[{index}].before", set(before_map))
        _private_manifest_shape(row_after, f"journal.scalars[{index}].after", set(before_map))
        _equal(row_before, row_after, f"journal.scalars[{index}].manifest")
        cases.add((operation, target, scalar_type, scalar))
    _equal(cases, expected_cases, "journal.scalars.cases")
    return triplet


_TAMPER_CASES = {
    "partial_event", "noncanonical_event", "crlf_event", "invalid_envelope",
    "missing_chain", "extra_chain", "crlf_chain", "noncanonical_chain",
    "wrong_event_hash", "wrong_previous_hash", "wrong_chain_hash", "forged_chain_and_head",
    "missing_head", "stale_head", "noncanonical_head", "wrong_head", "unsafe_mode",
}


def _recovery_observations_exact(value: object, triplet: dict[str, Any]) -> None:
    observations = _object(value, "recovery", {"reconcile", "tamper"})
    reconcile = _object(observations["reconcile"], "recovery.reconcile", {"damaged", "repaired_chain_sha256", "repaired_head_sha256", "snapshot_rows"})
    _check(_int(reconcile["snapshot_rows"], "recovery.reconcile.snapshot_rows") == 2, "recovery", "snapshot row count mismatch")
    _check(_sha256(reconcile["repaired_chain_sha256"]) == hashlib.sha256(triplet["chains_bytes"]).hexdigest(), "recovery", "repaired chain digest mismatch")
    _check(_sha256(reconcile["repaired_head_sha256"]) == hashlib.sha256(triplet["head_bytes"]).hexdigest(), "recovery", "repaired head digest mismatch")
    damaged = _file_manifest(reconcile["damaged"], "recovery.reconcile.damaged", count=5)
    damaged_map = _private_manifest_shape(damaged, "recovery.reconcile.damaged", {".", "journal", "journal/events.jsonl", "journal/chain.jsonl", "journal/lock"})
    _bind_file(damaged_map["journal/events.jsonl"], triplet["events_bytes"], "recovery.damaged.events")
    _bind_file(damaged_map["journal/chain.jsonl"], triplet["chain_rows"][0], "recovery.damaged.chain")
    _bind_file(damaged_map["journal/lock"], b"", "recovery.damaged.lock")
    tamper = _list(observations["tamper"], "recovery.tamper", length=17)
    seen: set[str] = set()
    event_cases = {"partial_event", "noncanonical_event", "crlf_event", "invalid_envelope"}
    chain_cases = {"missing_chain", "extra_chain", "crlf_chain", "noncanonical_chain", "wrong_event_hash", "wrong_previous_hash", "wrong_chain_hash", "forged_chain_and_head", "unsafe_mode"}
    head_cases = {"missing_head", "stale_head", "noncanonical_head", "wrong_head", "forged_chain_and_head"}
    for index, row_value in enumerate(tamper):
        row = _object(row_value, f"recovery.tamper[{index}]", {"case", "before", "after", "result"})
        case = _string(row["case"], f"recovery.tamper[{index}].case", choices=_TAMPER_CASES)
        _check(case not in seen, "recovery", "duplicate tamper case")
        seen.add(case)
        _check(_string(row["result"], f"recovery.tamper[{index}].result") == "JournalError", "recovery", "tamper must fail closed")
        expected_count = 5 if case == "missing_head" else 6
        before = _file_manifest(row["before"], f"recovery.tamper[{index}].before", count=expected_count)
        after = _file_manifest(row["after"], f"recovery.tamper[{index}].after", count=expected_count)
        expected_paths = {".", "journal", "journal/events.jsonl", "journal/chain.jsonl", "journal/lock"} | (set() if case == "missing_head" else {"journal/head.json"})
        unsafe = {"journal/chain.jsonl"} if case == "unsafe_mode" else set()
        mapped = _private_manifest_shape(before, f"recovery.tamper[{index}].before", expected_paths, allow_unsafe=unsafe)
        _private_manifest_shape(after, f"recovery.tamper[{index}].after", expected_paths, allow_unsafe=unsafe)
        _equal(before, after, f"recovery.tamper[{index}].manifest")
        if case not in event_cases:
            _bind_file(mapped["journal/events.jsonl"], triplet["event_rows"][0], f"recovery.{case}.events")
        if case not in chain_cases:
            _bind_file(mapped["journal/chain.jsonl"], triplet["chain_rows"][0], f"recovery.{case}.chain")
        if case not in head_cases:
            first_head = _canonical_compact({"sequence": 0, "entry_id": triplet["events"][0]["entry_id"], "chain_sha256": triplet["chains"][0]["chain_sha256"]})
            _bind_file(mapped["journal/head.json"], first_head, f"recovery.{case}.head")
    _equal(seen, _TAMPER_CASES, "recovery.tamper.cases")


def _fd_descriptors_exact(value: object, label: str) -> list[dict[str, Any]]:
    descriptors = _list(value, label, nonempty=True)
    fds: list[int] = []
    for index, item in enumerate(descriptors):
        descriptor = _object(item, f"{label}[{index}]", {"fd", "target"})
        fds.append(_int(descriptor["fd"], f"{label}[{index}].fd"))
        _string(descriptor["target"], f"{label}[{index}].target")
    _check(fds == sorted(set(fds)), label, "descriptors must be sorted and unique")
    return descriptors


def _outside_paths_exact(value: object, label: str) -> list[str]:
    paths = _list(value, label, nonempty=True)
    for index, path in enumerate(paths):
        _relative_path(path, f"{label}[{index}]")
    _check(paths == sorted(set(paths)), label, "outside paths must be sorted and unique")
    return paths


def _outside_manifest_exact(value: object, label: str) -> list[list[Any]]:
    rows = _file_manifest(value, label, count=2)
    _check(rows[0][0] == "." and rows[0][1] == "directory", label, "outside root is wrong")
    _check(rows[1][0] == "sentinel" and rows[1][1] == "file", label, "outside sentinel is wrong")
    _check(rows[1][8] == 25 and rows[1][11] == _OUTSIDE_SENTINEL_SHA256, label, "outside sentinel bytes changed")
    return rows


def _fd_observations_exact(value: object) -> None:
    observations = _object(value, "fd", {"paths"})
    rows = _list(observations["paths"], "fd.paths", length=6)
    expected = {
        "anchored_read": (64, 2, "paths"),
        "anchored_append": (64, 2, "paths"),
        "verified_snapshot": (64, 6, "manifest"),
        "direct_journal_append": (64, 6, "manifest"),
        "procfs_fstat_eio": (64, 1, "manifest"),
        "public_verified_snapshot": (5, 18, "public"),
    }
    seen: set[str] = set()
    common = {"path", "baseline", "after", "baseline_count", "after_count", "retry_count", "fd_delta", "before_state", "after_state"}
    for index, row_value in enumerate(rows):
        if type(row_value) is not dict:
            _fail(f"fd.paths[{index}]", "row must be object")
        path = _string(row_value.get("path"), f"fd.paths[{index}].path", choices=set(expected))
        _check(path not in seen, "fd", "duplicate path row")
        seen.add(path)
        retries, state_count, outside_kind = expected[path]
        extras = {"result"} if outside_kind == "public" else {"outside_before", "outside_after"}
        row = _object(row_value, f"fd.paths[{index}]", common | extras)
        baseline = _fd_descriptors_exact(row["baseline"], f"fd.{path}.baseline")
        after = _fd_descriptors_exact(row["after"], f"fd.{path}.after")
        baseline_count = _int(row["baseline_count"], f"fd.{path}.baseline_count")
        after_count = _int(row["after_count"], f"fd.{path}.after_count")
        _check(_int(row["retry_count"], f"fd.{path}.retry_count") == retries, "fd", "retry count mismatch")
        _check(_int(row["fd_delta"], f"fd.{path}.fd_delta", minimum=None) == 0, "fd", "FD delta must be zero")
        _check(baseline_count == len(baseline) + 1 and after_count == len(after) + 1, "fd", "scanner descriptor offset mismatch")
        _check(after_count - baseline_count == 0, "fd", "FD count changed")
        _equal(baseline, after, f"fd.{path}.descriptors")
        before_state = _inventory_exact(row["before_state"], f"fd.{path}.before_state", count=state_count)
        after_state = _inventory_exact(row["after_state"], f"fd.{path}.after_state", count=state_count)
        _equal(before_state, after_state, f"fd.{path}.state")
        if outside_kind == "public":
            _check(_string(row["result"], f"fd.{path}.result") == "invalid", "fd", "public verification must be invalid")
        elif outside_kind == "paths":
            outside_before = _outside_paths_exact(row["outside_before"], f"fd.{path}.outside_before")
            outside_after = _outside_paths_exact(row["outside_after"], f"fd.{path}.outside_after")
            _equal(outside_before, ["sentinel"], f"fd.{path}.outside-before")
            _equal(outside_after, outside_before, f"fd.{path}.outside")
        else:
            outside_before = _outside_manifest_exact(row["outside_before"], f"fd.{path}.outside_before")
            outside_after = _outside_manifest_exact(row["outside_after"], f"fd.{path}.outside_after")
            _equal(outside_before, outside_after, f"fd.{path}.outside")
    _equal(seen, set(expected), "fd.path-set")


def _procfs_observation(value: object, label: str) -> dict[str, Any]:
    observation = _object(value, label, {"empty_path_errno", "calls", "fallback_destinations", "state"})
    error_number = _int(observation["empty_path_errno"], f"{label}.empty_path_errno")
    _check(error_number in {errno.EPERM, errno.ENOENT}, label, "unexpected empty-path errno")
    calls = _list(observation["calls"], f"{label}.calls", length=4)
    parsed: list[list[Any]] = []
    for index, call_value in enumerate(calls):
        call = _list(call_value, f"{label}.calls[{index}]", length=5)
        _int(call[0], f"{label}.calls[{index}].source_fd")
        _string(call[1], f"{label}.calls[{index}].source", nonempty=False)
        _int(call[2], f"{label}.calls[{index}].destination_fd")
        destination = _string(call[3], f"{label}.calls[{index}].destination")
        _check(destination == "identity.json" or re.fullmatch(r"\.identity\.txn\.[0-9a-f]{32}\.new", destination) is not None, label, "invalid publication destination")
        _int(call[4], f"{label}.calls[{index}].flags")
        parsed.append(call)
    destinations = sorted({call[3] for call in parsed})
    _check(len(destinations) == 2 and destinations[0].startswith(".identity.txn.") and destinations[1] == "identity.json", label, "wrong destination set")
    direct = [call for call in parsed if call[1] == ""]
    fallback = [call for call in parsed if call[1] != ""]
    _check(len(direct) == len(fallback) == 2, label, "must contain direct/fallback pairs")
    for direct_call in direct:
        _check(direct_call[4] == 0x1000, label, "direct call must use AT_EMPTY_PATH")
        matches = [call for call in fallback if call[2] == direct_call[2] and call[3] == direct_call[3]]
        _check(len(matches) == 1, label, "direct call lacks fallback pair")
        fallback_call = matches[0]
        _check(fallback_call[4] == 0x400, label, "fallback must use AT_SYMLINK_FOLLOW")
        _check(fallback_call[1] == str(direct_call[0]), label, "fallback source does not name held FD")
    fallback_destinations = _list(observation["fallback_destinations"], f"{label}.fallback_destinations", length=2)
    for destination in fallback_destinations:
        _string(destination, f"{label}.fallback_destination")
    _equal(fallback_destinations, destinations, f"{label}.fallback_destinations")
    _clean_identity(observation["state"], f"{label}.state")
    return observation


def _identity_mode_observations(value: object) -> list[dict[str, Any]]:
    observations = _object(value, "identity-mode", {"lifetime", "procfs"})
    lifetime = _object(observations["lifetime"], "identity-mode.lifetime", {"child_phase", "locked_result", "child_exit", "reopen_result", "state"})
    _check(_string(lifetime["child_phase"], "identity-mode.lifetime.child_phase") == "locked", "identity-mode", "wrong child phase")
    _check(_string(lifetime["locked_result"], "identity-mode.lifetime.locked_result") == "ServiceIdentityLocked", "identity-mode", "wrong lock result")
    _check(_int(lifetime["child_exit"], "identity-mode.lifetime.child_exit", minimum=None) == -signal.SIGKILL, "identity-mode", "child must be SIGKILLed")
    _check(_string(lifetime["reopen_result"], "identity-mode.lifetime.reopen_result") == "opened", "identity-mode", "identity must reopen")
    _clean_identity(lifetime["state"], "identity-mode.lifetime.state")
    procfs_values = _list(observations["procfs"], "identity-mode.procfs", length=2)
    procfs = [_procfs_observation(item, f"identity-mode.procfs[{index}]") for index, item in enumerate(procfs_values)]
    _equal({item["empty_path_errno"] for item in procfs}, {errno.EPERM, errno.ENOENT}, "identity-mode.procfs.errnos")
    return procfs


def _transition_observations(value: object, mode_procfs: list[dict[str, Any]]) -> None:
    observations = _object(value, "identity-transition", {"procfs"})
    values = _list(observations["procfs"], "identity-transition.procfs", length=2)
    procfs = [_procfs_observation(item, f"identity-transition.procfs[{index}]") for index, item in enumerate(values)]
    _equal(procfs, mode_procfs, "identity-transition.procfs")


_BEFORE_PUBLICATION = {
    "before_identity_temp_write", "mid_identity_temp_write", "after_identity_temp_write",
    "after_identity_temp_fsync", "after_identity_marker_fsync", "after_identity_new_witness_link",
    "after_identity_old_witness_link", "after_identity_swap_witness_link",
    "after_identity_prepared_directory_fsync", "before_identity_publication",
}


def _crash_observations_exact(value: object, expected_nodes: list[str]) -> None:
    observations = _object(value, "identity-crash", {"matrix"})
    matrix = _list(observations["matrix"], "identity-crash.matrix", length=62)
    prefix = _REPORT_NODE_BASES["identity-crash-matrix.json"][0]
    expected_cases: set[tuple[str, str]] = set()
    for node in expected_nodes:
        matched = re.fullmatch(rf"{re.escape(prefix)}\[([a-z]+)-([a-z0-9_]+)\]", _string(node, "identity-crash.node"))
        _check(matched is not None, "identity-crash", "unexpected proving node")
        expected_cases.add((matched.group(1), matched.group(2)))
    _check(len(expected_cases) == 62, "identity-crash", "expected cases must be unique")
    actual: set[tuple[str, str]] = set()
    counts = {"create": 0, "rotate": 0, "retire": 0, "roll": 0}
    for index, row_value in enumerate(matrix):
        row = _object(row_value, f"identity-crash.matrix[{index}]", {"operation", "fault_point", "child_exit", "before_rename", "identity_sha256", "state"})
        operation = _string(row["operation"], f"identity-crash.matrix[{index}].operation", choices=set(counts))
        fault = _string(row["fault_point"], f"identity-crash.matrix[{index}].fault_point")
        _check(_int(row["child_exit"], f"identity-crash.matrix[{index}].child_exit") == 77, "identity-crash", "child exit mismatch")
        before = _bool(row["before_rename"], f"identity-crash.matrix[{index}].before_rename")
        _check(before is (fault in _BEFORE_PUBLICATION), "identity-crash", "before-publication classification mismatch")
        digest = _sha256(row["identity_sha256"])
        state = _clean_identity(row["state"], f"identity-crash.matrix[{index}].state")
        identity = next(item for item in state["entries"] if item["path"] == "service/identity.json")
        _check(identity["sha256"] == digest, "identity-crash", "identity digest does not bind state")
        case = (operation, fault)
        _check(case not in actual, "identity-crash", "duplicate crash case")
        actual.add(case)
        counts[operation] += 1
    _equal(actual, expected_cases, "identity-crash.cases")
    _equal(counts, {"create": 14, "rotate": 16, "retire": 16, "roll": 16}, "identity-crash.counts")


def _portability_observations_exact(value: object) -> None:
    observations = _object(value, "portability", {"identity_sha256", "states_equal", "relocated_state"})
    digest = _sha256(observations["identity_sha256"])
    _check(_bool(observations["states_equal"], "portability.states_equal"), "portability", "states_equal witness must be true")
    state = _clean_identity(observations["relocated_state"], "portability.relocated_state")
    identity = next(item for item in state["entries"] if item["path"] == "service/identity.json")
    _check(identity["sha256"] == digest, "portability", "identity digest does not bind relocated state")


_READ_FORBIDDEN = ["query", "cursor", "receipt", "ack", "subscriber", "cache", "hwm"]
_READ_OPERATIONS = ["first_page", "cursor_replay", "empty_source_query", "second_principal_query", "request_parse_rejection"]
_READ_PATHS = {".", "journal", "journal/chain.jsonl", "journal/events.jsonl", "journal/head.json", "journal/lock", "service", "service/identity.json", "service/lock"}


def _read_state_observations(value: object, label: str) -> dict[str, Any]:
    observations = _object(value, label, {"root", "before", "after", "forbidden_names", "forbidden_matches", "operations"})
    root = _string(observations["root"], f"{label}.root")
    _check(Path(root).is_absolute(), label, "root must be absolute")
    before = _inventory_exact(observations["before"], f"{label}.before", count=9)
    after = _inventory_exact(observations["after"], f"{label}.after", count=9)
    _check(before["root"] == after["root"] == root, label, "inventory roots differ")
    _equal({item["path"] for item in before["entries"]}, _READ_PATHS, label)
    _equal(before, after, f"{label}.state")
    forbidden_names = _list(observations["forbidden_names"], f"{label}.forbidden_names", length=7)
    for item in forbidden_names:
        _string(item, f"{label}.forbidden_name")
    _equal(forbidden_names, _READ_FORBIDDEN, f"{label}.forbidden_names")
    forbidden_matches = _list(observations["forbidden_matches"], f"{label}.forbidden_matches", length=0)
    derived = sorted(
        path
        for path in _READ_PATHS
        if any(name in Path(path).name.lower() for name in _READ_FORBIDDEN)
    )
    _equal(forbidden_matches, derived, f"{label}.forbidden_matches")
    operations = _list(observations["operations"], f"{label}.operations", length=5)
    for item in operations:
        _string(item, f"{label}.operation")
    _equal(operations, _READ_OPERATIONS, f"{label}.operations")
    return observations


def _node_base_exact(value: object, label: str) -> str:
    node = _string(value, label)
    matched = re.fullmatch(r"(tests/[A-Za-z0-9_./-]+\.py::test_[A-Za-z0-9_]+)(?:\[.*\])?", node)
    _check(matched is not None, label, "invalid pytest node ID")
    return matched.group(1)


def _expected_report_nodes_exact(focused_nodes: list[str]) -> dict[str, list[str]]:
    expected: dict[str, list[str]] = {}
    for report_name, bases in _REPORT_NODE_BASES.items():
        selected = sorted(node for node in focused_nodes if _node_base_exact(node, "focused-node") in bases)
        _equal({_node_base_exact(node, "focused-node") for node in selected}, set(bases), f"{report_name}.proving-bases")
        _check(len(selected) == len(set(selected)), report_name, "duplicate proving nodes")
        expected[report_name] = selected
    _equal(set(expected), REPORTS, "report-node-map")
    return expected


def _report_exact(evidence: Path, name: str, expected_nodes: list[str]) -> dict[str, Any]:
    report = _object(_load(evidence / name), name, {"schema_version", "observations", "proving_node_ids"})
    _check(_string(report["schema_version"], f"{name}.schema_version") == SCHEMA, name, "wrong evidence schema")
    if type(report["observations"]) is not dict:
        _fail(f"{name}.observations", "must be exact object")
    proving = _list(report["proving_node_ids"], f"{name}.proving_node_ids", nonempty=True)
    for index, node in enumerate(proving):
        _node_base_exact(node, f"{name}.proving_node_ids[{index}]")
    _check(len(proving) == len(set(proving)), name, "duplicate proving nodes")
    _equal(proving, expected_nodes, f"{name}.proving_node_ids")
    return report


def _acceptance_exact() -> None:
    acceptance = _load(ROOT / "tests" / "acceptance_slice3a.json", canonical=False)
    _object(acceptance, "acceptance", {"schema_version", "slice", "status", "provisional", "partial_hsps", "no_new_claim_hsps", "regression_only_hsps", "coverage", "artifacts", "acceptance_gate", "portable_boundary"})
    _equal(acceptance["partial_hsps"], ["HSP-08", "HSP-20", "HSP-21"], "acceptance.partial_hsps")
    _equal(acceptance["no_new_claim_hsps"], ["HSP-03", "HSP-09"], "acceptance.no_new_claim_hsps")
    artifacts = acceptance["artifacts"]
    if type(artifacts) is not dict:
        _fail("acceptance.artifacts", "must be object")
    evidence_map = {path: claim for path, claim in artifacts.items() if type(path) is str and path.startswith("tests/evidence/slice3a/")}
    _equal(set(evidence_map), {f"tests/evidence/slice3a/{name}" for name in LEAVES}, "acceptance.artifacts")
    _equal(set(evidence_map.values()), {"HSP-21"}, "acceptance.artifact-claims")
    coverage = _object(acceptance["coverage"], "acceptance.coverage", {"HSP-08", "HSP-20", "HSP-21"})
    required = {
        "HSP-08": {"tests/evidence/slice3a/canonical-query-matrix.json", "tests/evidence/slice3a/sqlite-independence.json"},
        "HSP-20": {"tests/evidence/slice3a/journal-snapshot-matrix.json", "tests/evidence/slice3a/identity-mode-lock-path-report.json"},
    }
    for hsp, paths in required.items():
        item = coverage[hsp]
        if type(item) is not dict:
            _fail(f"acceptance.coverage.{hsp}", "must be object")
        retained = _list(item.get("retained_artifacts"), f"acceptance.coverage.{hsp}.retained_artifacts", nonempty=True)
        _check(paths <= set(retained), "acceptance", f"{hsp} retained artifacts incomplete")


def _validate_manifest_and_junits(evidence: Path) -> tuple[dict[str, Any], dict[str, list[str]], tuple[str, ...]]:
    manifest = _object(_load(evidence / "run-manifest.json"), "run-manifest", {"schema_version", "run_id", "bb_thread_id", "reviewed", "cwd", "allowlisted_environment", "sources", "suites", "artifacts"})
    _check(_string(manifest["schema_version"], "run-manifest.schema_version") == SCHEMA, "run-manifest", "wrong schema")
    _canonical_uuid(manifest["run_id"])
    _string(manifest["bb_thread_id"], "run-manifest.bb_thread_id", pattern=r"thr_[a-z0-9]+")
    _check(_string(manifest["cwd"], "run-manifest.cwd") == str(ROOT), "run-manifest", "cwd mismatch")
    environment = _object(manifest["allowlisted_environment"], "run-manifest.allowlisted_environment", {"PYTHONDONTWRITEBYTECODE"})
    _check(_string(environment["PYTHONDONTWRITEBYTECODE"], "run-manifest.environment") == "1", "run-manifest", "wrong environment")
    reviewed = _object(manifest["reviewed"], "run-manifest.reviewed", {"commit", "tree"})
    commit = _string(reviewed["commit"], "run-manifest.reviewed.commit", pattern=r"[0-9a-f]{40}")
    tree = _string(reviewed["tree"], "run-manifest.reviewed.tree", pattern=r"[0-9a-f]{40}")
    try:
        actual_tree = _git("rev-parse", f"{commit}^{{tree}}")
    except subprocess.CalledProcessError as error:
        raise EvidenceValidationError("run-manifest: reviewed commit is unavailable") from error
    _check(actual_tree == tree, "run-manifest", "reviewed tree mismatch")
    expected_sources = source_paths(commit)
    sources = manifest["sources"]
    if type(sources) is not dict or any(type(key) is not str for key in sources):
        _fail("run-manifest.sources", "must be exact object with string paths")
    _equal(tuple(sorted(sources)), expected_sources, "run-manifest.sources")
    for relative in expected_sources:
        record = _object(sources[relative], f"run-manifest.sources.{relative}", {"blob", "sha256"})
        blob = _string(record["blob"], f"run-manifest.sources.{relative}.blob", pattern=r"[0-9a-f]{40}")
        digest = _sha256(record["sha256"])
        reviewed_bytes = subprocess.check_output(["git", "show", f"{commit}:{relative}"], cwd=ROOT)
        _check(reviewed_bytes == (ROOT / relative).read_bytes(), "run-manifest", f"worktree differs from reviewed source {relative}")
        _check(blob == _git("rev-parse", f"{commit}:{relative}"), "run-manifest", f"blob mismatch for {relative}")
        _check(digest == hashlib.sha256(reviewed_bytes).hexdigest(), "run-manifest", f"digest mismatch for {relative}")
    suites = _object(manifest["suites"], "run-manifest.suites", set(SUITE_FILES))
    suite_nodes: dict[str, list[str]] = {}
    for suite_name, files in SUITE_FILES.items():
        suite = _object(suites[suite_name], f"run-manifest.suites.{suite_name}", {"source_paths", "collect_command", "junit_command", "junit_file", "junit_sha256", "counts", "ordered_node_ids"})
        source_list = _list(suite["source_paths"], f"run-manifest.suites.{suite_name}.source_paths", length=len(files))
        for item in source_list:
            _string(item, "run-manifest.suite.source-path")
        _equal(tuple(source_list), files, f"run-manifest.suites.{suite_name}.source_paths")
        collect = _object(suite["collect_command"], f"run-manifest.suites.{suite_name}.collect", {"id", "argv", "exit"})
        junit = _object(suite["junit_command"], f"run-manifest.suites.{suite_name}.junit", {"id", "argv", "exit"})
        _check(_string(collect["id"], "collect.id") == f"{suite_name}-collect", "run-manifest", "collect command ID mismatch")
        _check(_string(junit["id"], "junit.id") == f"{suite_name}-junit", "run-manifest", "junit command ID mismatch")
        _check(_int(collect["exit"], "collect.exit") == 0 and _int(junit["exit"], "junit.exit") == 0, "run-manifest", "suite command failed")
        collect_argv = _list(collect["argv"], "collect.argv", length=5 + len(files))
        junit_argv = _list(junit["argv"], "junit.argv", length=6 + len(files))
        for item in [*collect_argv, *junit_argv]:
            _string(item, "command.argv")
        _equal(collect_argv, [sys.executable, "-m", "pytest", "--collect-only", "-q", *files], f"run-manifest.{suite_name}.collect.argv")
        junit_file = _string(suite["junit_file"], f"run-manifest.{suite_name}.junit_file", choices=JUNITS)
        _equal(junit_argv, [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", f"--junitxml={evidence / junit_file}", *files], f"run-manifest.{suite_name}.junit.argv")
        digest = _sha256(suite["junit_sha256"])
        _check(_sha(evidence / junit_file) == digest and digest not in STALE_JUNIT_SHA256, "run-manifest", "JUnit digest invalid")
        nodes, counts = _node_ids(evidence / junit_file)
        count_record = _object(suite["counts"], f"run-manifest.{suite_name}.counts", {"tests", "failures", "errors", "skipped"})
        for key in count_record:
            _int(count_record[key], f"run-manifest.{suite_name}.counts.{key}")
        _equal(count_record, counts, f"run-manifest.{suite_name}.counts")
        _check(counts["failures"] == counts["errors"] == counts["skipped"] == 0, "run-manifest", "JUnit has non-passing outcomes")
        ordered_nodes = _list(suite["ordered_node_ids"], f"run-manifest.{suite_name}.ordered_node_ids", length=len(nodes))
        for item in ordered_nodes:
            _node_base_exact(item, "run-manifest.ordered-node")
        _equal(ordered_nodes, nodes, f"run-manifest.{suite_name}.ordered_node_ids")
        suite_nodes[suite_name] = nodes
    expected_report_nodes = _expected_report_nodes_exact(suite_nodes["focused"])
    artifacts = _object(manifest["artifacts"], "run-manifest.artifacts", REPORTS | JUNITS)
    for name in sorted(REPORTS | JUNITS):
        artifact = _object(artifacts[name], f"run-manifest.artifacts.{name}", {"sha256", "producer_command", "source_paths", "proving_node_ids"})
        _check(_sha256(artifact["sha256"]) == _sha(evidence / name), "run-manifest", f"artifact hash mismatch for {name}")
        expected_producer = "focused-junit" if name == "slice3a-pytest.xml" else "compatibility-junit" if name == "compatibility-pytest.xml" else "evidence-observer"
        _check(_string(artifact["producer_command"], f"run-manifest.artifacts.{name}.producer") == expected_producer, "run-manifest", "producer mismatch")
        source_paths_value = _list(artifact["source_paths"], f"run-manifest.artifacts.{name}.source_paths", length=len(expected_sources))
        for item in source_paths_value:
            _string(item, "artifact.source-path")
        _equal(tuple(source_paths_value), expected_sources, f"run-manifest.artifacts.{name}.source_paths")
        expected_nodes = sorted(suite_nodes["focused"]) if name == "slice3a-pytest.xml" else sorted(suite_nodes["compatibility"]) if name == "compatibility-pytest.xml" else expected_report_nodes[name]
        proving = _list(artifact["proving_node_ids"], f"run-manifest.artifacts.{name}.proving_node_ids", length=len(expected_nodes))
        for item in proving:
            _node_base_exact(item, "artifact.proving-node")
        _equal(proving, expected_nodes, f"run-manifest.artifacts.{name}.proving_node_ids")
    return manifest, suite_nodes, expected_sources


def _bundle_exact(evidence: Path, expected_sources: tuple[str, ...]) -> None:
    bundle = _object(_load(evidence / "bundle-source-digests.json"), "bundle", {"schema_version", "files"})
    _check(_string(bundle["schema_version"], "bundle.schema_version") == SCHEMA, "bundle", "wrong schema")
    files = bundle["files"]
    if type(files) is not dict or any(type(key) is not str for key in files):
        _fail("bundle.files", "must be exact object")
    expected = set(expected_sources) | {f"tests/evidence/slice3a/{name}" for name in LEAVES - {"bundle-source-digests.json"}}
    _equal(set(files), expected, "bundle.files")
    _check("tests/evidence/slice3a/bundle-source-digests.json" not in files, "bundle", "bundle must not hash itself")
    for relative, digest_value in files.items():
        digest = _sha256(digest_value)
        path = evidence / Path(relative).name if relative.startswith("tests/evidence/") else ROOT / relative
        _check(path.is_file() and not path.is_symlink(), "bundle", f"invalid source path {relative}")
        _check(_sha(path) == digest, "bundle", f"hash mismatch for {relative}")


def _validate_bundle_exact(evidence: Path) -> None:
    _check(evidence.exists() and evidence.is_dir() and not evidence.is_symlink(), "evidence", "bundle directory is invalid")
    recursive = [path for path in evidence.rglob("*")]
    _check(all(path.is_file() and not path.is_symlink() for path in recursive), "evidence", "only regular leaf files are allowed")
    _equal({path.relative_to(evidence).as_posix() for path in recursive}, LEAVES, "evidence.leaves")
    _acceptance_exact()
    manifest, suite_nodes, expected_sources = _validate_manifest_and_junits(evidence)
    expected_nodes = _expected_report_nodes_exact(suite_nodes["focused"])
    reports = {name: _report_exact(evidence, name, expected_nodes[name]) for name in sorted(REPORTS)}
    canonical_ids = _canonical_query_observations(reports["canonical-query-matrix.json"]["observations"])
    fresh_id, fresh_sequence = _cursor_observations(reports["cursor-restart-hwm.json"]["observations"], canonical_ids)
    _sqlite_observations_exact(reports["sqlite-independence.json"]["observations"], canonical_ids, fresh_id, fresh_sequence)
    triplet = _journal_observations_exact(reports["journal-snapshot-matrix.json"]["observations"])
    _recovery_observations_exact(reports["recovery-vs-verification.json"]["observations"], triplet)
    _fd_observations_exact(reports["fd-failure-path-matrix.json"]["observations"])
    mode_procfs = _identity_mode_observations(reports["identity-mode-lock-path-report.json"]["observations"])
    _transition_observations(reports["identity-transition-report.json"]["observations"], mode_procfs)
    _crash_observations_exact(reports["identity-crash-matrix.json"]["observations"], expected_nodes["identity-crash-matrix.json"])
    _portability_observations_exact(reports["restore-portability-manifest.json"]["observations"])
    before = _read_state_observations(reports["read-state-before.json"]["observations"], "read-state-before")
    after = _read_state_observations(reports["read-state-after.json"]["observations"], "read-state-after")
    _equal(before, after, "read-state reports")
    _equal(reports["read-state-before.json"]["proving_node_ids"], reports["read-state-after.json"]["proving_node_ids"], "read-state nodes")
    _bundle_exact(evidence, expected_sources)





def validate_bundle(evidence: Path = EVIDENCE) -> None:
    """Validate the complete typed and relational Slice 3A evidence seal."""

    _validate_bundle_exact(evidence)


def test_slice3a_retained_evidence_is_a_complete_e2_seal() -> None:
    validate_bundle()


def test_inventory_allows_real_singleton_but_read_state_rejects_singletons_and_synthetic_roots() -> None:
    singleton = {
        "root": "/proc/self/fd",
        "entries": [{
            "path": ".", "kind": "directory", "dev": 1, "ino": 2,
            "mode": 0o40500, "nlink": 2, "uid": 0, "gid": 0,
            "rdev": 0, "size": 0, "blocks": 0, "blksize": 4096,
            "mtime_ns": 1, "ctime_ns": 1,
        }],
    }

    assert _inventory(singleton) == singleton
    with pytest.raises(AssertionError):
        _read_state_inventory(singleton)
    with pytest.raises(AssertionError):
        _read_state_inventory({**singleton, "root": "synthetic-read-state"})


def test_acceptance_json_is_strict_but_need_not_use_candidate_canonical_bytes(tmp_path: Path) -> None:
    path = tmp_path / "acceptance.json"
    path.write_bytes(b'{ "value": 1 }')
    assert _load(path, canonical=False) == {"value": 1}

    for raw in (b'{"value":1,"value":1}\n', b'{"value":NaN}\n', b'\xff'):
        path.write_bytes(raw)
        with pytest.raises(AssertionError):
            _load(path, canonical=False)


def test_rebound_slice3a_bundle_passes_without_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _copy_and_rebind_bundle(tmp_path, monkeypatch)
    validate_bundle(candidate)


def test_reseal_refreshes_suite_and_artifact_junit_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _copy_and_rebind_bundle(tmp_path, monkeypatch)
    repository = candidate.parents[2]
    _mutate_junit(candidate, lambda root: next(root.iter("testsuite")).set("time", "0.000"))
    compatibility = candidate / "compatibility-pytest.xml"
    compatibility_root = ElementTree.parse(compatibility).getroot()
    next(compatibility_root.iter("testsuite")).set("time", "0.000")
    ElementTree.ElementTree(compatibility_root).write(
        compatibility,
        encoding="utf-8",
        xml_declaration=True,
    )

    _reseal_bundle(candidate, repository)

    manifest = _load(candidate / "run-manifest.json")
    for suite_name in ("focused", "compatibility"):
        junit_file = manifest["suites"][suite_name]["junit_file"]
        digest = _sha(candidate / junit_file)
        assert manifest["suites"][suite_name]["junit_sha256"] == digest
        assert manifest["artifacts"][junit_file]["sha256"] == digest


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("child_exit", 77.0),
        ("child_exit", True),
        ("child_exit", False),
        ("before_rename", 1),
        ("operation", 1),
        ("fault_point", False),
        ("identity_sha256", 1),
        ("state", False),
        ("extra", "forged"),
    ],
)
def test_rebound_slice3a_bundle_rejects_resealed_noncanonical_identity_crash_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    forged: object,
) -> None:
    candidate = _copy_and_rebind_bundle(tmp_path, monkeypatch)
    repository = candidate.parents[2]
    report = _load(candidate / "identity-crash-matrix.json")
    report["observations"]["matrix"][0][field] = forged
    _write_json(candidate / "identity-crash-matrix.json", report)
    _reseal_bundle(candidate, repository)

    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validate_bundle(candidate)


@pytest.mark.parametrize("suite_name", sorted(SUITE_FILES))
@pytest.mark.parametrize(
    "field",
    [
        "collect_exit",
        "junit_exit",
        "count_tests",
        "count_failures",
        "count_errors",
        "count_skipped",
    ],
)
@pytest.mark.parametrize("scalar_type", ["bool", "float"])
def test_rebound_slice3a_bundle_rejects_resealed_noninteger_manifest_scalars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suite_name: str,
    field: str,
    scalar_type: str,
) -> None:
    candidate = _copy_and_rebind_bundle(tmp_path, monkeypatch)
    repository = candidate.parents[2]
    manifest = _load(candidate / "run-manifest.json")
    suite = manifest["suites"][suite_name]
    if field == "collect_exit":
        target = suite["collect_command"]
        key = "exit"
    elif field == "junit_exit":
        target = suite["junit_command"]
        key = "exit"
    else:
        target = suite["counts"]
        key = field.removeprefix("count_")
    honest = target[key]
    target[key] = False if scalar_type == "bool" else float(honest)
    _write_json(candidate / "run-manifest.json", manifest)
    _reseal_bundle(candidate, repository)

    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validate_bundle(candidate)


@pytest.mark.parametrize("outcome", ["failure", "error", "skipped"])
def test_node_ids_rejects_suite_level_outcome_children(tmp_path: Path, outcome: str) -> None:
    path = tmp_path / "junit.xml"
    path.write_text(
        (
            '<testsuites tests="1" failures="0" errors="0" skipped="0">'
            '<testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase classname="tests.test_example" name="test_example" />'
            f'<{outcome} />'
            '</testsuite>'
            '</testsuites>'
        ),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError):
        _node_ids(path)


def test_node_ids_rejects_unexpected_testcase_child(tmp_path: Path) -> None:
    path = tmp_path / "junit.xml"
    path.write_text(
        (
            '<testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase classname="tests.test_example" name="test_example">'
            '<system-out>forged</system-out>'
            '</testcase>'
            '</testsuite>'
        ),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError):
        _node_ids(path)


@pytest.mark.parametrize(
    "case",
    [
        "unrelated_proving_node",
        "append_node_substitution",
        "report_manifest_node_mismatch",
        "forged_outside_after",
        "missing_outside",
        "wrong_type_outside",
        "retry_count_one",
        "retry_count_bool",
        "retry_count_float",
        "extra_fd_path",
        "missing_fd_path",
        "extra_fd_row_key",
        "boolean_fd_delta",
        "mutated_after_state",
        "nested_extra_file",
        "changed_commit_binding",
        "changed_tree_binding",
        "junit_failure_child_with_zero_attrs",
        "junit_error_child_with_zero_attrs",
        "junit_skipped_child_with_zero_attrs",
        "junit_failure_attr_without_child",
        "junit_suite_failure_child",
        "junit_suite_error_child",
        "junit_suite_skipped_child",
        "junit_unexpected_testcase_child",
        "junit_unexpected_suite_child",
        "junit_unexpected_root_child",
        "junit_nested_suite",
        "junit_noncanonical_count",
        "junit_aggregate_mismatch",
        "json_duplicate_identical_value",
        "json_noncanonical_whitespace",
        "json_missing_final_lf",
        "json_nonfinite",
        "json_invalid_utf8",
        "collect_wrong_interpreter",
        "junit_wrong_interpreter",
        "producer_swap_both_directions",
        "empty_fd_inventories_count_one",
        "coherent_anchored_read_outside_forgery",
        "coherent_anchored_append_outside_forgery",
        "coherent_verified_snapshot_outside_forgery",
        "coherent_direct_append_outside_forgery",
        "coherent_procfs_outside_forgery",
    ],
)
def test_rebound_slice3a_bundle_rejects_resealed_provenance_and_fd_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    candidate = _copy_and_rebind_bundle(tmp_path, monkeypatch)
    repository = candidate.parents[2]
    manifest = _load(candidate / "run-manifest.json")
    unrelated = next(
        node
        for node in manifest["suites"]["focused"]["ordered_node_ids"]
        if "test_query_is_sqlite_independent" in node
    )

    if case == "unrelated_proving_node":
        report = _load(candidate / "cursor-restart-hwm.json")
        _tamper_report_nodes(candidate, "cursor-restart-hwm.json", [*report["proving_node_ids"], unrelated])
    elif case == "append_node_substitution":
        report = _load(candidate / "fd-failure-path-matrix.json")
        nodes = [unrelated if "anchored_leaf_validation" in node and "[append]" in node else node for node in report["proving_node_ids"]]
        _tamper_report_nodes(candidate, "fd-failure-path-matrix.json", nodes)
    elif case == "report_manifest_node_mismatch":
        report = _load(candidate / "cursor-restart-hwm.json")
        _tamper_report_nodes(candidate, "cursor-restart-hwm.json", [*report["proving_node_ids"], unrelated], manifest_too=False)
    elif case == "forged_outside_after":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "anchored_read").__setitem__("outside_after", ["forged"]))
    elif case == "missing_outside":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "verified_snapshot").pop("outside_after"))
    elif case == "wrong_type_outside":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "procfs_fstat_eio").__setitem__("outside_before", "forged"))
    elif case == "retry_count_one":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "anchored_read").__setitem__("retry_count", 1))
    elif case == "retry_count_bool":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "anchored_read").__setitem__("retry_count", True))
    elif case == "retry_count_float":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "anchored_read").__setitem__("retry_count", 64.0))
    elif case == "extra_fd_path":
        def add_path(report: dict[str, Any]) -> None:
            extra = dict(_fd_path(report, "anchored_read"))
            extra["path"] = "extra"
            report["observations"]["paths"].append(extra)
        _mutate_fd_report(candidate, add_path)
    elif case == "missing_fd_path":
        _mutate_fd_report(candidate, lambda report: report["observations"]["paths"].remove(_fd_path(report, "anchored_append")))
    elif case == "extra_fd_row_key":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "anchored_read").__setitem__("extra", "forged"))
    elif case == "boolean_fd_delta":
        _mutate_fd_report(candidate, lambda report: _fd_path(report, "anchored_read").__setitem__("fd_delta", False))
    elif case == "mutated_after_state":
        def mutate_state(report: dict[str, Any]) -> None:
            state = _fd_path(report, "anchored_read")["after_state"]
            state["entries"][0]["size"] += 1
        _mutate_fd_report(candidate, mutate_state)
    elif case == "nested_extra_file":
        extra = candidate / "nested" / "extra.json"
        extra.parent.mkdir()
        extra.write_text("{}\n", encoding="utf-8")
    elif case == "changed_commit_binding":
        manifest["reviewed"]["commit"] = "f" * 40
        _write_json(candidate / "run-manifest.json", manifest)
    elif case == "changed_tree_binding":
        manifest["reviewed"]["tree"] = "f" * 40
        _write_json(candidate / "run-manifest.json", manifest)
    elif case in {
        "junit_failure_child_with_zero_attrs",
        "junit_error_child_with_zero_attrs",
        "junit_skipped_child_with_zero_attrs",
    }:
        outcome = case.removeprefix("junit_").removesuffix("_child_with_zero_attrs")
        _mutate_junit(
            candidate,
            lambda root: ElementTree.SubElement(next(root.iter("testcase")), outcome),
        )
    elif case == "junit_failure_attr_without_child":
        _mutate_junit(
            candidate,
            lambda root: next(root.iter("testsuite")).set("failures", "1"),
        )
    elif case in {
        "junit_suite_failure_child",
        "junit_suite_error_child",
        "junit_suite_skipped_child",
    }:
        outcome = case.removeprefix("junit_suite_").removesuffix("_child")
        _mutate_junit(
            candidate,
            lambda root: ElementTree.SubElement(next(root.iter("testsuite")), outcome),
        )
    elif case == "junit_unexpected_testcase_child":
        _mutate_junit(
            candidate,
            lambda root: ElementTree.SubElement(next(root.iter("testcase")), "system-out"),
        )
    elif case == "junit_unexpected_suite_child":
        _mutate_junit(
            candidate,
            lambda root: ElementTree.SubElement(next(root.iter("testsuite")), "properties"),
        )
    elif case == "junit_unexpected_root_child":
        _mutate_junit(
            candidate,
            lambda root: ElementTree.SubElement(root, "properties"),
        )
    elif case == "junit_nested_suite":
        _mutate_junit(
            candidate,
            lambda root: ElementTree.SubElement(next(root.iter("testsuite")), "testsuite", {
                "name": "nested", "tests": "0", "failures": "0", "errors": "0", "skipped": "0",
            }),
        )
    elif case == "junit_noncanonical_count":
        _mutate_junit(
            candidate,
            lambda root: next(root.iter("testsuite")).set("failures", "00"),
        )
    elif case == "junit_aggregate_mismatch":
        _mutate_junit(candidate, lambda root: root.set("tests", "1"))
    elif case == "json_duplicate_identical_value":
        path = candidate / "canonical-query-matrix.json"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(
            b'{\n  "observations":',
            f'{{\n  "schema_version": "{SCHEMA}",\n  "observations":'.encode("ascii"),
            1,
        ))
    elif case == "json_noncanonical_whitespace":
        path = candidate / "canonical-query-matrix.json"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'{\n', b'{ \n', 1))
    elif case == "json_missing_final_lf":
        path = candidate / "canonical-query-matrix.json"
        raw = path.read_bytes()
        assert raw.endswith(b"\n")
        path.write_bytes(raw[:-1])
    elif case == "json_nonfinite":
        path = candidate / "canonical-query-matrix.json"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"observations": {', b'"observations": {\n    "nonfinite": NaN,', 1))
    elif case == "json_invalid_utf8":
        path = candidate / "canonical-query-matrix.json"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'{\n', b'{\n  "invalid": "\xff",\n', 1))
    elif case == "collect_wrong_interpreter":
        manifest["suites"]["focused"]["collect_command"]["argv"][0] = "/bin/false"
        _write_json(candidate / "run-manifest.json", manifest)
    elif case == "junit_wrong_interpreter":
        manifest["suites"]["focused"]["junit_command"]["argv"][0] = "/bin/false"
        _write_json(candidate / "run-manifest.json", manifest)
    elif case == "producer_swap_both_directions":
        manifest["artifacts"]["slice3a-pytest.xml"]["producer_command"] = "compatibility-junit"
        manifest["artifacts"]["compatibility-pytest.xml"]["producer_command"] = "focused-junit"
        _write_json(candidate / "run-manifest.json", manifest)
    elif case == "empty_fd_inventories_count_one":
        def empty_fd_inventories(report: dict[str, Any]) -> None:
            row = _fd_path(report, "anchored_read")
            row["baseline"] = row["after"] = []
            row["baseline_count"] = row["after_count"] = 1
        _mutate_fd_report(candidate, empty_fd_inventories)
    elif case in {
        "coherent_anchored_read_outside_forgery",
        "coherent_anchored_append_outside_forgery",
    }:
        path_name = "anchored_read" if "read" in case else "anchored_append"
        def forge_outside_paths(report: dict[str, Any]) -> None:
            row = _fd_path(report, path_name)
            row["outside_before"] = row["outside_after"] = ["forged"]
        _mutate_fd_report(candidate, forge_outside_paths)
    elif case in {
        "coherent_verified_snapshot_outside_forgery",
        "coherent_direct_append_outside_forgery",
        "coherent_procfs_outside_forgery",
    }:
        if case == "coherent_verified_snapshot_outside_forgery":
            path_name, field = "verified_snapshot", "path"
        elif case == "coherent_direct_append_outside_forgery":
            path_name, field = "direct_journal_append", "size"
        else:
            path_name, field = "procfs_fstat_eio", "digest"

        def forge_outside_manifest(report: dict[str, Any]) -> None:
            row = _fd_path(report, path_name)
            for side in ("outside_before", "outside_after"):
                manifest_rows = row[side]
                sentinel = next(item for item in manifest_rows if item[0] == "sentinel")
                if field == "path":
                    sentinel[0] = "forged"
                elif field == "size":
                    sentinel[8] = 26
                else:
                    sentinel[11] = "0" * 64
        _mutate_fd_report(candidate, forge_outside_manifest)
    else:  # pragma: no cover - parameter guard
        raise AssertionError(case)

    _reseal_bundle(candidate, repository)
    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validate_bundle(candidate)


def _fd_path(report: dict[str, Any], path: str) -> dict[str, Any]:
    return next(row for row in report["observations"]["paths"] if row["path"] == path)


_MANDATORY_TYPED_ATTACKS = {
    "cursor-sequence-bool": ("cursor-restart-hwm.json", ("observations", "fresh_first", "sequence"), True),
    "cursor-resumed-id-bool": ("cursor-restart-hwm.json", ("observations", "resumed_ids", 0), True),
    "identity-lifetime-child-float": ("identity-mode-lock-path-report.json", ("observations", "lifetime", "child_exit"), -9.0),
    "identity-procfs-errno-bool": ("identity-mode-lock-path-report.json", ("observations", "procfs", 0, "empty_path_errno"), True),
    "transition-procfs-errno-bool": ("identity-transition-report.json", ("observations", "procfs", 0, "empty_path_errno"), True),
    "recovery-snapshot-rows-bool": ("recovery-vs-verification.json", ("observations", "reconcile", "snapshot_rows"), True),
    "journal-state-number-bool": ("journal-snapshot-matrix.json", ("observations", "snapshot", "before", 0, 3), True),
    "portability-state-number-bool": ("restore-portability-manifest.json", ("observations", "relocated_state", "entries", 0, "dev"), True),
    "canonical-result-id-bool": ("canonical-query-matrix.json", ("observations", "requests", 0, "ordered_entry_ids", 0), True),
}

_ADDITIONAL_SCHEMA_ATTACKS: dict[str, tuple[str, str, tuple[object, ...], object]] = {
    "wrapper-missing-schema": ("report-wrapper", "canonical-query-matrix.json", ("schema_version",), None),
    "wrapper-extra-field": ("report-wrapper", "canonical-query-matrix.json", ("extra",), "forged"),
    "wrapper-schema-type": ("report-wrapper", "canonical-query-matrix.json", ("schema_version",), True),
    "wrapper-duplicate-node": ("report-wrapper", "canonical-query-matrix.json", ("proving_node_ids", 1), "__DUPLICATE_FIRST__"),
    "canonical-request-count": ("canonical-query", "canonical-query-matrix.json", ("observations", "requests"), "__DROP_LAST__"),
    "canonical-request-order": ("canonical-query", "canonical-query-matrix.json", ("observations", "requests"), "__SWAP_FIRST_TWO__"),
    "canonical-filter-nested-bool": ("canonical-query", "canonical-query-matrix.json", ("observations", "requests", 1, "filter", "time_range", "from"), True),
    "canonical-result-empty": ("canonical-query", "canonical-query-matrix.json", ("observations", "requests", 1, "ordered_entry_ids"), []),
    "canonical-unsupported-hook-bool": ("canonical-query", "canonical-query-matrix.json", ("observations", "unsupported", 0, "class_hook_calls", "Journal.verified_snapshot"), False),
    "cursor-terminal-nonnull": ("cursor", "cursor-restart-hwm.json", ("observations", "terminal_cursor"), "forged"),
    "cursor-resumed-duplicate": ("cursor", "cursor-restart-hwm.json", ("observations", "resumed_ids", 1), "__COPY_PREVIOUS__"),
    "sqlite-proof-integer": ("sqlite", "sqlite-independence.json", ("observations", "proofs_equal"), 1),
    "sqlite-call-bool": ("sqlite", "sqlite-independence.json", ("observations", "sqlite_connect_calls"), False),
    "sqlite-appended-sequence-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "appended", "sequence"), True),
    "sqlite-page-row-sequence-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "old_pages", 0, 0, 0, 1), True),
    "sqlite-page-row-time-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "old_pages", 0, 0, 0, 3), True),
    "sqlite-page-row-topics-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "old_pages", 0, 0, 0, 5), True),
    "sqlite-position-sequence-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "old_positions", 0, 0), True),
    "sqlite-hwm-sequence-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "old_high_watermark", 0), True),
    "sqlite-index-number-bool": ("sqlite", "sqlite-independence.json", ("observations", "states", "valid", "index_before", 2), True),
    "journal-event-hex-uppercase": ("journal", "journal-snapshot-matrix.json", ("observations", "snapshot", "triplet", "event_rows", 0), "__UPPER__"),
    "journal-lock-read-order": ("journal", "journal-snapshot-matrix.json", ("observations", "lock_order", "reads"), "__SWAP_FIRST_TWO__"),
    "journal-scalar-label": ("journal", "journal-snapshot-matrix.json", ("observations", "scalars", 0, "scalar_type"), "float"),
    "recovery-repair-digest-bool": ("recovery", "recovery-vs-verification.json", ("observations", "reconcile", "repaired_chain_sha256"), True),
    "recovery-tamper-result-type": ("recovery", "recovery-vs-verification.json", ("observations", "tamper", 0, "result"), 1),
    "recovery-tamper-duplicate-case": ("recovery", "recovery-vs-verification.json", ("observations", "tamper", 1, "case"), "missing_head"),
    "fd-state-number-bool": ("fd", "fd-failure-path-matrix.json", ("observations", "paths", 0, "before_state", "entries", 0, "dev"), True),
    "fd-descriptor-bool": ("fd", "fd-failure-path-matrix.json", ("observations", "paths", 0, "baseline", 0, "fd"), True),
    "identity-state-number-bool": ("identity-mode", "identity-mode-lock-path-report.json", ("observations", "lifetime", "state", "entries", 0, "dev"), True),
    "identity-procfs-call-arity": ("identity-mode", "identity-mode-lock-path-report.json", ("observations", "procfs", 0, "calls", 0), "__DROP_LAST__"),
    "transition-procfs-call-flag-bool": ("transition", "identity-transition-report.json", ("observations", "procfs", 0, "calls", 0, 4), True),
    "crash-before-integer": ("crash", "identity-crash-matrix.json", ("observations", "matrix", 0, "before_rename"), 1),
    "crash-state-number-bool": ("crash", "identity-crash-matrix.json", ("observations", "matrix", 0, "state", "entries", 0, "dev"), True),
    "portability-states-equal-integer": ("portability", "restore-portability-manifest.json", ("observations", "states_equal"), 1),
    "portability-identity-digest-bool": ("portability", "restore-portability-manifest.json", ("observations", "identity_sha256"), True),
    "read-state-root-type": ("read-state", "read-state-before.json", ("observations", "root"), True),
    "read-state-forbidden-insertion": ("read-state", "read-state-before.json", ("observations", "forbidden_matches"), ["cursor"]),
    "read-state-operation-order": ("read-state", "read-state-before.json", ("observations", "operations"), "__SWAP_FIRST_TWO__"),
    "manifest-source-blob-bool": ("run-manifest", "run-manifest.json", ("sources", "__FIRST_KEY__", "blob"), True),
    "manifest-artifact-producer-type": ("artifact", "run-manifest.json", ("artifacts", "canonical-query-matrix.json", "producer_command"), True),
    "manifest-artifact-node-type": ("artifact", "run-manifest.json", ("artifacts", "canonical-query-matrix.json", "proving_node_ids", 0), True),
    "bundle-digest-bool": ("bundle", "bundle-source-digests.json", ("files", "__FIRST_KEY__"), True),
}

_SCHEMA_FAMILIES = {
    "report-wrapper", "canonical-query", "cursor", "sqlite", "journal", "recovery",
    "fd", "identity-mode", "transition", "crash", "portability", "read-state",
    "run-manifest", "artifact", "bundle", "junit", "recursive-leaves",
}

_MANDATORY_FAMILIES = {
    "cursor-sequence-bool": "cursor",
    "cursor-resumed-id-bool": "cursor",
    "identity-lifetime-child-float": "identity-mode",
    "identity-procfs-errno-bool": "identity-mode",
    "transition-procfs-errno-bool": "transition",
    "recovery-snapshot-rows-bool": "recovery",
    "journal-state-number-bool": "journal",
    "portability-state-number-bool": "portability",
    "canonical-result-id-bool": "canonical-query",
}


def _set_nested(value: object, path: tuple[object, ...], replacement: object) -> None:
    current = value
    for component in path[:-1]:
        if component == "__FIRST_KEY__":
            component = sorted(current)[0]  # type: ignore[arg-type]
        current = current[component]  # type: ignore[index]
    final = path[-1]
    if final == "__FIRST_KEY__":
        final = sorted(current)[0]  # type: ignore[arg-type]
    if replacement == "__DROP_LAST__":
        current[final].pop()  # type: ignore[index]
    elif replacement == "__SWAP_FIRST_TWO__":
        current[final][0], current[final][1] = current[final][1], current[final][0]  # type: ignore[index]
    elif replacement == "__COPY_PREVIOUS__":
        current[final] = current[final - 1]  # type: ignore[index,operator]
    elif replacement == "__UPPER__":
        current[final] = current[final].upper()  # type: ignore[index]
    elif replacement is None and len(path) == 1:
        current.pop(final)  # type: ignore[union-attr]
    else:
        current[final] = replacement  # type: ignore[index]


@pytest.mark.parametrize("case", sorted(set(_MANDATORY_TYPED_ATTACKS) | set(_ADDITIONAL_SCHEMA_ATTACKS)))
def test_rebound_slice3a_bundle_rejects_complete_schema_mutation_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    candidate = _copy_and_rebind_bundle(tmp_path, monkeypatch)
    repository = candidate.parents[2]
    if case in _MANDATORY_TYPED_ATTACKS:
        report_name, path, replacement = _MANDATORY_TYPED_ATTACKS[case]
    else:
        _, report_name, path, replacement = _ADDITIONAL_SCHEMA_ATTACKS[case]
    report = _load(candidate / report_name)
    _set_nested(report, path, replacement)
    _write_json(candidate / report_name, report)
    if case == "bundle-digest-bool":
        # The digest manifest is the final seal and intentionally does not hash itself.
        pass
    else:
        _reseal_bundle(candidate, repository)

    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validate_bundle(candidate)


def test_complete_schema_mutation_registry_covers_every_declared_family_and_prior_attack() -> None:
    registered = {case: family for case, (family, *_rest) in _ADDITIONAL_SCHEMA_ATTACKS.items()}
    registered.update(_MANDATORY_FAMILIES)
    # Prior adversarial suites remain independently exercised below; register their
    # two schema families so coverage cannot silently narrow during refactors.
    registered.update({"prior-junit-grammar-and-outcome-attacks": "junit", "prior-recursive-extra-attack": "recursive-leaves"})
    _equal(set(registered.values()), _SCHEMA_FAMILIES, "mutation-registry.families")
    _check(set(_MANDATORY_TYPED_ATTACKS) <= set(registered), "mutation-registry", "mandatory attacks missing")
    _check(len(registered) == len(set(registered)), "mutation-registry", "duplicate mutation IDs")
