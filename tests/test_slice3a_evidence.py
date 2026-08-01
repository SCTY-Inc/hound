"""Strict checker for the retained, two-commit Slice 3A evidence seal."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest


ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "tests" / "evidence" / "slice3a"
SCHEMA = "houndd.slice3a.evidence-seal.v1"
REPORTS = {
    "canonical-query-matrix.json",
    "sqlite-independence.json",
    "journal-snapshot-matrix.json",
    "identity-mode-lock-path-report.json",
    "fd-failure-path-matrix.json",
    "read-state-before.json",
    "read-state-after.json",
}
JUNITS = {"slice3a-pytest.xml", "compatibility-pytest.xml"}
LEAVES = REPORTS | JUNITS | {"run-manifest.json", "bundle-source-digests.json"}
STALE_JUNIT_SHA256 = {
    "806f799cf947046b2799a322542c559cd795bbadbba5ebe9f1689a408156c9fc",
    "0a2e980f425cacbc41d8d5a4be48c253b5c8ab3189f38ae9241067e4a3422bc1",
}
SUITE_FILES = {
    "focused": (
        "tests/test_hsp05_transactions.py",
        "tests/test_hsp08_durable_query.py",
        "tests/test_hsp20_durable_state.py",
    ),
    "compatibility": (
        "tests/test_hsp04_contract.py",
        "tests/test_hsp05_transactions.py",
        "tests/test_hsp07_dedupe.py",
        "tests/test_hsp14_legacy_portability.py",
        "tests/test_hsp20_verification.py",
        "tests/test_hsp08_cursor.py",
        "tests/test_hsp08_query_contracts.py",
        "tests/test_hsp09_access.py",
        "tests/test_hsp08_query_engine.py",
        "tests/test_hsp09_query_authorization.py",
        "tests/test_hsp20_query_snapshot.py",
    ),
}
SOURCE_PATHS = tuple(
    sorted(
        {
            "tests/acceptance_slice3a.json",
            "tests/generate_slice3a_evidence.py",
            "tests/test_slice3a_evidence.py",
            "src/houndd/cursor.py",
            "src/houndd/journal.py",
            "src/houndd/provenance.py",
            "src/houndd/query_engine.py",
            "src/houndd/service_identity.py",
            "src/houndd/snapshot.py",
            *SUITE_FILES["focused"],
            *SUITE_FILES["compatibility"],
        }
    )
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert type(value) is dict, path
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _git_bytes(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def _node_ids(path: Path) -> tuple[list[str], dict[str, int]]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    assert suites, path
    counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    nodes: list[str] = []
    for suite in suites:
        for key in counts:
            counts[key] += int(suite.attrib.get(key, "0"))
    for case in root.iter("testcase"):
        classname = case.attrib.get("classname")
        name = case.attrib.get("name")
        assert classname and name, path
        nodes.append(f"{classname.replace('.', '/')}.py::{name}")
    assert counts["tests"] == len(nodes), path
    return nodes, counts


def _assert_inventory(value: object) -> None:
    assert type(value) is dict
    assert value.get("root") == "."
    entries = value.get("entries")
    assert type(entries) is list and entries
    paths: list[str] = []
    required = {"path", "kind", "dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "blocks", "blksize", "mtime_ns", "ctime_ns"}
    for entry in entries:
        assert type(entry) is dict and required <= set(entry)
        assert "atime" not in entry and "atime_ns" not in entry
        assert type(entry["path"]) is str
        paths.append(entry["path"])
        assert entry["kind"] in {"directory", "regular", "symlink", "other"}
        if entry["kind"] == "regular":
            assert type(entry.get("sha256")) is str and len(entry["sha256"]) == 64
        if entry["kind"] == "symlink":
            assert type(entry.get("symlink_target")) is str
    assert paths == sorted(paths) and len(paths) == len(set(paths))


def _required_nodes(report: dict[str, Any], nodes: set[str]) -> None:
    proving = report.get("proving_node_ids")
    assert type(proving) is list and proving and all(type(node) is str for node in proving)
    assert len(proving) == len(set(proving))
    assert set(proving) <= nodes


def validate_bundle(evidence: Path = EVIDENCE) -> None:
    """Validate E2 only; it deliberately reads but never regenerates evidence."""
    assert {path.name for path in evidence.iterdir() if path.is_file()} == LEAVES
    manifest = _load(evidence / "run-manifest.json")
    assert manifest.get("schema_version") == SCHEMA
    assert type(manifest.get("run_id")) is str and manifest["run_id"]
    assert type(manifest.get("bb_thread_id")) is str and manifest["bb_thread_id"]
    assert manifest.get("cwd") == str(ROOT)
    assert manifest.get("allowlisted_environment") == {"PYTHONDONTWRITEBYTECODE": "1"}
    reviewed = manifest.get("reviewed")
    assert type(reviewed) is dict
    commit = reviewed.get("commit")
    tree = reviewed.get("tree")
    assert type(commit) is str and type(tree) is str
    assert _git("rev-parse", f"{commit}^{{tree}}") == tree
    source = manifest.get("sources")
    assert type(source) is dict and set(source) == set(SOURCE_PATHS)
    for relative, record in source.items():
        assert type(record) is dict
        assert set(record) == {"blob", "sha256"}
        assert _sha(ROOT / relative) == record["sha256"]
        assert _git("rev-parse", f"{commit}:{relative}") == record["blob"]
        assert _git_bytes("show", f"{commit}:{relative}") == (ROOT / relative).read_bytes()

    suites = manifest.get("suites")
    assert type(suites) is dict and set(suites) == set(SUITE_FILES)
    all_nodes: set[str] = set()
    for suite_name, files in SUITE_FILES.items():
        suite = suites[suite_name]
        assert type(suite) is dict
        assert tuple(suite.get("source_paths", ())) == files
        assert set(suite) == {"source_paths", "collect_command", "junit_command", "junit_file", "junit_sha256", "counts", "ordered_node_ids"}
        for command_name in ("collect_command", "junit_command"):
            command = suite[command_name]
            assert type(command) is dict and set(command) == {"id", "argv", "exit"}
            assert type(command["id"]) is str and type(command["argv"]) is list
            assert command["exit"] == 0
        junit_name = suite["junit_file"]
        assert junit_name in JUNITS and _sha(evidence / junit_name) == suite["junit_sha256"]
        assert suite["junit_sha256"] not in STALE_JUNIT_SHA256
        nodes, counts = _node_ids(evidence / junit_name)
        assert nodes == suite["ordered_node_ids"]
        assert len(nodes) == len(set(nodes)) and nodes
        assert counts == suite["counts"]
        assert counts["failures"] == counts["errors"] == counts["skipped"] == 0
        assert counts["tests"] >= len(files)
        assert all("test_slice3a_evidence.py" not in node for node in nodes)
        all_nodes.update(nodes)

    artifacts = manifest.get("artifacts")
    expected_artifacts = (REPORTS | JUNITS) - {"run-manifest.json", "bundle-source-digests.json"}
    assert type(artifacts) is dict and set(artifacts) == expected_artifacts
    for name, artifact in artifacts.items():
        assert type(artifact) is dict
        assert set(artifact) == {"sha256", "producer_command", "source_paths", "proving_node_ids"}
        assert _sha(evidence / name) == artifact["sha256"]
        assert artifact["producer_command"] in {"focused-junit", "compatibility-junit", "evidence-observer"}
        assert type(artifact["source_paths"]) is list and artifact["source_paths"]
        assert set(artifact["source_paths"]) <= set(SOURCE_PATHS)
        _required_nodes(artifact, all_nodes)

    for name in REPORTS - {"read-state-before.json", "read-state-after.json"}:
        report = _load(evidence / name)
        assert report.get("schema_version") == SCHEMA
        _required_nodes(report, all_nodes)
        assert type(report.get("observations")) is dict and report["observations"]
    before = _load(evidence / "read-state-before.json")
    after = _load(evidence / "read-state-after.json")
    _assert_inventory(before)
    _assert_inventory(after)
    assert before == after
    _required_nodes(before, all_nodes)
    _required_nodes(after, all_nodes)

    canonical = _load(evidence / "canonical-query-matrix.json")
    assert canonical["observations"].get("unsupported_filter_hook") == "class-level"
    sqlite = _load(evidence / "sqlite-independence.json")
    states = sqlite["observations"].get("index_states")
    assert type(states) is dict and set(states) == {"valid", "corrupt", "absent"}
    for observed in states.values():
        assert type(observed) is dict
        assert observed.get("sqlite_connects") == 0
        assert observed.get("index_mutations_except_atime") == []
        assert observed.get("full_pagination") and observed.get("cursor_digest")
        assert observed.get("recovered_last_position") is not None
        assert observed.get("fixed_hwm") is not None
        assert observed.get("resumed_ids") and observed.get("resumed_positions")
        assert observed.get("terminal_cursor") is not None
        assert observed.get("appended_excluded_from_old_hwm")
        assert observed.get("appended_included_in_fresh_query")
    journal = _load(evidence / "journal-snapshot-matrix.json")
    scalars = journal["observations"].get("scalar_rejection_nodes")
    assert type(scalars) is dict and set(scalars) == {"true", "false", "0.0", "1.0"}
    assert journal["observations"].get("unchanged_byte_assertions")
    identity = _load(evidence / "identity-mode-lock-path-report.json")
    assert identity["observations"].get("lifetime_lock")
    fd = _load(evidence / "fd-failure-path-matrix.json")
    retries = fd["observations"].get("repeated_retry_inventories")
    assert type(retries) is dict and {"unsafe_mode_anchored_read", "anchored_append", "public_verified_snapshot"} <= set(retries)
    assert all(value.get("fd_delta") == 0 for value in retries.values() if type(value) is dict)
    assert fd["observations"].get("procfs_fstat_exception_paths")

    bundle = _load(evidence / "bundle-source-digests.json")
    assert bundle.get("schema_version") == SCHEMA
    files = bundle.get("files")
    expected_bundle = set(SOURCE_PATHS) | {f"tests/evidence/slice3a/{name}" for name in LEAVES - {"bundle-source-digests.json"}}
    assert type(files) is dict and set(files) == expected_bundle
    assert "tests/evidence/slice3a/bundle-source-digests.json" not in files
    for relative, digest in files.items():
        assert type(digest) is str and len(digest) == 64
        assert _sha(ROOT / relative) == digest
    assert manifest.get("run_manifest_sha256") is None


def test_slice3a_retained_evidence_is_a_complete_e2_seal() -> None:
    validate_bundle()
