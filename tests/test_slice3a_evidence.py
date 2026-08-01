"""Strict verifier for a staged or retained Slice 3A E2 seal.

It never runs tests or constructs observations.  The generator is the only
supported writer for a candidate; this verifier accepts only its closed leaf
set and values emitted by the proving pytest nodes.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


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


def source_paths(commit: str) -> tuple[str, ...]:
    tracked = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", commit], cwd=ROOT, text=True).splitlines()
    required = {"pyproject.toml", "uv.lock", "tests/acceptance_slice3a.json", "tests/generate_slice3a_evidence.py", "tests/test_slice3a_evidence.py", "tests/slice3a_evidence_capture.py", *SUITE_FILES["focused"], *SUITE_FILES["compatibility"]}
    required.update(path for path in tracked if path.startswith("src/") and path.endswith(".py"))
    required.update(path for path in tracked if path.startswith("tests/fixtures/"))
    return tuple(sorted(required))


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert type(value) is dict, path
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _node_ids(path: Path) -> tuple[list[str], dict[str, int]]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    nodes: list[str] = []
    for suite in suites:
        for key in counts:
            value = int(suite.attrib.get(key, "0"))
            assert type(value) is int
            counts[key] += value
    for case in root.iter("testcase"):
        classname, name = case.attrib.get("classname"), case.attrib.get("name")
        assert classname and name
        nodes.append(f"{classname.replace('.', '/')}.py::{name}")
    assert counts["tests"] == len(nodes) and len(nodes) == len(set(nodes)) and nodes
    return nodes, counts


def _exact_keys(value: object, keys: set[str]) -> dict[str, Any]:
    assert type(value) is dict and set(value) == keys
    return value


def _integer(value: object) -> int:
    assert type(value) is int
    return value


def _inventory(value: object) -> dict[str, Any]:
    result = _exact_keys(value, {"root", "entries"})
    assert type(result["root"]) is str and result["root"] and not result["root"].startswith("synthetic")
    entries = result["entries"]
    assert type(entries) is list and len(entries) > 1
    paths: list[str] = []
    required = {"path", "kind", "dev", "ino", "mode", "nlink", "uid", "gid", "rdev", "size", "blocks", "blksize", "mtime_ns", "ctime_ns"}
    for entry in entries:
        assert type(entry) is dict and set(entry) in (required, required | {"sha256"}, required | {"symlink_target"})
        assert "atime" not in entry and "atime_ns" not in entry
        assert type(entry["path"]) is str and entry["path"]
        paths.append(entry["path"])
        assert entry["kind"] in {"directory", "regular", "symlink", "other"}
        for key in required - {"path", "kind"}:
            _integer(entry[key])
        if entry["kind"] == "regular":
            assert type(entry.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        if entry["kind"] == "symlink":
            assert type(entry.get("symlink_target")) is str
    assert paths == sorted(paths) and len(paths) == len(set(paths)) and paths[0] == "."
    return result


def _report(evidence: Path, name: str, all_nodes: set[str]) -> dict[str, Any]:
    report = _load(evidence / name)
    _exact_keys(report, {"schema_version", "observations", "proving_node_ids"})
    assert report["schema_version"] == SCHEMA and type(report["observations"]) is dict
    proving = report["proving_node_ids"]
    assert type(proving) is list and proving == sorted(set(proving)) and proving and all(type(node) is str and node in all_nodes for node in proving)
    return report


def _require_nodes(report: dict[str, Any], *patterns: str) -> None:
    proving = report["proving_node_ids"]
    for pattern in patterns:
        assert any(pattern in node for node in proving), f"missing proving node {pattern}"


def validate_bundle(evidence: Path = EVIDENCE) -> None:
    """Validate either the retained E2 directory or a generator staging output."""
    assert evidence.exists() and evidence.is_dir() and not evidence.is_symlink()
    entries = list(evidence.iterdir())
    assert all(path.is_file() and not path.is_symlink() for path in entries)
    assert {path.name for path in entries} == LEAVES
    acceptance = _load(ROOT / "tests" / "acceptance_slice3a.json")
    assert acceptance.get("partial_hsps") == ["HSP-08", "HSP-20", "HSP-21"] and acceptance.get("no_new_claim_hsps") == ["HSP-03", "HSP-09"]
    artifact_map = acceptance.get("artifacts")
    evidence_map = {path: claim for path, claim in artifact_map.items() if path.startswith("tests/evidence/slice3a/")} if type(artifact_map) is dict else {}
    assert set(evidence_map) == {f"tests/evidence/slice3a/{name}" for name in LEAVES} and set(evidence_map.values()) == {"HSP-21"}
    coverage = acceptance.get("coverage")
    assert type(coverage) is dict and set(coverage) == {"HSP-08", "HSP-20", "HSP-21"}
    for hsp in ("HSP-08", "HSP-20"):
        retained = coverage[hsp].get("retained_artifacts") if type(coverage[hsp]) is dict else None
        required_retained = ("tests/evidence/slice3a/journal-snapshot-matrix.json", "tests/evidence/slice3a/identity-mode-lock-path-report.json") if hsp == "HSP-20" else ("tests/evidence/slice3a/canonical-query-matrix.json", "tests/evidence/slice3a/sqlite-independence.json")
        assert type(retained) is list and all(item in retained for item in required_retained)
    manifest = _load(evidence / "run-manifest.json")
    _exact_keys(manifest, {"schema_version", "run_id", "bb_thread_id", "reviewed", "cwd", "allowlisted_environment", "sources", "suites", "artifacts"})
    assert manifest["schema_version"] == SCHEMA
    uuid.UUID(manifest["run_id"])
    assert type(manifest["bb_thread_id"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,}", manifest["bb_thread_id"])
    assert manifest["cwd"] == str(ROOT) and manifest["allowlisted_environment"] == {"PYTHONDONTWRITEBYTECODE": "1"}
    reviewed = _exact_keys(manifest["reviewed"], {"commit", "tree"})
    assert type(reviewed["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", reviewed["commit"])
    assert type(reviewed["tree"]) is str and re.fullmatch(r"[0-9a-f]{40}", reviewed["tree"])
    assert _git("rev-parse", f"{reviewed['commit']}^{{tree}}") == reviewed["tree"]
    expected_sources = source_paths(reviewed["commit"])
    sources = manifest["sources"]
    assert type(sources) is dict and tuple(sorted(sources)) == expected_sources
    for relative in expected_sources:
        record = _exact_keys(sources[relative], {"blob", "sha256"})
        assert _git("show", f"{reviewed['commit']}:{relative}") == (ROOT / relative).read_text(encoding="utf-8") if False else True
        reviewed_bytes = subprocess.check_output(["git", "show", f"{reviewed['commit']}:{relative}"], cwd=ROOT)
        assert reviewed_bytes == (ROOT / relative).read_bytes()
        assert record["blob"] == _git("rev-parse", f"{reviewed['commit']}:{relative}") and record["sha256"] == hashlib.sha256(reviewed_bytes).hexdigest()
    suites = manifest["suites"]
    assert type(suites) is dict and set(suites) == set(SUITE_FILES)
    all_nodes: set[str] = set()
    for suite_name, files in SUITE_FILES.items():
        suite = _exact_keys(suites[suite_name], {"source_paths", "collect_command", "junit_command", "junit_file", "junit_sha256", "counts", "ordered_node_ids"})
        assert tuple(suite["source_paths"]) == files
        collect = _exact_keys(suite["collect_command"], {"id", "argv", "exit"})
        junit = _exact_keys(suite["junit_command"], {"id", "argv", "exit"})
        assert collect["id"] == f"{suite_name}-collect" and junit["id"] == f"{suite_name}-junit" and collect["exit"] == junit["exit"] == 0
        assert type(collect["argv"]) is list and type(junit["argv"]) is list
        assert collect["argv"][1:5] == ["-m", "pytest", "--collect-only", "-q"] and collect["argv"][5:] == list(files)
        assert junit["argv"][1:4] == ["-m", "pytest", "-p"] and junit["argv"][4:6] == ["no:cacheprovider", f"--junitxml={evidence / suite['junit_file']}"] and junit["argv"][6:] == list(files)
        assert suite["junit_file"] in JUNITS and _sha(evidence / suite["junit_file"]) == suite["junit_sha256"] and suite["junit_sha256"] not in STALE_JUNIT_SHA256
        nodes, counts = _node_ids(evidence / suite["junit_file"])
        assert nodes == suite["ordered_node_ids"] and counts == suite["counts"] and all(type(value) is int for value in counts.values())
        assert counts["failures"] == counts["errors"] == counts["skipped"] == 0 and counts["tests"] == len(nodes)
        all_nodes.update(nodes)
    artifacts = manifest["artifacts"]
    assert type(artifacts) is dict and set(artifacts) == REPORTS | JUNITS
    for name in REPORTS | JUNITS:
        artifact = _exact_keys(artifacts[name], {"sha256", "producer_command", "source_paths", "proving_node_ids"})
        assert artifact["sha256"] == _sha(evidence / name)
        assert artifact["producer_command"] in {"focused-junit", "compatibility-junit", "evidence-observer"}
        assert tuple(artifact["source_paths"]) == expected_sources
        assert type(artifact["proving_node_ids"]) is list and artifact["proving_node_ids"] == sorted(set(artifact["proving_node_ids"])) and set(artifact["proving_node_ids"]) <= all_nodes

    canonical = _report(evidence, "canonical-query-matrix.json", all_nodes)
    _require_nodes(canonical, "test_durable_query_uses_exact_persisted_chain", "test_projection_filters_fail_explicitly")
    requests = canonical["observations"].get("requests")
    unsupported = canonical["observations"].get("unsupported")
    assert type(requests) is list and len(requests) == 13 and all(type(item) is dict and type(item.get("filter")) is dict and type(item.get("ordered_entry_ids")) is list and item["ordered_entry_ids"] for item in requests)
    assert type(unsupported) is list and len(unsupported) == 4
    for item in unsupported:
        assert type(item) is dict and item["result_type"] == "QueryFilterNotAvailable" and item["filter_keys"] == sorted(item["filter"])
        calls = item["class_hook_calls"]
        assert type(calls) is dict and calls == {"Journal.verified_snapshot": 0, "ServiceIdentity.lease": 0} and all(type(value) is int for value in calls.values())

    sqlite = _report(evidence, "sqlite-independence.json", all_nodes)
    _require_nodes(sqlite, "test_query_is_sqlite_independent")
    states = sqlite["observations"].get("states")
    assert type(states) is dict and set(states) == {"valid", "corrupt", "absent"} and sqlite["observations"].get("sqlite_connect_calls") == 0 and type(sqlite["observations"].get("sqlite_connect_calls")) is int
    proof: list[object] = []
    for state in states.values():
        assert type(state) is dict and state["old_pages"] and state["fresh_pages"] and state["old_recoveries"] and state["fresh_recoveries"]
        assert state["terminal_cursor"] is None and state["appended"]["entry_id"] not in [row[1] for page in state["old_pages"] for row in page[0]] and state["appended"]["entry_id"] in [row[1] for page in state["fresh_pages"] for row in page[0]]
        assert state["index_before"] == state["index_after"]
        proof.append([state[key] for key in ("old_pages", "old_recoveries", "fresh_pages", "fresh_recoveries", "old_high_watermark", "fresh_high_watermark")])
    assert proof[0] == proof[1] == proof[2] and sqlite["observations"].get("proofs_equal") is True

    cursor = _report(evidence, "cursor-restart-hwm.json", all_nodes)
    _require_nodes(cursor, "test_fixed_hwm_cursor_resumes")
    assert type(cursor["observations"].get("resumed_ids")) is list and cursor["observations"]["terminal_cursor"] is None

    before = _report(evidence, "read-state-before.json", all_nodes)
    after = _report(evidence, "read-state-after.json", all_nodes)
    _require_nodes(before, "test_queries_and_replay_persist_no_server_read_state")
    assert before["observations"] == after["observations"] and before["proving_node_ids"] == after["proving_node_ids"]
    state = before["observations"]
    assert state["before"] == state["after"] and state["forbidden_matches"] == [] and state["operations"]
    _inventory(state["before"])

    journal = _report(evidence, "journal-snapshot-matrix.json", all_nodes)
    _require_nodes(journal, "test_verified_snapshot_returns_exact_triplet", "test_journal_operations_reject_noncanonical_sequence_scalars")
    scalar = journal["observations"].get("scalars")
    assert type(scalar) is list and {item["scalar_type"] for item in scalar} == {"bool", "float"} and {item["scalar"] for item in scalar} == {False, True, 0.0, 1.0}
    for item in scalar:
        assert item["before"] == item["after"] and item["result"] == "JournalError"
    recovery = _report(evidence, "recovery-vs-verification.json", all_nodes)
    _require_nodes(recovery, "test_verified_snapshot_is_non_repairing", "test_verified_snapshot_tampering")
    assert recovery["observations"].get("reconcile") and len(recovery["observations"].get("tamper", [])) == 17

    fd = _report(evidence, "fd-failure-path-matrix.json", all_nodes)
    _require_nodes(fd, "anchored_leaf_validation", "unsafe_mode_failures", "procfs_fstat")
    paths = fd["observations"].get("paths")
    assert type(paths) is list and {item["path"] for item in paths} >= {"anchored_read", "anchored_append", "verified_snapshot", "direct_journal_append", "public_verified_snapshot", "procfs_fstat_eio"}
    for item in paths:
        assert all(type(item[key]) is int for key in ("baseline_count", "after_count", "retry_count", "fd_delta"))
        assert item["fd_delta"] == item["after_count"] - item["baseline_count"] == 0 and item["before_state"] == item["after_state"]
        _inventory(item["before_state"])
        assert type(item["baseline"]) is list and type(item["after"]) is list

    identity = _report(evidence, "identity-mode-lock-path-report.json", all_nodes)
    _require_nodes(identity, "lifetime_lock", "exact_fd_procfs_fallback")
    assert identity["observations"].get("lifetime") and len(identity["observations"].get("procfs", [])) == 2
    crash = _report(evidence, "identity-crash-matrix.json", all_nodes)
    _require_nodes(crash, "real_process_death_matrix")
    assert type(crash["observations"].get("matrix")) is list and crash["observations"]["matrix"] and all(item["child_exit"] == 77 for item in crash["observations"]["matrix"])
    transition = _report(evidence, "identity-transition-report.json", all_nodes)
    assert transition["observations"].get("procfs")
    portability = _report(evidence, "restore-portability-manifest.json", all_nodes)
    _require_nodes(portability, "relocation_preserves_identity")
    assert portability["observations"].get("states_equal") is True

    bundle = _load(evidence / "bundle-source-digests.json")
    _exact_keys(bundle, {"schema_version", "files"})
    assert bundle["schema_version"] == SCHEMA
    files = bundle["files"]
    expected = set(expected_sources) | {f"tests/evidence/slice3a/{name}" for name in LEAVES - {"bundle-source-digests.json"}}
    assert type(files) is dict and set(files) == expected and "tests/evidence/slice3a/bundle-source-digests.json" not in files
    for relative, digest in files.items():
        assert type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
        path = ROOT / relative
        if relative.startswith("tests/evidence/"):
            path = evidence / Path(relative).name
        assert _sha(path) == digest


def test_slice3a_retained_evidence_is_a_complete_e2_seal() -> None:
    validate_bundle()
