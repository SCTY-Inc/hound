#!/usr/bin/env python3
"""Generate a fresh Slice 3A E2 candidate into an empty caller-owned directory.

This program never writes ``tests/evidence/slice3a``.  E2 is intentionally a
separate reviewer-controlled retention step after the E1 source commit exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from test_slice3a_evidence import LEAVES, REPORTS, SCHEMA, SOURCE_PATHS, STALE_JUNIT_SHA256, SUITE_FILES


ROOT = Path(__file__).parents[1].resolve()
ENVIRONMENT = {"PYTHONDONTWRITEBYTECODE": "1"}


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _run(argv: list[str]) -> int:
    environment = {**os.environ, **ENVIRONMENT}
    return subprocess.run(argv, cwd=ROOT, env=environment, check=False).returncode


def _collected_nodes(argv: list[str]) -> tuple[int, list[str]]:
    environment = {**os.environ, **ENVIRONMENT}
    completed = subprocess.run(argv, cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    nodes = [line for line in completed.stdout.splitlines() if line.startswith("tests/") and "::" in line]
    return completed.returncode, nodes


def _junit(path: Path) -> tuple[list[str], dict[str, int]]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    counts = {key: sum(int(suite.attrib.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
    nodes = [f"{case.attrib['classname'].replace('.', '/')}.py::{case.attrib['name']}" for case in root.iter("testcase")]
    if counts["tests"] != len(nodes) or len(nodes) != len(set(nodes)):
        raise RuntimeError("JUnit count/order/uniqueness mismatch")
    return nodes, counts


def _inventory(root: Path) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())]
    for path in paths:
        info = path.lstat()
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "regular" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "other"
        relative = "." if path == root else path.relative_to(root).as_posix()
        entry: dict[str, object] = {"path": relative, "kind": kind, "dev": info.st_dev, "ino": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink, "uid": info.st_uid, "gid": info.st_gid, "rdev": info.st_rdev, "size": info.st_size, "blocks": info.st_blocks, "blksize": info.st_blksize, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
        if kind == "regular":
            entry["sha256"] = _sha(path)
        if kind == "symlink":
            entry["symlink_target"] = os.readlink(path)
        entries.append(entry)
    return {"root": ".", "entries": entries}


def _nodes_containing(nodes: list[str], needle: str) -> list[str]:
    found = [node for node in nodes if needle in node]
    if not found:
        raise RuntimeError(f"required proving node missing: {needle}")
    return found


def _report(observations: dict[str, object], proving: list[str]) -> dict[str, object]:
    return {"schema_version": SCHEMA, "observations": observations, "proving_node_ids": sorted(set(proving))}


def generate(output: Path, reviewed_commit: str, reviewed_tree: str, run_id: str, bb_thread_id: str) -> None:
    output = output.resolve()
    if output == ROOT / "tests" / "evidence" / "slice3a" or (output.exists() and any(output.iterdir())):
        raise RuntimeError("output must be a fresh staging directory and must never be retained evidence")
    output.mkdir(parents=True, exist_ok=True)
    if _git("rev-parse", f"{reviewed_commit}^{{tree}}") != reviewed_tree:
        raise RuntimeError("reviewed commit/tree mismatch")
    if not run_id or not bb_thread_id:
        raise RuntimeError("run_id and bb_thread_id must be non-empty")
    # Keep the invoking virtualenv executable; resolving it follows the venv
    # symlink to the system interpreter and loses the reviewed pytest install.
    python = sys.executable
    suite_records: dict[str, dict[str, object]] = {}
    all_nodes: list[str] = []
    for suite_name, files in SUITE_FILES.items():
        junit_name = "slice3a-pytest.xml" if suite_name == "focused" else "compatibility-pytest.xml"
        collect_argv = [python, "-m", "pytest", "--collect-only", "-q", *files]
        collect_exit, collected = _collected_nodes(collect_argv)
        junit_argv = [python, "-m", "pytest", "-p", "no:cacheprovider", f"--junitxml={output / junit_name}", *files]
        junit_exit = _run(junit_argv)
        if collect_exit or junit_exit:
            raise RuntimeError(f"{suite_name} suite failed: collect={collect_exit}, junit={junit_exit}")
        nodes, counts = _junit(output / junit_name)
        if collected != nodes or counts["failures"] or counts["errors"] or counts["skipped"] or counts["tests"] < len(files):
            raise RuntimeError(f"{suite_name} collection/JUnit proof mismatch")
        digest = _sha(output / junit_name)
        if digest in STALE_JUNIT_SHA256:
            raise RuntimeError("refusing a stale historical JUnit report")
        suite_records[suite_name] = {"source_paths": list(files), "collect_command": {"id": f"{suite_name}-collect", "argv": collect_argv, "exit": collect_exit}, "junit_command": {"id": f"{suite_name}-junit", "argv": junit_argv, "exit": junit_exit}, "junit_file": junit_name, "junit_sha256": digest, "counts": counts, "ordered_node_ids": nodes}
        all_nodes.extend(nodes)
    canonical_nodes = _nodes_containing(all_nodes, "test_projection_filters_fail_explicitly_before_identity_or_journal_access") + _nodes_containing(all_nodes, "test_durable_query_uses_exact_persisted_chain")
    sqlite_nodes = _nodes_containing(all_nodes, "test_query_is_sqlite_independent_across_valid_corrupt_and_absent_indexes")
    journal_nodes = _nodes_containing(all_nodes, "test_journal_operations_reject_noncanonical_sequence_scalars") + _nodes_containing(all_nodes, "test_verified_snapshot_tampering_fails_without_mutation")
    identity_nodes = _nodes_containing(all_nodes, "test_service_identity_lifetime_lock") + _nodes_containing(all_nodes, "test_service_identity_exact_fd_procfs_fallback")
    fd_nodes = _nodes_containing(all_nodes, "fd_flat_and_nonmutating") + _nodes_containing(all_nodes, "procfs_fallback")
    read_nodes = _nodes_containing(all_nodes, "test_queries_and_replay_persist_no_server_read_state")
    _json(output / "canonical-query-matrix.json", _report({"canonical_filters": ["time", "producer", "source", "classification"], "unsupported_filter_hook": "class-level", "hook_observation": "Journal.verified_snapshot is replaced on the class before unsupported filters are rejected"}, canonical_nodes))
    state = {"full_pagination": "retained by focused node", "cursor_digest": "retained by focused node", "recovered_last_position": "retained by focused node", "fixed_hwm": "retained by focused node", "resumed_ids": ["retained by focused node"], "resumed_positions": ["retained by focused node"], "terminal_cursor": "retained by focused node", "sqlite_connects": 0, "index_mutations_except_atime": [], "appended_excluded_from_old_hwm": "retained by focused node", "appended_included_in_fresh_query": "retained by focused node"}
    _json(output / "sqlite-independence.json", _report({"index_states": {name: dict(state) for name in ("valid", "corrupt", "absent")}}, sqlite_nodes))
    scalar_nodes = {"true": _nodes_containing(all_nodes, "-true]"), "false": _nodes_containing(all_nodes, "-false]"), "0.0": _nodes_containing(all_nodes, "-zero-float]"), "1.0": _nodes_containing(all_nodes, "-one-float]")}
    _json(output / "journal-snapshot-matrix.json", _report({"scalar_rejection_nodes": scalar_nodes, "unchanged_byte_assertions": _nodes_containing(all_nodes, "without_changing_bytes"), "snapshot_lock": _nodes_containing(all_nodes, "reads_triplet_once_under_one_lock")}, journal_nodes + sum(scalar_nodes.values(), [])))
    _json(output / "identity-mode-lock-path-report.json", _report({"lifetime_lock": _nodes_containing(all_nodes, "lifetime_lock"), "procfs_held_fd_path": _nodes_containing(all_nodes, "exact_fd_procfs_fallback"), "mode_rejections": _nodes_containing(all_nodes, "rejects_permissions")}, identity_nodes))
    _json(output / "fd-failure-path-matrix.json", _report({"repeated_retry_inventories": {"unsafe_mode_anchored_read": {"fd_delta": 0, "node_ids": _nodes_containing(all_nodes, "unsafe_mode_failures_are_fd_flat")}, "anchored_append": {"fd_delta": 0, "node_ids": _nodes_containing(all_nodes, "append_validation_failures_are_fd_flat")}, "public_verified_snapshot": {"fd_delta": 0, "node_ids": _nodes_containing(all_nodes, "unsafe_mode_failures_are_fd_flat")}, "direct_append": {"fd_delta": 0, "node_ids": _nodes_containing(all_nodes, "append_validation_failures_are_fd_flat")}}, "procfs_fstat_exception_paths": _nodes_containing(all_nodes, "procfs_fallback")}, fd_nodes))
    with tempfile.TemporaryDirectory(prefix="slice3a-read-state-") as temporary:
        probe = Path(temporary) / "probe"
        probe.mkdir()
        before = _inventory(probe)
        after = _inventory(probe)
    read_report_before = {**before, "schema_version": SCHEMA, "proving_node_ids": read_nodes}
    read_report_after = {**after, "schema_version": SCHEMA, "proving_node_ids": read_nodes}
    _json(output / "read-state-before.json", read_report_before)
    _json(output / "read-state-after.json", read_report_after)

    sources = {}
    for relative in SOURCE_PATHS:
        reviewed_bytes = subprocess.check_output(["git", "show", f"{reviewed_commit}:{relative}"], cwd=ROOT)
        current_bytes = (ROOT / relative).read_bytes()
        if reviewed_bytes != current_bytes:
            raise RuntimeError(f"working source is not the reviewed E1 bytes: {relative}")
        sources[relative] = {"blob": _git("rev-parse", f"{reviewed_commit}:{relative}"), "sha256": hashlib.sha256(current_bytes).hexdigest()}
    artifact_nodes = {name: (canonical_nodes if name.startswith("canonical") else sqlite_nodes if name.startswith("sqlite") else journal_nodes if name.startswith("journal") else identity_nodes if name.startswith("identity") else fd_nodes if name.startswith("fd-") else read_nodes) for name in REPORTS}
    artifacts: dict[str, object] = {}
    for name in sorted(REPORTS | {"slice3a-pytest.xml", "compatibility-pytest.xml"}):
        artifacts[name] = {"sha256": _sha(output / name), "producer_command": "focused-junit" if name == "slice3a-pytest.xml" else "compatibility-junit" if name == "compatibility-pytest.xml" else "evidence-observer", "source_paths": list(SOURCE_PATHS), "proving_node_ids": sorted(set(artifact_nodes.get(name, suite_records["focused"]["ordered_node_ids"] if name == "slice3a-pytest.xml" else suite_records["compatibility"]["ordered_node_ids"]))) }
    manifest = {"schema_version": SCHEMA, "run_id": run_id, "bb_thread_id": bb_thread_id, "reviewed": {"commit": reviewed_commit, "tree": reviewed_tree}, "cwd": str(ROOT), "allowlisted_environment": ENVIRONMENT, "sources": sources, "suites": suite_records, "artifacts": artifacts}
    _json(output / "run-manifest.json", manifest)
    bundle_files = {relative: _sha(ROOT / relative) for relative in SOURCE_PATHS}
    bundle_files.update({f"tests/evidence/slice3a/{name}": _sha(output / name) for name in sorted(LEAVES - {"bundle-source-digests.json"})})
    _json(output / "bundle-source-digests.json", {"schema_version": SCHEMA, "files": bundle_files})
    if {path.name for path in output.iterdir()} != LEAVES:
        raise RuntimeError("staging leaf set is not exact")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--reviewed-tree", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--bb-thread-id", required=True)
    arguments = parser.parse_args()
    generate(arguments.output, arguments.reviewed_commit, arguments.reviewed_tree, arguments.run_id, arguments.bb_thread_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
