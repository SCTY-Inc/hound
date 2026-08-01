#!/usr/bin/env python3
"""Build a reviewed Slice 3A candidate from staging-only pytest captures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from test_slice3a_evidence import JUNITS, LEAVES, REPORTS, ROOT, SCHEMA, STALE_JUNIT_SHA256, SUITE_FILES, source_paths, validate_bundle


ENVIRONMENT = {"PYTHONDONTWRITEBYTECODE": "1"}
MARKER = ".hound-slice3a-capture-owner.json"
RULES = {
    "canonical_query": "test_durable_query_uses_exact_persisted_chain",
    "unsupported_filter": "test_projection_filters_fail_explicitly",
    "sqlite_independence": "test_query_is_sqlite_independent",
    "cursor_restart": "test_fixed_hwm_cursor_resumes",
    "read_state": "test_queries_and_replay_persist_no_server_read_state",
    "journal_snapshot": "test_verified_snapshot_returns_exact_triplet",
    "journal_lock_order": "test_verified_snapshot_reads_triplet_once",
    "journal_reconcile": "test_verified_snapshot_is_non_repairing",
    "journal_tamper": "test_verified_snapshot_tampering",
    "journal_scalar": "test_journal_operations_reject_noncanonical_sequence_scalars",
    "fd_failure": ("test_verified_snapshot_unsafe_mode_failures", "test_journal_append_validation", "test_procfs_fstat_failures", "test_hsp20_anchored_leaf_validation", "test_hsp20_verify_store_closes"),
    "identity_lifetime": "test_service_identity_lifetime_lock",
    "identity_procfs": "test_service_identity_exact_fd_procfs_fallback",
    "identity_process_death": "test_service_identity_real_process_death_matrix",
    "identity_relocation": "test_service_identity_relocation_preserves",
}


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _run(argv: list[str], *, capture_dir: Path | None = None, capture_token: str | None = None) -> int:
    environment = {**os.environ, **ENVIRONMENT}
    if capture_dir is not None:
        environment["HOUND_SLICE3A_CAPTURE_DIR"] = str(capture_dir)
        assert capture_token is not None
        environment["HOUND_SLICE3A_CAPTURE_TOKEN"] = capture_token
    return subprocess.run(argv, cwd=ROOT, env=environment, check=False).returncode


def _collect(argv: list[str]) -> tuple[int, list[str]]:
    completed = subprocess.run(argv, cwd=ROOT, env={**os.environ, **ENVIRONMENT}, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return completed.returncode, [line for line in completed.stdout.splitlines() if line.startswith("tests/") and "::" in line]


def _junit(path: Path) -> tuple[list[str], dict[str, int]]:
    from xml.etree import ElementTree
    root = ElementTree.parse(path).getroot()
    nodes = [f"{case.attrib['classname'].replace('.', '/')}.py::{case.attrib['name']}" for case in root.iter("testcase")]
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    counts = {key: sum(int(suite.attrib.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
    if counts["tests"] != len(nodes) or len(nodes) != len(set(nodes)):
        raise RuntimeError("JUnit lost order or duplicated a node")
    return nodes, counts


def _owner(directory: Path) -> str:
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    token = secrets.token_hex(32)
    _json(directory / MARKER, {"schema": "houndd.slice3a.capture-owner.v1", "pid": os.getpid(), "token": token})
    (directory / MARKER).chmod(0o600)
    return token


def _fragments(directory: Path, focused_nodes: list[str]) -> dict[str, list[dict[str, Any]]]:
    fragments: dict[str, list[dict[str, Any]]] = {name: [] for name in RULES}
    expected: set[tuple[str, str]] = set()
    for observation, rule in RULES.items():
        patterns = (rule,) if type(rule) is str else rule
        for node in focused_nodes:
            if any(pattern in node for pattern in patterns):
                expected.add((node, observation))
    seen: set[tuple[str, str]] = set()
    for path in directory.iterdir():
        if path.name == MARKER:
            continue
        if not path.is_file() or path.is_symlink() or path.suffix != ".json":
            raise RuntimeError("unsafe capture leaf")
        value = json.loads(path.read_bytes())
        if type(value) is not dict or set(value) != {"schema_version", "node_id", "observation", "value"} or value["schema_version"] != "houndd.slice3a.capture.v1":
            raise RuntimeError("malformed capture fragment")
        node, observation = value["node_id"], value["observation"]
        if type(node) is not str or type(observation) is not str or (node, observation) not in expected or (node, observation) in seen:
            raise RuntimeError("unexpected, unrelated, or duplicate capture fragment")
        seen.add((node, observation))
        fragments[observation].append(value)
    if seen != expected:
        missing = sorted(expected - seen)
        raise RuntimeError(f"missing exact capture fragments: {missing[:3]}")
    return fragments


def _report(observations: dict[str, object], fragments: list[dict[str, Any]]) -> dict[str, object]:
    return {"schema_version": SCHEMA, "observations": observations, "proving_node_ids": sorted(fragment["node_id"] for fragment in fragments)}


def generate(output: Path, reviewed_commit: str, reviewed_tree: str, run_id: str, bb_thread_id: str) -> None:
    output = output.resolve()
    retained = ROOT / "tests" / "evidence" / "slice3a"
    if output == retained or retained in output.parents or output.exists() and any(output.iterdir()):
        raise RuntimeError("output must be a fresh staging directory, never retained evidence")
    if type(run_id) is not str or str(uuid.UUID(run_id)) != run_id:
        raise RuntimeError("run id must be canonical UUID text")
    if type(bb_thread_id) is not str or not re.fullmatch(r"thr_[a-z0-9]+", bb_thread_id):
        raise RuntimeError("invalid BB thread id")
    if _git("rev-parse", f"{reviewed_commit}^{{tree}}") != reviewed_tree:
        raise RuntimeError("reviewed commit/tree mismatch")
    output.mkdir(mode=0o700, parents=True)
    output.chmod(0o700)
    python = sys.executable
    suites: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="hound-slice3a-capture-") as temporary:
        capture_dir = Path(temporary) / "capture"
        capture_token = _owner(capture_dir)
        for suite_name, files in SUITE_FILES.items():
            junit_name = "slice3a-pytest.xml" if suite_name == "focused" else "compatibility-pytest.xml"
            collect_argv = [python, "-m", "pytest", "--collect-only", "-q", *files]
            collect_exit, collected = _collect(collect_argv)
            junit_argv = [python, "-m", "pytest", "-p", "no:cacheprovider", f"--junitxml={output / junit_name}", *files]
            junit_exit = _run(junit_argv, capture_dir=capture_dir if suite_name == "focused" else None, capture_token=capture_token if suite_name == "focused" else None)
            if collect_exit or junit_exit:
                raise RuntimeError(f"{suite_name} suite failed")
            nodes, counts = _junit(output / junit_name)
            if collected != nodes or any(counts[key] for key in ("failures", "errors", "skipped")) or counts["tests"] != len(nodes):
                raise RuntimeError("collection/JUnit exactness failure")
            digest = _sha(output / junit_name)
            if digest in STALE_JUNIT_SHA256:
                raise RuntimeError("stale JUnit digest")
            suites[suite_name] = {"source_paths": list(files), "collect_command": {"id": f"{suite_name}-collect", "argv": collect_argv, "exit": collect_exit}, "junit_command": {"id": f"{suite_name}-junit", "argv": junit_argv, "exit": junit_exit}, "junit_file": junit_name, "junit_sha256": digest, "counts": counts, "ordered_node_ids": nodes}
        fragments = _fragments(capture_dir, suites["focused"]["ordered_node_ids"])  # type: ignore[arg-type]

    value = lambda name: [fragment["value"] for fragment in fragments[name]]
    focused = [fragment for group in fragments.values() for fragment in group]
    canonical_values = value("canonical_query")[0]
    _json(output / "canonical-query-matrix.json", _report({"requests": canonical_values["requests"], "unsupported": value("unsupported_filter")}, fragments["canonical_query"] + fragments["unsupported_filter"]))
    sqlite_values = value("sqlite_independence")[0]
    _json(output / "sqlite-independence.json", _report(sqlite_values, fragments["sqlite_independence"]))
    _json(output / "cursor-restart-hwm.json", _report(value("cursor_restart")[0], fragments["cursor_restart"]))
    read = value("read_state")[0]
    for name in ("read-state-before.json", "read-state-after.json"):
        _json(output / name, _report(read, fragments["read_state"]))
    _json(output / "journal-snapshot-matrix.json", _report({"snapshot": value("journal_snapshot")[0], "lock_order": value("journal_lock_order")[0], "scalars": value("journal_scalar")}, fragments["journal_snapshot"] + fragments["journal_lock_order"] + fragments["journal_scalar"]))
    _json(output / "recovery-vs-verification.json", _report({"reconcile": value("journal_reconcile")[0], "tamper": value("journal_tamper")}, fragments["journal_reconcile"] + fragments["journal_tamper"]))
    _json(output / "fd-failure-path-matrix.json", _report({"paths": value("fd_failure")}, fragments["fd_failure"]))
    _json(output / "identity-mode-lock-path-report.json", _report({"lifetime": value("identity_lifetime")[0], "procfs": value("identity_procfs")}, fragments["identity_lifetime"] + fragments["identity_procfs"]))
    _json(output / "identity-crash-matrix.json", _report({"matrix": value("identity_process_death")}, fragments["identity_process_death"]))
    _json(output / "identity-transition-report.json", _report({"procfs": value("identity_procfs")}, fragments["identity_procfs"]))
    _json(output / "restore-portability-manifest.json", _report(value("identity_relocation")[0], fragments["identity_relocation"]))

    paths = source_paths(reviewed_commit)
    sources: dict[str, object] = {}
    for relative in paths:
        reviewed_bytes = subprocess.check_output(["git", "show", f"{reviewed_commit}:{relative}"], cwd=ROOT)
        if reviewed_bytes != (ROOT / relative).read_bytes():
            raise RuntimeError(f"working tree does not match reviewed source: {relative}")
        sources[relative] = {"blob": _git("rev-parse", f"{reviewed_commit}:{relative}"), "sha256": hashlib.sha256(reviewed_bytes).hexdigest()}
    artifacts = {}
    for name in sorted(REPORTS | JUNITS):
        producer = "focused-junit" if name == "slice3a-pytest.xml" else "compatibility-junit" if name == "compatibility-pytest.xml" else "evidence-observer"
        report_nodes = suites["focused"]["ordered_node_ids"] if name == "slice3a-pytest.xml" else suites["compatibility"]["ordered_node_ids"] if name == "compatibility-pytest.xml" else _load_report_nodes(output / name)
        artifacts[name] = {"sha256": _sha(output / name), "producer_command": producer, "source_paths": list(paths), "proving_node_ids": sorted(report_nodes)}
    manifest = {"schema_version": SCHEMA, "run_id": run_id, "bb_thread_id": bb_thread_id, "reviewed": {"commit": reviewed_commit, "tree": reviewed_tree}, "cwd": str(ROOT), "allowlisted_environment": ENVIRONMENT, "sources": sources, "suites": suites, "artifacts": artifacts}
    _json(output / "run-manifest.json", manifest)
    bundle = {relative: _sha(ROOT / relative) for relative in paths}
    bundle.update({f"tests/evidence/slice3a/{name}": _sha(output / name) for name in sorted(LEAVES - {"bundle-source-digests.json"})})
    _json(output / "bundle-source-digests.json", {"schema_version": SCHEMA, "files": bundle})
    if {path.name for path in output.iterdir()} != LEAVES:
        raise RuntimeError("candidate leaf set is not exact")
    validate_bundle(output)


def _load_report_nodes(path: Path) -> list[str]:
    value = json.loads(path.read_bytes())
    return value["proving_node_ids"]


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
