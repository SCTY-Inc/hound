"""Regression tests for the independent Slice 3B retained-evidence verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from tests.verify_slice3b_evidence import EvidenceError, verify


def _run(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repository, text=True).strip()


def _candidate(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "source.txt").write_bytes(b"raw source bytes\n")
    _run(repository, "init", "-q", "-b", "main")
    _run(repository, "config", "user.name", "evidence test")
    _run(repository, "config", "user.email", "evidence@example.invalid")
    _run(repository, "add", "source.txt")
    _run(repository, "commit", "-q", "-m", "source")
    commit = _run(repository, "rev-parse", "HEAD")
    tree = _run(repository, "rev-parse", "HEAD^{tree}")
    raw = (repository / "source.txt").read_bytes()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    junit = b'<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="tests.example" name="test_node"/></testsuite></testsuites>'
    (evidence / "slice3b-pytest.xml").write_bytes(junit)
    manifest = {
        "schema_version": "houndd.slice3b.evidence.v2",
        "run_id": "slice3b-12345678-1234-1234-1234-123456789abc",
        "bb_thread_id": "thr_test",
        "source": {"commit": commit, "tree": tree},
        "argv": ["python", "-m", "pytest", "--junitxml=tests/evidence/slice3b/slice3b-pytest.xml"],
        "source_files": {"source.txt": {"blob": _run(repository, "rev-parse", f"{commit}:source.txt"), "sha256": hashlib.sha256(raw).hexdigest()}},
        "junit": {"path": "tests/evidence/slice3b/slice3b-pytest.xml", "sha256": hashlib.sha256(junit).hexdigest(), "node_ids": ["tests.example::test_node"]},
        "observations": {
            "protocol": {"wire_version": "houndd.uds.v1", "logical_statuses": [200, 400, 404, 503], "one_request_per_connection": True},
            "framing": {"recoverable_id_400_cases": 4, "unrecoverable_id_response_cases": 0, "fragment_reads_are_linear": True},
            "policy": {"held_fd": True, "replacement_fails_closed": True, "one_policy_no_union": True},
            "socket": {"preexisting_socket_refused": True, "replacement_cleanup_refused": True, "transport": "AF_UNIX/SOCK_STREAM"},
        },
    }
    (evidence / "run-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    return repository, evidence


def test_slice3b_verifier_binds_raw_git_bytes_blobs_junit_and_typed_observations(tmp_path: Path) -> None:
    repository, evidence = _candidate(tmp_path)
    verify(evidence, repository)
    manifest_path = evidence / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_files"]["source.txt"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceError, match="raw Git binding"):
        verify(evidence, repository)
