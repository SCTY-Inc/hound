"""Independent, non-generating verifier for a retained Slice 3B attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from xml.etree import ElementTree


ROOT = Path(__file__).parents[1]
_RUN_ID = re.compile(r"slice3b-[0-9a-f-]{36}\Z")


class EvidenceError(ValueError):
    pass


def _fail(message: str) -> None:
    raise EvidenceError(message)


def _git_bytes(repository: Path, spec: str) -> bytes:
    return subprocess.check_output(["git", "show", spec], cwd=repository)


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repository, text=True).strip()


def verify(evidence: Path, repository: Path = ROOT) -> None:
    try:
        manifest = json.loads((evidence / "run-manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise EvidenceError("manifest is unavailable or invalid JSON") from error
    required = {"schema_version", "run_id", "bb_thread_id", "source", "argv", "source_files", "junit", "observations"}
    if type(manifest) is not dict or set(manifest) != required or manifest["schema_version"] != "houndd.slice3b.evidence.v2":
        _fail("manifest schema is not exact")
    if type(manifest["run_id"]) is not str or _RUN_ID.fullmatch(manifest["run_id"]) is None or type(manifest["bb_thread_id"]) is not str or not manifest["bb_thread_id"].startswith("thr_"):
        _fail("run identity is invalid")
    source = manifest["source"]
    if type(source) is not dict or set(source) != {"commit", "tree"} or any(type(source[key]) is not str for key in source):
        _fail("source binding is invalid")
    if _git(repository, "rev-parse", f"{source['commit']}^{{tree}}") != source["tree"]:
        _fail("source commit/tree binding is false")
    if type(manifest["argv"]) is not list or not all(type(item) is str and item for item in manifest["argv"]) or "--junitxml=" not in " ".join(manifest["argv"]):
        _fail("exact argv is invalid")
    files = manifest["source_files"]
    if type(files) is not dict or list(files) != sorted(files) or not files:
        _fail("source file binding set is invalid")
    for path, binding in files.items():
        if type(path) is not str or type(binding) is not dict or set(binding) != {"blob", "sha256"}:
            _fail("source file binding shape is invalid")
        raw = _git_bytes(repository, f"{source['commit']}:{path}")
        if _git(repository, "rev-parse", f"{source['commit']}:{path}") != binding["blob"] or hashlib.sha256(raw).hexdigest() != binding["sha256"]:
            _fail(f"raw Git binding failed for {path}")
    junit = manifest["junit"]
    if type(junit) is not dict or set(junit) != {"path", "sha256", "node_ids"} or junit["path"] != "tests/evidence/slice3b/slice3b-pytest.xml":
        _fail("JUnit binding shape is invalid")
    junit_path = evidence / "slice3b-pytest.xml"
    if hashlib.sha256(junit_path.read_bytes()).hexdigest() != junit["sha256"]:
        _fail("JUnit hash is false")
    root = ElementTree.parse(junit_path).getroot()
    nodes = sorted(f"{case.attrib.get('classname', '')}::{case.attrib.get('name', '')}" for case in root.iter("testcase"))
    if not nodes or nodes != junit["node_ids"] or len(nodes) != len(set(nodes)):
        _fail("JUnit node IDs are incomplete")
    if any(case.find("failure") is not None or case.find("error") is not None or case.find("skipped") is not None for case in root.iter("testcase")):
        _fail("JUnit records a non-passing node")
    observations = manifest["observations"]
    if type(observations) is not dict or set(observations) != {"protocol", "framing", "policy", "socket"}:
        _fail("typed observations are incomplete")
    if observations["protocol"] != {"wire_version": "houndd.uds.v1", "logical_statuses": [200, 400, 404, 503], "one_request_per_connection": True}:
        _fail("protocol observation is invalid")
    if observations["framing"] != {"recoverable_id_400_cases": 4, "unrecoverable_id_response_cases": 0, "fragment_reads_are_linear": True}:
        _fail("framing observation is invalid")
    if observations["policy"] != {"held_fd": True, "replacement_fails_closed": True, "one_policy_no_union": True}:
        _fail("policy observation is invalid")
    if observations["socket"] != {"preexisting_socket_refused": True, "replacement_cleanup_refused": True, "transport": "AF_UNIX/SOCK_STREAM"}:
        _fail("socket observation is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=ROOT / "tests" / "evidence" / "slice3b")
    parser.add_argument("--repository", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        verify(args.evidence, args.repository)
    except EvidenceError as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
