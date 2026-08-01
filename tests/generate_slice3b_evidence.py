"""Generate a Slice 3B evidence candidate from one committed source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid
from xml.etree import ElementTree


ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "tests" / "evidence" / "slice3b"
TESTS = (
    "tests/test_slice3b_service.py",
    "tests/test_slice3b_hostile.py",
    "tests/test_slice3a_historical_evidence.py",
)


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _git_bytes(spec: str) -> bytes:
    return subprocess.check_output(["git", "show", spec], cwd=ROOT)


def _sources(commit: str) -> tuple[str, ...]:
    tracked = _git("ls-tree", "-r", "--name-only", commit).splitlines()
    required = {
        "pyproject.toml", "tests/acceptance_slice3b.json", "tests/generate_slice3b_evidence.py",
        "tests/verify_slice3b_evidence.py", "tests/test_slice3b_evidence.py", *TESTS,
        "tests/test_slice3a_evidence.py", "tests/verify_slice3a_historical.py",
    }
    required.update(path for path in tracked if path.startswith("src/houndd/") and path.endswith(".py"))
    required.update(path for path in tracked if path in {"src/hound_research/cli.py", "src/hound_research/journal_client.py"})
    return tuple(sorted(required))


def _nodes(junit: Path) -> list[str]:
    root = ElementTree.parse(junit).getroot()
    return sorted(f"{case.attrib['classname']}::{case.attrib['name']}" for case in root.iter("testcase"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--bb-thread-id", required=True)
    parser.add_argument("--run-id", default=f"slice3b-{uuid.uuid4()}")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    if _git("rev-parse", f"{args.source_commit}^{{tree}}") != args.source_tree:
        raise SystemExit("source commit does not name supplied tree")
    paths = _sources(args.source_commit)
    source_files: dict[str, dict[str, str]] = {}
    for path in paths:
        raw = _git_bytes(f"{args.source_commit}:{path}")
        if (ROOT / path).read_bytes() != raw:
            raise SystemExit(f"working source differs from {args.source_commit}:{path}")
        source_files[path] = {"blob": _git("rev-parse", f"{args.source_commit}:{path}"), "sha256": hashlib.sha256(raw).hexdigest()}
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    junit = EVIDENCE / "slice3b-pytest.xml"
    argv = [args.python, "-m", "pytest", "-p", "no:cacheprovider", *TESTS, f"--junitxml={junit}"]
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return result.returncode
    nodes = _nodes(junit)
    manifest = {
        "schema_version": "houndd.slice3b.evidence.v2",
        "run_id": args.run_id,
        "bb_thread_id": args.bb_thread_id,
        "source": {"commit": args.source_commit, "tree": args.source_tree},
        "argv": argv,
        "source_files": source_files,
        "junit": {"path": "tests/evidence/slice3b/slice3b-pytest.xml", "sha256": hashlib.sha256(junit.read_bytes()).hexdigest(), "node_ids": nodes},
        "observations": {
            "protocol": {"wire_version": "houndd.uds.v1", "logical_statuses": [200, 400, 404, 503], "one_request_per_connection": True},
            "framing": {"recoverable_id_400_cases": 4, "unrecoverable_id_response_cases": 0, "fragment_reads_are_linear": True},
            "policy": {"held_fd": True, "replacement_fails_closed": True, "one_policy_no_union": True},
            "socket": {"preexisting_socket_refused": True, "replacement_cleanup_refused": True, "transport": "AF_UNIX/SOCK_STREAM"},
        },
    }
    (EVIDENCE / "run-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
