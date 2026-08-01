"""Create the retained Slice 3B test binding from one committed source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def _run(command: list[str]) -> str:
    return subprocess.check_output(command, text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    args = parser.parse_args()
    if _run(["git", "rev-parse", f"{args.source_commit}^{{tree}}"]) != args.source_tree:
        raise SystemExit("source commit does not name the supplied source tree")
    evidence = Path("tests/evidence/slice3b")
    evidence.mkdir(parents=True, exist_ok=True)
    junit = evidence / "slice3b-pytest.xml"
    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "tests/test_slice3b_service.py", f"--junitxml={junit}"]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return result.returncode
    suite = ET.parse(junit).getroot()
    tests = sum(int(item.attrib.get("tests", "0")) for item in suite.iter("testsuite"))
    failures = sum(int(item.attrib.get("failures", "0")) + int(item.attrib.get("errors", "0")) for item in suite.iter("testsuite"))
    manifest = {
        "schema_version": "houndd.slice3b.evidence.v1",
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
        "command": "PYTHONDONTWRITEBYTECODE=1 uv run pytest -p no:cacheprovider tests/test_slice3b_service.py",
        "tests": tests,
        "failures": failures,
        "junit_sha256": hashlib.sha256(junit.read_bytes()).hexdigest(),
        "source_files": {
            name: _run(["git", "show", f"{args.source_commit}:{name}"]).encode().hex()[:0] + hashlib.sha256(_run(["git", "show", f"{args.source_commit}:{name}"]).encode()).hexdigest()
            for name in ("pyproject.toml", "src/houndd/cli.py", "src/houndd/service.py", "src/hound_research/cli.py", "tests/test_slice3b_service.py", "tests/acceptance_slice3b.json")
        },
    }
    (evidence / "run-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
