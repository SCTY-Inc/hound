"""Run the retained Slice 3A seal with its exact historical source checkout."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import types
from typing import Any


ROOT = Path(__file__).parents[1].resolve()
REVIEWED_COMMIT = "7737cb09c6b7528468ec8d96b887b7e548b26adc"
REVIEWED_TREE = "7d8d3fc1ae5ae7bc8439b8bfd8beaa672edec029"
CHECKER_PATH = "tests/test_slice3a_evidence.py"
CHECKER_BLOB = "bceab6e8c726db53c2d09262891cdeafdc4bc041"
RETENTION_COMMIT = "4f6bb1ca904c7778df6a78cd05491dbb1092498e"
EVIDENCE_PREFIX = "tests/evidence/slice3a"
EVIDENCE_TREE = "d931c731ff2d4ab77c826efc0750a6bfc0affd77"


class HistoricalEvidenceError(ValueError):
    pass


def _git(repository: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.check_output(["git", *args], cwd=repository)
    return result.decode().strip() if text else result


def _require(value: bool, message: str) -> None:
    if not value:
        raise HistoricalEvidenceError(message)


def _retained_files(repository: Path) -> dict[str, str]:
    try:
        listing = _git(repository, "ls-tree", "-r", "--full-tree", RETENTION_COMMIT, "--", EVIDENCE_PREFIX)
    except subprocess.CalledProcessError as error:
        raise HistoricalEvidenceError("pinned retention commit is unavailable") from error
    result: dict[str, str] = {}
    for line in str(listing).splitlines():
        metadata, path = line.split("\t", 1)
        _mode, kind, blob = metadata.split()
        _require(kind == "blob" and path.startswith(f"{EVIDENCE_PREFIX}/"), "retained evidence tree is malformed")
        result[path.removeprefix(f"{EVIDENCE_PREFIX}/")] = blob
    _require(result and _git(repository, "rev-parse", f"{RETENTION_COMMIT}:{EVIDENCE_PREFIX}") == EVIDENCE_TREE, "retained evidence subtree binding is false")
    return result


def _verify_retained_bytes(evidence: Path, repository: Path) -> dict[str, Any]:
    expected = _retained_files(repository)
    _require(evidence.is_dir() and not evidence.is_symlink(), "retained evidence directory is unavailable")
    actual_paths = {path.relative_to(evidence).as_posix() for path in evidence.rglob("*")}
    _require(actual_paths == set(expected), "retained evidence leaves differ from the pinned subtree")
    for relative in expected:
        path = evidence / relative
        _require(path.is_file() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), f"retained leaf is unsafe: {relative}")
        pinned = _git(repository, "show", f"{RETENTION_COMMIT}:{EVIDENCE_PREFIX}/{relative}", text=False)
        _require(path.read_bytes() == pinned, f"retained bytes differ: {relative}")
    raw_manifest = (evidence / "run-manifest.json").read_bytes()
    _require(raw_manifest == _git(repository, "show", f"{RETENTION_COMMIT}:{EVIDENCE_PREFIX}/run-manifest.json", text=False), "retained manifest bytes differ")
    try:
        manifest = json.loads(raw_manifest)
    except ValueError as error:
        raise HistoricalEvidenceError("retained manifest is not JSON") from error
    _require(type(manifest) is dict and manifest.get("reviewed") == {"commit": REVIEWED_COMMIT, "tree": REVIEWED_TREE}, "retained manifest reviewed binding is false")
    source = manifest.get("sources", {})
    checker = source.get(CHECKER_PATH) if type(source) is dict else None
    raw_checker = _git(repository, "show", f"{REVIEWED_COMMIT}:{CHECKER_PATH}", text=False)
    _require(type(checker) is dict and checker == {"blob": CHECKER_BLOB, "sha256": hashlib.sha256(raw_checker).hexdigest()}, "retained checker binding is false")
    return manifest


def _historical_module(checkout: Path, evidence: Path, manifest: dict[str, Any]) -> None:
    checker = checkout / CHECKER_PATH
    _require(_git(checkout, "hash-object", checker) == CHECKER_BLOB, "historical checker bytes differ")
    spec = importlib.util.spec_from_file_location("_hound_slice3a_historical_checker", checker)
    _require(spec is not None and spec.loader is not None, "historical checker cannot be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = checkout
    module.EVIDENCE = evidence
    original_load = module._load

    def location_neutral_load(path: Path, *, canonical: bool = True):
        value = original_load(path, canonical=canonical)
        if path == evidence / "run-manifest.json":
            value = dict(value)
            value["cwd"] = str(checkout)
        return value

    module._load = location_neutral_load
    python = manifest["suites"]["focused"]["collect_command"]["argv"][0]
    module.sys = types.SimpleNamespace(executable=python)
    module.validate_bundle(evidence)


def verify_historical(evidence: Path = ROOT / EVIDENCE_PREFIX, repository: Path = ROOT) -> None:
    """Verify immutable retention, then execute the pinned historical checker."""

    try:
        try:
            reviewed_tree = _git(repository, "rev-parse", f"{REVIEWED_COMMIT}^{{tree}}")
            checker_blob = _git(repository, "rev-parse", f"{REVIEWED_COMMIT}:{CHECKER_PATH}")
        except subprocess.CalledProcessError as error:
            raise HistoricalEvidenceError("pinned reviewed history is unavailable") from error
        _require(reviewed_tree == REVIEWED_TREE, "pinned reviewed tree is unavailable or false")
        _require(checker_blob == CHECKER_BLOB, "pinned historical checker blob is unavailable or false")
        manifest = _verify_retained_bytes(evidence, repository)
        with tempfile.TemporaryDirectory(prefix="hound-slice3a-historical-") as temporary:
            checkout = Path(temporary) / "checkout"
            subprocess.run(["git", "clone", "--shared", "--no-checkout", str(repository), str(checkout)], check=True, capture_output=True, text=True)
            subprocess.run(["git", "checkout", "--detach", REVIEWED_COMMIT], cwd=checkout, check=True, capture_output=True, text=True)
            target = checkout / EVIDENCE_PREFIX
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(evidence, target, copy_function=shutil.copy2)
            _historical_module(checkout, target, manifest)
    except (OSError, subprocess.CalledProcessError, HistoricalEvidenceError) as error:
        if isinstance(error, HistoricalEvidenceError):
            raise
        raise HistoricalEvidenceError("historical Slice 3A verification failed closed") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=ROOT / EVIDENCE_PREFIX)
    parser.add_argument("--repository", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        verify_historical(args.evidence, args.repository)
    except HistoricalEvidenceError as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
