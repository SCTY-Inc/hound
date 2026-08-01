"""Adversarial tests for the non-weakening archival Slice 3A wrapper."""

from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess
import sys

import pytest

from tests.verify_slice3a_historical import HistoricalEvidenceError, ROOT, verify_historical


def _copy(tmp_path: Path) -> Path:
    candidate = tmp_path / "slice3a"
    shutil.copytree(ROOT / "tests" / "evidence" / "slice3a", candidate)
    return candidate


def test_historical_wrapper_accepts_later_source_evolution() -> None:
    verify_historical()


@pytest.mark.parametrize("leaf", ["run-manifest.json", "slice3a-pytest.xml"])
def test_historical_wrapper_rejects_any_retained_byte_mutation(tmp_path: Path, leaf: str) -> None:
    candidate = _copy(tmp_path)
    path = candidate / leaf
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(HistoricalEvidenceError, match="retained"):
        verify_historical(candidate)


def test_historical_wrapper_rejects_missing_or_extra_leaf(tmp_path: Path) -> None:
    candidate = _copy(tmp_path)
    (candidate / "run-manifest.json").unlink()
    with pytest.raises(HistoricalEvidenceError, match="leaves"):
        verify_historical(candidate)
    candidate = _copy(tmp_path / "second")
    (candidate / "unexpected.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(HistoricalEvidenceError, match="leaves"):
        verify_historical(candidate)


@pytest.mark.parametrize("mutation", ["reviewed", "source-entry"])
def test_historical_wrapper_rejects_manifest_reseal_attempts(tmp_path: Path, mutation: str) -> None:
    candidate = _copy(tmp_path)
    path = candidate / "run-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "reviewed":
        manifest["reviewed"] = {"commit": "0" * 40, "tree": "0" * 40}
    else:
        del manifest["sources"]["pyproject.toml"]
    path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(HistoricalEvidenceError, match="retained"):
        verify_historical(candidate)


def test_historical_wrapper_rejects_altered_checkout_checker(tmp_path: Path) -> None:
    from tests.verify_slice3a_historical import _historical_module

    checkout = tmp_path / "checkout"
    checker = checkout / "tests" / "test_slice3a_evidence.py"
    checker.parent.mkdir(parents=True)
    checker.write_text("raise RuntimeError('tampered')\n", encoding="utf-8")
    with pytest.raises(HistoricalEvidenceError, match="checker bytes"):
        _historical_module(checkout, tmp_path / "evidence", {})


def test_default_collection_uses_historical_wrapper_not_legacy_checker() -> None:
    result = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"], cwd=ROOT, capture_output=True, text=True, check=True)
    assert "tests/test_slice3a_historical_evidence.py::test_historical_wrapper_accepts_later_source_evolution" in result.stdout
    assert "tests/test_slice3a_evidence.py::test_slice3a_retained_evidence_is_a_complete_e2_seal" not in result.stdout


def test_historical_wrapper_fails_closed_without_pinned_history(tmp_path: Path) -> None:
    repository = tmp_path / "empty"
    repository.mkdir()
    import subprocess
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
    with pytest.raises(HistoricalEvidenceError, match="pinned"):
        verify_historical(ROOT / "tests" / "evidence" / "slice3a", repository)
