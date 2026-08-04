"""Adversarial regression tests for the independent Slice 3C1 verifier."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree

import pytest

from tests.generate_slice3c1_evidence import (
    EvidenceError as GeneratorEvidenceError,
    GIT_ENVIRONMENT,
    TESTS as GENERATOR_TESTS,
    _git_argv,
    generate,
    source_paths as generator_source_paths,
)
from tests.verify_slice3c1_evidence import EvidenceError, TESTS, _source_paths, verify


RUN_ID = "slice3c1-12345678-1234-1234-1234-123456789abc"
THREAD_ID = "thr_gz1v0adzhc"
OBSERVATION_NODE = "tests/test_slice3c1_observations.py::test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner"
OBSERVATION_PROPERTY = "hound.slice3c1.observation"
SUPPORT_FILES = {
    "README.md",
    "LICENSE.md",
    "src/hound_fake_support/__init__.py",
    "src/hound_fake_support/resource.txt",
}


def _run(repository: Path, *args: str) -> str:
    return subprocess.check_output(_git_argv(*args), cwd=repository, env=GIT_ENVIRONMENT, text=True).strip()


def _write(repository: Path, relative: str, data: bytes = b"pass\n") -> None:
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _observation_source() -> bytes:
    return (
        "import json\n"
        "NODE = 'tests/test_slice3c1_observations.py::test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner'\n"
        "PAYLOAD = {'schema_version':'houndd.slice3c1.live-observations.v1','named_tests':[NODE],'producer':{'node_id':NODE,'classname':'tests.test_slice3c1_observations','name':'test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner'},'wire':{'version':'houndd.uds.v1','encoded_json_limit':1048576}}\n"
        "OBSERVATION = json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        item.user_properties.append(('hound.slice3c1.nodeid', item.nodeid))\n"
        "        if item.nodeid == NODE:\n"
        "            item.user_properties.append(('hound.slice3c1.observation', OBSERVATION))\n"
        "def test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner():\n"
        "    assert OBSERVATION == json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))\n"
    ).encode()


def _candidate(tmp_path: Path) -> tuple[Path, Path, str, str]:
    repository = tmp_path / "repo"
    repository.mkdir()
    required = {
        "pyproject.toml", "uv.lock", "tests/acceptance_slice3c1.json",
        "tests/generate_slice3c1_evidence.py", "tests/verify_slice3c1_evidence.py",
        *TESTS,
    }
    for relative in required | SUPPORT_FILES:
        _write(repository, relative)
    _write(repository, "pyproject.toml", b"")
    _write(repository, "tests/test_slice3c1_service_authz.py", b"def test_node():\n    pass\n")
    _write(repository, "tests/test_slice3c1_commit_runtime.py", b"def test_other_node():\n    pass\n")
    _write(repository, "tests/test_slice3c1_contract_source_phi.py", b"def test_later():\n    pass\n")
    _write(repository, "tests/test_slice3c1_observations.py", _observation_source())
    _write(repository, "tests/test_slice3c1_evidence.py", b"def test_final_evidence():\n    pass\n")
    _run(repository, "init", "-q", "-b", "main")
    _run(repository, "config", "user.name", "evidence test")
    _run(repository, "config", "user.email", "evidence@example.invalid")
    _run(repository, "add", ".")
    _run(repository, "commit", "-q", "-m", "source")
    commit = _run(repository, "rev-parse", "HEAD")
    tree = _run(repository, "rev-parse", "HEAD^{tree}")
    evidence = tmp_path / "evidence"
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=evidence, python=sys.executable, repository=repository)
    return repository, evidence, commit, tree


def _verify(repository: Path, evidence: Path, commit: str, tree: str) -> None:
    verify(evidence, repository, expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, expected_python=sys.executable)


def _manifest(evidence: Path) -> dict[str, object]:
    return json.loads((evidence / "run-manifest.json").read_text(encoding="utf-8"))


def _save(evidence: Path, manifest: dict[str, object]) -> None:
    (evidence / "run-manifest.json").write_bytes(json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _replace_resealed_artifact(evidence: Path, artifact: str, value: object) -> None:
    raw = _canonical(value)
    (evidence / artifact).write_bytes(raw)
    manifest = _manifest(evidence)
    binding = "collection" if artifact == "slice3c1-collection.json" else "observations"
    manifest[binding]["sha256"] = hashlib.sha256(raw).hexdigest()
    _save(evidence, manifest)


def test_verifier_binds_isolated_source_argv_nodes_and_typed_observations(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    _verify(repository, evidence, commit, tree)


def test_test_files_match_between_generator_and_verifier() -> None:
    assert GENERATOR_TESTS == TESTS
    assert "tests/test_slice3c1_evidence.py" in TESTS
    assert "tests/test_slice3c1_observations.py" in TESTS


def test_source_closure_is_every_tracked_regular_source_and_python_test_file(tmp_path: Path) -> None:
    repository, _evidence, commit, _tree = _candidate(tmp_path)
    tracked = _run(repository, "ls-tree", "-r", "--name-only", commit).splitlines()
    expected = tuple(sorted({
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE.md",
        "tests/acceptance_slice3c1.json",
        *(path for path in tracked if path.startswith("src/") or (path.startswith("tests/") and path.endswith(".py"))),
    }))
    assert generator_source_paths(repository, commit) == expected
    assert _source_paths(repository, commit) == expected


@pytest.mark.parametrize("value", [False, 0.0, -0.0, True, 1])
def test_verifier_rejects_resealed_non_exact_collection_exit_code(tmp_path: Path, value: object) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    collection_path = evidence / "slice3c1-collection.json"
    collection = json.loads(collection_path.read_text(encoding="utf-8"))
    collection["exit_code"] = value
    _replace_resealed_artifact(evidence, collection_path.name, collection)

    with pytest.raises(EvidenceError, match="collection exit code"):
        _verify(repository, evidence, commit, tree)


def test_verifier_rejects_noncanonical_junit_counter_after_reseal(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit_path = evidence / "slice3c1-pytest.xml"
    root = ElementTree.parse(junit_path).getroot()
    suite = root.find("./testsuite")
    assert suite is not None
    suite.attrib["failures"] = "00"
    junit_path.write_bytes(ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))
    manifest = _manifest(evidence)
    manifest["junit"]["sha256"] = hashlib.sha256(junit_path.read_bytes()).hexdigest()
    _save(evidence, manifest)

    with pytest.raises(EvidenceError, match="JUnit failures counter"):
        _verify(repository, evidence, commit, tree)


def test_generator_runs_the_exact_commit_in_an_isolated_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository, _evidence, commit, tree = _candidate(tmp_path)
    _write(repository, "tests/test_slice3c1_service_authz.py", b"raise RuntimeError('dirty worktree must not execute')\n")
    generated = tmp_path / "generated"
    monkeypatch.setenv("PYTEST_ADDOPTS", "--ambient-option-must-not-reach-pytest")
    monkeypatch.setenv("PYTEST_PLUGINS", "ambient_plugin_must_not_load")
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=generated, python=sys.executable, repository=repository)
    _verify(repository, generated, commit, tree)


def test_generator_and_verifier_ignore_malicious_ambient_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    fake = tmp_path / "malicious-bin" / "git"
    sentinel = tmp_path / "ambient-git-ran"
    _write(tmp_path, "malicious-bin/git", f'#!/bin/sh\n: > "{sentinel}"\nexit 97\n'.encode())
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", os.fspath(fake.parent))
    generated = tmp_path / "ambient-generated"
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=generated, python=sys.executable, repository=repository)
    _verify(repository, evidence, commit, tree)
    _verify(repository, generated, commit, tree)
    assert not sentinel.exists()


def test_verifier_rejects_duplicate_manifest_and_collection_keys(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    manifest = _manifest(evidence)
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).replace(
        f'"run_id":"{RUN_ID}"', f'"run_id":"{RUN_ID}","run_id":"{RUN_ID}"', 1
    ).encode() + b"\n"
    (evidence / "run-manifest.json").write_bytes(manifest_bytes)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("artifact", ["run-manifest.json", "slice3c1-collection.json", "observations.json"])
def test_verifier_rejects_noncanonical_json_whitespace_after_reseal(tmp_path: Path, artifact: str) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    path = evidence / artifact
    value = json.loads(path.read_text(encoding="utf-8"))
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path.write_bytes(raw)
    if artifact != "run-manifest.json":
        manifest = _manifest(evidence)
        manifest["collection" if artifact.startswith("slice3c1-collection") else "observations"]["sha256"] = hashlib.sha256(raw).hexdigest()
        _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("mutation", ["argv", "node", "source", "observation", "run", "thread", "interpreter", "git"])
def test_verifier_rejects_forged_bindings(tmp_path: Path, mutation: str) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    manifest = _manifest(evidence)
    if mutation == "argv":
        manifest["argv"] = ["python", "-m", "pytest", "tests/unrelated.py"]
    elif mutation == "node":
        manifest["junit"]["node_ids"] = ["tests.unrelated::test_only"]
    elif mutation == "source":
        del manifest["source_files"]["pyproject.toml"]
    elif mutation == "observation":
        (evidence / "observations.json").write_text("{}", encoding="utf-8")
    elif mutation == "run":
        manifest["run_id"] = "slice3c1-not-a-uuid"
    elif mutation == "thread":
        manifest["bb_thread_id"] = "thr_other"
    elif mutation == "interpreter":
        manifest["interpreter"]["sha256"] = "0" * 64
    else:
        manifest["git"]["sha256"] = "0" * 64
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("relative", sorted(SUPPORT_FILES))
def test_verifier_rejects_omitted_test_support_source(tmp_path: Path, relative: str) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    manifest = _manifest(evidence)
    assert relative in manifest["source_files"]
    del manifest["source_files"][relative]
    _save(evidence, manifest)
    with pytest.raises(EvidenceError, match="source file binding"):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("kind", ["extra", "nested", "symlink"])
def test_verifier_rejects_nonexact_evidence_inventory(tmp_path: Path, kind: str) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    if kind == "extra":
        (evidence / "extra.json").write_text("{}", encoding="utf-8")
    elif kind == "nested":
        (evidence / "nested").mkdir()
        (evidence / "nested" / "extra.json").write_text("{}", encoding="utf-8")
    else:
        (evidence / "observations.json").unlink()
        (evidence / "observations.json").symlink_to("run-manifest.json")
    with pytest.raises(EvidenceError, match="inventory"):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_node", "wrong_case"])
def test_verifier_binds_observation_to_the_exact_unique_passing_testcase(tmp_path: Path, mutation: str) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit_path = evidence / "slice3c1-pytest.xml"
    root = ElementTree.parse(junit_path).getroot()
    source = next(
        case
        for case in root.iter("testcase")
        if (case.attrib.get("classname"), case.attrib.get("name")) == ("tests.test_slice3c1_observations", "test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner")
    )
    properties = source.find("properties")
    assert properties is not None
    observation = next(prop for prop in properties if prop.attrib.get("name") == OBSERVATION_PROPERTY)
    node = next(prop for prop in properties if prop.attrib.get("name") == "hound.slice3c1.nodeid")
    if mutation == "missing":
        properties.remove(observation)
    elif mutation == "duplicate":
        ElementTree.SubElement(properties, "property", {"name": OBSERVATION_PROPERTY, "value": observation.attrib["value"]})
    elif mutation == "wrong_node":
        node.attrib["value"] = "tests/test_slice3c1_service_authz.py::test_node"
    else:
        source.attrib["classname"] = "tests.unrelated"

    junit_path.write_bytes(ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))
    manifest = _manifest(evidence)
    manifest["junit"]["sha256"] = hashlib.sha256(junit_path.read_bytes()).hexdigest()
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_verifier_detects_altered_imported_hound_cli_source(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    _write(repository, "src/hound_fake_support/__init__.py", b"altered\n")
    _run(repository, "add", ".")
    _run(repository, "commit", "-q", "-m", "altered")
    with pytest.raises(EvidenceError, match="external source"):
        _verify(repository, evidence, _run(repository, "rev-parse", "HEAD"), _run(repository, "rev-parse", "HEAD^{tree}"))
