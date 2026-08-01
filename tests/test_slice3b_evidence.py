"""Adversarial regression tests for the independent Slice 3B verifier."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from tests.generate_slice3b_evidence import (
    CORE_TESTS as GENERATOR_CORE_TESTS,
    EvidenceError as GeneratorEvidenceError,
    GIT_ENVIRONMENT,
    TESTS as GENERATOR_TESTS,
    _git_argv,
    generate,
    source_paths as generator_source_paths,
)
from tests.verify_slice3b_evidence import CORE_TESTS, EvidenceError, TESTS, _source_paths, verify


RUN_ID = "slice3b-12345678-1234-1234-1234-123456789abc"
THREAD_ID = "thr_czqb7qxvtc"
OBSERVATION_NODE = "tests/test_slice3b_observations.py::test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner"
BASE_NODE = "tests/test_slice3b_service.py::test_node"
LATER_NODE = "tests/test_slice3b_evidence.py::test_later"
OBSERVATION_PROPERTY = "hound.slice3b.observation"
SUPPORT_FILES = {
    "README.md",
    "LICENSE.md",
    "src/hound_web_adapters/__init__.py",
    "src/hound_web_adapters/resource.txt",
    "src/houndd/schema.json",
    "tests/__init__.py",
    "tests/conftest.py",
    "tests/test_hsp08_durable_query.py",
    "tests/slice3a_evidence_capture.py",
    "tests/test_hsp08_query_engine.py",
    "tests/support/deep_fixture.py",
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
        "NODE = 'tests/test_slice3b_observations.py::test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner'\n"
        "PAYLOAD = {'schema_version':'houndd.slice3b.live-observations.v1','named_tests':[NODE],'producer':{'node_id':NODE,'classname':'tests.test_slice3b_observations','name':'test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner'},'wire':{'version':'houndd.uds.v1','encoded_json_limit':1048576}}\n"
        "OBSERVATION = json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        item.user_properties.append(('hound.slice3b.nodeid', item.nodeid))\n"
        "        if item.nodeid == NODE:\n"
        "            item.user_properties.append(('hound.slice3b.observation', OBSERVATION))\n"
        "def test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner():\n"
        "    assert OBSERVATION == json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))\n"
    ).encode()


def _candidate(tmp_path: Path) -> tuple[Path, Path, str, str]:
    repository = tmp_path / "repo"
    repository.mkdir()
    required = {
        "pyproject.toml", "uv.lock", "tests/acceptance_slice3b.json",
        "tests/generate_slice3b_evidence.py", "tests/verify_slice3b_evidence.py",
        "tests/test_slice3b_evidence.py", "tests/test_slice3a_evidence.py",
        "tests/test_slice3a_historical_evidence.py", "tests/verify_slice3a_historical.py", *TESTS,
    }
    for relative in required | SUPPORT_FILES:
        _write(repository, relative)
    _write(repository, "pyproject.toml", b"")
    _write(repository, "tests/test_slice3b_service.py", b"def test_node():\n    pass\n")
    _write(repository, "tests/test_slice3b_evidence.py", b"def test_later():\n    pass\n")
    _write(repository, "tests/test_slice3b_final_evidence_integrity.py", b"def test_final_integrity():\n    pass\n")
    _write(repository, "tests/test_slice3b_observations.py", _observation_source())
    _run(repository, "init", "-q", "-b", "main")
    _run(repository, "config", "user.name", "evidence test")
    _run(repository, "config", "user.email", "evidence@example.invalid")
    _run(repository, "add", ".")
    _run(repository, "commit", "-q", "-m", "source")
    commit = _run(repository, "rev-parse", "HEAD")
    tree = _run(repository, "rev-parse", "HEAD^{tree}")
    evidence = tmp_path / "evidence"
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=evidence, python=sys.executable, repository=repository, test_selection="core")
    return repository, evidence, commit, tree


def _verify(repository: Path, evidence: Path, commit: str, tree: str, *, test_selection: str = "core") -> None:
    verify(evidence, repository, expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, expected_python=sys.executable, test_selection=test_selection)


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
    binding = "collection" if artifact == "slice3b-collection.json" else "observations"
    manifest[binding]["sha256"] = hashlib.sha256(raw).hexdigest()
    _save(evidence, manifest)


@pytest.mark.parametrize("value", [False, 0.0, -0.0, True, 1])
def test_verifier_rejects_resealed_non_exact_collection_exit_code(tmp_path: Path, value: object) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    collection_path = evidence / "slice3b-collection.json"
    collection = json.loads(collection_path.read_text(encoding="utf-8"))
    collection["exit_code"] = value
    _replace_resealed_artifact(evidence, collection_path.name, collection)

    with pytest.raises(EvidenceError, match="collection exit code"):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("value", [1_048_576.0, True])
def test_verifier_rejects_resealed_non_exact_observation_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    import tests.verify_slice3b_evidence as verifier

    repository, evidence, commit, tree = _candidate(tmp_path)
    observation_path = evidence / "observations.json"
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    observation["wire"]["encoded_json_limit"] = value
    _replace_resealed_artifact(evidence, observation_path.name, observation)
    junit_path = evidence / "slice3b-pytest.xml"
    root = ElementTree.parse(junit_path).getroot()
    property_ = next(
        prop
        for case in root.iter("testcase")
        for prop in case.findall("./properties/property")
        if prop.attrib.get("name") == OBSERVATION_PROPERTY
    )
    property_.attrib["value"] = _canonical(observation).decode().strip()
    junit_path.write_bytes(ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))
    manifest = _manifest(evidence)
    manifest["junit"]["sha256"] = hashlib.sha256(junit_path.read_bytes()).hexdigest()
    _save(evidence, manifest)
    expected = json.loads(json.dumps(observation))
    expected["wire"]["encoded_json_limit"] = 1_048_576
    monkeypatch.setattr(verifier, "OBSERVATION", expected)
    monkeypatch.setattr(verifier, "OBSERVATION_JSON", _canonical(observation).decode().strip())

    with pytest.raises(EvidenceError, match="observation encoded JSON limit"):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("value", [3.0, True])
def test_verifier_rejects_resealed_non_exact_interpreter_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    import tests.verify_slice3b_evidence as verifier

    repository, evidence, commit, tree = _candidate(tmp_path)
    manifest = _manifest(evidence)
    interpreter = manifest["interpreter"]
    assert type(interpreter) is dict
    expected = dict(interpreter)
    expected["version"] = [3 if type(value) is float else 1, 0, 0]
    interpreter["version"] = [value, 0, 0]
    _save(evidence, manifest)
    monkeypatch.setattr(verifier, "_interpreter", lambda _python: expected)

    with pytest.raises(EvidenceError, match="Python interpreter version component"):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("value", [3.0, True])
def test_generator_rejects_non_exact_interpreter_version(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    import tests.generate_slice3b_evidence as generator

    monkeypatch.setattr(
        generator.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout=json.dumps({"executable": sys.executable, "implementation": "cpython", "version": [value, 0, 0]})
        ),
    )

    with pytest.raises(GeneratorEvidenceError, match="Python interpreter version component"):
        generator._interpreter(sys.executable)


def test_verifier_rejects_noncanonical_junit_counter_after_reseal(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit_path = evidence / "slice3b-pytest.xml"
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


def test_verifier_binds_isolated_source_argv_nodes_and_typed_observations(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    _verify(repository, evidence, commit, tree)


def test_generator_runs_the_exact_commit_in_an_isolated_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository, _evidence, commit, tree = _candidate(tmp_path)
    _write(repository, "tests/test_slice3b_service.py", b"raise RuntimeError('dirty worktree must not execute')\n")
    generated = tmp_path / "generated"
    monkeypatch.setenv("PYTEST_ADDOPTS", "--ambient-option-must-not-reach-pytest")
    monkeypatch.setenv("PYTEST_PLUGINS", "ambient_plugin_must_not_load")
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=generated, python=sys.executable, repository=repository, test_selection="core")
    _verify(repository, generated, commit, tree)


def test_test_selection_runs_the_verifier_regressions() -> None:
    assert GENERATOR_TESTS == TESTS
    assert GENERATOR_CORE_TESTS == CORE_TESTS
    assert "tests/test_slice3b_final_evidence_integrity.py" in TESTS
    assert "tests/test_slice3b_final_evidence_integrity.py" not in CORE_TESTS
    assert "tests/test_slice3b_evidence.py" in TESTS


def test_retained_selection_includes_final_integrity_without_recursive_generation(tmp_path: Path) -> None:
    repository, _evidence, commit, tree = _candidate(tmp_path)
    retained = tmp_path / "retained"
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=retained, python=sys.executable, repository=repository)
    _verify(repository, retained, commit, tree, test_selection="retained")
    collection = json.loads((retained / "slice3b-collection.json").read_text(encoding="utf-8"))
    assert collection["selection"] == "retained"
    assert "tests/test_slice3b_final_evidence_integrity.py::test_final_integrity" in collection["node_ids"]


def test_source_closure_is_every_tracked_regular_source_and_python_test_file(tmp_path: Path) -> None:
    repository, _evidence, commit, _tree = _candidate(tmp_path)
    tracked = _run(repository, "ls-tree", "-r", "--name-only", commit).splitlines()
    expected = tuple(sorted({
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE.md",
        "tests/acceptance_slice3b.json",
        *(path for path in tracked if path.startswith("src/") or (path.startswith("tests/") and path.endswith(".py"))),
    }))
    assert generator_source_paths(repository, commit) == expected
    assert _source_paths(repository, commit) == expected


def test_verifier_rejects_trimmed_resealed_junit(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit = f'<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="tests.test_slice3b_observations" name="test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner"><properties><property name="hound.slice3b.nodeid" value="{OBSERVATION_NODE}"/></properties></testcase></testsuite></testsuites>'.encode()
    (evidence / "slice3b-pytest.xml").write_bytes(junit)
    manifest = _manifest(evidence)
    manifest["junit"]["sha256"] = hashlib.sha256(junit).hexdigest()
    manifest["junit"]["node_ids"] = [OBSERVATION_NODE]
    collection = json.loads((evidence / "slice3b-collection.json").read_text(encoding="utf-8"))
    collection["node_ids"] = [OBSERVATION_NODE]
    collection_bytes = json.dumps(collection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    (evidence / "slice3b-collection.json").write_bytes(collection_bytes)
    manifest["collection"]["sha256"] = hashlib.sha256(collection_bytes).hexdigest()
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_verifier_rejects_wrong_passing_observation_producer(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    observations = {"schema_version": "houndd.slice3b.live-observations.v1", "named_tests": [BASE_NODE], "wire": {"version": "houndd.uds.v1", "encoded_json_limit": 1_048_576}}
    observation_bytes = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    (evidence / "observations.json").write_bytes(observation_bytes)
    manifest = _manifest(evidence)
    manifest["observations"]["sha256"] = hashlib.sha256(observation_bytes).hexdigest()
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_verifier_rejects_observation_property_moved_to_another_passing_test(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit_path = evidence / "slice3b-pytest.xml"
    root = ElementTree.parse(junit_path).getroot()
    cases = list(root.iter("testcase"))
    source = next(case for case in cases if any(prop.attrib.get("value") == OBSERVATION_NODE for prop in case.findall("./properties/property")))
    target = next(case for case in cases if any(prop.attrib.get("value") == LATER_NODE for prop in case.findall("./properties/property")))
    source_properties = source.find("properties")
    properties = target.find("properties")
    assert source_properties is not None and properties is not None
    for prop in list(source_properties):
        if prop.attrib.get("name") == OBSERVATION_PROPERTY:
            source_properties.remove(prop)
    observation = json.dumps({"schema_version": "houndd.slice3b.live-observations.v1", "named_tests": [OBSERVATION_NODE], "wire": {"version": "houndd.uds.v1", "encoded_json_limit": 1_048_576}}, sort_keys=True, separators=(",", ":"))
    ElementTree.SubElement(properties, "property", {"name": OBSERVATION_PROPERTY, "value": observation})
    junit_bytes = ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
    junit_path.write_bytes(junit_bytes)
    manifest = _manifest(evidence)
    manifest["junit"]["sha256"] = hashlib.sha256(junit_bytes).hexdigest()
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_verifier_rejects_noncanonical_braced_run_uuid(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    braced = "slice3b-{12345678-1234-1234-1234-123456789abc}"
    manifest = _manifest(evidence)
    manifest["run_id"] = braced
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        verify(evidence, repository, expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=braced, expected_python=sys.executable, test_selection="core")


def test_generator_rejects_noncanonical_braced_run_uuid(tmp_path: Path) -> None:
    repository, _evidence, commit, tree = _candidate(tmp_path)
    with pytest.raises(ValueError, match="canonical"):
        generate(
            expected_commit=commit,
            expected_tree=tree,
            expected_thread_id=THREAD_ID,
            expected_run_id="slice3b-{12345678-1234-1234-1234-123456789abc}",
            evidence_dir=tmp_path / "braced",
            python=sys.executable,
            repository=repository,
        )


def test_generator_and_verifier_ignore_malicious_ambient_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    fake = tmp_path / "malicious-bin" / "git"
    sentinel = tmp_path / "ambient-git-ran"
    _write(tmp_path, "malicious-bin/git", f'#!/bin/sh\n: > "{sentinel}"\nexit 97\n'.encode())
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", os.fspath(fake.parent))
    generated = tmp_path / "ambient-generated"
    generate(expected_commit=commit, expected_tree=tree, expected_thread_id=THREAD_ID, expected_run_id=RUN_ID, evidence_dir=generated, python=sys.executable, repository=repository, test_selection="core")
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

    collection_root = tmp_path / "collection"
    collection_root.mkdir()
    repository, evidence, commit, tree = _candidate(collection_root)
    collection_path = evidence / "slice3b-collection.json"
    collection = json.loads(collection_path.read_text(encoding="utf-8"))
    collection_bytes = json.dumps(collection, sort_keys=True, separators=(",", ":")).replace('"exit_code":0', '"exit_code":0,"exit_code":0', 1).encode() + b"\n"
    collection_path.write_bytes(collection_bytes)
    manifest = _manifest(evidence)
    manifest["collection"]["sha256"] = hashlib.sha256(collection_bytes).hexdigest()
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("artifact", ["run-manifest.json", "slice3b-collection.json", "observations.json"])
def test_verifier_rejects_noncanonical_json_whitespace_after_reseal(tmp_path: Path, artifact: str) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    path = evidence / artifact
    value = json.loads(path.read_text(encoding="utf-8"))
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path.write_bytes(raw)
    if artifact != "run-manifest.json":
        manifest = _manifest(evidence)
        manifest["collection" if artifact.startswith("slice3b-collection") else "observations"]["sha256"] = hashlib.sha256(raw).hexdigest()
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
        manifest["run_id"] = "slice3b-not-a-uuid"
    elif mutation == "thread":
        manifest["bb_thread_id"] = "thr_other"
    elif mutation == "interpreter":
        manifest["interpreter"]["sha256"] = "0" * 64
    else:
        manifest["git"]["sha256"] = "0" * 64
    _save(evidence, manifest)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("relative", ["README.md", "LICENSE.md", "src/hound_web_adapters/__init__.py", "src/hound_web_adapters/resource.txt", "src/houndd/schema.json", "tests/__init__.py", "tests/conftest.py", "tests/test_hsp08_durable_query.py", "tests/slice3a_evidence_capture.py", "tests/test_hsp08_query_engine.py"])
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


def test_verifier_detects_altered_imported_hound_cli_source(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    _write(repository, "src/hound_cli/__init__.py", b"altered\n")
    _run(repository, "add", ".")
    _run(repository, "commit", "-q", "-m", "altered")
    with pytest.raises(EvidenceError, match="external source"):
        _verify(repository, evidence, _run(repository, "rev-parse", "HEAD"), _run(repository, "rev-parse", "HEAD^{tree}"))
