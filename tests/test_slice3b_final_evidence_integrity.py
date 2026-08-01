"""Final adversarial evidence-integrity regressions for Slice 3B."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from xml.etree import ElementTree

import pytest

from tests.generate_slice3b_evidence import EvidenceError as GeneratorEvidenceError
from tests.generate_slice3b_evidence import _git_argv as generator_git_argv
from tests.generate_slice3b_evidence import source_paths as generator_source_paths
from tests.test_slice3b_evidence import (
    OBSERVATION_NODE,
    OBSERVATION_PROPERTY,
    RUN_ID,
    THREAD_ID,
    _candidate,
    _manifest,
    _run,
    _save,
    _verify,
    _write,
)
from tests.verify_slice3b_evidence import EvidenceError, _source_paths


OBSERVATION_CASE = (
    "tests.test_slice3b_observations",
    "test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner",
)
NODE_ID_PROPERTY = "hound.slice3b.nodeid"


def _rebind_junit(evidence: Path) -> None:
    manifest = _manifest(evidence)
    raw = (evidence / "slice3b-pytest.xml").read_bytes()
    manifest["junit"]["sha256"] = hashlib.sha256(raw).hexdigest()
    _save(evidence, manifest)


def _rebind_artifact(evidence: Path, artifact: str) -> None:
    manifest = _manifest(evidence)
    raw = (evidence / artifact).read_bytes()
    manifest["collection" if artifact == "slice3b-collection.json" else "observations"]["sha256"] = hashlib.sha256(raw).hexdigest()
    _save(evidence, manifest)


@pytest.mark.parametrize("relative", ["src/houndd/linked.py", "tests/test_linked.py"])
def test_source_closure_rejects_nonregular_tracked_targets(tmp_path: Path, relative: str) -> None:
    repository, _evidence, _commit, _tree = _candidate(tmp_path)
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to("../elsewhere.py")
    _run(repository, "add", relative)
    _run(repository, "commit", "-qm", "add nonregular source target")
    commit = _run(repository, "rev-parse", "HEAD")

    with pytest.raises(ValueError, match="non-regular"):
        generator_source_paths(repository, commit)
    with pytest.raises(EvidenceError, match="non-regular"):
        _source_paths(repository, commit)


def test_verifier_rejects_extra_source_binding_even_when_resealed(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    manifest = _manifest(evidence)
    manifest["source_files"]["src/not-in-source-tree.py"] = {
        "blob": "0" * 40,
        "sha256": "0" * 64,
    }
    _save(evidence, manifest)

    with pytest.raises(EvidenceError, match="source file binding"):
        _verify(repository, evidence, commit, tree)


def test_exact_hard_coded_passing_producer_with_one_property_is_accepted(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("artifact", ["run-manifest.json", "slice3b-collection.json", "observations.json"])
@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_verifier_rejects_nonfinite_json_at_every_evidence_boundary(
    tmp_path: Path, artifact: str, constant: str
) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    path = evidence / artifact
    raw = path.read_bytes().replace(b"{", b'{"attack":' + constant.encode() + b",", 1)
    path.write_bytes(raw)
    if artifact != "run-manifest.json":
        _rebind_artifact(evidence, artifact)

    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_verifier_rejects_duplicate_observation_keys_after_reseal(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    path = evidence / "observations.json"
    raw = path.read_bytes().replace(b"{", b'{"schema_version":"forged",', 1)
    path.write_bytes(raw)
    _rebind_artifact(evidence, path.name)

    with pytest.raises(EvidenceError, match="invalid JSON"):
        _verify(repository, evidence, commit, tree)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_node", "wrong_case"])
def test_verifier_binds_observation_to_the_exact_unique_passing_testcase(
    tmp_path: Path, mutation: str
) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit_path = evidence / "slice3b-pytest.xml"
    root = ElementTree.parse(junit_path).getroot()
    source = next(
        case
        for case in root.iter("testcase")
        if (case.attrib.get("classname"), case.attrib.get("name")) == OBSERVATION_CASE
    )
    properties = source.find("properties")
    assert properties is not None
    observation = next(prop for prop in properties if prop.attrib.get("name") == OBSERVATION_PROPERTY)
    node = next(prop for prop in properties if prop.attrib.get("name") == NODE_ID_PROPERTY)
    if mutation == "missing":
        properties.remove(observation)
    elif mutation == "duplicate":
        ElementTree.SubElement(properties, "property", {"name": OBSERVATION_PROPERTY, "value": observation.attrib["value"]})
    elif mutation == "wrong_node":
        node.attrib["value"] = "tests/test_slice3b_service.py::test_node"
    else:
        source.attrib["classname"] = "tests.unrelated"

    junit_path.write_bytes(ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))
    _rebind_junit(evidence)
    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_verifier_rejects_a_canonical_producer_property_that_mismatches_observations(tmp_path: Path) -> None:
    repository, evidence, commit, tree = _candidate(tmp_path)
    junit_path = evidence / "slice3b-pytest.xml"
    root = ElementTree.parse(junit_path).getroot()
    source = next(
        case
        for case in root.iter("testcase")
        if (case.attrib.get("classname"), case.attrib.get("name")) == OBSERVATION_CASE
    )
    properties = source.find("properties")
    assert properties is not None
    observation = next(prop for prop in properties if prop.attrib.get("name") == OBSERVATION_PROPERTY)
    observation.attrib["value"] = json.dumps(
        {"schema_version": "houndd.slice3b.live-observations.v1", "named_tests": [OBSERVATION_NODE], "producer": {"node_id": OBSERVATION_NODE, "classname": OBSERVATION_CASE[0], "name": OBSERVATION_CASE[1]}, "wire": {"version": "houndd.uds.v1", "encoded_json_limit": 1_048_575}},
        sort_keys=True,
        separators=(",", ":"),
    )
    junit_path.write_bytes(ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))
    _rebind_junit(evidence)

    with pytest.raises(EvidenceError):
        _verify(repository, evidence, commit, tree)


def test_trusted_git_fingerprint_is_stable_after_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tests.generate_slice3b_evidence as generator
    import tests.verify_slice3b_evidence as verifier

    repository, evidence, commit, tree = _candidate(tmp_path)
    replacement = tmp_path / "replacement-git"
    replacement.write_bytes(b"not a git executable")
    monkeypatch.setattr(verifier, "GIT_EXECUTABLE", str(replacement))
    monkeypatch.setattr(generator, "GIT_EXECUTABLE", str(replacement))

    with pytest.raises(EvidenceError, match="trusted Git"):
        _verify(repository, evidence, commit, tree)

    with pytest.raises(GeneratorEvidenceError, match="trusted Git"):
        generator_git_argv("status")


def test_trusted_git_fingerprint_rejects_an_unreadable_executable_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tests.verify_slice3b_evidence as verifier

    repository, evidence, commit, tree = _candidate(tmp_path)
    original_read_bytes = verifier.Path.read_bytes

    def unreadable(path: Path) -> bytes:
        if path == verifier.Path(verifier.GIT_EXECUTABLE):
            raise OSError("simulated unreadable executable")
        return original_read_bytes(path)

    monkeypatch.setattr(verifier.Path, "read_bytes", unreadable)
    with pytest.raises(EvidenceError, match="trusted Git"):
        _verify(repository, evidence, commit, tree)
