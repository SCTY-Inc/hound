"""HSP-21: machine-check the retained provisional Slice 3A proof bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "tests" / "evidence" / "slice3a"
REPORTS = {
    "canonical-query-matrix.json",
    "cursor-restart-hwm.json",
    "identity-crash-matrix.json",
    "identity-mode-lock-path-report.json",
    "identity-transition-report.json",
    "journal-snapshot-matrix.json",
    "read-state-after.json",
    "read-state-before.json",
    "recovery-vs-verification.json",
    "restore-portability-manifest.json",
    "sqlite-independence.json",
}
JUNIT_REPORTS = {"slice3a-pytest.xml", "compatibility-pytest.xml"}


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert type(value) is dict
    return value


def _junit_counts(path: Path) -> tuple[int, int, int]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    assert suites
    tests = sum(int(suite.attrib.get("tests", "0")) for suite in suites)
    failures = sum(int(suite.attrib.get("failures", "0")) for suite in suites)
    errors = sum(int(suite.attrib.get("errors", "0")) for suite in suites)
    return tests, failures, errors


def test_slice3a_acceptance_maps_every_changed_and_retained_artifact_once() -> None:
    acceptance = _json(ROOT / "tests" / "acceptance_slice3a.json")
    assert acceptance["schema_version"] == "houndd.slice3a.acceptance.v1"
    assert acceptance["slice"] == "3A"
    assert acceptance["status"] == "partial_hsp_coverage"
    assert acceptance["provisional"] is True
    assert "documentation change" in acceptance["acceptance_gate"]
    assert acceptance["no_new_claim_hsps"] == ["HSP-03", "HSP-09"]
    artifacts = acceptance["artifacts"]
    assert type(artifacts) is dict
    expected_changed = {
        "src/houndd/cursor.py",
        "src/houndd/journal.py",
        "src/houndd/provenance.py",
        "src/houndd/query_engine.py",
        "src/houndd/service_identity.py",
        "src/houndd/snapshot.py",
        "tests/test_hsp05_transactions.py",
        "tests/test_hsp08_durable_query.py",
        "tests/test_hsp20_durable_state.py",
        "tests/test_slice3a_evidence.py",
        "tests/acceptance_slice3a.json",
    }
    assert expected_changed <= set(artifacts)
    assert {f"tests/evidence/slice3a/{name}" for name in REPORTS | JUNIT_REPORTS} <= set(artifacts)
    assert all(claim in {"HSP-05", "HSP-08", "HSP-20", "HSP-21"} for claim in artifacts.values())
    assert all((ROOT / path).is_file() for path in artifacts)


def test_slice3a_json_reports_are_complete_consistent_and_secret_free() -> None:
    assert REPORTS <= {path.name for path in EVIDENCE.glob("*.json")}
    for name in REPORTS:
        report = _json(EVIDENCE / name)
        assert report["schema_version"].startswith("houndd.slice3a.")
        assert report["result"] == "pass"
        assert "source" in report or name.startswith("read-state-")
    assert (EVIDENCE / "read-state-before.json").read_bytes() == (
        EVIDENCE / "read-state-after.json"
    ).read_bytes()
    crash = _json(EVIDENCE / "identity-crash-matrix.json")
    assert crash["process_exit"] == "os._exit(77)"
    assert crash["cases"] == 62
    assert len(crash["fault_points"]) == 16
    transition = _json(EVIDENCE / "identity-transition-report.json")
    assert transition["persisted_generation_field"] == "generation"
    assert transition["key_material_retained"] is False
    boundary = _json(EVIDENCE / "restore-portability-manifest.json")
    assert "provisional" in boundary["claim_status"]
    assert "held /proc/self/fd dirfd" in boundary["exact_fd_fallback"]
    serialized = b"".join((EVIDENCE / name).read_bytes() for name in REPORTS)
    assert b'"secret"' not in serialized and b'"keys"' not in serialized


def test_slice3a_retained_junit_reports_have_no_failures_or_errors() -> None:
    counts = {name: _junit_counts(EVIDENCE / name) for name in JUNIT_REPORTS}
    assert all(tests > 0 and failures == 0 and errors == 0 for tests, failures, errors in counts.values())
    assert counts["slice3a-pytest.xml"][0] >= 200
    assert counts["compatibility-pytest.xml"][0] >= 200


def test_slice3a_source_digest_manifest_binds_the_reviewed_files() -> None:
    manifest = _json(EVIDENCE / "bundle-source-digests.json")
    assert manifest["schema_version"] == "houndd.slice3a.source-digests.v1"
    assert manifest["result"] == "pass"
    files = manifest["files"]
    assert type(files) is dict and files
    for relative, expected in files.items():
        assert type(relative) is str and type(expected) is str and len(expected) == 64
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected
