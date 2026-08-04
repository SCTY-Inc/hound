from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import migration.consumer_inventory as consumer_inventory

from migration.consumer_inventory import (
    InventoryError,
    _path_problem,
    _scan_candidates,
    _scan_workspace,
    load_catalog,
    load_inventory,
    validate_catalog,
    validate_inventory,
)


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "migration" / "consumer-inventory.v1.json"
CATALOG = ROOT / "migration" / "provider-indicators.v1.json"

def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text())


def _write_manifest(tmp_path: Path, value: dict[str, object]) -> Path:
    path = tmp_path / "consumer-inventory.json"
    path.write_text(json.dumps(value))
    return path


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "migration/check_consumer_inventory.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _workspace_for_manifest(tmp_path: Path, manifest: dict[str, object]) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for row in manifest["consumers"]:
        for path in row["scan_roots"] + row["legacy_paths"]:
            candidate = workspace / path
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text("# fixture\n")
        if "/" in row["contract_ref"]:
            candidate = workspace / row["contract_ref"]
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text("# fixture\n")
    return workspace


def test_canonical_manifest_validates() -> None:
    assert validate_inventory(_manifest()) == []


@pytest.mark.parametrize(
    ("loader", "payload"),
    [
        (load_inventory, '{"schema_version":"x","schema_version":"y"}'),
        (load_inventory, '{"consumers":[{"id":"a","id":"b"}]}'),
        (load_catalog, '{"schema_version":"x","pairing_rules":{},"indicators":[],"pairing_rules":{}}'),
    ],
)
def test_json_duplicate_keys_are_rejected(tmp_path: Path, loader, payload: str) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(payload)
    with pytest.raises(InventoryError, match="duplicate JSON object key"):
        loader(path)


@pytest.mark.parametrize(("flag", "label"), [("--manifest", "inventory"), ("--catalog", "provider catalog")])
def test_deep_json_cli_fails_in_the_canonical_error_domain(
    tmp_path: Path, flag: str, label: str
) -> None:
    path = tmp_path / "deep.json"
    path.write_text('{"value":' + "[" * 1101 + "null" + "]" * 1101 + "}")

    completed = _cli("--schema-only", flag, str(path), "--json")

    expected = f"cannot load {label} {path}: JSON nesting exceeds maximum depth"
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert json.loads(completed.stdout)["errors"] == [expected]


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        (lambda m: m["consumers"].pop(), "exactly"),
        (lambda m: m["consumers"].append(m["consumers"][0].copy()), "duplicate consumer id"),
        (lambda m: m["consumers"][0]["legacy_paths"].append(m["consumers"][0]["legacy_paths"][0]), "duplicate"),
        (lambda m: m["consumers"][0]["scan_roots"].append(m["consumers"][0]["scan_roots"][0]), "duplicate"),
        (lambda m: m["consumers"][0]["scan_roots"].append("**"), "broad"),
        (lambda m: m["consumers"][0].update({"unexpected": True}), "field closure"),
        (lambda m: m["consumers"][0]["target_ops"].append("provider.call"), "target operation"),
    ],
)
def test_manifest_rejects_inventory_mutations(tmp_path: Path, mutation, needle: str) -> None:
    manifest = _manifest()
    mutation(manifest)
    errors = validate_inventory(manifest, require_paths=False)
    assert any(needle.lower() in error.lower() for error in errors), errors


def test_manifest_rejects_invalid_builtin_types(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["consumers"][0]["wave"] = True
    assert any("wave" in error for error in validate_inventory(manifest))


@pytest.mark.parametrize("field", ["owner", "cadence_category", "cadence_authority", "contract_ref", "credential_boundary"])
def test_manifest_rejects_empty_authoritative_text(field: str) -> None:
    manifest = _manifest()
    manifest["consumers"][0][field] = ""
    assert any(field in error for error in validate_inventory(manifest))


def test_manifest_rejects_absolute_filesystem_references() -> None:
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"][0] = "/home/deploy/repos/givecare/gc-web/scripts/pulse-lane.sh"
    manifest["consumers"][0]["evidence"]["baseline_scan"] = "/tmp/baseline.json"
    assert sum("workspace-relative" in error for error in validate_inventory(manifest)) >= 2


@pytest.mark.parametrize("field", ["stage_order", "allowed_kinds", "allowed_statuses", "allowed_exclusions", "adapter_allowlist", "consumers"])
def test_hostile_top_level_scalar_returns_errors(field: str) -> None:
    manifest = _manifest()
    manifest[field] = True
    errors = validate_inventory(manifest)
    assert errors


def test_hostile_nested_containers_return_errors() -> None:
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = {"bad": "container"}
    manifest["consumers"][1]["evidence"] = []
    errors = validate_inventory(manifest)
    assert any("scan_roots" in error for error in errors)
    assert any("evidence" in error for error in errors)


def test_duplicate_evidence_pointer_is_rejected() -> None:
    manifest = _manifest()
    manifest["consumers"][0]["evidence"]["baseline_scan"] = "migration/evidence.json"
    manifest["consumers"][0]["evidence"]["parity"] = "migration/evidence.json"
    assert any("duplicate evidence" in error for error in validate_inventory(manifest))


def test_baseline_evidence_may_be_null_but_nonnull_pointers_are_bounded() -> None:
    manifest = _manifest()
    manifest["consumers"][0]["evidence"]["baseline_scan"] = None
    manifest["consumers"][0]["evidence"]["stage_ledger"] = ""
    errors = validate_inventory(manifest)
    assert not any("baseline_scan" in error for error in errors)
    assert any("stage_ledger" in error for error in errors)


def test_freeze_baseline_has_no_future_evidence_pointers() -> None:
    for row in _manifest()["consumers"]:
        assert row["evidence"]["baseline_scan"] is None
        assert row["evidence"]["stage_ledger"] is None


@pytest.mark.parametrize("value", ["OnCalendar=Mon *-*-* 00:00", "0 0 * * 1", "FIRECRAWL_API_KEY=not-a-real-key", "sk-abcdefghijklm"])
def test_manifest_rejects_timer_and_secret_values(value: str) -> None:
    manifest = _manifest()
    manifest["consumers"][0]["contract_ref"] = value
    errors = validate_inventory(manifest)
    assert any("timer" in error.lower() or "secret" in error.lower() for error in errors)


def test_workspace_path_checks_are_opt_in(tmp_path: Path) -> None:
    manifest = _manifest()
    errors = validate_inventory(manifest, require_paths=True, workspace=tmp_path)
    assert any("does not exist" in error for error in errors)
    assert validate_inventory(manifest) == []


def test_migrated_stage_requires_all_evidence(tmp_path: Path) -> None:
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["stage"] = "migrated"
    item["status"] = "migrated"
    errors = validate_inventory(manifest, require_paths=False)
    assert any("credential_unset" in error for error in errors)
    assert any("recovery_drill" in error for error in errors)
    assert any("unix_socket" in error for error in errors)
    assert any("full_cycle" in error for error in errors)


def test_catalog_is_versioned_typed_and_not_blanket_http() -> None:
    catalog = load_catalog(CATALOG)
    assert all(type(item["match"]) is dict and type(item["match"]["kind"]) is str and type(item["match"]["value"]) is str for item in catalog["indicators"])
    invalid = json.loads(CATALOG.read_text())
    invalid["schema_version"] = "v0"
    assert any("version" in error for error in __import__("migration.consumer_inventory", fromlist=["validate_catalog"]).validate_catalog(invalid))
    invalid = json.loads(CATALOG.read_text())
    invalid["indicators"][0]["match"] = {"kind": "literal", "value": "https://"}
    assert any("blanket HTTP" in error for error in __import__("migration.consumer_inventory", fromlist=["validate_catalog"]).validate_catalog(invalid))
    invalid = json.loads(CATALOG.read_text())
    invalid["indicators"][0]["provider"] = []
    assert __import__("migration.consumer_inventory", fromlist=["validate_catalog"]).validate_catalog(invalid)
    invalid = json.loads(CATALOG.read_text())
    invalid["pairing_rules"]["outbound_transport_requires"] = ["anything"]
    assert any("pairing" in error for error in __import__("migration.consumer_inventory", fromlist=["validate_catalog"]).validate_catalog(invalid))


def test_catalog_hostile_nested_entry_types_return_errors() -> None:
    from migration.consumer_inventory import validate_catalog

    catalog = load_catalog(CATALOG)
    catalog["indicators"][0] = []
    assert validate_catalog(catalog)
    catalog = load_catalog(CATALOG)
    catalog["indicators"][0]["pattern"] = {}
    assert validate_catalog(catalog)
    catalog = load_catalog(CATALOG)
    catalog["indicators"][0]["provider"] = "generic"
    assert any("generic provider" in error for error in validate_catalog(catalog))


def test_non_acquisition_rows_are_restricted() -> None:
    rows = {row["id"]: row for row in _manifest()["consumers"]}
    assert rows["workpad-intake-ledger"]["kind"] == "partial_read_client"
    assert rows["workpad-intake-ledger"]["target_ops"] == ["journal.query"]
    assert rows["gc-gtm-crm"]["kind"] == "consumer_only"
    assert all(not op.startswith("ingest.") for op in rows["gc-gtm-crm"]["target_ops"])
    assert "repos/givecare/gc-gtm/gmail_adapter.py" in rows["gc-gtm-crm"]["legacy_paths"]
    assert "repos/givecare/gc-gtm/gmail_adapter.py" not in rows["gc-gtm-crm"]["scan_roots"]
    mutated = _manifest()
    mutated["consumers"][-1]["target_ops"] = ["journal.get"]
    assert any("restricted journal-only CRM" in error for error in validate_inventory(mutated))


def test_canonical_path_layout_is_workspace_relative() -> None:
    manifest = _manifest()
    for row in manifest["consumers"]:
        for path in row["scan_roots"] + row["legacy_paths"]:
            assert not Path(path).is_absolute()
            assert path.startswith(("repos/", "agents/"))
        if "/" in row["contract_ref"]:
            assert row["contract_ref"].startswith(("repos/", "agents/"))


def test_scanner_reports_known_baseline_and_rejects_unclassified(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy = workspace / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "runner.py").write_text("import firecrawl\n# FIRECRAWL_API_KEY\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["legacy"]
    item["legacy_paths"] = ["legacy/runner.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    assert any("exact canonical" in error for error in validate_inventory(manifest))
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert result.failures == []
    assert {finding["category"] for finding in result.baseline_findings} >= {"sdk_import", "credential_name"}

    (legacy / "unknown.py").write_text("MYSTERY_PROVIDER_API_KEY = 'x'\n")
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert any("unclassified" in error for error in result.failures)


def test_provider_transport_requires_provider_pair(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy = workspace / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "transport.py").write_text("import requests\nrequests.get('https://example.test')\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["legacy"]
    item["legacy_paths"] = ["legacy/transport.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert not any(f["category"] == "outbound_transport" for f in result.findings)


def test_provider_transport_pairs_only_same_provider(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy = workspace / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "transport.py").write_text("import firecrawl\nrequests.get('https://api.firecrawl.dev')\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["legacy"]
    item["legacy_paths"] = ["legacy/transport.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    outbound = {finding["indicator_id"] for finding in result.findings if finding["category"] == "outbound_transport"}
    assert outbound == {"firecrawl-http-transport"}


def test_artifact_hound_id_on_another_line_does_not_mask_finding(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy = workspace / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "artifact.txt").write_text("firecrawl provider_response\nhound_id: known\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["legacy"]
    item["legacy_paths"] = ["legacy/artifact.txt"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert any(finding["category"] == "evidence_artifact" for finding in result.baseline_findings)


def test_cli_supports_workspace_and_json_output(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "migration/check_consumer_inventory.py", "--schema-only", "--json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output["valid"] is True
    assert "baseline_findings" in output


def test_cli_workspace_missing_root_fails(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "migration/check_consumer_inventory.py", "--workspace", str(tmp_path), "--json"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 1
    assert "does not exist" in completed.stdout


def test_cli_malformed_arguments_return_error_without_traceback() -> None:
    completed = subprocess.run(
        [sys.executable, "migration/check_consumer_inventory.py", "--workspace"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 2
    assert "Traceback" not in completed.stderr


def test_allowlist_is_exact_file_not_sibling_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    allowed = workspace / "repos" / "hound" / "src" / "hound_web_adapters" / "exa.py"
    path = workspace / "repos" / "hound" / "src" / "hound_web_adapters" / "exa-helper.py"
    allowed.parent.mkdir(parents=True)
    allowed.write_text("import firecrawl\n")
    path.write_text("import firecrawl\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["repos/hound/src/hound_web_adapters"]
    item["legacy_paths"] = []
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert not any(finding["path"] == "repos/hound/src/hound_web_adapters/exa.py" for finding in result.findings)
    assert any("outside legacy_paths" in error for error in result.failures)
    assert all(finding["path"] != "repos/hound/src/hound_web_adapters/exa.py" for finding in result.findings)


def test_scan_root_can_be_exact_file_without_directory_walk(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    file_path = workspace / "legacy.py"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("import firecrawl\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["legacy.py"]
    item["legacy_paths"] = ["legacy.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert result.baseline_findings


def test_migrated_stage_rejects_baseline_direct_provider(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    legacy = workspace / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "runner.py").write_text("import firecrawl\n")
    manifest = _manifest()
    item = manifest["consumers"][0]
    item["scan_roots"] = ["legacy"]
    item["legacy_paths"] = ["legacy/runner.py"]
    item["stage"] = "migrated"
    item["status"] = "migrated"
    for key in ("static_no_direct_provider", "credential_unset", "unix_socket", "recovery_drill", "full_cycle"):
        evidence = workspace / f"{key}.json"
        evidence.write_text("{}")
        item["evidence"][key] = f"{key}.json"
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert any("migrated" in error for error in result.failures)


@pytest.mark.parametrize(
    "source",
    [
        "MYSTERY_API_KEY = 'x'\n",
        "MYSTERY_ENDPOINT = 'https://unknown.example/api'\n",
        "import mystery_sdk\n",
        "mystery_sdk.Client()\n",
    ],
)
def test_unknown_provider_signals_fail_closed_without_provider_word_gating(tmp_path: Path, source: str) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text(source)
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert any("unclassified" in error for error in result.failures)


def test_raw_provider_endpoint_fails_closed_unless_exact_indicator_is_cataloged(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text('requests.post("https://api.tavily.com/search")\n')
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []

    uncataloged = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert any("unclassified provider-specific indicator" in error for error in uncataloged.failures)


def test_acceptance_manifest_does_not_claim_hsp15_and_vision_commands_are_runnable() -> None:
    acceptance = json.loads((ROOT / "migration" / "acceptance.v1.json").read_text())
    assert "HSP-15" not in acceptance["claims"]
    assert "HSP-15" in acceptance["no_new_claim_hsps"]
    vision = (ROOT / "VISION.md").read_text()
    assert "PYTHONDONTWRITEBYTECODE=1 .venv/bin/python migration/check_consumer_inventory.py --workspace /home/deploy" in vision
    assert "`python migration/check_consumer_inventory.py`" not in vision


@pytest.mark.parametrize("field", ["stage", "status", "cadence_authority", "credential_boundary", "evidence", "approval_ref"])
def test_canonical_rows_freeze_all_authoritative_fields(field: str) -> None:
    manifest = _manifest()
    manifest["consumers"][0][field] = "migrated" if field not in {"evidence", "approval_ref"} else ({"baseline_scan": "x"} if field == "evidence" else "x")
    assert validate_inventory(manifest)


@pytest.mark.parametrize("field", ["cadence_category", "contract_ref", "owner", "kind", "scan_roots", "legacy_paths", "target_ops", "blocked_reason", "wave"])
def test_canonical_row_digest_covers_every_row_field(field: str) -> None:
    manifest = _manifest(); row = manifest["consumers"][0]
    row[field] = (row[field] + "-changed") if isinstance(row[field], str) else (row[field] + 1 if isinstance(row[field], int) else (["changed"] if row[field] is None else list(row[field]) + ["changed"]))
    assert any("canonical closure" in error for error in validate_inventory(manifest))


@pytest.mark.parametrize("source", ["TOKEN = 'x'\n", "MYSTERY_TOKEN = 'x'\n", "httpx.post('https://api.unknown.example/x')\n", "urllib.request.urlopen('https://api.unknown.example/x')\n"])
def test_adversarial_raw_signals_are_bounded(tmp_path: Path, source: str) -> None:
    workspace = tmp_path / "workspace"; workspace.mkdir(); (workspace / "x.py").write_text(source)
    manifest = _manifest(); manifest["consumers"][0]["scan_roots"] = ["x.py"]; manifest["consumers"][0]["legacy_paths"] = ["x.py"]
    for row in manifest["consumers"][1:]: row["scan_roots"] = []; row["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    if source.startswith("TOKEN"):
        assert not result.failures
    else:
        assert any("unclassified" in error for error in result.failures)


def test_path_validation_rejects_lexical_escape(tmp_path: Path) -> None:
    manifest = _manifest(); manifest["consumers"][0]["contract_ref"] = "../outside.json"
    assert any("workspace-relative" in error or "broad" in error for error in validate_inventory(manifest))


@pytest.mark.parametrize("bad_match", [{"kind": [], "value": "x"}, {"kind": "literal", "value": []}])
def test_catalog_nested_types_are_reported_without_crash(bad_match) -> None:
    from migration.consumer_inventory import validate_catalog
    catalog = load_catalog(CATALOG); catalog["indicators"][0]["match"] = bad_match
    errors = validate_catalog(catalog)
    assert any("match." in error and "exact builtin type" in error for error in errors)


@pytest.mark.parametrize("kind", ["extra", "too-many", "oversize", "control"])
def test_catalog_bounds_and_exact_closure(kind: str, tmp_path: Path) -> None:
    from migration.consumer_inventory import validate_catalog
    catalog = load_catalog(CATALOG)
    if kind == "extra": catalog["indicators"].append({"id":"new","category":"endpoint","provider":"new","match":{"kind":"literal","value":"api.new.example"}})
    elif kind == "too-many": catalog["indicators"] = catalog["indicators"] * 4
    elif kind == "oversize": catalog["indicators"][0]["match"]["value"] = "x" * 257
    else: catalog["indicators"][0]["id"] = "bad\x00id"
    assert validate_catalog(catalog)


def test_artifact_pairing_uses_bounded_same_provider_window(tmp_path: Path) -> None:
    workspace = tmp_path / "w"; workspace.mkdir(); (workspace / "x.py").write_text("firecrawl\nprovider_response\n\n\n\nprovider_response\n")
    manifest = _manifest(); manifest["consumers"][0]["scan_roots"] = ["x.py"]; manifest["consumers"][0]["legacy_paths"] = ["x.py"]
    for row in manifest["consumers"][1:]: row["scan_roots"] = []; row["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert [f["line"] for f in result.findings if f["category"] == "evidence_artifact"] == [2]


def test_checked_in_rows_are_fully_frozen() -> None:
    for row in _manifest()["consumers"]:
        assert row["stage"] == "freeze_contracts" and row["approval_ref"] is None
        assert all(value is None for value in row["evidence"].values())


@pytest.mark.parametrize("name, payload, needle", [
    ("linked.py", "import firecrawl\n", "symlink"),
    ("bad.py", b"\xff", "non-UTF-8"),
    ("large.py", b"x" * (1_048_577), "oversize"),
    ("line.py", b"x" * 16_385, "line exceeds"),
])
def test_scanner_fails_closed_for_unsafe_or_unreadable_inputs(tmp_path: Path, name: str, payload: str | bytes, needle: str) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / name
    if name == "linked.py":
        target = tmp_path / "outside.py"
        target.write_text(payload)
        path.symlink_to(target)
    elif type(payload) is bytes:
        path.write_bytes(payload)
    else:
        path.write_text(payload)
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = [name]
    manifest["consumers"][0]["legacy_paths"] = [name]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert any(needle in error for error in result.failures)


def test_catalog_rejects_regex_and_requires_safe_match_schema() -> None:
    from migration.consumer_inventory import validate_catalog

    catalog = load_catalog(CATALOG)
    catalog["indicators"][0]["match"] = {"kind": "regex", "value": ".*"}
    assert any("literal or token" in error for error in validate_catalog(catalog))


def test_scan_coverage_reports_root_file_bytes_and_lines(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text("import firecrawl\n")
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for other in manifest["consumers"][1:]:
        other["scan_roots"] = []
        other["legacy_paths"] = []
    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    assert result.coverage == [{"consumer_id": "pulse", "scan_root": "legacy.py", "path": "legacy.py", "bytes": 17, "lines": 1}]


@pytest.mark.parametrize(
    ("match", "error"),
    [
        ({"kind": [], "value": "x"}, "catalog.indicators[0].match.kind must be exact builtin type str"),
        ({"kind": "literal", "value": []}, "catalog.indicators[0].match.value must be exact builtin type str"),
    ],
)
def test_catalog_match_container_failures_are_canonical_cli_errors(
    tmp_path: Path, match: dict[str, object], error: str
) -> None:
    catalog = json.loads(CATALOG.read_text())
    catalog["indicators"][0]["match"] = match
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))

    completed = _cli("--schema-only", "--catalog", str(path), "--json")

    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert json.loads(completed.stdout)["errors"] == [error]


def test_catalog_extra_indicator_fails_exact_closure_through_cli(tmp_path: Path) -> None:
    catalog = json.loads(CATALOG.read_text())
    catalog["indicators"].append(
        {"id": "new-endpoint", "category": "endpoint", "provider": "new", "match": {"kind": "literal", "value": "api.new.example"}}
    )
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))

    completed = _cli("--schema-only", "--catalog", str(path), "--json")

    assert completed.returncode == 1
    assert json.loads(completed.stdout)["errors"] == ["catalog must match the exact approved provider indicator set"]


def test_catalog_indicator_count_bound_is_exact(tmp_path: Path) -> None:
    catalog = json.loads(CATALOG.read_text())
    template = catalog["indicators"][0]
    catalog["indicators"] = [
        {**template, "id": f"indicator-{index}", "match": {**template["match"], "value": f"token-{index}"}}
        for index in range(129)
    ]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))

    completed = _cli("--schema-only", "--catalog", str(path), "--json")

    assert completed.returncode == 1
    assert json.loads(completed.stdout)["errors"] == ["catalog.indicators exceeds maximum size"]


def test_catalog_raw_byte_bound_precedes_json_parse_and_use(tmp_path: Path) -> None:
    path = tmp_path / "oversize-catalog.json"
    path.write_bytes(b"{" + b" " * 65_536)

    completed = _cli("--schema-only", "--catalog", str(path), "--json")

    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert json.loads(completed.stdout)["errors"] == ["provider catalog exceeds 65536 bytes"]


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("id", "x" * 129, "catalog.indicators[0].id is unbounded or contains control characters"),
        ("provider", "x" * 129, "catalog.indicators[0].provider is unbounded or contains control characters"),
        ("match.value", "x" * 257, "catalog.indicators[0].match.value is unbounded or contains control characters"),
        ("id", "bad\x00id", "catalog.indicators[0].id is unbounded or contains control characters"),
        ("provider", "bad\x00provider", "catalog.indicators[0].provider is unbounded or contains control characters"),
        ("match.value", "bad\x00value", "catalog.indicators[0].match.value is unbounded or contains control characters"),
    ],
)
def test_catalog_field_bounds_and_controls_have_exact_error_domain(field: str, value: str, error: str) -> None:
    catalog = json.loads(CATALOG.read_text())
    if field == "match.value":
        catalog["indicators"][0]["match"]["value"] = value
    else:
        catalog["indicators"][0][field] = value

    assert validate_catalog(catalog) == [error]


@pytest.mark.parametrize(
    ("source", "expected_lines"),
    [
        ("firecrawl\nprovider_response\n", [2]),
        ("firecrawl\n\nprovider_response\n", [3]),
        ("provider_response\nfirecrawl\n", [1]),
        ("provider_response\n\nfirecrawl\n", [1]),
        ("firecrawl\n\n\nprovider_response\n", []),
    ],
)
def test_evidence_artifact_pairing_is_same_provider_and_within_two_lines(
    tmp_path: Path, source: str, expected_lines: list[int]
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text(source)
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert [finding["line"] for finding in result.findings if finding["category"] == "evidence_artifact"] == expected_lines


def test_evidence_artifact_does_not_pair_across_providers(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text("firecrawl\nprovider_response\n")
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []
    catalog = load_catalog(CATALOG)
    next(item for item in catalog["indicators"] if item["id"] == "firecrawl-artifact")["match"]["value"] = "firecrawl_artifact"

    # Both fixture manifest and catalog deliberately differ from their exact
    # checked-in closures; exercise pairing after those public-boundary checks.
    result = _scan_workspace(manifest, catalog, workspace)

    assert result.failures == []
    assert not [finding for finding in result.findings if finding["category"] == "evidence_artifact"]


def test_evidence_artifact_hound_id_masks_only_its_own_line(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text("# firecrawl provider_response hound_id: known\n# firecrawl provider_response\n")
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert [finding["line"] for finding in result.findings if finding["category"] == "evidence_artifact"] == [2]


@pytest.mark.parametrize("pointer", ["contract_ref", "evidence.baseline_scan"])
def test_live_path_checks_reject_ancestor_symlinks(tmp_path: Path, pointer: str) -> None:
    manifest = _manifest()
    workspace = _workspace_for_manifest(tmp_path, manifest)
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = workspace / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    if pointer == "contract_ref":
        manifest["consumers"][0]["contract_ref"] = "linked/contract.md"
        (outside / "contract.md").write_text("fixture")
    else:
        manifest["consumers"][0]["evidence"]["baseline_scan"] = "linked/evidence.json"
        (outside / "evidence.json").write_text("fixture")

    errors = validate_inventory(manifest, require_paths=True, workspace=workspace)

    assert any("uses symlink" in error and pointer.split(".")[0] in error for error in errors)


def test_path_problem_rejects_lexical_escape_before_filesystem_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    escaped = workspace / ".." / "outside"
    calls: list[Path] = []
    original = Path.lstat

    def lstat(path: Path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(Path, "lstat", lstat)

    assert _path_problem(escaped, workspace) == "escapes workspace"
    assert calls == []


@pytest.mark.parametrize("path", ["/tmp/outside", "../outside", "nested/../../outside"])
def test_path_problem_rejects_absolute_and_parent_escapes_with_bounded_error(tmp_path: Path, path: str) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    candidate = Path(path) if Path(path).is_absolute() else workspace / path

    assert _path_problem(candidate, workspace) == "escapes workspace"


@pytest.mark.parametrize("contract_ref", ["/tmp/outside", "../outside", "nested/../../outside"])
def test_live_contract_references_report_absolute_and_parent_escapes(
    tmp_path: Path, contract_ref: str
) -> None:
    manifest = _manifest()
    workspace = _workspace_for_manifest(tmp_path, manifest)
    manifest["consumers"][0]["contract_ref"] = contract_ref

    errors = validate_inventory(manifest, require_paths=True, workspace=workspace)

    assert any("contract_ref path escapes workspace" in error for error in errors)


@pytest.mark.parametrize(
    "field",
    [
        "id", "kind", "owner", "cadence_category", "cadence_authority", "contract_ref", "scan_roots",
        "legacy_paths", "target_ops", "blocked_reason", "wave", "stage", "status", "credential_boundary",
        "evidence", "approval_ref",
    ],
)
def test_every_authoritative_row_field_has_exact_canonical_closure(field: str) -> None:
    manifest = _manifest()
    row = manifest["consumers"][0]
    replacements: dict[str, object] = {
        "id": "pulse-altered",
        "kind": "consumer_only",
        "owner": "altered-owner",
        "cadence_category": "altered-cadence",
        "cadence_authority": "altered-authority",
        "contract_ref": "contracts/altered.md",
        "scan_roots": ["repos/altered.py"],
        "legacy_paths": ["repos/altered-legacy.py"],
        "target_ops": ["ingest.url"],
        "blocked_reason": "altered",
        "wave": row["wave"] + 1,
        "stage": "shadow",
        "status": "baseline",
        "credential_boundary": "altered-boundary",
        "evidence": {key: None for key in row["evidence"]},
        "approval_ref": None,
    }
    if field == "approval_ref":
        replacements[field] = "approvals/altered.json"
    elif field == "evidence":
        replacements[field]["baseline_scan"] = "evidence/altered.json"
    row[field] = replacements[field]

    errors = validate_inventory(manifest)

    assert "consumer rows must match the exact canonical closure" in errors


def test_checked_in_rows_are_all_null_baseline_freeze_contracts() -> None:
    rows = _manifest()["consumers"]
    assert len(rows) == 13
    assert all(row["stage"] == "freeze_contracts" and row["approval_ref"] is None for row in rows)
    assert all(all(value is None for value in row["evidence"].values()) for row in rows)


def test_unknown_raw_provider_transports_and_bare_token_are_classified_exactly(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []

    for source, expected in [
        ("TOKEN = 'x'\n", []),
        ("MYSTERY_TOKEN = 'x'\n", ["unclassified provider-specific indicator: legacy.py:1"]),
        ("requests.get('https://api.unknown.example/x')\n", ["unclassified provider-specific indicator: legacy.py:1"]),
        ("httpx.get('https://api.unknown.example/x')\n", ["unclassified provider-specific indicator: legacy.py:1"]),
        ("urllib.request.urlopen('https://api.unknown.example/x')\n", ["unclassified provider-specific indicator: legacy.py:1"]),
    ]:
        (workspace / "legacy.py").write_text(source)
        assert _scan_workspace(manifest, load_catalog(CATALOG), workspace).failures == expected


def test_catalog_has_no_tavily_entry() -> None:
    catalog = load_catalog(CATALOG)
    assert all("tavily" not in str(value).lower() for indicator in catalog["indicators"] for value in indicator.values())


def test_acceptance_claims_are_limited_to_hsp13_and_hsp18_regression() -> None:
    acceptance = json.loads((ROOT / "migration" / "acceptance.v1.json").read_text())
    assert acceptance["partial_hsps"] == ["HSP-13"]
    assert acceptance["regression_only_hsps"] == ["HSP-18"]
    assert "HSP-15" not in acceptance["claims"]
    assert acceptance["no_new_claim_hsps"] == ["HSP-15"]


def test_vision_retains_future_hsp15_contract_and_eventual_commands() -> None:
    vision = (ROOT / "VISION.md").read_text()

    assert "Fixture: stage ledger with one lane per gate and scheduled-cycle evidence." in vision
    assert "Retain: signed stage ledger, recovery-drill report, and per-lane cycle receipts." in vision
    for command in (
        "hound-research ingest search",
        "hound-research ingest url",
        "hound-research ingest file",
        "hound-research ingest media",
        "hound-research transcribe --capture-id <capture-id>",
        "hound-research journal query",
        "hound-research journal get",
        "hound-research journal verify",
        "hound-research journal rebuild-index",
        "hound-research import-record",
    ):
        assert command in vision


def _scanner_fixture(tmp_path: Path, source: str):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "legacy.py").write_text(source)
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy.py"]
    manifest["consumers"][0]["legacy_paths"] = ["legacy.py"]
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []
    return manifest, workspace


@pytest.mark.parametrize(
    "source",
    [
        'requests.post("https://api.tavily.com/search")\n',
        'requests.post(url="https://api.tavily.com/search")\n',
        'requests.request("POST", "https://api.tavily.com/search")\n',
        'requests.request(method="POST", url="https://api.tavily.com/search")\n',
        'requests.request(url="https://api.tavily.com/search", method="POST")\n',
        'httpx.request("POST", "https://api.tavily.com/search")\n',
        'httpx.request(method="POST", url="https://api.tavily.com/search")\n',
        'httpx.request(url="https://api.tavily.com/search", method="POST")\n',
        'urllib.request.urlopen(urllib.request.Request("https://api.tavily.com/search"))\n',
        'urllib.request.urlopen(urllib.request.Request(url="https://api.tavily.com/search"))\n',
    ],
)
def test_raw_api_host_call_forms_fail_with_exact_unclassified_error(tmp_path: Path, source: str) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == ["unclassified provider-specific indicator: legacy.py:1"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ('requests.post(\n    "https://api.tavily.com/search"\n)\n', 1),
        ('urllib.request.urlopen(\n    urllib.request.Request(\n        "https://api.tavily.com/search"\n    )\n)\n', 1),
        ('import requests as rq\nrq.post("https://api.tavily.com/search")\n', 2),
        ('from requests import post\npost("https://api.tavily.com/search")\n', 2),
        ('import httpx as hx\nhx.post("https://api.tavily.com/search")\n', 2),
        ('from httpx import post as send\nsend("https://api.tavily.com/search")\n', 2),
        ('import urllib.request as ur\nur.urlopen(ur.Request("https://api.tavily.com/search"))\n', 2),
        ('from urllib.request import Request as Req, urlopen as open_url\nopen_url(Req("https://api.tavily.com/search"))\n', 2),
    ],
)
def test_multiline_and_aliased_raw_api_calls_fail_closed(
    tmp_path: Path, source: str, line: int
) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == [f"unclassified provider-specific indicator: legacy.py:{line}"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ('requests.post(\n    # )\n    "https://api.tavily.com/search"\n)\n', 1),
        ('from requests import (\n    post as send,\n)\nsend(\n    "https://api.tavily.com/search"\n)\n', 4),
        ('requests.Session().post("https://api.tavily.com/search")\n', 1),
        ('urllib.request.build_opener().open(urllib.request.Request("https://api.tavily.com/search"))\n', 1),
        ('import requests as rq\nrq.Session().post("https://api.tavily.com/search")\n', 2),
        ('from requests import Session as TrustedSession\nTrustedSession().post("https://api.tavily.com/search")\n', 2),
        ('import httpx as hx\nhx.Client().post("https://api.tavily.com/search")\n', 2),
        ('from httpx import Client as TrustedClient\nTrustedClient().post("https://api.tavily.com/search")\n', 2),
        ('import urllib.request as ur\nur.build_opener().open(ur.Request("https://api.tavily.com/search"))\n', 2),
        ('from urllib.request import build_opener as opener\nopener().open("https://api.tavily.com/search")\n', 2),
    ],
)
def test_python_ast_transport_forms_fail_with_exact_unclassified_error(
    tmp_path: Path, source: str, line: int
) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == [f"unclassified provider-specific indicator: legacy.py:{line}"]


def test_python_transport_parse_error_fails_closed(tmp_path: Path) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, "requests.post(\n")

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == ["scan file legacy.py: python transport parse error"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ('import requests\nsession = requests.Session()\nsession.post("https://api.tavily.com/search")\n', 3),
        ('from requests import Session as MakeSession\nsession = MakeSession()\nsession.post("https://api.tavily.com/search")\n', 3),
        ('import httpx\nclient: httpx.Client = httpx.Client()\nclient.post("https://api.tavily.com/search")\n', 3),
        ('from httpx import AsyncClient as MakeClient\nclient: MakeClient = MakeClient()\nclient.post("https://api.tavily.com/search")\n', 3),
        ('import urllib.request\nopener = urllib.request.build_opener()\nopener.open("https://api.tavily.com/search")\n', 3),
        ('import requests\nsession = requests.Session()\nsession = object()\nsession.post("https://api.tavily.com/search")\n', 4),
    ],
)
def test_public_cli_detects_bound_transport_instances(
    tmp_path: Path, source: str, line: int
) -> None:
    manifest = _manifest()
    workspace = _workspace_for_manifest(tmp_path, manifest)
    scan_root = next(
        Path(path)
        for row in manifest["consumers"]
        for path in row["scan_roots"]
        if Path(path).suffix == ".py"
    )
    (workspace / scan_root).write_text(source)

    completed = _cli("--workspace", str(workspace), "--json")

    report = json.loads(completed.stdout)
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert report["errors"] == [f"unclassified provider-specific indicator: {scan_root}:{line}"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ('import requests\nwith requests.Session() as session:\n    session.post("https://api.tavily.com/search")\n', 3),
        ('import httpx\nasync def run():\n    async with httpx.AsyncClient() as client:\n        await client.post("https://api.tavily.com/search")\n', 4),
        ('from requests import Session as MakeSession\nwith MakeSession() as session:\n    session.post("https://api.tavily.com/search")\n', 3),
        ('import httpx as hx\nasync def run():\n    async with hx.AsyncClient() as client:\n        await client.post("https://api.tavily.com/search")\n', 4),
        ('from urllib.request import build_opener as make_opener\nwith make_opener() as opener:\n    opener.open("https://api.tavily.com/search")\n', 3),
        ('import requests\nwith requests.Session() as session:\n    session = object()\n    session.post("https://api.tavily.com/search")\n', 4),
    ],
)
def test_public_cli_detects_context_managed_transport_instances(
    tmp_path: Path, source: str, line: int
) -> None:
    manifest = _manifest()
    workspace = _workspace_for_manifest(tmp_path, manifest)
    scan_root = next(
        Path(path)
        for row in manifest["consumers"]
        for path in row["scan_roots"]
        if Path(path).suffix == ".py"
    )
    (workspace / scan_root).write_text(source)

    completed = _cli("--workspace", str(workspace), "--json")

    report = json.loads(completed.stdout)
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert report["errors"] == [f"unclassified provider-specific indicator: {scan_root}:{line}"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ('import httpx as hx\nbound = hx.Client()\nbound.post("https://api.tavily.com/search")\n', 3),
        ('import httpx as hx\nbound: hx.AsyncClient = hx.AsyncClient()\nbound.post("https://api.tavily.com/search")\n', 3),
        ('import httpx as hx\nwith hx.Client() as bound:\n    bound.post("https://api.tavily.com/search")\n', 3),
        ('import httpx as hx\nasync def run():\n    async with hx.AsyncClient() as bound:\n        await bound.post("https://api.tavily.com/search")\n', 4),
        ('import requests as rq\nbound = rq.Session()\nbound.post("https://api.tavily.com/search")\n', 3),
        ('import urllib.request as ur\nwith ur.build_opener() as bound:\n    bound.open("https://api.tavily.com/search")\n', 3),
    ],
)
def test_public_cli_module_alias_constructor_bindings_report_only_endpoint(
    tmp_path: Path, source: str, line: int
) -> None:
    manifest = _manifest()
    workspace = _workspace_for_manifest(tmp_path, manifest)
    scan_root = next(
        Path(path)
        for row in manifest["consumers"]
        for path in row["scan_roots"]
        if Path(path).suffix == ".py"
    )
    (workspace / scan_root).write_text(source)

    completed = _cli("--workspace", str(workspace), "--json")

    report = json.loads(completed.stdout)
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert report["errors"] == [f"unclassified provider-specific indicator: {scan_root}:{line}"]


def test_transport_alias_suppression_is_limited_to_its_import_and_call_nodes(tmp_path: Path) -> None:
    source = (
        "import requests as MYSTERY_TOKEN\n"
        'MYSTERY_TOKEN.post("https://example.com")\n'
        'MYSTERY_TOKEN = os.getenv("MYSTERY_TOKEN")\n'
    )
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == ["unclassified provider-specific indicator: legacy.py:3"]


def test_trusted_client_alias_on_known_provider_host_has_no_alias_false_positive(tmp_path: Path) -> None:
    source = (
        "from httpx import Client as TrustedClient\n"
        'TrustedClient().post("https://api.exa.ai/search")\n'
    )
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.failures == []
    assert [finding["indicator_id"] for finding in result.findings] == ["exa-endpoint"]


@pytest.mark.parametrize(("blocked", "expected"), [("legacy", "legacy"), ("legacy/blocked", "legacy/blocked")])
def test_directory_scan_fails_closed_for_unreadable_directories(
    tmp_path: Path, blocked: str, expected: str
) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "legacy"
    root.mkdir(parents=True)
    path = workspace / blocked
    path.mkdir(exist_ok=True)
    os.chmod(path, 0)
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy"]
    manifest["consumers"][0]["legacy_paths"] = []
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []
    try:
        result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)
    finally:
        os.chmod(path, 0o700)

    assert result.findings == []
    assert result.failures == [f"scan directory {expected}: unreadable"]


def test_scan_candidate_limit_stops_stream_before_materialising_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "legacy"
    root.mkdir(parents=True)
    seen = 0

    class Entry:
        def __init__(self, name: str) -> None:
            self.name = name
            self.path = str(root / name)

        def is_dir(self, *, follow_symlinks: bool) -> bool:
            return False

    class Entries:
        def __iter__(self):
            return self

        def __next__(self):
            nonlocal seen
            if seen == 3:
                raise AssertionError("directory stream was materialised past the cap")
            seen += 1
            return Entry(str(seen))

    class ScanDir:
        def __enter__(self):
            return Entries()

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(consumer_inventory, "MAX_SCAN_ENTRIES", 2)
    monkeypatch.setattr(consumer_inventory.os, "scandir", lambda _path: ScanDir())
    monkeypatch.setattr(consumer_inventory, "_path_problem", lambda _path, _workspace: None)
    failures: list[str] = []

    candidates = _scan_candidates(root, workspace, failures)

    assert candidates == []
    assert seen == 3
    assert failures == ["scan directory legacy: exceeds 2 entries"]


@pytest.mark.parametrize(
    ("source", "bound", "expected"),
    [
        (
            "import requests as r1\nimport requests as r2\nimport requests as r3\n",
            "MAX_TRANSPORT_ALIASES",
            "scan file legacy.py: transport aliases exceeds 2",
        ),
        (
            'requests.post("https://api.tavily.com/search")\n' * 3,
            "MAX_TRANSPORT_CALLS",
            "scan file legacy.py: transport calls exceeds 2",
        ),
    ],
)
def test_transport_scan_bounds_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, bound: str, expected: str
) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, source)
    monkeypatch.setattr(consumer_inventory, bound, 2)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == [expected]


@pytest.mark.parametrize(
    ("source", "expected_failures"),
    [
        ("EXA_API_KEY = 'known'\n", []),
        ("EXA_API_KEY = 'known'; MYSTERY_TOKEN = 'unknown'\n", ["unclassified provider-specific indicator: legacy.py:1"]),
        ("# firecrawl provider_response hound_id: known MYSTERY_TOKEN\n", ["unclassified provider-specific indicator: legacy.py:1"]),
    ],
)
def test_unknown_candidates_are_suppressed_only_by_their_own_known_indicator(
    tmp_path: Path, source: str, expected_failures: list[str]
) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.failures == expected_failures
    if source.startswith("EXA_API_KEY"):
        assert [finding["indicator_id"] for finding in result.findings] == ["exa-credential"]


@pytest.mark.parametrize(
    ("source", "expected_failures"),
    [
        ("CSRF_TOKEN = 'local'\n", []),
        ("PAGINATION_TOKEN = 'local'\n", []),
        ("LOCAL_CANCEL_TOKEN = 'local'\n", []),
        ("LOCAL_TAVILY_TOKEN = 'unknown'\n", ["unclassified provider-specific indicator: legacy.py:1"]),
        ("MYSTERY_TOKEN = 'unknown'\n", ["unclassified provider-specific indicator: legacy.py:1"]),
        ("MYSTERY_API_KEY = 'unknown'\n", ["unclassified provider-specific indicator: legacy.py:1"]),
    ],
)
def test_provider_token_classifier_ignores_local_control_tokens(
    tmp_path: Path, source: str, expected_failures: list[str]
) -> None:
    manifest, workspace = _scanner_fixture(tmp_path, source)

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == expected_failures


@pytest.mark.parametrize(("pointer", "control"), [("contract_ref", "\x00"), ("evidence.baseline_scan", "\x00"), ("contract_ref", "\u202e"), ("evidence.baseline_scan", "\u202e")])
def test_control_bearing_path_references_fail_closed_in_validator_and_live_cli(
    tmp_path: Path, pointer: str, control: str
) -> None:
    manifest = _manifest()
    workspace = _workspace_for_manifest(tmp_path, manifest)
    if pointer == "contract_ref":
        manifest["consumers"][0]["contract_ref"] = f"contracts/{control}bad.md"
        expected = "consumers[0].contract_ref contains control characters"
    else:
        manifest["consumers"][0]["evidence"]["baseline_scan"] = f"evidence/{control}bad.json"
        expected = "consumers[0].evidence.baseline_scan contains control characters"
    manifest_path = _write_manifest(tmp_path, manifest)

    errors = validate_inventory(manifest, require_paths=True, workspace=workspace)
    completed = _cli("--workspace", str(workspace), "--manifest", str(manifest_path), "--json")

    assert expected in errors
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert expected in json.loads(completed.stdout)["errors"]


def test_directory_scan_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "legacy"
    root.mkdir(parents=True)
    os.mkfifo(root / "pipe")
    manifest = _manifest()
    manifest["consumers"][0]["scan_roots"] = ["legacy"]
    manifest["consumers"][0]["legacy_paths"] = []
    for row in manifest["consumers"][1:]:
        row["scan_roots"] = []
        row["legacy_paths"] = []

    result = _scan_workspace(manifest, load_catalog(CATALOG), workspace)

    assert result.findings == []
    assert result.failures == ["scan file legacy/pipe: not a regular file"]


class _StringSubclass(str):
    pass


class _RaisingString(str):
    hooks = 0

    def __eq__(self, other: object) -> bool:
        type(self).hooks += 1
        raise AssertionError("hostile string equality")

    def __ne__(self, other: object) -> bool:
        type(self).hooks += 1
        raise AssertionError("hostile string inequality")


class _RaisingList(list):
    hooks = 0

    def __eq__(self, other: object) -> bool:
        type(self).hooks += 1
        raise AssertionError("hostile list equality")

    def __ne__(self, other: object) -> bool:
        type(self).hooks += 1
        raise AssertionError("hostile list inequality")


class _RaisingIterList(list):
    hooks = 0

    def __iter__(self):
        type(self).hooks += 1
        raise AssertionError("hostile list iteration")


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("inventory-schema", "inventory.schema_version must be exact builtin type str"),
        ("catalog-schema", "catalog.schema_version must be exact builtin type str"),
        ("adapter-list", "inventory.adapter_allowlist must be exact builtin type list"),
        ("stage-element", "inventory.stage_order[0] must be exact builtin type str"),
        ("exclusion-element", "inventory.allowed_exclusions[0] must be exact builtin type str"),
        ("adapter-element", "inventory.adapter_allowlist[0] must be exact builtin type str"),
        ("row-stage", "consumers[0].stage must be exact builtin type str"),
    ],
)
def test_invalid_exact_types_never_run_hostile_comparison_hooks(
    target: str, expected: str
) -> None:
    _RaisingString.hooks = 0
    _RaisingList.hooks = 0
    if target == "catalog-schema":
        value = json.loads(CATALOG.read_text())
        value["schema_version"] = _RaisingString(value["schema_version"])
        errors = validate_catalog(value)
    else:
        value = _manifest()
        if target == "inventory-schema":
            value["schema_version"] = _RaisingString(value["schema_version"])
        elif target == "adapter-list":
            value["adapter_allowlist"] = _RaisingList(value["adapter_allowlist"])
        elif target == "stage-element":
            value["stage_order"][0] = _RaisingString(value["stage_order"][0])
        elif target == "exclusion-element":
            value["allowed_exclusions"][0] = _RaisingString(value["allowed_exclusions"][0])
        elif target == "adapter-element":
            value["adapter_allowlist"][0] = _RaisingString(value["adapter_allowlist"][0])
        elif target == "row-stage":
            value["consumers"][0]["stage"] = _RaisingString(value["consumers"][0]["stage"])
        else:
            raise AssertionError(target)
        errors = validate_inventory(value)

    assert expected in errors
    assert _RaisingString.hooks == 0
    assert _RaisingList.hooks == 0


def test_invalid_nested_container_never_reaches_canonical_digest() -> None:
    _RaisingIterList.hooks = 0
    inventory = _manifest()
    inventory["consumers"][0]["scan_roots"] = _RaisingIterList(
        inventory["consumers"][0]["scan_roots"]
    )

    errors = validate_inventory(inventory)

    assert "consumers[0].scan_roots must be exact builtin type list" in errors
    assert "consumer rows must match the exact canonical closure" in errors
    assert _RaisingIterList.hooks == 0


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("inventory-top-int", "inventory key must be exact builtin type str"),
        ("inventory-top-subclass", "inventory key must be exact builtin type str"),
        ("catalog-pairing-int", "catalog.pairing_rules key must be exact builtin type str"),
        ("catalog-pairing-subclass", "catalog.pairing_rules key must be exact builtin type str"),
    ],
)
def test_object_key_boundaries_reject_hostile_key_types_without_crashing(
    target: str, expected: str
) -> None:
    if target.startswith("inventory"):
        value = _manifest()
        if target.endswith("int"):
            value[1] = "unexpected"
        else:
            value = {
                (_StringSubclass(key) if key == "schema_version" else key): child
                for key, child in value.items()
            }
        errors = validate_inventory(value)
    else:
        value = json.loads(CATALOG.read_text())
        rules = value["pairing_rules"]
        if target.endswith("int"):
            rules[1] = ["unexpected"]
        else:
            value["pairing_rules"] = {
                _StringSubclass(key): child for key, child in rules.items()
            }
        errors = validate_catalog(value)

    assert expected in errors


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda value: value.__setitem__("schema_version", _StringSubclass(value["schema_version"])), "inventory.schema_version must be exact builtin type str"),
        (lambda value: value["stage_order"].__setitem__(0, _StringSubclass(value["stage_order"][0])), "inventory.stage_order[0] must be exact builtin type str"),
        (lambda value: value["allowed_exclusions"].__setitem__(0, _StringSubclass(value["allowed_exclusions"][0])), "inventory.allowed_exclusions[0] must be exact builtin type str"),
        (lambda value: value["adapter_allowlist"].__setitem__(0, _StringSubclass(value["adapter_allowlist"][0])), "inventory.adapter_allowlist[0] must be exact builtin type str"),
    ],
)
def test_inventory_public_validator_rejects_string_subclasses(
    mutation, error: str
) -> None:
    inventory = _manifest()
    mutation(inventory)

    errors = validate_inventory(inventory)

    assert error in errors


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda value: value.__setitem__("schema_version", _StringSubclass(value["schema_version"])), "catalog.schema_version must be exact builtin type str"),
        (
            lambda value: value.__setitem__(
                "pairing_rules",
                {_StringSubclass(key): list(rule) for key, rule in value["pairing_rules"].items()},
            ),
            "catalog.pairing_rules key must be exact builtin type str",
        ),
        (
            lambda value: value["pairing_rules"]["outbound_transport_requires"].__setitem__(
                0, _StringSubclass(value["pairing_rules"]["outbound_transport_requires"][0])
            ),
            "catalog.pairing_rules.outbound_transport_requires[0] must be exact builtin type str",
        ),
    ],
)
def test_catalog_public_validator_rejects_equality_only_string_subclasses(
    mutation, error: str
) -> None:
    catalog = json.loads(CATALOG.read_text())
    mutation(catalog)

    errors = validate_catalog(catalog)

    assert error in errors
