from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from migration.consumer_inventory import InventoryError, load_catalog
from migration.check_domain_ownership import (
    ALLOWLIST_SCHEMA_VERSION,
    DOMAIN_LOGIC_INDICATORS,
    HOUND_INTERNAL_INDICATORS,
    HOUND_LANE,
    classify_line,
    lane_for_path,
    load_allowlist,
    scan_workspace,
    severity_for_path,
)


ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "migration" / "provider-indicators.v1.json"
REAL_ALLOWLIST = ROOT / "migration" / "domain-ownership-allowlist.v1.json"


def _catalog() -> dict[str, object]:
    return load_catalog(CATALOG)


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "migration/check_domain_ownership.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _write(workspace: Path, relative: str, text: str) -> Path:
    path = workspace / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _write_allowlist(path: Path, entries: list[dict[str, object]], schema_version: str | None = None) -> None:
    path.write_text(json.dumps({"schema_version": schema_version or ALLOWLIST_SCHEMA_VERSION, "entries": entries}))


# --- lane grouping -----------------------------------------------------------


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("repos/hound/src/houndd/journal.py", "repos/hound"),
        ("repos/hound/README.md", "repos/hound"),
        ("repos/givecare/gc-sms/lib/foo.ts", "repos/givecare/gc-sms"),
        ("repos/givecare/gc-web/apps/foo.tsx", "repos/givecare/gc-web"),
        ("repos/scty-civic/foo.py", "repos/scty-civic"),
        ("agents/helm/events.db", "agents/helm"),
        ("agents/_skills/foo/SKILL.md", "agents/_skills"),
        ("CLAUDE.md", "CLAUDE.md"),
    ],
)
def test_lane_for_path_groups_by_repo(relative: str, expected: str) -> None:
    assert lane_for_path(Path(relative)) == expected


# --- line classification ------------------------------------------------------


def test_classify_line_detects_domain_logic_indicator() -> None:
    domain_ids, evidence_ids = classify_line("from apscheduler import BackgroundScheduler\n", _catalog())
    assert "scheduler-apscheduler" in domain_ids
    assert evidence_ids == []


def test_classify_line_detects_provider_credential() -> None:
    domain_ids, evidence_ids = classify_line("EXA_API_KEY = os.environ['EXA_API_KEY']\n", _catalog())
    assert domain_ids == []
    assert "exa-credential" in evidence_ids


def test_classify_line_detects_houndd_internal_import() -> None:
    domain_ids, evidence_ids = classify_line("from houndd.journal import Journal\n", _catalog())
    assert domain_ids == []
    assert "houndd-journal-import" in evidence_ids


def test_classify_line_no_indicators_is_empty() -> None:
    assert classify_line("print('hello world')\n", _catalog()) == ([], [])


def test_classify_line_ignores_unpaired_transport_and_artifact_categories() -> None:
    # outbound_transport/evidence_artifact need same-file provider pairing to
    # be meaningful (consumer_inventory owns that nuance); E3 deliberately
    # does not re-derive it, so a bare "requests." must not, by itself, read
    # as evidence mechanics.
    domain_ids, evidence_ids = classify_line("requests.get(url)\n", _catalog())
    assert domain_ids == []
    assert evidence_ids == []


def test_classify_line_detects_prompt_skill_acquisition() -> None:
    domain_ids, evidence_ids = classify_line("use the playwright skill directly\n", _catalog())
    assert domain_ids == []
    assert "playwright-skill" in evidence_ids


def test_indicator_catalogs_have_no_duplicate_ids() -> None:
    ids = [item["id"] for item in DOMAIN_LOGIC_INDICATORS]
    assert len(ids) == len(set(ids))
    ids = [item["id"] for item in HOUND_INTERNAL_INDICATORS]
    assert len(ids) == len(set(ids))


# --- scan_workspace: Hound side (repos/hound) ---------------------------------


def test_hound_repo_domain_logic_is_a_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/scheduler.py", "import croniter\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.failures == []
    assert any("Hound repo path" in v and "croniter" in v for v in result.violations)
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == HOUND_LANE)
    assert lane["domain_logic_files"] == [{"path": "repos/hound/src/houndd/scheduler.py", "indicator_ids": ["scheduler-croniter"]}]


def test_hound_repo_evidence_mechanics_is_not_a_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/journal.py", "# writes chain.jsonl\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.failures == []
    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == HOUND_LANE)
    assert lane["evidence_mechanics_files"] == [
        {"path": "repos/hound/src/houndd/journal.py", "indicator_ids": ["chain-jsonl-reference"]}
    ]


# --- scan_workspace: domain repos ---------------------------------------------


def test_domain_repo_evidence_mechanics_is_a_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-sms/lib/exa.py", "EXA_API_KEY = 'x'\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.failures == []
    assert any("domain repo path" in v and "exa-credential" in v for v in result.violations)
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-sms")
    assert lane["evidence_mechanics_files"] == [
        {"path": "repos/givecare/gc-sms/lib/exa.py", "indicator_ids": ["exa-credential"]}
    ]


def test_domain_repo_houndd_internal_import_is_a_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-sms/lib/bypass.py", "from houndd.store import Store\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert any("domain repo path" in v and "houndd-store-import" in v for v in result.violations)


def test_domain_repo_domain_logic_is_not_a_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-gtm/crm.py", "class ContactStore: ...\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-gtm")
    assert lane["domain_logic_files"] == [{"path": "repos/givecare/gc-gtm/crm.py", "indicator_ids": ["crm-contact-store"]}]


def test_clean_file_appears_with_no_findings(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/scty-civic/main.py", "print('civic')\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/scty-civic")
    assert lane == {
        "lane": "repos/scty-civic",
        "domain_logic_files": [],
        "evidence_mechanics_files": [],
        "evidence_mechanics_documentation": [],
        "evidence_mechanics_allowlisted": [],
    }


def test_multiple_lanes_are_grouped_and_reported_independently(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/scheduler.py", "import croniter\n")
    _write(workspace, "repos/givecare/gc-sms/lib/exa.py", "EXA_API_KEY = 'x'\n")
    _write(workspace, "agents/helm/watcher.py", "print('helm ok')\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos", "agents"))

    lanes = {entry["lane"] for entry in result.capability_dump["lanes"]}
    assert lanes == {"repos/hound", "repos/givecare/gc-sms", "agents/helm"}
    assert len(result.violations) == 2


def test_default_roots_cover_repos_and_agents(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/scty-civic/main.py", "print('civic')\n")
    _write(workspace, "agents/helm/watcher.py", "print('helm')\n")

    result = scan_workspace(workspace, _catalog())

    lanes = {entry["lane"] for entry in result.capability_dump["lanes"]}
    assert lanes == {"repos/scty-civic", "agents/helm"}


# --- safety / fail-closed -----------------------------------------------------


def test_symlink_escape_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    outside.mkdir(parents=True)
    (outside / "evil.py").write_text("import croniter\n")
    linked_dir = workspace / "repos" / "hound"
    linked_dir.parent.mkdir(parents=True)
    linked_dir.symlink_to(outside, target_is_directory=True)

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert any("symlink" in failure for failure in result.failures)
    assert result.violations == []


def test_missing_scan_root_reports_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert any("repos" in failure for failure in result.failures)


def test_non_utf8_file_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    path = workspace / "repos" / "hound" / "bad.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xff\xfe\x00")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert any("non-UTF-8" in failure for failure in result.failures)


def test_symlinks_inside_node_modules_do_not_produce_scan_failures(tmp_path: Path) -> None:
    # Whole-repo HSP-19 scanning hits pnpm's node_modules trees, which are
    # thousands of hoisting symlinks. Pruning excluded directory names
    # (node_modules, .venv, .hound, ...) before descending -- rather than
    # only filtering the returned candidate list afterward -- keeps that
    # from flooding the report with scanner-infrastructure noise. On the
    # real gc-sms repo this dropped a whole-lane scan from 1212 "uses
    # symlink" failures to zero.
    workspace = tmp_path / "workspace"
    real_target = tmp_path / "outside-package"
    real_target.mkdir()
    (real_target / "index.js").write_text("module.exports = {};\n")

    node_modules = workspace / "repos" / "givecare" / "gc-x" / "node_modules" / ".pnpm" / "some-pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "linked").symlink_to(real_target, target_is_directory=True)
    _write(workspace, "repos/givecare/gc-x/main.py", "print('clean')\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert not any("symlink" in failure for failure in result.failures)
    assert result.violations == []


def test_symlink_directly_under_a_scanned_path_still_fails_closed(tmp_path: Path) -> None:
    # Pruning only skips *excluded* directory names. A symlink anywhere else
    # in the tree must still be refused -- pruning narrows scope, it does
    # not weaken the fail-closed symlink discipline.
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_text("import croniter\n")
    linked = workspace / "repos" / "givecare" / "gc-x" / "src"
    linked.parent.mkdir(parents=True)
    linked.symlink_to(outside, target_is_directory=True)

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert any("uses symlink" in failure for failure in result.failures)
    assert result.violations == []


def test_hound_receipt_directory_is_excluded_from_domain_repo_scan(tmp_path: Path) -> None:
    # .hound holds Hound's own run/plan/record receipts written into a
    # driven consumer repo -- those are Hound's evidence-mechanics
    # artifacts by construction, not the domain repo authoring evidence
    # mechanics. On the real gc-benefits repo this excluded 285
    # false-positive hits (adapter-manifest.json/record.json receipts).
    workspace = tmp_path / "workspace"
    _write(
        workspace,
        "repos/givecare/gc-x/.hound/web/abc123/adapter-manifest.json",
        '{"provider": "firecrawl", "endpoint": "api.firecrawl.dev"}\n',
    )
    _write(workspace, "repos/givecare/gc-x/main.py", "print('clean')\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-x")
    assert lane["evidence_mechanics_files"] == []
    assert not any(hit["path"].startswith("repos/givecare/gc-x/.hound/") for hit in result.capability_dump["hits"])


# --- canonical output ----------------------------------------------------------


def test_capability_dump_is_sorted_and_deterministic(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/b_scheduler.py", "import croniter\n")
    _write(workspace, "repos/hound/src/houndd/a_scheduler.py", "import croniter\n")

    first = scan_workspace(workspace, _catalog(), roots=("repos",))
    second = scan_workspace(workspace, _catalog(), roots=("repos",))

    paths = [item["path"] for item in first.capability_dump["lanes"][0]["domain_logic_files"]]
    assert paths == sorted(paths)
    assert json.dumps(first.capability_dump, sort_keys=True) == json.dumps(second.capability_dump, sort_keys=True)


def test_hits_carry_line_number_category_and_class(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(
        workspace,
        "repos/givecare/gc-x/pipeline.py",
        "print('noop')\nFIRECRAWL_API_KEY = os.environ['FIRECRAWL_API_KEY']\n",
    )

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    hits = [h for h in result.capability_dump["hits"] if h["path"] == "repos/givecare/gc-x/pipeline.py"]
    assert hits == [
        {
            "lane": "repos/givecare/gc-x",
            "path": "repos/givecare/gc-x/pipeline.py",
            "line": 2,
            "indicator_id": "firecrawl-credential",
            "category": "credential_name",
            "class": "evidence_mechanics",
            "severity": "code",
            "allowlisted": False,
            "allowlist_reason": None,
        }
    ]


def test_hound_repo_domain_logic_hit_is_classed_correctly(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/scheduler.py", "import croniter\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    hit = next(h for h in result.capability_dump["hits"] if h["indicator_id"] == "scheduler-croniter")
    assert hit["lane"] == HOUND_LANE
    assert hit["class"] == "domain_logic"
    assert hit["category"] == "scheduler"


# --- documentation severity: docs are reported, not enforced -------------------


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("repos/givecare/gc-benefits/README.md", "documentation"),
        ("repos/givecare/gc-benefits/docs/agents.md", "documentation"),
        ("repos/givecare/gc-benefits/AUTOMATION.md", "documentation"),
        ("repos/givecare/gc-benefits/src/benefit_engine/firecrawl.py", "code"),
        ("repos/givecare/gc-benefits/.env", "code"),
        ("repos/givecare/gc-benefits/data/source_registry.jsonl", "code"),
    ],
)
def test_severity_for_path(relative: str, expected: str) -> None:
    assert severity_for_path(Path(relative)) == expected


def test_readme_credential_mention_is_documentation_not_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-x/README.md", "Export FIRECRAWL_API_KEY before running the pipeline.\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-x")
    assert lane["evidence_mechanics_files"] == []
    assert lane["evidence_mechanics_documentation"] == [
        {"path": "repos/givecare/gc-x/README.md", "indicator_ids": ["firecrawl-credential"]}
    ]


def test_code_file_credential_use_is_still_a_violation_alongside_docs(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-x/README.md", "Export FIRECRAWL_API_KEY first.\n")
    _write(workspace, "repos/givecare/gc-x/pipeline.py", "FIRECRAWL_API_KEY = os.environ['FIRECRAWL_API_KEY']\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert any("pipeline.py" in v and "firecrawl-credential" in v for v in result.violations)
    assert not any("README.md" in v for v in result.violations)


# --- clean repo fixture: green end-to-end ---------------------------------------


def test_clean_repo_fixture_scans_green(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-clean/README.md", "# gc-clean\nA repo with no provider acquisition.\n")
    _write(workspace, "repos/givecare/gc-clean/src/main.py", "def main():\n    print('hello')\n")
    _write(workspace, "repos/givecare/gc-clean/scripts/build.sh", "#!/bin/sh\necho building\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",))

    assert result.failures == []
    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-clean")
    assert lane["evidence_mechanics_files"] == []
    assert lane["evidence_mechanics_documentation"] == []
    assert lane["domain_logic_files"] == []


def test_sibling_direct_provider_pipeline_outside_scan_roots_is_detected(tmp_path: Path) -> None:
    """Reproduces the 2026-08-05 federation-review finding at fixture scale:
    a consumer lane's declared scan_roots (e.g. AUTOMATION.md,
    daily_hound_radar.py, hound-driver.json) name only the houndd-integrated
    entry point. A sibling direct-provider pipeline living elsewhere in the
    same repo must still be caught because scan_workspace's DEFAULT_ROOTS
    already walk whole repos, not a scan_roots list -- the scan_roots
    limitation lives in consumer_inventory's per-lane evidence, not here."""

    workspace = tmp_path / "workspace"
    # The lane's declared scan_roots analog -- clean, houndd-integrated.
    _write(workspace, "repos/givecare/gc-benefits/hound-driver.json", '{"owner": {"repo": "gc-benefits"}}\n')
    _write(workspace, "repos/givecare/gc-benefits/scripts/daily_hound_radar.py", "# uses houndd only\n")
    # The sibling pipeline a scan_roots-limited scanner would never look at.
    _write(
        workspace,
        "repos/givecare/gc-benefits/src/benefit_engine/firecrawl.py",
        "import firecrawl\nFIRECRAWL_API_KEY = os.environ['FIRECRAWL_API_KEY']\nENDPOINT = 'api.firecrawl.dev'\n",
    )
    _write(workspace, "repos/givecare/gc-benefits/scripts/enrich_programs.py", "import firecrawl\n")
    _write(workspace, "repos/givecare/gc-benefits/.env", "FIRECRAWL_API_KEY=secret\n")

    # A scanner limited to the declared scan_roots would only see these two files:
    scoped_result = scan_workspace(
        workspace,
        _catalog(),
        roots=("repos/givecare/gc-benefits/hound-driver.json", "repos/givecare/gc-benefits/scripts/daily_hound_radar.py"),
    )
    assert scoped_result.violations == []  # this is the bug the review found

    # scan_workspace's whole-repo walk catches it.
    whole_repo_result = scan_workspace(workspace, _catalog(), roots=("repos",))
    violation_paths = set(whole_repo_result.violations)
    assert any("firecrawl.py" in v for v in violation_paths)
    assert any("enrich_programs.py" in v for v in violation_paths)
    assert any(".env" in v for v in violation_paths)


# --- allowlist: loading and validation ------------------------------------------


def test_real_allowlist_config_is_valid_and_starts_empty() -> None:
    entries = load_allowlist(REAL_ALLOWLIST)
    assert entries == ()


def test_load_allowlist_accepts_a_well_formed_entry(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(
        path,
        [
            {
                "path_pattern": "repos/givecare/gc-benefits/src/benefit_engine/*.py",
                "reason": "pending owner decision",
                "decision_ref": "task-8",
            }
        ],
    )

    entries = load_allowlist(path)

    assert len(entries) == 1
    assert entries[0]["path_pattern"] == "repos/givecare/gc-benefits/src/benefit_engine/*.py"


@pytest.mark.parametrize(
    "entries",
    [
        [{"path_pattern": "x", "reason": "", "decision_ref": "D1"}],  # empty reason
        [{"path_pattern": "x", "reason": "ok"}],  # missing decision_ref
        [{"path_pattern": "", "reason": "ok", "decision_ref": "D1"}],  # empty pattern
        [{"reason": "ok", "decision_ref": "D1"}],  # missing path_pattern
        ["not-an-object"],
    ],
)
def test_load_allowlist_rejects_malformed_entries(tmp_path: Path, entries: list[object]) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, entries)  # type: ignore[arg-type]

    with pytest.raises(InventoryError):
        load_allowlist(path)


def test_load_allowlist_rejects_wrong_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _write_allowlist(path, [], schema_version="hound.migration.domain-ownership-allowlist.v0")

    with pytest.raises(InventoryError):
        load_allowlist(path)


def test_load_allowlist_rejects_non_object_top_level(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text("[]")

    with pytest.raises(InventoryError):
        load_allowlist(path)


def test_load_allowlist_rejects_entries_not_a_list(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"schema_version": ALLOWLIST_SCHEMA_VERSION, "entries": "nope"}))

    with pytest.raises(InventoryError):
        load_allowlist(path)


def test_load_allowlist_rejects_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text("{not json")

    with pytest.raises(InventoryError):
        load_allowlist(path)


def test_load_allowlist_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(InventoryError):
        load_allowlist(tmp_path / "missing.json")


# --- allowlist: suppression + visibility ----------------------------------------


def test_allowlisted_path_is_not_a_violation_but_stays_visible(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-benefits/src/benefit_engine/firecrawl.py", "FIRECRAWL_API_KEY = 'x'\n")
    allowlist = (
        {
            "path_pattern": "repos/givecare/gc-benefits/src/benefit_engine/*.py",
            "reason": "pending owner decision on residual provider keys (task #8)",
            "decision_ref": "pending owner decision",
        },
    )

    result = scan_workspace(workspace, _catalog(), roots=("repos",), allowlist=allowlist)

    assert result.violations == []
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-benefits")
    assert lane["evidence_mechanics_files"] == []
    assert lane["evidence_mechanics_allowlisted"] == [
        {
            "path": "repos/givecare/gc-benefits/src/benefit_engine/firecrawl.py",
            "indicator_ids": ["firecrawl-credential"],
            "reason": "pending owner decision on residual provider keys (task #8)",
            "decision_ref": "pending owner decision",
        }
    ]
    hit = next(h for h in result.capability_dump["hits"] if h["path"].endswith("firecrawl.py"))
    assert hit["allowlisted"] is True
    assert hit["allowlist_reason"] == "pending owner decision on residual provider keys (task #8)"


def test_allowlist_pattern_does_not_match_unrelated_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-benefits/scripts/ingest_batch.py", "FIRECRAWL_API_KEY = 'x'\n")
    allowlist = (
        {"path_pattern": "repos/givecare/gc-benefits/src/benefit_engine/*.py", "reason": "narrowly scoped", "decision_ref": "D1"},
    )

    result = scan_workspace(workspace, _catalog(), roots=("repos",), allowlist=allowlist)

    assert any("ingest_batch.py" in v for v in result.violations)
    lane = next(entry for entry in result.capability_dump["lanes"] if entry["lane"] == "repos/givecare/gc-benefits")
    assert lane["evidence_mechanics_allowlisted"] == []


def test_empty_allowlist_suppresses_nothing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/givecare/gc-benefits/.env", "FIRECRAWL_API_KEY=secret\n")

    result = scan_workspace(workspace, _catalog(), roots=("repos",), allowlist=())

    assert any(".env" in v for v in result.violations)


def test_allowlist_does_not_suppress_documentation_or_domain_logic(tmp_path: Path) -> None:
    # The allowlist is scoped to evidence-mechanics suppression; it must not
    # accidentally reach into Hound-repo domain-logic violations via a
    # broad glob.
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/scheduler.py", "import croniter\n")
    allowlist = ({"path_pattern": "repos/hound/**", "reason": "too broad on purpose", "decision_ref": "D1"},)

    result = scan_workspace(workspace, _catalog(), roots=("repos",), allowlist=allowlist)

    assert any("croniter" in v for v in result.violations)


# --- CLI -----------------------------------------------------------------


def test_cli_clean_workspace_passes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/scty-civic/main.py", "print('civic')\n")

    completed = _cli("--workspace", str(workspace), "--root", "repos", "--json")

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["valid"] is True
    assert report["capability_dump"] is not None


def test_cli_violation_exits_nonzero_and_reports(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "repos/hound/src/houndd/scheduler.py", "import croniter\n")

    completed = _cli("--workspace", str(workspace), "--root", "repos", "--json")

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["valid"] is False
    assert any("croniter" in error for error in report["errors"])


def test_cli_malformed_arguments_return_error_without_traceback() -> None:
    completed = _cli("--workspace")
    assert completed.returncode == 2
    assert "Traceback" not in completed.stderr


def test_cli_missing_workspace_reports_failure_without_traceback(tmp_path: Path) -> None:
    completed = _cli("--workspace", str(tmp_path / "missing"), "--json")
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    report = json.loads(completed.stdout)
    assert report["valid"] is False
