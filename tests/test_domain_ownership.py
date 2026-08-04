from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from migration.consumer_inventory import load_catalog
from migration.check_domain_ownership import (
    DOMAIN_LOGIC_INDICATORS,
    HOUND_INTERNAL_INDICATORS,
    HOUND_LANE,
    classify_line,
    lane_for_path,
    scan_workspace,
)


ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "migration" / "provider-indicators.v1.json"


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
    assert lane == {"lane": "repos/scty-civic", "domain_logic_files": [], "evidence_mechanics_files": []}


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
