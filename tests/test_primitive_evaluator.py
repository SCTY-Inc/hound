from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from hound_cli.orchestrator import (
    check_driver,
    create_approval,
    execute_plan,
    invoke_read,
    make_plan,
    verify_run,
)


def test_generic_config_migration_exercises_the_complete_primitive(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "golden" / "config_migration"
    repo = tmp_path / "config-owner"
    shutil.copytree(fixture, repo)
    (repo / ".gitignore").write_text(".hound/\n", encoding="utf-8")
    (repo / "config.json").write_text(
        json.dumps({"feature": "legacy", "version": 1}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "hound@example.test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Hound Evaluator"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)

    manifest = repo / "hound-driver.json"
    payload = json.loads((repo / "input.json").read_text())
    assert check_driver(manifest)["ok"] is True
    assert invoke_read(manifest, "config.inspect", {})["data"]["config"]["version"] == 1

    plan = make_plan(manifest, "config.migrate", payload, as_of="2026-07-27")
    approval = create_approval(
        plan,
        reviewer="operator@example.test",
        approved_at="2026-07-27T12:00:00Z",
    )
    result = execute_plan(manifest, plan, approval=approval)

    assert json.loads((repo / "config.json").read_text()) == payload["target"]
    assert result["effects"] == plan["proposal"]["data"]["expected_effects"]
    assert verify_run(result["run_dir"])["valid"] is True

    copied = tmp_path / "copied" / plan["plan_id"]
    copied.parent.mkdir()
    shutil.copytree(result["run_dir"], copied)
    assert verify_run(copied)["valid"] is True
