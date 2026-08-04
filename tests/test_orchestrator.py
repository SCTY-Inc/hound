from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
from importlib.metadata import version as distribution_version
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from hound_cli import orchestrator
from hound_cli.orchestrator import (
    HoundError,
    check_driver,
    create_approval,
    execute_plan,
    invoke_read,
    make_plan,
    verify_run,
)


def test_plan_is_deterministic_and_bound_to_repo(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    first = make_plan(
        manifest_path,
        "corpus.apply",
        {"value": "caregiving"},
        as_of="2026-07-17T00:00:00Z",
    )
    second = make_plan(
        manifest_path,
        "corpus.apply",
        {"value": "caregiving"},
        as_of="2026-07-17T00:00:00Z",
    )

    assert first == second
    assert first["schema_version"] == "hound.plan.v2"
    assert len(first["plan_id"]) == 64
    assert first["gate"] == "human"
    assert first["proposal"]["data"]["expected_writes"] == ["output/result.json"]
    assert not {"driver_plan", "driver_outcome", "planning_response", "expected_writes"} & set(
        first
    )
    assert first["kernel"]["version"] == distribution_version("evidence-hound")
    assert first["kernel"]["dependencies"] == {}
    assert len(first["kernel"]["sha256"]) == 64


def test_exact_effects_bind_and_verify_created_bytes(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "bound", "exact_effects": True},
        as_of="2026-07-17",
    )

    effect = plan["proposal"]["data"]["expected_effects"][0]
    assert effect == {
        "path": "output/result.json",
        "mode": "0600",
        "before_sha256": None,
        "after_sha256": hashlib.sha256(b'{"value": "bound"}\n').hexdigest(),
    }

    result = execute_plan(manifest_path, plan)

    assert result["effects"] == [effect]
    assert verify_run(result["run_dir"])["valid"] is True
    assert hashlib.sha256((repo / effect["path"]).read_bytes()).hexdigest() == effect[
        "after_sha256"
    ]


def test_plan_rejects_exact_effect_with_wrong_before_hash(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    target = repo / "output" / "result.json"
    target.parent.mkdir()
    target.write_text('{"value": "old"}\n', encoding="utf-8")

    with pytest.raises(HoundError, match="before_sha256"):
        make_plan(
            manifest_path,
            "edition.build",
            {"exact_effects": True, "wrong_before_hash": True},
            as_of="2026-07-17",
        )


def test_exact_effect_rejects_parent_symlink_escape(
    driver_repo: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    repo, manifest_path = driver_repo
    (repo / "output").symlink_to(tmp_path / "outside", target_is_directory=True)

    with pytest.raises(HoundError, match="inside owner repository"):
        make_plan(
            manifest_path,
            "edition.build",
            {"exact_effects": True},
            as_of="2026-07-17",
        )


def test_execute_rejects_bytes_that_differ_from_exact_effect(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"exact_effects": True, "wrong_after_hash": True},
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError, match="approved effect"):
        execute_plan(manifest_path, plan)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text())
    assert result["outcome"] == "failed"
    assert result["effects"][0]["after_sha256"] != "0" * 64
    assert verify_run(run_dir)["valid"] is True


def test_execute_rejects_mode_that_differs_from_exact_effect(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"exact_effects": True, "execute_mode": "0755"},
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError, match="approved effect"):
        execute_plan(manifest_path, plan)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text())
    assert result["effects"][0]["mode"] == "0755"
    assert verify_run(run_dir)["valid"] is True


def test_exact_effect_path_escape_is_finalized_as_a_failed_run(
    driver_repo: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    repo, manifest_path = driver_repo
    outside = tmp_path / "outside"
    outside.mkdir()
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"exact_effects": True, "effect_symlink_target": str(outside)},
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError, match="outside declared scopes"):
        execute_plan(manifest_path, plan)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text())
    assert result["outcome"] == "failed"
    assert verify_run(run_dir)["valid"] is True


def test_kernel_identity_binds_core_but_not_provider_implementations() -> None:
    source_root = Path(orchestrator.__file__).parent
    digest = hashlib.sha256()
    source_paths = sorted(source_root.glob("*.py"))
    assert {path.name for path in source_paths} == {
        "__init__.py",
        "_supervisor.py",
        "_version.py",
        "cli.py",
        "contracts.py",
        "orchestrator.py",
        "runtime.py",
        "safety.py",
    }
    assert all(path.parent == source_root for path in source_paths)
    assert all(
        "hound_research" not in path.read_text(encoding="utf-8")
        and "hound_web_adapters" not in path.read_text(encoding="utf-8")
        for path in source_paths
    )
    for source in source_paths:
        digest.update(source.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")

    assert orchestrator._kernel_identity()["sha256"] == digest.hexdigest()


@pytest.mark.parametrize("expected_write", [".", "./"])
def test_plan_rejects_repository_root_as_an_expected_write(
    driver_repo: tuple[Path, Path], expected_write: str
) -> None:
    _, manifest_path = driver_repo

    with pytest.raises(HoundError, match="expected write") as caught:
        make_plan(
            manifest_path,
            "corpus.apply",
            {"expected_writes": [expected_write]},
            as_of="2026-07-17",
        )

    assert caught.value.exit_code == 2


def test_plan_requires_driver_ok(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo

    with pytest.raises(HoundError, match="review blocked"):
        make_plan(
            manifest_path,
            "corpus.apply",
            {
                "plan_ok": False,
                "plan_diagnostics": [
                    {"level": "error", "message": "review blocked"}
                ],
            },
            as_of="2026-07-17",
        )


def test_execute_surfaces_driver_diagnostics(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {
            "exact_effects": True,
            "skip_write": True,
            "execute_fail": True,
            "execute_diagnostics": [
                {"level": "error", "message": "upstream rejected candidate"}
            ],
        },
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError) as caught:
        execute_plan(manifest_path, plan)

    error = str(caught.value)
    assert "upstream rejected candidate" in error
    assert "did not produce its approved writes: output/result.json" in error
    result = json.loads(
        (
            repo / ".hound" / "runs" / plan["plan_id"] / "result.json"
        ).read_text(encoding="utf-8")
    )
    assert result["error"] == error


def test_plan_requires_object_driver_data(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo

    with pytest.raises(HoundError, match="data must be an object") as caught:
        make_plan(
            manifest_path,
            "corpus.apply",
            {"plan_data_nonobject": True},
            as_of="2026-07-17",
        )

    assert caught.value.exit_code == 2


def test_plan_binds_one_complete_proposal(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "corpus.apply",
        {
            "plan_artifacts": [{"kind": "capture", "id": "abc"}],
            "plan_proofs": [{"kind": "schema", "passed": True}],
            "plan_diagnostics": [{"level": "warning", "message": "review me"}],
        },
        as_of="2026-07-17",
    )

    assert plan["proposal"]["artifacts"] == [{"kind": "capture", "id": "abc"}]
    assert plan["proposal"]["proofs"] == [{"kind": "schema", "passed": True}]
    assert plan["proposal"]["diagnostics"] == [{"level": "warning", "message": "review me"}]


def test_plan_binds_allowlisted_environment_without_storing_cleartext(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest_path = driver_repo
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["env_allowlist"] = ["HOUND_ACCOUNT"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("HOUND_ACCOUNT", "approved-account-secret")
    plan = make_plan(
        manifest_path,
        "corpus.apply",
        {"value": "x"},
        as_of="2026-07-17",
    )
    approval = create_approval(plan, reviewer="operator@example.test")

    assert len(plan["driver_environment_sha256"]) == 64
    assert "approved-account-secret" not in json.dumps(plan)

    monkeypatch.setenv("HOUND_ACCOUNT", "different-account")
    with pytest.raises(HoundError, match="environment|inputs changed"):
        execute_plan(manifest_path, plan, approval=approval)


def test_orchestrator_uses_capability_scoped_environment(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest_path = driver_repo
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["capabilities"]["corpus.status"]["env_allowlist"] = ["STATUS_TOKEN"]
    manifest["capabilities"]["corpus.apply"]["env_allowlist"] = ["APPLY_TOKEN"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("STATUS_TOKEN", "status-secret")
    monkeypatch.setenv("APPLY_TOKEN", "apply-secret")

    response = invoke_read(
        manifest_path,
        "corpus.status",
        {"require_env": "STATUS_TOKEN", "forbid_env": "APPLY_TOKEN"},
    )
    plan = make_plan(
        manifest_path,
        "corpus.apply",
        {"value": "x", "require_env": "APPLY_TOKEN", "forbid_env": "STATUS_TOKEN"},
        as_of="2026-07-17",
    )

    assert response["outcome"] == "completed"
    assert len(plan["driver_environment_sha256"]) == 64


def test_plan_mode_must_not_modify_owner_repo(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo

    with pytest.raises(HoundError, match="plan mode modified"):
        make_plan(
            manifest_path,
            "corpus.apply",
            {"plan_write_path": "plan-side-effect.txt"},
            as_of="2026-07-17",
        )

    assert (repo / "plan-side-effect.txt").exists()


def test_failed_plan_mode_still_detects_owner_repo_mutation(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo

    with pytest.raises(HoundError, match="plan mode modified"):
        make_plan(
            manifest_path,
            "corpus.apply",
            {"plan_write_path": "failed-plan-side-effect.txt", "emit_noise": True},
            as_of="2026-07-17",
        )

    assert (repo / "failed-plan-side-effect.txt").exists()


def test_read_mode_must_not_modify_owner_repo(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo

    with pytest.raises(HoundError, match="read mode modified"):
        invoke_read(
            manifest_path,
            "corpus.status",
            {"read_write_path": "read-side-effect.txt"},
        )

    assert (repo / "read-side-effect.txt").exists()


def test_failed_read_mode_still_detects_owner_repo_mutation(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo

    with pytest.raises(HoundError, match="read mode modified"):
        invoke_read(
            manifest_path,
            "corpus.status",
            {"read_write_path": "failed-read-side-effect.txt", "emit_noise": True},
        )

    assert (repo / "failed-read-side-effect.txt").exists()


def test_failed_check_mode_still_detects_owner_repo_mutation(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    driver = repo / "mutating-check.py"
    driver.write_text(
        "from pathlib import Path\n"
        "Path('check-side-effect.txt').write_text('changed')\n"
        "print('not-json')\n",
        encoding="utf-8",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["exec"] = [sys.executable, str(driver)]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(HoundError, match="check mode modified"):
        check_driver(manifest_path)

    assert (repo / "check-side-effect.txt").exists()


def test_read_mode_rejects_plan_outcome(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo

    with pytest.raises(HoundError, match="invalid outcome"):
        invoke_read(manifest_path, "corpus.status", {"read_outcome": "planned"})


def test_human_gate_requires_approval(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")

    with pytest.raises(HoundError, match="approval") as caught:
        execute_plan(manifest_path, plan)

    assert caught.value.exit_code == 3


def test_execute_and_verify_immutable_run(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    approval = create_approval(
        plan, reviewer="operator@example.test", approved_at="2026-07-17T01:00:00Z"
    )

    result = execute_plan(manifest_path, plan, approval=approval)

    assert result["outcome"] == "completed"
    assert json.loads((repo / "output" / "result.json").read_text())["value"] == "x"
    run_dir = Path(result["run_dir"])
    assert (run_dir / "approval.json").is_file()
    assert verify_run(run_dir)["valid"] is True

    with pytest.raises(HoundError, match="already exists"):
        execute_plan(manifest_path, plan, approval=approval)


def test_execute_fails_when_driver_omits_an_expected_write(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"expected_writes": ["output/result.json"], "skip_write": True},
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError, match="did not produce its approved writes"):
        execute_plan(manifest_path, plan)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["outcome"] == "failed"
    assert result["changed_paths"] == []
    assert verify_run(run_dir)["valid"] is True


def test_execute_default_run_root_need_not_be_git_ignored(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    (repo / ".gitignore").unlink()
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "track manifest without run ignore"],
        cwd=repo,
        check=True,
    )
    assert (
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x"},
        as_of="2026-07-17",
    )

    result = execute_plan(manifest_path, plan)

    assert result["outcome"] == "completed"
    assert Path(result["run_dir"]) == repo / ".hound" / "runs" / plan["plan_id"]
    assert verify_run(result["run_dir"])["valid"] is True
    stored = json.loads((Path(result["run_dir"]) / "result.json").read_text())
    assert stored["schema_version"] == "hound.run.result.v2"
    assert "run_dir" not in stored
    copied = tmp_path / "copied" / plan["plan_id"]
    copied.parent.mkdir()
    shutil.copytree(result["run_dir"], copied)
    assert verify_run(copied)["valid"] is True


def test_post_driver_snapshot_failure_is_finalized(
    driver_repo: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x"},
        as_of="2026-07-17",
    )
    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    real_run_driver = orchestrator.run_driver

    def corrupt_index_after_execution(manifest, request, **kwargs):
        response = real_run_driver(manifest, request, **kwargs)
        if request.get("mode") == "execute":
            (repo / ".git" / "index").write_bytes(b"not a Git index\n")
        return response

    monkeypatch.setattr(orchestrator, "run_driver", corrupt_index_after_execution)

    with pytest.raises(HoundError, match="snapshot"):
        execute_plan(manifest_path, plan)

    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    index = json.loads((run_dir / "index.json").read_text(encoding="utf-8"))
    assert result["schema_version"] == "hound.run.result.v2"
    assert result["outcome"] == "failed"
    assert result["changed_paths"] == []
    assert index["schema_version"] == "hound.run.index.v1"
    assert verify_run(run_dir)["valid"] is True
    assert (repo / "output" / "result.json").exists()


def test_pre_driver_snapshot_failure_after_reservation_is_finalized(
    driver_repo: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x"},
        as_of="2026-07-17",
    )
    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    real_snapshot = orchestrator.snapshot_repo

    def fail_reserved_snapshot(repo_path):
        if (run_dir / "result.json").exists():
            raise orchestrator.RuntimeErrorHound("synthetic pre-driver snapshot failure")
        return real_snapshot(repo_path)

    monkeypatch.setattr(orchestrator, "snapshot_repo", fail_reserved_snapshot)

    with pytest.raises(HoundError, match="snapshot"):
        execute_plan(manifest_path, plan)

    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    index = json.loads((run_dir / "index.json").read_text(encoding="utf-8"))
    assert result["schema_version"] == "hound.run.result.v2"
    assert result["outcome"] == "failed"
    assert result["changed_paths"] == []
    assert index["schema_version"] == "hound.run.index.v1"
    assert verify_run(run_dir)["valid"] is True
    assert not (repo / "output" / "result.json").exists()


@pytest.mark.parametrize("failure_point", ["before", "after"])
def test_snapshot_interrupt_after_reservation_is_finalized_and_reraised(
    driver_repo: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x"},
        as_of="2026-07-17",
    )
    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    real_snapshot = orchestrator.snapshot_repo
    real_run_driver = orchestrator.run_driver
    driver_finished = False

    def mark_execution(manifest, request, **kwargs):
        nonlocal driver_finished
        response = real_run_driver(manifest, request, **kwargs)
        if request.get("mode") == "execute":
            driver_finished = True
        return response

    def interrupt_snapshot(repo_path):
        reserved = (run_dir / "result.json").exists()
        if reserved and (failure_point == "before" or driver_finished):
            raise KeyboardInterrupt
        return real_snapshot(repo_path)

    monkeypatch.setattr(orchestrator, "run_driver", mark_execution)
    monkeypatch.setattr(orchestrator, "snapshot_repo", interrupt_snapshot)

    with pytest.raises(KeyboardInterrupt):
        execute_plan(manifest_path, plan)

    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["outcome"] == "failed"
    assert result["error"] == (
        f"repository snapshot interrupted {failure_point} driver "
        + ("launch" if failure_point == "before" else "execution")
    )
    assert verify_run(run_dir)["valid"] is True
    assert (repo / "output" / "result.json").exists() is (failure_point == "after")


def test_interrupted_execute_is_finalized_as_a_failed_immutable_run(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    approval = create_approval(plan, reviewer="operator", approved_at="2026-07-17T01:00:00Z")
    real_run_driver = orchestrator.run_driver

    def interrupt_execute(manifest, request, **kwargs):
        if request.get("mode") == "execute":
            target = repo / "output" / "result.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("partial\n", encoding="utf-8")
            raise KeyboardInterrupt
        return real_run_driver(manifest, request, **kwargs)

    monkeypatch.setattr(orchestrator, "run_driver", interrupt_execute)

    with pytest.raises(KeyboardInterrupt):
        execute_plan(manifest_path, plan, approval=approval)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["outcome"] == "failed"
    assert result["error"] == "driver interrupted"
    assert verify_run(run_dir)["valid"] is True


def test_repo_drift_invalidates_plan(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    approval = create_approval(plan, reviewer="operator", approved_at="2026-07-17T00:00:00Z")
    (repo / "seed.txt").write_text("changed\n", encoding="utf-8")

    with pytest.raises(HoundError, match="repository fingerprint"):
        execute_plan(manifest_path, plan, approval=approval)


def test_kernel_drift_invalidates_plan(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    approval = create_approval(plan, reviewer="operator", approved_at="2026-07-17T00:00:00Z")
    monkeypatch.setattr(
        orchestrator,
        "_kernel_identity",
        lambda: {"version": distribution_version("evidence-hound"), "sha256": "0" * 64},
    )

    with pytest.raises(HoundError, match="kernel"):
        execute_plan(manifest_path, plan, approval=approval)


def test_out_of_scope_write_fails_closed_and_is_recorded(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "corpus.apply",
        {"value": "x", "write_path": "escape.txt"},
        as_of="2026-07-17",
    )
    approval = create_approval(plan, reviewer="operator", approved_at="2026-07-17T00:00:00Z")

    with pytest.raises(HoundError, match="outside"):
        execute_plan(manifest_path, plan, approval=approval)

    assert (repo / "escape.txt").exists()
    run_dirs = list((repo / ".hound" / "runs").iterdir())
    assert len(run_dirs) == 1
    assert json.loads((run_dirs[0] / "result.json").read_text())["outcome"] == "failed"


def test_approval_is_bound_to_exact_plan(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    plan_a = make_plan(manifest_path, "corpus.apply", {"value": "a"}, as_of="2026-07-17")
    plan_b = make_plan(manifest_path, "corpus.apply", {"value": "b"}, as_of="2026-07-17")
    approval = create_approval(plan_a, reviewer="operator", approved_at="2026-07-17T00:00:00Z")

    with pytest.raises(HoundError, match="does not match") as caught:
        execute_plan(manifest_path, plan_b, approval=approval)

    assert caught.value.exit_code == 3


def test_human_approval_requires_strict_witness_fields(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    body = {
        "schema_version": "hound.approval.v1",
        "plan_id": plan["plan_id"],
        "driver_id": plan["driver_id"],
        "operation": plan["operation"],
        "write_scope_sha256": plan["write_scope_sha256"],
    }
    approval = {**body, "approval_id": orchestrator.canonical_hash(body)}

    with pytest.raises(HoundError, match="approval artifact") as caught:
        execute_plan(manifest_path, plan, approval=approval)

    assert caught.value.exit_code == 3


def test_approval_timestamps_are_timezone_aware_and_ordered(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")

    with pytest.raises(HoundError, match="timezone"):
        create_approval(plan, reviewer="operator", approved_at="2026-07-17")
    with pytest.raises(HoundError, match="after approved_at"):
        create_approval(
            plan,
            reviewer="operator",
            approved_at="2026-07-17T01:00:00Z",
            expires_at="2026-07-17T00:00:00Z",
        )


def test_expired_approval_is_held(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    approval = create_approval(
        plan,
        reviewer="operator",
        approved_at="1999-12-31T23:00:00Z",
        expires_at="2000-01-01T00:00:00Z",
    )

    with pytest.raises(HoundError, match="expired") as caught:
        execute_plan(manifest_path, plan, approval=approval)

    assert caught.value.exit_code == 3


def test_approval_is_revalidated_immediately_before_driver_launch(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(manifest_path, "corpus.apply", {"value": "x"}, as_of="2026-07-17")
    approval = create_approval(
        plan,
        reviewer="operator",
        approved_at="2026-07-17T00:00:00Z",
    )
    real_validate = orchestrator._validate_approval
    validations = 0

    def expire_before_launch(plan_value, approval_value):
        nonlocal validations
        validations += 1
        if validations == 3:
            raise HoundError("approval has expired", exit_code=3)
        return real_validate(plan_value, approval_value)

    monkeypatch.setattr(orchestrator, "_validate_approval", expire_before_launch)

    with pytest.raises(HoundError, match="expired") as caught:
        execute_plan(manifest_path, plan, approval=approval)

    assert caught.value.exit_code == 3
    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["outcome"] == "held"
    assert verify_run(run_dir)["valid"] is True


def test_repo_lock_serializes_competing_approved_plans(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plans = [
        make_plan(manifest_path, "edition.build", {"value": value}, as_of="2026-07-17")
        for value in ("first", "second")
    ]

    def execute(plan):
        try:
            return execute_plan(manifest_path, plan)["outcome"]
        except HoundError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(execute, plans))

    assert outcomes.count("completed") == 1
    assert sum("fingerprint" in outcome for outcome in outcomes) == 1
    final_value = json.loads((repo / "output" / "result.json").read_text())["value"]
    assert final_value in {"first", "second"}


def test_execute_rejects_plan_outcome_and_records_failure(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "corpus.apply",
        {"value": "x", "execute_outcome": "planned"},
        as_of="2026-07-17",
    )
    approval = create_approval(plan, reviewer="operator", approved_at="2026-07-17T00:00:00Z")

    with pytest.raises(HoundError, match="invalid outcome"):
        execute_plan(manifest_path, plan, approval=approval)

    result_path = repo / ".hound" / "runs" / plan["plan_id"] / "result.json"
    assert json.loads(result_path.read_text())["outcome"] == "failed"


def test_run_verification_rejects_unindexed_files_and_index_plan_mismatch(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "edition.build", {"value": "x"}, as_of="2026-07-17")
    result = execute_plan(manifest_path, plan)
    run_dir = Path(result["run_dir"])
    (run_dir / "unexpected.txt").write_text("not indexed\n", encoding="utf-8")

    extra = verify_run(run_dir)
    assert extra["valid"] is False
    assert "unexpected.txt" in extra["failures"]

    (run_dir / "unexpected.txt").unlink()
    index_path = run_dir / "index.json"
    index = json.loads(index_path.read_text())
    index["plan_id"] = "0" * 64
    index_path.write_text(json.dumps(index), encoding="utf-8")

    mismatched = verify_run(run_dir)
    assert mismatched["valid"] is False
    assert "index.plan_id" in mismatched["failures"]


def test_driver_cannot_modify_core_run_records(driver_repo: tuple[Path, Path]) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x", "tamper_run_record": True},
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError, match="run record"):
        execute_plan(manifest_path, plan)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    assert json.loads((run_dir / "result.json").read_text())["outcome"] == "failed"
    assert verify_run(run_dir)["valid"] is True


def test_unreadable_protected_record_is_finalized_as_tampering(
    driver_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x"},
        as_of="2026-07-17",
    )
    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    real_run_driver = orchestrator.run_driver
    real_snapshot = orchestrator.snapshot_repo
    driver_finished = False

    def mark_execution(manifest, request, **kwargs):
        nonlocal driver_finished
        response = real_run_driver(manifest, request, **kwargs)
        if request.get("mode") == "execute":
            driver_finished = True
        return response

    def make_plan_record_unreadable(repo_path):
        snapshot = real_snapshot(repo_path)
        if driver_finished:
            (run_dir / "plan.json").chmod(0)
        return snapshot

    monkeypatch.setattr(orchestrator, "run_driver", mark_execution)
    monkeypatch.setattr(orchestrator, "snapshot_repo", make_plan_record_unreadable)

    with pytest.raises(HoundError, match="run record"):
        execute_plan(manifest_path, plan)

    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["outcome"] == "failed"
    assert "plan.json" in result["error"]
    assert verify_run(run_dir)["valid"] is True


def test_driver_cannot_preempt_result_or_index_finalization(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    plan = make_plan(
        manifest_path,
        "edition.build",
        {"value": "x", "forge_result_record": True},
        as_of="2026-07-17",
    )

    with pytest.raises(HoundError, match="run record"):
        execute_plan(manifest_path, plan)

    run_dir = repo / ".hound" / "runs" / plan["plan_id"]
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert result["outcome"] == "failed"
    assert verify_run(run_dir)["valid"] is True


def test_run_verification_rejects_rehashed_manifest_tampering(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "edition.build", {"value": "x"}, as_of="2026-07-17")
    result = execute_plan(manifest_path, plan)
    run_dir = Path(result["run_dir"])
    manifest_record = run_dir / "driver-manifest.json"
    manifest = json.loads(manifest_record.read_text())
    manifest["id"] = "tampered"
    manifest_record.write_text(json.dumps(manifest), encoding="utf-8")
    index_path = run_dir / "index.json"
    index = json.loads(index_path.read_text())
    index["files"]["driver-manifest.json"] = hashlib.sha256(
        manifest_record.read_bytes()
    ).hexdigest()
    index_path.write_text(json.dumps(index), encoding="utf-8")

    verification = verify_run(run_dir)
    assert verification["valid"] is False
    assert "driver-manifest.json" in verification["failures"]


def test_historical_manifest_verification_uses_its_recorded_contract() -> None:
    manifest = {
        "schema_version": "hound.driver.v1",
        "id": "historical",
        "protocol": "hound.protocol.v1",
        "owner": {"repo": "."},
        "exec": ["driver"],
        "capabilities": {"write": {"effect": "write", "gate": "none"}},
        "capture_root": ".hound/captures",
        "ignored_snapshot_excludes": None,
    }
    plan = {
        "schema_version": "hound.plan.v1",
        "driver_manifest_sha256": orchestrator.canonical_hash(manifest),
    }

    assert orchestrator._recorded_manifest_matches(manifest, plan) is True
    assert orchestrator._recorded_manifest_matches(
        manifest, {**plan, "schema_version": "hound.plan.v2"}
    ) is False


def test_historical_no_change_result_can_supersede_planned_write(
    tmp_path: Path,
) -> None:
    response = {
        "schema_version": "hound.driver.response.v1",
        "ok": True,
        "outcome": "no-change",
        "data_schema": "historical.result.v1",
        "data": {"written": []},
        "artifacts": [],
        "proofs": [],
        "diagnostics": [],
    }
    plan = {
        "schema_version": "hound.plan.v1",
        "plan_id": "a" * 64,
        "expected_writes": ["output/result.json"],
    }
    result = {
        "schema_version": "hound.run.result.v1",
        "plan_id": plan["plan_id"],
        "run_dir": str(tmp_path),
        "outcome": "no-change",
        "ok": True,
        "changed_paths": [],
        "driver_response": response,
        "data": response["data"],
    }

    assert orchestrator._result_matches_plan(result, plan, tmp_path) is True


def test_run_verification_rejects_rehashed_forged_result(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "edition.build", {"value": "x"}, as_of="2026-07-17")
    executed = execute_plan(manifest_path, plan)
    run_dir = Path(executed["run_dir"])
    result_record = run_dir / "result.json"
    result_record.write_text(
        json.dumps({"plan_id": plan["plan_id"], "forged": "anything"}),
        encoding="utf-8",
    )
    index_path = run_dir / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["files"]["result.json"] = hashlib.sha256(result_record.read_bytes()).hexdigest()
    index_path.write_text(json.dumps(index), encoding="utf-8")

    verification = verify_run(run_dir)

    assert verification["valid"] is False
    assert "result.json" in verification["failures"]


def test_run_verification_rejects_rehashed_missing_planned_write(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo
    plan = make_plan(manifest_path, "edition.build", {"value": "x"}, as_of="2026-07-17")
    executed = execute_plan(manifest_path, plan)
    run_dir = Path(executed["run_dir"])
    result_record = run_dir / "result.json"
    result = json.loads(result_record.read_text(encoding="utf-8"))
    result["changed_paths"] = []
    result_record.write_text(json.dumps(result), encoding="utf-8")
    index_path = run_dir / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["files"]["result.json"] = hashlib.sha256(result_record.read_bytes()).hexdigest()
    index_path.write_text(json.dumps(index), encoding="utf-8")

    verification = verify_run(run_dir)

    assert verification["valid"] is False
    assert "result.json" in verification["failures"]
