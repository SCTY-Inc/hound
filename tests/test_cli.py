from __future__ import annotations

import json
from pathlib import Path

import pytest

from hound_cli import cli
from hound_research import cli as research_cli


def run_cli(*args: str):
    from io import StringIO
    from contextlib import redirect_stderr, redirect_stdout

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli.main(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


def run_research_cli(*args: str):
    from io import StringIO
    from contextlib import redirect_stderr, redirect_stdout

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = research_cli.main(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


def test_help_exposes_primitives_not_owner_domain_names(capsys) -> None:
    try:
        cli.main(["--help"])
    except SystemExit as error:
        assert error.code == 0
    output = capsys.readouterr().out

    for command in (
        "driver",
        "invoke",
        "plan",
        "approve",
        "execute",
        "verify",
    ):
        assert command in output
    for removed in (
        "source",
        "search",
        "extract",
        "interact",
        "capture",
        "provider",
        "corpus",
        "edition",
        "approval",
        "run",
    ):
        assert f"  {removed}" not in output


def test_invoke_runs_an_arbitrary_declared_read_capability(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo

    code, stdout, stderr = run_cli(
        "invoke",
        "--driver",
        str(manifest_path),
        "--operation",
        "corpus.status",
        "--json",
        '{"value":"x"}',
    )

    assert code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["schema_version"] == "hound.invoke.result.v1"
    assert result["data"] == {"operation": "corpus.status", "echo": {"value": "x"}}
    assert result["receipt"]["request"]["operation"] == "corpus.status"
    assert len(result["receipt"]["receipt_id"]) == 64


def test_saved_invoke_result_is_verifiable_and_tamper_evident(
    driver_repo: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    _, manifest_path = driver_repo
    code, stdout, _ = run_cli(
        "invoke",
        "--driver",
        str(manifest_path),
        "--operation",
        "corpus.status",
        "--json",
        '{"value":"x"}',
    )
    assert code == 0
    record = tmp_path / "invoke.json"
    record.write_text(stdout, encoding="utf-8")

    verified, output, _ = run_cli("verify", str(record))
    assert verified == 0
    assert json.loads(output)["valid"] is True

    value = json.loads(stdout)
    value["data"]["echo"]["value"] = "tampered"
    record.write_text(json.dumps(value), encoding="utf-8")
    rejected, _, error = run_cli("verify", str(record))
    assert rejected == 1
    assert "response_sha256" in json.loads(error)["error"]


def test_invoke_rejects_write_capabilities(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo

    code, _, stderr = run_cli(
        "invoke",
        "--driver",
        str(manifest_path),
        "--operation",
        "corpus.apply",
    )

    assert code == 2
    assert "must be planned" in json.loads(stderr)["error"]


def test_plan_approve_execute_and_verify_use_saved_artifacts(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"

    planned, stdout, _ = run_cli(
        "plan",
        "--driver",
        str(manifest_path),
        "--operation",
        "corpus.apply",
        "--json",
        '{"value":"reviewed"}',
        "--as-of",
        "2026-07-21",
        "--output",
        str(plan_path),
    )
    assert planned == 0
    assert json.loads(stdout) == json.loads(plan_path.read_text())

    approved, _, _ = run_cli(
        "approve",
        "--plan",
        str(plan_path),
        "--reviewer",
        "operator@example.test",
        "--approved-at",
        "2026-07-21T12:00:00Z",
        "--output",
        str(approval_path),
    )
    assert approved == 0

    executed, stdout, stderr = run_cli(
        "execute",
        "--driver",
        str(manifest_path),
        "--plan",
        str(plan_path),
        "--approval",
        str(approval_path),
    )
    assert executed == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert json.loads((repo / "output" / "result.json").read_text()) == {"value": "reviewed"}

    verified, stdout, _ = run_cli("verify", result["run_dir"])
    assert verified == 0
    assert json.loads(stdout)["valid"] is True


def test_plan_requires_an_output_path_and_cutoff(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo

    code, _, stderr = run_cli(
        "plan",
        "--driver",
        str(manifest_path),
        "--operation",
        "corpus.apply",
    )

    assert code == 2
    assert "required" in json.loads(stderr)["error"]


def test_research_source_command_fails_closed_after_no_bypass_cutover(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo

    code, stdout, stderr = run_research_cli(
        "source",
        "discover",
        "--driver",
        str(manifest_path),
        "--json",
        '{"date":"2026-07-21"}',
        "--as-of",
        "2026-07-21",
    )

    assert code == 5
    assert stdout == ""
    assert "disabled" in json.loads(stderr)["error"]


def test_research_web_commands_fail_closed_after_no_bypass_cutover(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    _, manifest_path = driver_repo
    record_root = tmp_path / "records"

    code, stdout, stderr = run_research_cli(
        "search",
        "--adapter",
        str(manifest_path),
        "--json",
        '{"query":"care","limit":2}',
        "--record-root",
        str(record_root),
    )

    assert code == 5
    assert stdout == ""
    assert "disabled" in json.loads(stderr)["error"]


def test_research_capture_store_fails_closed_after_no_bypass_cutover(tmp_path: Path) -> None:
    body = tmp_path / "body.bin"
    body.write_bytes(b"source bytes")
    root = tmp_path / "captures"

    stored, stdout, stderr = run_research_cli(
        "capture",
        "store",
        "--root",
        str(root),
        "--provider",
        "direct-api",
        "--source-url",
        "https://example.test/source",
        "--body",
        str(body),
        "--media-type",
        "application/json",
        "--retrieved-at",
        "2026-07-21T12:00:00Z",
    )
    assert stored == 5
    assert stdout == ""
    assert "disabled" in json.loads(stderr)["error"]
    assert not root.exists()


def test_invalid_json_returns_a_machine_readable_error(
    driver_repo: tuple[Path, Path],
) -> None:
    _, manifest_path = driver_repo

    code, stdout, stderr = run_cli(
        "invoke",
        "--driver",
        str(manifest_path),
        "--operation",
        "corpus.status",
        "--json",
        "{",
    )

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


def test_verify_error_names_failed_checks(
    driver_repo: tuple[Path, Path],
) -> None:
    repo, manifest_path = driver_repo
    from hound_cli.orchestrator import execute_plan, make_plan

    plan = make_plan(manifest_path, "edition.build", {"value": "x"}, as_of="2026-07-21")
    result = execute_plan(manifest_path, plan)
    (Path(result["run_dir"]) / "unexpected.txt").write_text("tampered\n", encoding="utf-8")

    code, _, stderr = run_cli("verify", result["run_dir"])

    assert code == 1
    assert "unexpected.txt" in json.loads(stderr)["error"]


def test_installed_tool_matches_this_source_tree() -> None:
    """An installed command must match every shipped Python package."""
    import hashlib
    import shutil

    binary = shutil.which("hound")
    if binary is None:
        pytest.skip("no installed hound on PATH")

    candidates = list(
        Path("/home/deploy/.local/share/uv/tools/evidence-hound/lib").glob(
            "python*/site-packages"
        )
    )
    if not candidates:
        pytest.skip("installed layout not recognized")

    def package_digest(root: Path, package: str) -> dict[str, str]:
        return {
            path.relative_to(root / package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((root / package).glob("*.py"))
        }

    source_root = Path(__file__).parents[1] / "src"
    installed_root = candidates[0]
    packages = ("hound_cli", "hound_research", "hound_web_adapters")
    assert {
        package: package_digest(installed_root, package) for package in packages
    } == {
        package: package_digest(source_root, package) for package in packages
    }, (
        "installed hound differs from this source tree -- "
        "run `uv tool install --force --refresh-package evidence-hound .` "
        "or consumers keep running the old code"
    )
