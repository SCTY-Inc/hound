from __future__ import annotations

import json
from pathlib import Path

import pytest

from hound_cli import cli


def run_cli(*args: str):
    from io import StringIO
    from contextlib import redirect_stderr, redirect_stdout

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli.main(list(args))
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
        "source",
        "search",
        "extract",
        "interact",
        "capture",
    ):
        assert command in output
    for removed in ("provider", "corpus", "edition", "approval", "run"):
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
    assert result["data"] == {"operation": "corpus.status", "echo": {"value": "x"}}


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


def test_source_command_uses_source_v2_composition(
    driver_repo: tuple[Path, Path], monkeypatch
) -> None:
    _, manifest_path = driver_repo
    seen: list[tuple[Path, dict[str, object]]] = []

    def discover(path: Path, payload: dict[str, object], *, as_of: str | None = None):
        seen.append((path, payload))
        return {"ok": True, "outcome": "completed", "as_of": as_of}

    monkeypatch.setattr(cli, "discover_sources", discover)

    code, stdout, _ = run_cli(
        "source",
        "discover",
        "--driver",
        str(manifest_path),
        "--json",
        '{"date":"2026-07-21"}',
        "--as-of",
        "2026-07-21",
    )

    assert code == 0
    assert json.loads(stdout)["outcome"] == "completed"
    assert seen == [(manifest_path.resolve(), {"date": "2026-07-21"})]


def test_web_commands_require_explicit_adapter_and_preserve_record_root(
    driver_repo: tuple[Path, Path], tmp_path: Path, monkeypatch
) -> None:
    _, manifest_path = driver_repo
    seen: list[tuple[Path, str, dict[str, object], Path]] = []

    def run_web(adapter, verb, payload, *, record_root, as_of=None):
        seen.append((adapter, verb, payload, record_root))
        return {"ok": True, "outcome": "completed", "record_id": "a" * 64}

    monkeypatch.setattr(cli, "run_web", run_web)
    record_root = tmp_path / "records"

    code, _, _ = run_cli(
        "search",
        "--adapter",
        str(manifest_path),
        "--json",
        '{"query":"care","limit":2}',
        "--record-root",
        str(record_root),
    )

    assert code == 0
    assert seen == [
        (
            manifest_path.resolve(),
            "search",
            {"query": "care", "limit": 2},
            record_root.resolve(),
        )
    ]


def test_capture_store_and_verify_round_trip(tmp_path: Path) -> None:
    body = tmp_path / "body.bin"
    body.write_bytes(b"source bytes")
    root = tmp_path / "captures"

    stored, stdout, _ = run_cli(
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
    assert stored == 0
    capture_id = json.loads(stdout)["capture_id"]

    verified, stdout, _ = run_cli(
        "capture",
        "verify",
        "--root",
        str(root),
        "--capture-id",
        capture_id,
    )
    assert verified == 0
    assert json.loads(stdout)["valid"] is True


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


def test_installed_tool_matches_this_source_tree() -> None:
    """The `hound` on PATH is an installed copy, not this checkout.

    Consumers invoke the installed binary -- `pulse-daily` calls
    /home/deploy/.local/bin/hound -- so editing src/ changes nothing until
    `uv tool install --force .` runs. On 2026-07-26 a snapshot fix measured at
    20.5s -> 2.5s was committed, verified against this tree, and had no effect on
    the lane for a full run because the installed copy was three days stale.
    Silent divergence between source and runtime is the defect; this makes it
    loud. Skips when no installed copy exists, so a fresh clone still passes.
    """
    import hashlib
    import shutil

    binary = shutil.which("hound")
    if binary is None:
        pytest.skip("no installed hound on PATH")

    candidates = list(
        Path("/home/deploy/.local/share/uv/tools/evidence-hound/lib").glob(
            "python*/site-packages/hound_cli/runtime.py"
        )
    )
    if not candidates:
        pytest.skip("installed layout not recognized")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    source = Path(__file__).parents[1] / "src" / "hound_cli" / "runtime.py"
    assert digest(candidates[0]) == digest(source), (
        "installed hound differs from this source tree -- "
        "run `uv tool install --force .` or consumers keep running the old code"
    )
