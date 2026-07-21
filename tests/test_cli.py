from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from hound_cli import cli


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    src = str(Path(__file__).parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "hound_cli.cli", *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_installed_console_script_smoke() -> None:
    executable = shutil.which("hound")
    assert executable is not None

    result = subprocess.run(
        [executable, "--version"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "hound 0.2.3"


def test_help_exposes_lifecycle_namespaces() -> None:
    result = run_cli("--help")

    assert result.returncode == 0
    assert "source" in result.stdout
    assert "corpus" in result.stdout
    assert "edition" in result.stdout
    assert "approval" in result.stdout
    assert "run" in result.stdout
    assert "provider" in result.stdout
    assert "capture" in result.stdout


def test_usage_errors_are_machine_readable_json() -> None:
    result = run_cli("provider", "run")

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "schema_version": "hound.error.v1",
        "error": "one of the arguments --request --json is required",
    }


def test_provider_run_uses_central_transport(
    monkeypatch, capsys,
) -> None:
    seen: list[dict[str, object]] = []

    def fake_execute(request: object) -> dict[str, object]:
        assert isinstance(request, dict)
        seen.append(request)
        return {
            "schema_version": "hound.provider.response.v1",
            "provider": "exa",
            "operation": "search",
            "request_sha256": "abc",
            "raw_data": {"results": []},
            "leads": [],
        }

    monkeypatch.setattr(cli, "execute_provider_request", fake_execute)
    exit_code = cli.main(
        [
            "provider",
            "run",
            "--json",
            '{"schema_version":"hound.provider.request.v1","provider":"exa",'
            '"operation":"search","parameters":{"query":"caregiving","numResults":2}}',
        ]
    )

    assert exit_code == 0
    assert seen[0]["provider"] == "exa"
    assert json.loads(capsys.readouterr().out)["leads"] == []


def test_provider_run_loads_only_selected_credential_from_private_env_file(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    env_file = tmp_path / "providers.env"
    env_file.write_text(
        "EXA_API_KEY=exa-file-secret\n"
        "FIRECRAWL_API_KEY=firecrawl-file-secret\n"
        "UNRELATED_SECRET=must-not-load\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    seen: list[dict[str, str]] = []

    def fake_execute(
        request: object, *, env: dict[str, str]
    ) -> dict[str, object]:
        assert isinstance(request, dict)
        seen.append(env)
        return {
            "schema_version": "hound.provider.response.v1",
            "provider": "exa",
            "operation": "search",
            "request_sha256": "abc",
            "raw_data": {"results": []},
            "leads": [],
        }

    monkeypatch.setattr(cli, "execute_provider_request", fake_execute)
    exit_code = cli.main(
        [
            "provider",
            "run",
            "--env-file",
            str(env_file),
            "--json",
            '{"schema_version":"hound.provider.request.v1","provider":"exa",'
            '"operation":"search","parameters":{"query":"caregiving","numResults":2}}',
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert seen == [{"EXA_API_KEY": "exa-file-secret"}]
    assert "exa-file-secret" not in output.out
    assert "firecrawl-file-secret" not in output.out
    assert "must-not-load" not in output.out


def test_provider_run_rejects_non_private_env_file(tmp_path: Path, capsys) -> None:
    env_file = tmp_path / "providers.env"
    env_file.write_text("EXA_API_KEY=must-not-leak\n", encoding="utf-8")
    env_file.chmod(0o644)

    exit_code = cli.main(
        [
            "provider",
            "run",
            "--env-file",
            str(env_file),
            "--json",
            '{"schema_version":"hound.provider.request.v1","provider":"exa",'
            '"operation":"search","parameters":{"query":"caregiving","numResults":2}}',
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 1
    assert output.out == ""
    assert json.loads(output.err) == {
        "schema_version": "hound.error.v1",
        "error": "provider credential file must not be accessible by group or other users",
    }
    assert "must-not-leak" not in output.err


def test_non_utf8_json_file_returns_structured_usage_error(tmp_path: Path) -> None:
    request = tmp_path / "request.json"
    request.write_bytes(b"\xff\xfe")

    result = run_cli("provider", "run", "--request", str(request))

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "schema_version": "hound.error.v1",
        "error": f"cannot read {request}: input is not UTF-8",
    }


def test_capture_store_and_verify_cli(tmp_path: Path, capsys) -> None:
    body = tmp_path / "page.md"
    body.write_text("# Durable source\n", encoding="utf-8")
    root = tmp_path / "captures"

    stored_exit = cli.main(
        [
            "capture",
            "store",
            "--root",
            str(root),
            "--provider",
            "direct-fetch",
            "--source-url",
            "https://example.test/source",
            "--body",
            str(body),
            "--media-type",
            "text/markdown",
            "--retrieved-at",
            "2026-07-17T12:00:00Z",
        ]
    )
    stored = json.loads(capsys.readouterr().out)
    verified_exit = cli.main(
        [
            "capture",
            "verify",
            "--root",
            str(root),
            "--capture-id",
            stored["capture_id"],
        ]
    )
    verified = json.loads(capsys.readouterr().out)

    assert stored_exit == 0
    assert verified_exit == 0
    assert verified == {
        "schema_version": "hound.capture.verification.v1",
        "capture_id": stored["capture_id"],
        "valid": True,
    }


def test_driver_check_and_read_operation(driver_repo: tuple[Path, Path]) -> None:
    _, manifest_path = driver_repo
    checked = run_cli("driver", "check", "--driver", str(manifest_path))
    status = run_cli(
        "corpus",
        "status",
        "--driver",
        str(manifest_path),
        "--json",
        '{"question":"what changed?"}',
    )

    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout)["outcome"] == "completed"
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["data"]["echo"]["question"] == "what changed?"


def test_source_commands_use_kernel_composition(monkeypatch, capsys, driver_repo) -> None:
    _, manifest_path = driver_repo
    seen: list[tuple[str, object]] = []

    def discover(path: object, payload: object, *, as_of: object = None) -> dict[str, object]:
        seen.append((str(path), payload))
        return {"schema_version": "hound.driver.response.v1", "ok": True, "outcome": "completed"}

    monkeypatch.setattr(cli, "discover_sources", discover)
    exit_code = cli.main([
        "source",
        "discover",
        "--driver",
        str(manifest_path),
        "--json",
        '{"date":"2026-07-20"}',
    ])

    assert exit_code == 0
    assert seen == [(str(manifest_path.resolve()), {"date": "2026-07-20"})]
    assert json.loads(capsys.readouterr().out)["outcome"] == "completed"


def test_source_commands_without_composition_remain_driver_reads(driver_repo) -> None:
    _, manifest_path = driver_repo
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for operation in ("source.discover", "source.capture", "source.inspect"):
        manifest["capabilities"][operation].pop("composition")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    result = run_cli(
        "source",
        "discover",
        "--driver",
        str(manifest_path),
        "--json",
        '{"question":"legacy"}',
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["data"]["echo"] == {"question": "legacy"}


def test_cli_plan_approve_execute_e2e(driver_repo: tuple[Path, Path], tmp_path: Path) -> None:
    _, manifest_path = driver_repo
    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"

    planned = run_cli(
        "corpus",
        "apply",
        "--driver",
        str(manifest_path),
        "--json",
        '{"value":"canonical"}',
        "--as-of",
        "2026-07-17",
        "--plan-out",
        str(plan_path),
    )
    approved = run_cli(
        "approval",
        "create",
        "--plan",
        str(plan_path),
        "--reviewer",
        "operator@example.test",
        "--approved-at",
        "2026-07-17T01:00:00Z",
        "--output",
        str(approval_path),
    )
    executed = run_cli(
        "corpus",
        "apply",
        "--driver",
        str(manifest_path),
        "--execute",
        str(plan_path),
        "--approval",
        str(approval_path),
    )

    assert planned.returncode == 0, planned.stderr
    assert approved.returncode == 0, approved.stderr
    assert executed.returncode == 0, executed.stderr
    assert json.loads(executed.stdout)["outcome"] == "completed"


def test_missing_human_approval_is_exit_three(driver_repo: tuple[Path, Path], tmp_path: Path) -> None:
    _, manifest_path = driver_repo
    plan_path = tmp_path / "plan.json"
    planned = run_cli(
        "corpus", "apply", "--driver", str(manifest_path), "--as-of", "2026-07-17",
        "--plan-out", str(plan_path),
    )
    assert planned.returncode == 0

    result = run_cli(
        "corpus", "apply", "--driver", str(manifest_path), "--execute", str(plan_path),
    )

    assert result.returncode == 3
    assert "approval" in result.stderr.lower()
