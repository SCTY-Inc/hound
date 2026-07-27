from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hound_cli.contracts import canonical_hash
from hound_cli.runtime import (
    RuntimeErrorHound,
    changed_paths,
    paths_within_scopes,
    repo_fingerprint,
    run_driver,
    run_driver_with_receipt,
    snapshot_repo,
    write_json_atomic,
    write_json_create_only,
)


VALID_RESPONSE = {
    "schema_version": "hound.driver.response.v1",
    "ok": True,
    "outcome": "completed",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "hound@example.test")
    _git(repo, "config", "user.name", "Hound Test")
    (repo / "tracked.txt").write_text("original\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-qm", "initial")
    return repo


def _manifest(repo: Path, argv: list[str], **extra: object) -> tuple[dict, Path]:
    path = repo.parent / "driver.json"
    manifest = {
        "schema_version": "hound.driver.v1",
        "id": "test-driver",
        "protocol": "hound.protocol.v1",
        "owner": {"repo": repo.name},
        "exec": argv,
        "capabilities": {"diagnose": {"effect": "read", "gate": "none"}},
        **extra,
    }
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest, path


def _driver(repo: Path, body: str) -> Path:
    path = repo / "driver.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_run_driver_rejects_credentials_hidden_in_decoded_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    secret = "secret-inside-provider-body"
    raw = json.dumps({"token": secret}, separators=(",", ":")).encode()
    response = {
        **VALID_RESPONSE,
        "data": {"raw": {"body_base64": base64.b64encode(raw).decode("ascii")}},
    }
    driver = _driver(repo, f"print({json.dumps(json.dumps(response))})\n")
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["HOUND_API_KEY"],
    )
    monkeypatch.setenv("HOUND_API_KEY", secret)

    with pytest.raises(RuntimeErrorHound, match="credential"):
        run_driver_with_receipt(
            manifest,
            {},
            manifest_path=manifest_path,
            decoded_outputs=lambda value: [
                base64.b64decode(value["data"]["raw"]["body_base64"], validate=True)
            ],
        )


def test_public_endpoint_environment_cannot_hide_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    driver = _driver(repo, f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n")
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["SERVICE_ENDPOINT"],
    )
    monkeypatch.setenv("SERVICE_ENDPOINT", "https://user:secret@example.test")

    with pytest.raises(RuntimeErrorHound, match="without credentials"):
        run_driver(manifest, {}, manifest_path=manifest_path)


def test_run_driver_receipt_binds_the_executed_manifest_repo_and_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    driver = _driver(repo, f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n")
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["HOUND_CONFIG"],
    )
    monkeypatch.setenv("HOUND_CONFIG", "configuration")

    response, receipt = run_driver_with_receipt(
        manifest,
        {},
        manifest_path=manifest_path,
    )

    assert response == VALID_RESPONSE
    assert receipt["schema_version"] == "hound.invocation.receipt.v1"
    assert receipt["manifest"] == manifest
    assert receipt["manifest_sha256"]
    fingerprint = repo_fingerprint(repo)
    assert receipt["repository"] == {
        "head": fingerprint["head"],
        "fingerprint_sha256": fingerprint["fingerprint_sha256"],
    }
    assert receipt["environment_sha256"]
    assert receipt["request"] == {}
    assert len(receipt["request_sha256"]) == 64
    assert receipt["response_sha256"] == canonical_hash(response)
    assert len(receipt["receipt_id"]) == 64


def test_run_driver_uses_argv_and_treats_shell_metacharacters_literally(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "shell-was-used"
    literal = f"; touch {marker}"
    driver = _driver(
        repo,
        """
import json
import pathlib
import sys

request = json.load(sys.stdin)
if request != {"operation": "diagnose"}:
    raise SystemExit(3)
if pathlib.Path.cwd() != pathlib.Path(__file__).parent:
    raise SystemExit(4)
if sys.argv[1] != sys.argv[2]:
    raise SystemExit(5)
print(json.dumps({"schema_version": "hound.driver.response.v1", "ok": True, "outcome": "completed"}))
""".lstrip(),
    )
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver), literal, literal],
    )

    result = run_driver(
        manifest,
        {"operation": "diagnose"},
        manifest_path=manifest_path,
    )

    assert result == VALID_RESPONSE
    assert not marker.exists()


def test_nested_manifest_can_declare_parent_git_root(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    research = repo / "research"
    research.mkdir()
    driver = _driver(
        repo,
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])
    nested_manifest = research / "hound-driver.json"
    manifest["owner"] = {"repo": ".."}
    nested_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.unlink()

    assert run_driver(manifest, {}, manifest_path=nested_manifest) == VALID_RESPONSE


def test_owner_repo_cannot_shadow_kernel_supervisor(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "shadow-supervisor-ran"
    shadow = repo / "hound_cli"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "_supervisor.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('shadowed')\n",
        encoding="utf-8",
    )
    driver = _driver(
        repo,
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    assert run_driver(manifest, {}, manifest_path=manifest_path) == VALID_RESPONSE
    assert not marker.exists()


def test_run_driver_rejects_extra_stdout_even_when_one_line_is_valid_json(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    driver = _driver(
        repo,
        f"print('debug output')\nprint({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    with pytest.raises(RuntimeErrorHound, match="exactly one JSON"):
        run_driver(manifest, {}, manifest_path=manifest_path)


def test_run_driver_filters_environment_but_preserves_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    driver = _driver(
        repo,
        """
import json
import os
import sys

if os.environ.get("HOUND_ALLOWED") != "allowed":
    print("allowlisted value missing", file=sys.stderr)
    raise SystemExit(10)
if "HOUND_SECRET" in os.environ:
    print("secret leaked", file=sys.stderr)
    raise SystemExit(11)
if not os.environ.get("PATH"):
    print("PATH missing", file=sys.stderr)
    raise SystemExit(12)
print(json.dumps({"schema_version": "hound.driver.response.v1", "ok": True, "outcome": "completed"}))
""".lstrip(),
    )
    monkeypatch.setenv("HOUND_ALLOWED", "allowed")
    monkeypatch.setenv("HOUND_SECRET", "must-not-cross-boundary")
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["HOUND_ALLOWED"],
    )

    assert run_driver(manifest, {}, manifest_path=manifest_path) == VALID_RESPONSE


def test_run_driver_uses_fixed_system_path_not_ambient_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "ambient-python-ran"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python3"
    fake_python.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    driver = _driver(
        repo,
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(repo, ["python3", str(driver)])
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.defpath}")

    assert run_driver(manifest, {}, manifest_path=manifest_path) == VALID_RESPONSE
    assert not marker.exists()


def test_run_driver_can_use_a_frozen_allowlisted_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    repo = _repo(tmp_path)
    driver = _driver(
        repo,
        "import json, os\n"
        "if os.environ.get('HOUND_ACCOUNT') != 'approved-account':\n"
        "    raise SystemExit(9)\n"
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["HOUND_ACCOUNT"],
    )
    monkeypatch.setenv("HOUND_ACCOUNT", "approved-account")
    approved_environment = runtime.capture_driver_environment(manifest)
    approved_fingerprint = runtime.driver_environment_fingerprint(manifest, approved_environment)
    monkeypatch.setenv("HOUND_ACCOUNT", "different-account")

    assert (
        runtime.driver_environment_fingerprint(
            manifest, runtime.capture_driver_environment(manifest)
        )
        != approved_fingerprint
    )
    assert (
        run_driver(
            manifest,
            {},
            manifest_path=manifest_path,
            driver_environment=approved_environment,
        )
        == VALID_RESPONSE
    )


def test_run_driver_exports_only_the_selected_capability_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    driver = _driver(
        repo,
        "import json, os, sys\n"
        "operation = json.load(sys.stdin).get('operation')\n"
        "expected = {'diagnose': 'DIAGNOSE_TOKEN', 'report': 'REPORT_TOKEN'}[operation]\n"
        "other = {'diagnose': 'REPORT_TOKEN', 'report': 'DIAGNOSE_TOKEN'}[operation]\n"
        "if os.environ.get('GLOBAL_ACCOUNT') != 'account':\n"
        "    raise SystemExit(7)\n"
        "if os.environ.get(expected) != operation:\n"
        "    raise SystemExit(8)\n"
        "if other in os.environ:\n"
        "    raise SystemExit(9)\n"
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["GLOBAL_ACCOUNT"],
    )
    manifest["capabilities"] = {
        "diagnose": {
            "effect": "read",
            "gate": "none",
            "env_allowlist": ["DIAGNOSE_TOKEN"],
        },
        "report": {
            "effect": "read",
            "gate": "none",
            "env_allowlist": ["REPORT_TOKEN"],
        },
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("GLOBAL_ACCOUNT", "account")
    monkeypatch.setenv("DIAGNOSE_TOKEN", "diagnose")
    monkeypatch.setenv("REPORT_TOKEN", "report")

    assert (
        run_driver(
            manifest,
            {"operation": "diagnose"},
            manifest_path=manifest_path,
        )
        == VALID_RESPONSE
    )
    assert (
        run_driver(
            manifest,
            {"operation": "report"},
            manifest_path=manifest_path,
        )
        == VALID_RESPONSE
    )


@pytest.mark.parametrize("variable_name", ["FIRECRAWL_API_KEY", "DATABASE_URL"])
def test_run_driver_never_returns_or_reports_allowlisted_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variable_name: str
) -> None:
    repo = _repo(tmp_path)
    secret = "fc-super-secret-value"
    monkeypatch.setenv(variable_name, secret)
    leaking = _driver(
        repo,
        """
import json
import os
import sys

secret = os.environ[sys.argv[1]]
print(json.dumps({
    "schema_version": "hound.driver.response.v1",
    "ok": True,
    "outcome": "completed",
    "data": {"echo": secret},
}))
""".lstrip(),
    )
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(leaking), variable_name],
        env_allowlist=[variable_name],
    )

    with pytest.raises(RuntimeErrorHound, match="credential") as caught:
        run_driver(manifest, {}, manifest_path=manifest_path)

    assert secret not in str(caught.value)


def test_run_driver_allows_public_allowlisted_configuration_in_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    public_url = "https://media.example.test"
    monkeypatch.setenv("CLOUDFLARE_R2_PUBLIC_URL", public_url)
    driver = _driver(
        repo,
        f"print({json.dumps(json.dumps({**VALID_RESPONSE, 'data': {'url': public_url}}))})\n",
    )
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        env_allowlist=["CLOUDFLARE_R2_PUBLIC_URL"],
    )

    response = run_driver(manifest, {}, manifest_path=manifest_path)

    assert response["data"]["url"] == public_url


def test_run_driver_fails_closed_on_nonzero_and_reports_stderr(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    driver = _driver(
        repo,
        "import sys\nprint('bounded diagnostic', file=sys.stderr)\nraise SystemExit(7)\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    with pytest.raises(RuntimeErrorHound, match="bounded diagnostic"):
        run_driver(manifest, {}, manifest_path=manifest_path)


def test_run_driver_fails_closed_on_timeout(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    driver = _driver(repo, "import time\ntime.sleep(1)\n")
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    with pytest.raises(RuntimeErrorHound, match="timed out"):
        run_driver(manifest, {}, manifest_path=manifest_path, timeout=0.01)


def test_run_driver_uses_manifest_timeout_when_no_override(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    driver = _driver(repo, "import time\ntime.sleep(1)\n")
    manifest, manifest_path = _manifest(
        repo,
        [sys.executable, str(driver)],
        timeouts_seconds={"default": 0.01},
    )

    with pytest.raises(RuntimeErrorHound, match="timed out"):
        run_driver(manifest, {}, manifest_path=manifest_path)


@pytest.mark.parametrize("timeout", [float("inf"), float("nan")])
def test_run_driver_rejects_nonfinite_explicit_timeout(tmp_path: Path, timeout: float) -> None:
    repo = _repo(tmp_path)
    driver = _driver(
        repo,
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    with pytest.raises(RuntimeErrorHound, match="finite"):
        run_driver(manifest, {}, manifest_path=manifest_path, timeout=timeout)


def test_timeout_terminates_driver_process_group(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "orphan-wrote"
    child_code = (
        "import pathlib,time; time.sleep(0.3); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    driver = _driver(
        repo,
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "time.sleep(2)\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    with pytest.raises(RuntimeErrorHound, match="timed out"):
        run_driver(manifest, {}, manifest_path=manifest_path, timeout=0.1)
    time.sleep(0.45)

    assert not marker.exists()


@pytest.mark.skipif(not Path("/proc/self").is_dir(), reason="Linux containment proof")
def test_timeout_terminates_detached_driver_descendant(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "detached-wrote"
    child_code = (
        "import pathlib,time; time.sleep(0.3); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    driver = _driver(
        repo,
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], start_new_session=True)\n"
        "time.sleep(2)\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    with pytest.raises(RuntimeErrorHound, match="timed out"):
        run_driver(manifest, {}, manifest_path=manifest_path, timeout=0.1)
    time.sleep(0.45)

    assert not marker.exists()


@pytest.mark.skipif(not Path("/proc/self").is_dir(), reason="Linux containment proof")
def test_successful_driver_cannot_leave_detached_descendant(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "detached-after-success"
    child_code = (
        "import pathlib,time; time.sleep(0.3); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    driver = _driver(
        repo,
        "import subprocess,sys\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], start_new_session=True)\n"
        f"print({json.dumps(json.dumps(VALID_RESPONSE))})\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    assert run_driver(manifest, {}, manifest_path=manifest_path) == VALID_RESPONSE
    time.sleep(0.45)

    assert not marker.exists()


@pytest.mark.skipif(not Path("/proc/self").is_dir(), reason="Linux containment proof")
def test_keyboard_interrupt_terminates_supervised_driver_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    repo = _repo(tmp_path)
    marker = tmp_path / "detached-after-interrupt"
    child_code = (
        "import pathlib,time; time.sleep(0.3); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    driver = _driver(
        repo,
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], start_new_session=True)\n"
        "time.sleep(2)\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])

    def interrupt_after_spawn(*_: object) -> tuple[bytes, bytes, str | None]:
        time.sleep(0.1)
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime, "_collect_driver_output", interrupt_after_spawn)

    with pytest.raises(KeyboardInterrupt):
        run_driver(manifest, {}, manifest_path=manifest_path)
    time.sleep(0.45)

    assert not marker.exists()


@pytest.mark.skipif(not Path("/proc/self").is_dir(), reason="Linux containment proof")
def test_supervisor_terminates_driver_tree_if_hound_parent_dies(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "detached-after-parent-death"
    started = tmp_path / "driver-started"
    child_code = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    driver = _driver(
        repo,
        "import pathlib,subprocess,sys,time\n"
        f"pathlib.Path({str(started)!r}).write_text('started')\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], start_new_session=True)\n"
        "time.sleep(5)\n",
    )
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])
    runner = tmp_path / "runner.py"
    runner.write_text(
        "import json,sys\n"
        "from pathlib import Path\n"
        "from hound_cli.runtime import run_driver\n"
        "manifest_path = Path(sys.argv[1])\n"
        "manifest = json.loads(manifest_path.read_text())\n"
        "run_driver(manifest, {}, manifest_path=manifest_path, timeout=10)\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, str(runner), str(manifest_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 2
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()

    process.kill()
    process.wait(timeout=2)
    time.sleep(0.65)

    assert not marker.exists()


def test_driver_output_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hound_cli.runtime as runtime

    repo = _repo(tmp_path)
    driver = _driver(repo, "print('x' * 100)\n")
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])
    monkeypatch.setattr(runtime, "MAX_DRIVER_OUTPUT_BYTES", 32)

    with pytest.raises(RuntimeErrorHound, match="output size"):
        run_driver(manifest, {}, manifest_path=manifest_path)


def test_driver_output_is_streamed_through_bounded_pipes_not_temp_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    repo = _repo(tmp_path)
    driver = _driver(repo, "import os\nos.write(1, b'x' * 1048576)\n")
    manifest, manifest_path = _manifest(repo, [sys.executable, str(driver)])
    monkeypatch.setattr(runtime, "MAX_DRIVER_OUTPUT_BYTES", 4096)
    real_temporary_file = runtime.tempfile.TemporaryFile
    temporary_file_calls = 0

    def counted_temporary_file(*args: object, **kwargs: object):
        nonlocal temporary_file_calls
        temporary_file_calls += 1
        return real_temporary_file(*args, **kwargs)

    monkeypatch.setattr(runtime.tempfile, "TemporaryFile", counted_temporary_file)

    with pytest.raises(RuntimeErrorHound, match="output size"):
        run_driver(manifest, {}, manifest_path=manifest_path)

    assert temporary_file_calls == 1


def test_repo_fingerprint_detects_staged_unstaged_and_untracked_drift(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    initial = repo_fingerprint(repo)

    assert initial == repo_fingerprint(repo)
    assert initial["head"] == _git(repo, "rev-parse", "HEAD")
    assert initial["untracked"] == {}

    (repo / "tracked.txt").write_text("unstaged\n", encoding="utf-8")
    unstaged = repo_fingerprint(repo)
    assert unstaged["head"] == initial["head"]
    assert unstaged["staged_diff_sha256"] == initial["staged_diff_sha256"]
    assert unstaged["unstaged_diff_sha256"] != initial["unstaged_diff_sha256"]

    _git(repo, "add", "tracked.txt")
    staged = repo_fingerprint(repo)
    assert staged["staged_diff_sha256"] != initial["staged_diff_sha256"]
    assert staged["unstaged_diff_sha256"] == initial["unstaged_diff_sha256"]

    (repo / "untracked.txt").write_text("new material\n", encoding="utf-8")
    untracked = repo_fingerprint(repo)
    assert set(untracked["untracked"]) == {"untracked.txt"}

    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    ignored = repo_fingerprint(repo)
    assert "ignored.txt" not in ignored["untracked"]


def test_repo_fingerprint_hashes_tracked_bytes_even_when_git_hides_change(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    initial = repo_fingerprint(repo)
    _git(repo, "update-index", "--assume-unchanged", "tracked.txt")
    (repo / "tracked.txt").write_text("hidden change\n", encoding="utf-8")

    changed = repo_fingerprint(repo)

    assert changed["unstaged_diff_sha256"] == initial["unstaged_diff_sha256"]
    assert changed["tracked"] != initial["tracked"]


def test_repo_fingerprint_binds_git_index_flags(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    initial = repo_fingerprint(repo)

    _git(repo, "update-index", "--assume-unchanged", "tracked.txt")

    assert repo_fingerprint(repo) != initial


def test_snapshot_observes_shallow_history_state(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "tracked.txt").write_text("second\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "second")
    before = snapshot_repo(repo)

    (repo / ".git" / "shallow").write_text(
        _git(repo, "rev-parse", "HEAD") + "\n",
        encoding="utf-8",
    )
    after = snapshot_repo(repo)

    assert _git(repo, "rev-list", "--count", "HEAD") == "1"
    assert changed_paths(before, after) == [".git/hound-refs-state"]


def test_snapshot_observes_reflog_mutation(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = snapshot_repo(repo)

    with (repo / ".git" / "logs" / "HEAD").open("a", encoding="utf-8") as log:
        log.write("# unexpected mutation\n")

    assert changed_paths(before, snapshot_repo(repo)) == [".git/hound-refs-state"]


def test_repo_fingerprint_binds_effective_git_config_and_hooks(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    hooks = tmp_path / "trusted-hooks"
    hooks.mkdir()
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)
    _git(repo, "config", "core.hooksPath", str(hooks))
    initial = repo_fingerprint(repo)

    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")

    assert repo_fingerprint(repo) != initial


def test_snapshot_binds_sensitive_metadata_for_linked_worktree(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    worktree = tmp_path / "linked-worktree"
    _git(repo, "worktree", "add", "-q", str(worktree))
    before = snapshot_repo(worktree)

    _git(worktree, "config", "hound.test-setting", "changed")
    after = snapshot_repo(worktree)

    assert ".git/hound-sensitive-state" in changed_paths(before, after)


def test_git_checks_ignore_ambient_git_redirection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner_parent = tmp_path / "owner-parent"
    other_parent = tmp_path / "other-parent"
    owner_parent.mkdir()
    other_parent.mkdir()
    owner = _repo(owner_parent)
    other = _repo(other_parent)
    expected_head = _git(owner, "rev-parse", "HEAD")
    (other / "tracked.txt").write_text("other repository\n", encoding="utf-8")
    _git(other, "add", "tracked.txt")
    _git(other, "commit", "-qm", "different head")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))

    fingerprint = repo_fingerprint(owner)

    assert fingerprint["head"] == expected_head


def test_git_command_has_a_wall_clock_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    fake_git = tmp_path / "fake-git"
    fake_git.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(1)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setattr(runtime, "_GIT_EXECUTABLE", str(fake_git))
    monkeypatch.setattr(runtime, "GIT_COMMAND_TIMEOUT_SECONDS", 0.02)

    with pytest.raises(RuntimeErrorHound, match="git .* timed out"):
        runtime._git(tmp_path, "status")


def test_git_command_output_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hound_cli.runtime as runtime

    fake_git = tmp_path / "fake-git"
    fake_git.write_text(
        f"#!{sys.executable}\nimport os\nos.write(1, b'x' * 1048576)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setattr(runtime, "_GIT_EXECUTABLE", str(fake_git))
    monkeypatch.setattr(runtime, "MAX_GIT_OUTPUT_BYTES", 4096)

    with pytest.raises(RuntimeErrorHound, match="git .* output size"):
        runtime._git(tmp_path, "status")


def test_repository_must_be_the_declared_git_root(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    nested = repo / "nested"
    nested.mkdir()

    with pytest.raises(RuntimeErrorHound, match="Git root"):
        repo_fingerprint(nested)


def test_repository_file_hashing_streams_without_reading_whole_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    candidate = tmp_path / "large.bin"
    candidate.write_bytes(b"0123456789abcdef" * 131072)

    def prohibit_read_bytes(_path: Path) -> bytes:
        raise AssertionError("whole-file read is prohibited")

    monkeypatch.setattr(Path, "read_bytes", prohibit_read_bytes)

    assert len(runtime._path_hash(candidate)) == 64


def test_snapshot_and_changed_paths_include_content_changes_additions_and_deletions(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / "delete-me.txt").write_text("gone soon\n", encoding="utf-8")
    _git(repo, "add", "delete-me.txt")
    _git(repo, "commit", "-qm", "add deletion fixture")
    before = snapshot_repo(repo)

    (repo / "tracked.txt").write_text("changed\n", encoding="utf-8")
    (repo / "new.txt").write_text("new\n", encoding="utf-8")
    (repo / "delete-me.txt").unlink()
    after = snapshot_repo(repo)

    assert changed_paths(before, after) == ["delete-me.txt", "new.txt", "tracked.txt"]


def test_snapshot_observes_ignored_files_modes_and_sensitive_git_config(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("before\n", encoding="utf-8")
    before = snapshot_repo(repo)

    (repo / "ignored.txt").write_text("after\n", encoding="utf-8")
    os.chmod(repo / "tracked.txt", 0o755)
    with (repo / ".git" / "config").open("a", encoding="utf-8") as stream:
        stream.write("\n[hound]\n\ttest = changed\n")
    after = snapshot_repo(repo)

    assert changed_paths(before, after) == [
        ".git/hound-sensitive-state",
        "ignored.txt",
        "tracked.txt",
    ]


def test_snapshot_exclusions_skip_only_ignored_files_under_declared_prefixes(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("cache/\n", encoding="utf-8")
    cache = repo / "cache"
    cache.mkdir()
    (cache / "tracked.txt").write_text("tracked before\n", encoding="utf-8")
    (cache / "ignored.txt").write_text("ignored before\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "add", "-f", "cache/tracked.txt")
    _git(repo, "commit", "-qm", "add cache fixture")
    before = snapshot_repo(repo, ignored_snapshot_excludes=["cache"])

    (cache / "tracked.txt").write_text("tracked after\n", encoding="utf-8")
    (cache / "ignored.txt").write_text("ignored after\n", encoding="utf-8")
    after = snapshot_repo(repo, ignored_snapshot_excludes=["cache"])

    assert changed_paths(before, after) == ["cache/tracked.txt"]
    assert "cache/ignored.txt" in snapshot_repo(repo)


def test_snapshot_observes_index_changes_without_worktree_byte_changes(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / "candidate.txt").write_text("same bytes\n", encoding="utf-8")
    before = snapshot_repo(repo)

    _git(repo, "add", "candidate.txt")
    after = snapshot_repo(repo)

    assert changed_paths(before, after) == [".git/hound-index-state"]


def test_snapshot_observes_head_and_ref_changes_after_commit(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "candidate.txt").write_text("same bytes\n", encoding="utf-8")
    _git(repo, "add", "candidate.txt")
    before = snapshot_repo(repo)

    _git(repo, "commit", "-qm", "advance history")
    after = snapshot_repo(repo)

    assert changed_paths(before, after) == [".git/hound-refs-state"]


def test_snapshot_observes_reachable_git_object_corruption(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = snapshot_repo(repo)
    head = _git(repo, "rev-parse", "HEAD")
    (repo / ".git" / "objects" / head[:2] / head[2:]).unlink()

    after = snapshot_repo(repo)

    assert changed_paths(before, after) == [".git/hound-integrity-state"]


def test_snapshot_observes_reachable_git_blob_corruption(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = snapshot_repo(repo)
    blob = _git(repo, "rev-parse", "HEAD:tracked.txt")
    object_path = repo / ".git" / "objects" / blob[:2] / blob[2:]
    os.chmod(object_path, 0o600)
    object_path.write_bytes(object_path.read_bytes()[:4])

    after = snapshot_repo(repo)

    assert changed_paths(before, after) == [".git/hound-integrity-state"]


def test_paths_within_scopes_rejects_out_of_scope_and_symlink_escape(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    allowed = repo / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (allowed / "escape").symlink_to(outside, target_is_directory=True)

    ok, violations = paths_within_scopes(
        repo,
        ["allowed/report.json", "outside.txt", "allowed/escape/secret.txt"],
        ["allowed"],
    )

    assert ok is False
    assert violations == ["allowed/escape/secret.txt", "outside.txt"]

    assert paths_within_scopes(repo, ["allowed/report.json"], ["allowed"]) == (
        True,
        [],
    )


def test_create_only_byte_write_does_not_publish_on_link_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hound_cli.runtime as runtime

    path = tmp_path / "state" / "capture"

    def fail_link(_source: Path, _destination: Path) -> None:
        raise OSError("synthetic publication failure")

    monkeypatch.setattr(runtime.os, "link", fail_link)

    with pytest.raises(RuntimeErrorHound, match="cannot create"):
        runtime.write_bytes_create_only(path, b"complete bytes")

    assert not path.exists()
    assert list(path.parent.iterdir()) == []


def test_write_json_create_only_never_changes_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "state" / "run.json"
    write_json_create_only(path, {"b": 2, "a": 1})
    original = path.read_bytes()

    with pytest.raises(RuntimeErrorHound, match="already exists"):
        write_json_create_only(path, {"replacement": True})

    assert path.read_bytes() == original
    assert json.loads(original) == {"a": 1, "b": 2}


def test_write_json_atomic_replaces_the_complete_document(tmp_path: Path) -> None:
    path = tmp_path / "state" / "latest.json"
    write_json_atomic(path, {"version": 1})
    write_json_atomic(path, {"version": 2, "complete": True})

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "complete": True,
        "version": 2,
    }
    assert [entry.name for entry in path.parent.iterdir()] == ["latest.json"]


def test_snapshot_excludes_match_path_semantics_not_string_prefixes(tmp_path: Path) -> None:
    """Prefix matching must not swallow a sibling whose name merely starts the same.

    snapshot_repo filters ignored paths by string prefix because building a
    PurePosixPath per entry and walking its .parents cost 20.9s against 0.01s on
    a real working tree (65,550 ignored paths, 24 excludes) -- and two snapshots
    bracket every adapter call. The speed is only safe if it still means "within
    this directory", so `.venv-old/` must survive an exclude of `.venv`.
    """
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text(".venv\n.venv-old\ncache\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-qm", "ignore")

    for directory in (".venv", ".venv-old", "cache"):
        (repo / directory).mkdir()
        (repo / directory / "f.txt").write_text(directory, encoding="utf-8")

    snapshot = snapshot_repo(repo, ignored_snapshot_excludes=[".venv", "cache/"])

    assert ".venv/f.txt" not in snapshot, "excluded directory must be skipped"
    assert "cache/f.txt" not in snapshot, "a trailing separator must not change meaning"
    assert ".venv-old/f.txt" in snapshot, ".venv must not swallow the .venv-old sibling"
