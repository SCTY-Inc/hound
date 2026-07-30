"""Deterministic planning and guarded execution for Hound drivers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Any

from .contracts import (
    ContractError,
    canonical_hash,
    canonical_json,
    load_manifest,
    validate_manifest,
    validate_response,
)
from .runtime import (
    capture_driver_environment,
    changed_paths,
    driver_environment_fingerprint,
    kernel_identity as _kernel_identity,
    paths_within_scopes,
    repo_execution_lock,
    repo_fingerprint,
    run_driver,
    run_driver_with_receipt,
    snapshot_repo,
    write_json_atomic,
    write_json_create_only,
)


class HoundError(Exception):
    """An operator-facing orchestration failure with a stable exit code."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FILE_MODE = re.compile(r"0[0-7]{3}\Z")


def _owner_repo(manifest: dict[str, Any], manifest_path: Path) -> Path:
    raw = Path(manifest["owner"]["repo"])
    repo = raw if raw.is_absolute() else manifest_path.parent / raw
    resolved = repo.resolve()
    if not resolved.is_dir():
        raise HoundError(f"owner repository does not exist: {resolved}", exit_code=2)
    return resolved


def _snapshot_owner_repo(manifest: dict[str, Any], repo: Path) -> dict[str, str]:
    excludes = manifest.get("ignored_snapshot_excludes", [])
    if excludes:
        return snapshot_repo(repo, ignored_snapshot_excludes=excludes)
    return snapshot_repo(repo)


def _capability(manifest: dict[str, Any], operation: str) -> dict[str, Any]:
    capability = manifest["capabilities"].get(operation)
    if capability is None:
        raise HoundError(
            f"driver {manifest['id']!r} does not declare capability {operation!r}",
            exit_code=2,
        )
    return capability


def _expected_write_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise HoundError("expected write must be a non-empty relative path", exit_code=2)
    path = PurePosixPath(value.replace("\\", "/"))
    windows_path = PureWindowsPath(value)
    if (
        path == PurePosixPath(".")
        or path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or ".." in path.parts
    ):
        raise HoundError(
            f"expected write must identify a path inside the owner repository: {value!r}",
            exit_code=2,
        )
    if path.parts[0] == ".git":
        raise HoundError(
            f"driver planned a prohibited Git metadata write: {path.as_posix()}",
            exit_code=2,
        )
    return path.as_posix()


def _scope_contains(scope: str, path: str) -> bool:
    scope_path = PurePosixPath(scope)
    path_obj = PurePosixPath(path)
    return scope == "." or path_obj == scope_path or scope_path in path_obj.parents


def _validated_expected_writes(data: dict[str, Any], scopes: list[str]) -> list[str]:
    effects = _validated_expected_effects(data, scopes)
    if effects is not None:
        return [effect["path"] for effect in effects]
    raw = data.get("expected_writes", [])
    if not isinstance(raw, list):
        raise HoundError("driver plan expected_writes must be a list", exit_code=2)
    writes = sorted({_expected_write_path(item) for item in raw})
    for path in writes:
        if not any(_scope_contains(scope, path) for scope in scopes):
            raise HoundError(
                f"driver planned a write outside declared scopes: {path}",
                exit_code=2,
            )
    return writes


def _validated_expected_effects(
    data: dict[str, Any], scopes: list[str]
) -> list[dict[str, Any]] | None:
    if "expected_effects" not in data:
        return None
    if "expected_writes" in data:
        raise HoundError(
            "driver plan must use either expected_effects or expected_writes, not both",
            exit_code=2,
        )
    raw = data["expected_effects"]
    if not isinstance(raw, list):
        raise HoundError("driver plan expected_effects must be a list", exit_code=2)
    effects: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "mode",
            "before_sha256",
            "after_sha256",
        }:
            raise HoundError("driver plan contains a malformed expected effect", exit_code=2)
        path = _expected_write_path(item["path"])
        mode = item["mode"]
        before = item["before_sha256"]
        after = item["after_sha256"]
        if before is not None and (not isinstance(before, str) or not _SHA256.fullmatch(before)):
            raise HoundError("expected effect before_sha256 must be null or SHA-256", exit_code=2)
        if after is not None and (not isinstance(after, str) or not _SHA256.fullmatch(after)):
            raise HoundError("expected effect after_sha256 must be null or SHA-256", exit_code=2)
        if before is None and after is None:
            raise HoundError("expected effect must create, update, or delete a file", exit_code=2)
        if after is None:
            if mode is not None:
                raise HoundError("deleted expected effect mode must be null", exit_code=2)
        elif not isinstance(mode, str) or not _FILE_MODE.fullmatch(mode):
            raise HoundError("expected effect mode must be a four-digit POSIX mode", exit_code=2)
        if not any(_scope_contains(scope, path) for scope in scopes):
            raise HoundError(f"driver planned a write outside declared scopes: {path}", exit_code=2)
        effects.append(
            {
                "path": path,
                "mode": mode,
                "before_sha256": before,
                "after_sha256": after,
            }
        )
    if len({effect["path"] for effect in effects}) != len(effects):
        raise HoundError("driver plan contains duplicate expected effect paths", exit_code=2)
    return sorted(effects, key=lambda effect: effect["path"])


def _file_state(repo: Path, relative: str) -> tuple[str | None, str | None]:
    path = repo / relative
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise HoundError(f"cannot resolve exact effect path: {relative}", exit_code=2) from exc
    if not resolved.is_relative_to(repo):
        raise HoundError(
            f"exact effect path must remain inside owner repository: {relative}",
            exit_code=2,
        )
    if not path.exists():
        return None, None
    if path.is_symlink() or not path.is_file():
        raise HoundError(f"exact effects support regular files only: {relative}", exit_code=2)
    try:
        return (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            f"{stat.S_IMODE(path.stat().st_mode):04o}",
        )
    except OSError as exc:
        raise HoundError(f"cannot hash exact effect path: {relative}", exit_code=2) from exc


def _validate_effects_against_repo(
    data: dict[str, Any], scopes: list[str], repo: Path
) -> None:
    effects = _validated_expected_effects(data, scopes)
    if effects is None:
        return
    for effect in effects:
        before_sha256, _ = _file_state(repo, effect["path"])
        if before_sha256 != effect["before_sha256"]:
            raise HoundError(
                f"expected effect before_sha256 does not match repository: {effect['path']}",
                exit_code=2,
            )


def _invoke_nonmutating_driver_with_receipt(
    manifest: dict[str, Any],
    request: dict[str, Any],
    *,
    manifest_path: Path,
    repo: Path,
    mode: str,
    driver_environment: dict[str, str] | None = None,
    decoded_outputs: Callable[[dict[str, Any]], Iterable[object]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected_environment = (
        capture_driver_environment(manifest, operation=request.get("operation"))
        if driver_environment is None
        else driver_environment
    )
    before = _snapshot_owner_repo(manifest, repo)
    if not before.get(".git/hound-integrity-state", "").startswith("0:"):
        raise HoundError("repository Git object integrity check failed")
    invocation: tuple[dict[str, Any], dict[str, Any]] | None = None
    driver_error: BaseException | None = None
    try:
        invocation = run_driver_with_receipt(
            manifest,
            request,
            manifest_path=manifest_path,
            driver_environment=selected_environment,
            decoded_outputs=decoded_outputs,
        )
    except BaseException as exc:
        driver_error = exc
    changes = changed_paths(before, _snapshot_owner_repo(manifest, repo))
    if changes:
        raise HoundError(
            f"driver {mode} mode modified the owner repository: {', '.join(changes)}"
        ) from driver_error
    if driver_error is not None:
        raise driver_error
    assert invocation is not None
    return invocation


def _invoke_nonmutating_driver(
    manifest: dict[str, Any],
    request: dict[str, Any],
    *,
    manifest_path: Path,
    repo: Path,
    mode: str,
    driver_environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    response, _ = _invoke_nonmutating_driver_with_receipt(
        manifest,
        request,
        manifest_path=manifest_path,
        repo=repo,
        mode=mode,
        driver_environment=driver_environment,
    )
    return response


def _plan_without_id(plan: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in plan.items() if key != "plan_id"}


def _driver_failure(message: str, response: dict[str, Any]) -> str:
    diagnostics = response.get("diagnostics", [])
    if not diagnostics:
        return message
    detail = canonical_json(diagnostics)
    if len(detail) > 2048:
        detail = detail[:2045] + "..."
    return f"{message}: {detail}"


def _validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or plan.get("schema_version") not in {
        "hound.plan.v1",
        "hound.plan.v2",
    }:
        raise HoundError("unsupported or malformed Hound plan", exit_code=2)
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or canonical_hash(_plan_without_id(plan)) != plan_id:
        raise HoundError("plan_id does not match plan contents", exit_code=2)
    if plan["schema_version"] == "hound.plan.v2":
        try:
            proposal = validate_response(plan.get("proposal"))
        except ContractError as error:
            raise HoundError("plan proposal is malformed", exit_code=2) from error
        if proposal["outcome"] not in {"planned", "no-change", "no-op", "no-edition"}:
            raise HoundError("plan proposal has an invalid outcome", exit_code=2)
        data = proposal.get("data")
        if not isinstance(data, dict):
            raise HoundError("plan proposal data must be an object", exit_code=2)
        _validated_expected_writes(data, plan.get("write_scopes", []))


def _plan_proposal(plan: dict[str, Any]) -> dict[str, Any]:
    if plan.get("schema_version") == "hound.plan.v2":
        return plan["proposal"]
    return plan["planning_response"]


def _plan_expected_writes(plan: dict[str, Any]) -> list[str]:
    if plan.get("schema_version") == "hound.plan.v2":
        return _validated_expected_writes(
            _plan_proposal(plan)["data"], plan.get("write_scopes", [])
        )
    return plan["expected_writes"]


def _plan_expected_effects(plan: dict[str, Any]) -> list[dict[str, Any]] | None:
    if plan.get("schema_version") != "hound.plan.v2":
        return None
    return _validated_expected_effects(
        _plan_proposal(plan)["data"], plan.get("write_scopes", [])
    )


def make_plan(
    manifest_path: str | Path,
    operation: str,
    payload: dict[str, Any] | None,
    *,
    as_of: str,
) -> dict[str, Any]:
    """Ask a driver for a plan and bind it to code, inputs, and repository state."""

    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    repo = _owner_repo(manifest, path)
    capability = _capability(manifest, operation)
    driver_environment = capture_driver_environment(manifest, operation=operation)
    environment_sha256 = driver_environment_fingerprint(
        manifest, driver_environment, operation=operation
    )
    request = {
        "schema_version": "hound.driver.request.v1",
        "mode": "plan",
        "operation": operation,
        "as_of": as_of,
        "input": payload or {},
    }
    response = _invoke_nonmutating_driver(
        manifest,
        request,
        manifest_path=path,
        repo=repo,
        mode="plan",
        driver_environment=driver_environment,
    )
    if (
        driver_environment_fingerprint(
            manifest,
            capture_driver_environment(manifest, operation=operation),
            operation=operation,
        )
        != environment_sha256
    ):
        raise HoundError("driver environment changed while planning", exit_code=2)
    if not response["ok"]:
        raise HoundError(_driver_failure("driver reported failure while planning", response))
    if response["outcome"] not in {"planned", "no-change", "no-op", "no-edition"}:
        raise HoundError(f"driver returned non-plan outcome: {response['outcome']}")

    scopes = sorted(manifest.get("write_scopes", []))
    driver_data = response.get("data", {})
    if not isinstance(driver_data, dict):
        raise HoundError("driver plan data must be an object", exit_code=2)
    _validated_expected_writes(driver_data, scopes)
    _validate_effects_against_repo(driver_data, scopes, repo)
    body: dict[str, Any] = {
        "schema_version": "hound.plan.v2",
        "driver_id": manifest["id"],
        "driver_manifest_sha256": canonical_hash(manifest),
        "driver_environment_sha256": environment_sha256,
        "kernel": _kernel_identity(),
        "operation": operation,
        "effect": capability["effect"],
        "gate": capability["gate"],
        "as_of": as_of,
        "input": payload or {},
        "input_sha256": canonical_hash(payload or {}),
        "repo_fingerprint": repo_fingerprint(repo),
        "write_scopes": scopes,
        "write_scope_sha256": canonical_hash(scopes),
        "proposal": response,
    }
    return {**body, "plan_id": canonical_hash(body)}


def check_driver(manifest_path: str | Path) -> dict[str, Any]:
    """Handshake with a driver while enforcing the non-mutating boundary."""

    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    repo = _owner_repo(manifest, path)
    request = {"schema_version": "hound.driver.request.v1", "mode": "check"}
    return _invoke_nonmutating_driver(
        manifest,
        request,
        manifest_path=path,
        repo=repo,
        mode="check",
    )


def create_approval(
    plan: dict[str, Any],
    *,
    reviewer: str,
    approved_at: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Create an explicit approval artifact bound to exactly one plan."""

    _validate_plan(plan)
    if plan["schema_version"] != "hound.plan.v2":
        raise HoundError("historical plans are verification-only", exit_code=2)
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise HoundError("reviewer must not be empty", exit_code=2)
    timestamp = approved_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    approved_timestamp = _approval_timestamp(timestamp, "approved_at", exit_code=2)
    body: dict[str, Any] = {
        "schema_version": "hound.approval.v1",
        "plan_id": plan["plan_id"],
        "driver_id": plan["driver_id"],
        "operation": plan["operation"],
        "write_scope_sha256": plan["write_scope_sha256"],
        "reviewer": reviewer,
        "approved_at": timestamp,
    }
    if expires_at is not None:
        expiration = _approval_timestamp(expires_at, "expires_at", exit_code=2)
        if expiration <= approved_timestamp:
            raise HoundError("expires_at must be after approved_at", exit_code=2)
        body["expires_at"] = expires_at
    return {**body, "approval_id": canonical_hash(body)}


def _approval_timestamp(value: object, label: str, *, exit_code: int) -> datetime:
    if not isinstance(value, str) or not value:
        raise HoundError(f"approval {label} is malformed", exit_code=exit_code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HoundError(f"approval {label} is malformed", exit_code=exit_code) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HoundError(f"approval {label} must include a timezone", exit_code=exit_code)
    return parsed


def _validate_approval_artifact(
    plan: dict[str, Any],
    approval: object,
    *,
    enforce_expiration: bool,
) -> None:
    if not isinstance(approval, dict):
        raise HoundError("approval artifact is malformed", exit_code=3)
    required = {
        "schema_version",
        "plan_id",
        "driver_id",
        "operation",
        "write_scope_sha256",
        "reviewer",
        "approved_at",
        "approval_id",
    }
    optional = {"expires_at"}
    if required - approval.keys() or set(approval) - required - optional:
        raise HoundError("approval artifact is malformed", exit_code=3)
    expected = {
        "plan_id": plan["plan_id"],
        "driver_id": plan["driver_id"],
        "operation": plan["operation"],
        "write_scope_sha256": plan["write_scope_sha256"],
    }
    if any(approval.get(key) != value for key, value in expected.items()):
        raise HoundError("approval does not match the exact plan and write scope", exit_code=3)
    body = {key: value for key, value in approval.items() if key != "approval_id"}
    if approval.get("schema_version") != "hound.approval.v1" or approval.get(
        "approval_id"
    ) != canonical_hash(body):
        raise HoundError("approval artifact is malformed or has been modified", exit_code=3)
    reviewer = approval["reviewer"]
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise HoundError("approval reviewer must not be empty", exit_code=3)
    approved_at = _approval_timestamp(approval["approved_at"], "approved_at", exit_code=3)
    expires_at = approval.get("expires_at")
    if expires_at is not None:
        expiration = _approval_timestamp(expires_at, "expires_at", exit_code=3)
        if expiration <= approved_at:
            raise HoundError("approval expires_at must be after approved_at", exit_code=3)
        if enforce_expiration and expiration <= datetime.now(timezone.utc):
            raise HoundError("approval has expired", exit_code=3)


def _validate_approval(plan: dict[str, Any], approval: dict[str, Any] | None) -> None:
    if plan["gate"] != "human":
        return
    if approval is None:
        raise HoundError("this plan requires an approval artifact", exit_code=3)
    _validate_approval_artifact(plan, approval, enforce_expiration=True)


def _run_root(manifest: dict[str, Any], manifest_path: Path, repo: Path) -> Path:
    raw = Path(manifest.get("run_root", ".hound/runs"))
    candidate = raw if raw.is_absolute() else repo / raw
    root = candidate.resolve()
    try:
        root.relative_to(repo)
    except ValueError as exc:
        raise HoundError("run_root must remain inside the owner repository", exit_code=2) from exc
    return root


def _fingerprint_without_run_records(
    repo: Path, run_dir: Path, record_names: list[str]
) -> dict[str, Any]:
    record_paths = {(run_dir / name).relative_to(repo).as_posix() for name in record_names}
    fingerprint = repo_fingerprint(repo)
    fingerprint["untracked"] = {
        path: digest
        for path, digest in fingerprint["untracked"].items()
        if path not in record_paths
    }
    fingerprint["fingerprint_sha256"] = canonical_hash(
        {key: value for key, value in fingerprint.items() if key != "fingerprint_sha256"}
    )
    return fingerprint


def _protected_record_matches(path: Path, expected_size: int, expected_sha256: str) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return False
            digest = hashlib.sha256()
            remaining = expected_size
            while remaining:
                chunk = stream.read(min(64 * 1024, remaining))
                if not chunk:
                    return False
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                return False
    except OSError:
        return False
    return digest.hexdigest() == expected_sha256


def _write_run_index(run_dir: Path, plan_id: str, *, replace: bool = False) -> None:
    names = ["driver-manifest.json", "plan.json", "request.json", "result.json"]
    if (run_dir / "approval.json").is_file():
        names.append("approval.json")
    hashes = {name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest() for name in names}
    writer = write_json_atomic if replace else write_json_create_only
    writer(
        run_dir / "index.json",
        {
            "schema_version": "hound.run.index.v1",
            "plan_id": plan_id,
            "files": hashes,
        },
    )


def _actual_matches_expected(path: str, expected: list[str]) -> bool:
    return path in expected


def _result_matches_plan(result: object, plan: dict[str, Any], root: Path) -> bool:
    if not isinstance(result, dict):
        return False
    required = {
        "schema_version",
        "plan_id",
        "outcome",
        "ok",
        "changed_paths",
        "driver_response",
    }
    optional = {"error", "data", "effects"}
    schema = result.get("schema_version")
    if schema == "hound.run.result.v1":
        required.add("run_dir")
    elif schema != "hound.run.result.v2":
        return False
    if set(result) - required - optional or required - result.keys():
        return False
    if (
        result["plan_id"] != plan.get("plan_id")
        or (schema == "hound.run.result.v1" and result["run_dir"] != str(root))
        or not isinstance(result["ok"], bool)
        or result["outcome"]
        not in {"completed", "no-change", "no-op", "no-edition", "held", "failed"}
    ):
        return False
    changed = result["changed_paths"]
    if (
        not isinstance(changed, list)
        or any(not isinstance(path, str) for path in changed)
        or changed != sorted(set(changed))
    ):
        return False
    response = result["driver_response"]
    if response is not None:
        try:
            response = validate_response(response)
        except ContractError:
            return False
    if result["ok"]:
        expected_effects = _plan_expected_effects(plan)
        expected_changed = _plan_expected_writes(plan)
        if (
            plan.get("schema_version") == "hound.plan.v1"
            and result["outcome"] in {"no-change", "no-op", "no-edition"}
        ):
            expected_changed = []
        if (
            result["outcome"] == "failed"
            or "error" in result
            or response is None
            or not response["ok"]
            or response["outcome"] != result["outcome"]
            or result.get("data") != response.get("data", {})
            or changed != expected_changed
            or (
                expected_effects is not None
                and result.get("effects") != expected_effects
            )
            or (expected_effects is None and "effects" in result)
        ):
            return False
    elif (
        result["outcome"] not in {"failed", "held"}
        or not isinstance(result.get("error"), str)
        or not result["error"]
        or "data" in result
    ):
        return False
    return True


def _recorded_manifest_matches(manifest: object, plan: dict[str, Any]) -> bool:
    if not isinstance(manifest, dict):
        return False
    try:
        if plan.get("schema_version") == "hound.plan.v2":
            validate_manifest(manifest)
        else:
            canonical_json(manifest)
    except (ContractError, ValueError):
        return False
    return canonical_hash(manifest) == plan.get("driver_manifest_sha256")


def execute_plan(
    manifest_path: str | Path,
    plan: dict[str, Any],
    *,
    approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute an unchanged plan once, recording proof and checking writes."""

    _validate_plan(plan)
    if plan["schema_version"] != "hound.plan.v2":
        raise HoundError("historical plans are verification-only", exit_code=2)
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    repo = _owner_repo(manifest, path)
    with repo_execution_lock(repo):
        return _execute_plan_locked(path, manifest, repo, plan, approval)


def _execute_plan_locked(
    path: Path,
    manifest: dict[str, Any],
    repo: Path,
    plan: dict[str, Any],
    approval: dict[str, Any] | None,
) -> dict[str, Any]:
    capability = _capability(manifest, plan["operation"])
    if capability["effect"] != "write":
        raise HoundError(
            "read capabilities are invoked directly, not executed as plans", exit_code=2
        )
    if _kernel_identity() != plan.get("kernel"):
        raise HoundError("Hound kernel no longer matches the approved plan", exit_code=2)
    if (
        manifest["id"] != plan["driver_id"]
        or canonical_hash(manifest) != plan["driver_manifest_sha256"]
    ):
        raise HoundError("driver manifest no longer matches the plan", exit_code=2)
    root = _run_root(manifest, path, repo)
    run_dir = root / plan["plan_id"]
    if run_dir.exists():
        raise HoundError(f"immutable run already exists: {run_dir}", exit_code=2)
    if repo_fingerprint(repo) != plan["repo_fingerprint"]:
        raise HoundError("repository fingerprint no longer matches the plan", exit_code=2)
    _validate_approval(plan, approval)

    replanned = make_plan(path, plan["operation"], plan["input"], as_of=plan["as_of"])
    if replanned != plan:
        raise HoundError("driver plan is not deterministic or its inputs changed", exit_code=2)
    _validate_approval(plan, approval)

    root.mkdir(parents=True, exist_ok=True)
    try:
        run_dir.mkdir()
    except FileExistsError as exc:
        raise HoundError(f"immutable run already exists: {run_dir}", exit_code=2) from exc

    request = {
        "schema_version": "hound.driver.request.v1",
        "mode": "execute",
        "operation": plan["operation"],
        "as_of": plan["as_of"],
        "input": plan["input"],
        "plan_id": plan["plan_id"],
        "driver_plan": _plan_proposal(plan)["data"],
    }
    reserved_records: dict[str, Any] = {
        "driver-manifest.json": manifest,
        "plan.json": plan,
        "request.json": request,
    }
    if plan["gate"] == "human" and approval is not None:
        reserved_records["approval.json"] = approval
    reserved_records.update(
        {
            "result.json": {
                "schema_version": "hound.run.pending.v1",
                "plan_id": plan["plan_id"],
                "record": "result",
            },
            "index.json": {
                "schema_version": "hound.run.pending.v1",
                "plan_id": plan["plan_id"],
                "record": "index",
            },
        }
    )
    for name, record in reserved_records.items():
        write_json_create_only(run_dir / name, record)
    protected_records = {
        name: (
            len(payload),
            hashlib.sha256(payload).hexdigest(),
        )
        for name, record in reserved_records.items()
        for payload in [(canonical_json(record) + "\n").encode("utf-8")]
    }
    protected_names = list(protected_records)

    before: dict[str, str] = {}
    after: dict[str, str] = {}
    snapshot_error: str | None = None
    response: dict[str, Any] | None = None
    driver_error: Exception | None = None
    driver_interrupt: BaseException | None = None
    snapshot_interrupt: BaseException | None = None
    try:
        before = _snapshot_owner_repo(manifest, repo)
    except Exception:
        snapshot_error = "repository snapshot failed before driver launch"
    except BaseException as exc:
        snapshot_error = "repository snapshot interrupted before driver launch"
        snapshot_interrupt = exc
    if snapshot_error is None:
        try:
            current_manifest = load_manifest(path)
            execution_environment = capture_driver_environment(
                current_manifest, operation=plan["operation"]
            )
            if (
                _kernel_identity() != plan.get("kernel")
                or current_manifest["id"] != plan["driver_id"]
                or canonical_hash(current_manifest) != plan["driver_manifest_sha256"]
                or driver_environment_fingerprint(
                    current_manifest,
                    execution_environment,
                    operation=plan["operation"],
                )
                != plan.get("driver_environment_sha256")
                or _fingerprint_without_run_records(repo, run_dir, protected_names)
                != plan["repo_fingerprint"]
            ):
                raise HoundError(
                    "approved kernel, manifest, or repository state changed before launch",
                    exit_code=2,
                )
            _validate_approval(plan, approval)
            response = run_driver(
                manifest,
                request,
                manifest_path=path,
                driver_environment=execution_environment,
            )
        except Exception as exc:  # preserve the failed attempt as an immutable run
            driver_error = exc
        except BaseException as exc:  # finalize the immutable run before propagating
            driver_interrupt = exc
        try:
            after = _snapshot_owner_repo(manifest, repo)
        except Exception:
            after = before
            snapshot_error = "repository snapshot failed after driver execution"
        except BaseException as exc:
            after = before
            snapshot_error = "repository snapshot interrupted after driver execution"
            snapshot_interrupt = exc
    altered_records = [
        name
        for name, (expected_size, expected_hash) in protected_records.items()
        if not _protected_record_matches(run_dir / name, expected_size, expected_hash)
    ]
    changed = changed_paths(before, after)
    in_scope, violations = paths_within_scopes(repo, changed, plan["write_scopes"])
    expected = _plan_expected_writes(plan)
    expected_effects = _plan_expected_effects(plan)
    observed_effects: list[dict[str, Any]] | None = None
    effect_error: str | None = None
    if expected_effects is not None:
        try:
            observed_effects = [
                {
                    **effect,
                    "after_sha256": state[0],
                    "mode": state[1],
                }
                for effect in expected_effects
                for state in [_file_state(repo, effect["path"])]
            ]
        except HoundError as exc:
            effect_error = str(exc)
    unexpected = [
        item for item in changed if not _actual_matches_expected(item, expected)
    ]
    missing = [item for item in expected if item not in changed]
    reported_failure = (
        _driver_failure("driver reported failure", response)
        if response is not None
        and (not response["ok"] or response["outcome"] == "failed")
        else None
    )

    if driver_interrupt is not None:
        error = "driver interrupted"
    elif snapshot_interrupt is not None:
        error = snapshot_error
    elif snapshot_error is not None:
        error = snapshot_error
    elif driver_error is not None:
        error = str(driver_error)
    elif altered_records:
        error = f"driver modified protected run record: {', '.join(altered_records)}"
    elif not in_scope:
        error = f"driver wrote outside declared scopes: {', '.join(violations)}"
    elif effect_error is not None:
        error = effect_error
    elif unexpected:
        error = f"driver wrote outside its approved plan: {', '.join(unexpected)}"
    elif missing:
        missing_error = (
            f"driver did not produce its approved writes: {', '.join(missing)}"
        )
        error = (
            f"{reported_failure}; {missing_error}"
            if reported_failure is not None
            else missing_error
        )
    elif expected_effects is not None and observed_effects != expected_effects:
        mismatched = [
            expected_effect["path"]
            for expected_effect, observed_effect in zip(expected_effects, observed_effects)
            if expected_effect != observed_effect
        ]
        error = f"driver produced bytes different from approved effect: {', '.join(mismatched)}"
    elif response is not None and response["outcome"] not in {
        "completed",
        "no-change",
        "no-op",
        "no-edition",
        "held",
        "failed",
    }:
        error = f"driver returned invalid outcome for execute mode: {response['outcome']}"
    elif reported_failure is not None:
        error = reported_failure
    else:
        error = None

    held = isinstance(driver_error, HoundError) and driver_error.exit_code == 3
    result: dict[str, Any] = {
        "schema_version": "hound.run.result.v2",
        "plan_id": plan["plan_id"],
        "outcome": "held" if held else ("failed" if error else response["outcome"]),
        "ok": error is None,
        "changed_paths": changed,
        "driver_response": response,
    }
    if observed_effects is not None:
        result["effects"] = observed_effects
    if error:
        result["error"] = error
    elif response is not None:
        result["data"] = response.get("data", {})

    canonical_records: dict[str, Any] = {
        "driver-manifest.json": manifest,
        "plan.json": plan,
        "request.json": request,
    }
    if plan["gate"] == "human" and approval is not None:
        canonical_records["approval.json"] = approval
    for name, record in canonical_records.items():
        write_json_atomic(run_dir / name, record)
    write_json_atomic(run_dir / "result.json", result)
    _write_run_index(run_dir, plan["plan_id"], replace=True)
    if driver_interrupt is not None:
        raise driver_interrupt
    if snapshot_interrupt is not None:
        raise snapshot_interrupt
    if error:
        raise HoundError(error, exit_code=3 if held else 1)
    return {**result, "run_dir": str(run_dir)}


def verify_run(run_dir: str | Path) -> dict[str, Any]:
    """Verify the content hashes in an immutable Hound run directory."""

    root = Path(run_dir).resolve()
    try:
        index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HoundError(f"cannot read run index: {exc}", exit_code=2) from exc
    valid = index.get("schema_version") == "hound.run.index.v1"
    failures: list[str] = []

    def fail(label: str) -> None:
        nonlocal valid
        valid = False
        if label not in failures:
            failures.append(label)

    try:
        plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
        _validate_plan(plan)
    except (OSError, json.JSONDecodeError, HoundError):
        plan = {}
        fail("plan.json")
    files = index.get("files", {})
    if not isinstance(files, dict):
        fail("index.files")
        files = {}
    expected_files = {"driver-manifest.json", "plan.json", "request.json", "result.json"}
    if plan.get("gate") == "human":
        expected_files.add("approval.json")
    if set(files) != expected_files:
        fail("index.files")
    try:
        actual_files = {entry.name for entry in root.iterdir()}
    except OSError as exc:
        raise HoundError(f"cannot inspect run directory: {exc}", exit_code=2) from exc
    for unexpected in sorted(actual_files - expected_files - {"index.json"}):
        fail(unexpected)
    for name, expected in files.items():
        if name not in expected_files:
            continue
        target = root / name
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            fail(name)
    if index.get("plan_id") != plan.get("plan_id") or root.name != plan.get("plan_id"):
        fail("index.plan_id")

    try:
        manifest = json.loads((root / "driver-manifest.json").read_text(encoding="utf-8"))
        if not _recorded_manifest_matches(manifest, plan):
            fail("driver-manifest.json")
    except (OSError, json.JSONDecodeError, ValueError):
        fail("driver-manifest.json")

    try:
        request = json.loads((root / "request.json").read_text(encoding="utf-8"))
        expected_request = {
            "schema_version": "hound.driver.request.v1",
            "mode": "execute",
            "operation": plan["operation"],
            "as_of": plan["as_of"],
            "input": plan["input"],
            "plan_id": plan["plan_id"],
            "driver_plan": _plan_proposal(plan)["data"],
        }
        if request != expected_request:
            fail("request.json")
    except (OSError, json.JSONDecodeError, KeyError):
        fail("request.json")

    try:
        result = json.loads((root / "result.json").read_text(encoding="utf-8"))
        if not _result_matches_plan(result, plan, root):
            fail("result.json")
    except (OSError, json.JSONDecodeError, AttributeError):
        fail("result.json")

    if plan.get("gate") == "human":
        try:
            approval = json.loads((root / "approval.json").read_text(encoding="utf-8"))
            _validate_approval_artifact(
                plan,
                approval,
                enforce_expiration=False,
            )
        except (OSError, json.JSONDecodeError, HoundError):
            fail("approval.json")
    return {
        "schema_version": "hound.run.verification.v1",
        "valid": valid,
        "plan_id": index.get("plan_id"),
        "failures": sorted(failures),
    }


def verify_invocation(record_path: str | Path) -> dict[str, Any]:
    """Verify a saved read-invocation result and its self-hashed receipt."""

    path = Path(record_path).resolve()
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HoundError(f"cannot read invocation record: {exc}", exit_code=2) from exc

    failures: list[str] = []

    def fail(label: str) -> None:
        if label not in failures:
            failures.append(label)

    if not isinstance(result, dict):
        fail("result")
        result = {}
    if result.get("schema_version") != "hound.invoke.result.v1":
        fail("schema_version")

    response_fields = {
        "ok",
        "outcome",
        "data_schema",
        "data",
        "artifacts",
        "proofs",
        "diagnostics",
    }
    unknown = set(result) - response_fields - {"schema_version", "receipt"}
    if unknown:
        fail("result.fields")
    response = {
        "schema_version": "hound.driver.response.v1",
        **{key: result[key] for key in response_fields if key in result},
    }
    try:
        validate_response(response)
    except ContractError:
        fail("response")

    receipt = result.get("receipt")
    receipt_fields = {
        "schema_version",
        "manifest",
        "manifest_sha256",
        "repository",
        "environment_sha256",
        "kernel",
        "request",
        "request_sha256",
        "response_sha256",
        "receipt_id",
    }
    if not isinstance(receipt, dict):
        fail("receipt")
        receipt = {}
    elif set(receipt) != receipt_fields:
        fail("receipt.fields")

    if receipt.get("schema_version") != "hound.invocation.receipt.v1":
        fail("receipt.schema_version")
    manifest = receipt.get("manifest")
    try:
        validate_manifest(manifest)
    except ContractError:
        fail("manifest")
    try:
        if receipt.get("manifest_sha256") != canonical_hash(manifest):
            fail("manifest_sha256")
    except ContractError:
        fail("manifest_sha256")

    request = receipt.get("request")
    if not isinstance(request, dict):
        fail("request")
    else:
        required_request = {"schema_version", "mode", "operation", "input"}
        if (
            not required_request.issubset(request)
            or set(request) - required_request - {"as_of"}
            or request.get("schema_version") != "hound.driver.request.v1"
            or request.get("mode") != "read"
            or not isinstance(request.get("operation"), str)
            or not request.get("operation")
            or not isinstance(request.get("input"), dict)
            or ("as_of" in request and not isinstance(request["as_of"], str))
        ):
            fail("request")
    try:
        if receipt.get("request_sha256") != canonical_hash(request):
            fail("request_sha256")
    except ContractError:
        fail("request_sha256")
    try:
        if receipt.get("response_sha256") != canonical_hash(response):
            fail("response_sha256")
    except ContractError:
        fail("response_sha256")

    repository = receipt.get("repository")
    if (
        not isinstance(repository, dict)
        or set(repository) != {"head", "fingerprint_sha256"}
        or not isinstance(repository.get("head"), str)
        or not repository.get("head")
        or not isinstance(repository.get("fingerprint_sha256"), str)
        or not _SHA256.fullmatch(repository["fingerprint_sha256"])
    ):
        fail("repository")
    environment_sha256 = receipt.get("environment_sha256")
    if not isinstance(environment_sha256, str) or not _SHA256.fullmatch(environment_sha256):
        fail("environment_sha256")
    kernel = receipt.get("kernel")
    if (
        not isinstance(kernel, dict)
        or set(kernel) != {"version", "sha256", "dependencies"}
        or not isinstance(kernel.get("version"), str)
        or not kernel.get("version")
        or not isinstance(kernel.get("sha256"), str)
        or not _SHA256.fullmatch(kernel["sha256"])
        or kernel.get("dependencies") != {}
    ):
        fail("kernel")

    if isinstance(receipt, dict):
        receipt_body = {key: value for key, value in receipt.items() if key != "receipt_id"}
        try:
            if receipt.get("receipt_id") != canonical_hash(receipt_body):
                fail("receipt_id")
        except ContractError:
            fail("receipt_id")

    return {
        "schema_version": "hound.invocation.verification.v1",
        "valid": not failures,
        "receipt_id": receipt.get("receipt_id"),
        "failures": sorted(failures),
    }


def invoke_read_with_receipt(
    manifest_path: str | Path,
    operation: str,
    payload: dict[str, Any] | None,
    *,
    as_of: str | None = None,
    decoded_outputs: Callable[[dict[str, Any]], Iterable[object]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Invoke one declared read capability and return its execution receipt."""

    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    repo = _owner_repo(manifest, path)
    capability = _capability(manifest, operation)
    if capability["effect"] != "read":
        raise HoundError(f"{operation} is a write capability and must be planned", exit_code=2)
    request: dict[str, Any] = {
        "schema_version": "hound.driver.request.v1",
        "mode": "read",
        "operation": operation,
        "input": payload or {},
    }
    if as_of is not None:
        request["as_of"] = as_of
    response, receipt = _invoke_nonmutating_driver_with_receipt(
        manifest,
        request,
        manifest_path=path,
        repo=repo,
        mode="read",
        decoded_outputs=decoded_outputs,
    )
    if response["outcome"] == "planned":
        raise HoundError("driver returned invalid outcome for read mode: planned", exit_code=2)
    return response, receipt


def invoke_read(
    manifest_path: str | Path,
    operation: str,
    payload: dict[str, Any] | None,
    *,
    as_of: str | None = None,
) -> dict[str, Any]:
    """Invoke a declared read capability without entering the write lifecycle."""

    response, _ = invoke_read_with_receipt(
        manifest_path,
        operation,
        payload,
        as_of=as_of,
    )
    return response
