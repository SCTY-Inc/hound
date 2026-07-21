"""Fail-closed execution and repository safety primitives."""

from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from hound_cli.contracts import (
    ContractError,
    canonical_hash,
    canonical_json,
    load_manifest,
    validate_response,
)
from hound_cli.safety import contains_credential, credential_forms

try:
    import fcntl
except ImportError:  # pragma: no cover - write execution fails closed off POSIX
    fcntl = None


class RuntimeErrorHound(RuntimeError):
    """A runtime boundary could not be enforced safely."""


_GIT_EXECUTABLE = shutil.which("git", path=os.defpath) or "/usr/bin/git"
_SUPERVISOR_EXECUTABLE = Path(__file__).with_name("_supervisor.py").resolve()
MAX_DRIVER_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 30.0


@contextmanager
def repo_execution_lock(repo: str | Path, *, timeout: float = 30) -> Iterator[None]:
    """Serialize Hound write executions for one owner Git repository."""

    if fcntl is None:
        raise RuntimeErrorHound("repository execution locking is unavailable")
    root = _git_root(repo)
    git_dir = Path(
        _git(root, "rev-parse", "--absolute-git-dir").decode("utf-8").strip()
    ).resolve()
    lock_path = git_dir / "hound-execute.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise RuntimeErrorHound("cannot open repository execution lock") from error
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeErrorHound("repository execution lock timed out")
                time.sleep(0.05)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def run_driver(
    manifest: Mapping[str, Any],
    request: Any,
    *,
    manifest_path: str | Path,
    timeout: float | None = None,
    driver_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).resolve()
    try:
        persisted = load_manifest(manifest_file)
        if canonical_hash(dict(manifest)) != canonical_hash(persisted):
            raise RuntimeErrorHound("manifest does not match manifest_path")
        request_json = canonical_json(request)
    except ContractError as error:
        raise RuntimeErrorHound(f"invalid driver contract: {error}") from error

    repo = (manifest_file.parent / persisted["owner"]["repo"]).resolve()
    if not repo.is_dir():
        raise RuntimeErrorHound("manifest owner.repo does not resolve to a directory")
    repo = _git_root(repo)
    operation = request.get("operation") if isinstance(request, Mapping) else None
    selected_timeout = timeout
    if selected_timeout is None:
        configured = persisted.get("timeouts_seconds", {})
        selected_timeout = configured.get(operation, configured.get("default", 30))
    if (
        isinstance(selected_timeout, bool)
        or not isinstance(selected_timeout, (int, float))
        or not math.isfinite(selected_timeout)
        or selected_timeout <= 0
    ):
        raise RuntimeErrorHound("timeout must be a positive finite number")

    selected_environment = (
        capture_driver_environment(persisted, operation=operation)
        if driver_environment is None
        else _validate_driver_environment(
            persisted, driver_environment, operation=operation
        )
    )
    environment = {"PATH": os.defpath, **selected_environment}
    credential_forms = _credential_forms(
        _driver_environment_names(persisted, operation), selected_environment
    )

    failure: str | None = None
    try:
        with tempfile.TemporaryFile(mode="w+b") as stdin_stream:
            stdin_stream.write((request_json + "\n").encode("utf-8"))
            stdin_stream.seek(0)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    str(_SUPERVISOR_EXECUTABLE),
                    "--parent-pid",
                    str(os.getpid()),
                    "--",
                    *persisted["exec"],
                ],
                cwd=repo,
                env=environment,
                stdin=stdin_stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=os.name == "posix",
                shell=False,
            )
            try:
                stdout_bytes, stderr_bytes, failure = _collect_driver_output(
                    process, float(selected_timeout)
                )
            finally:
                if process.poll() is None:
                    _terminate_driver_group(process)
                else:
                    # A driver may not leave background descendants behind.
                    _kill_lingering_driver_group(process)
                _close_driver_pipes(process)

            returncode = process.returncode
    except OSError as error:
        raise RuntimeErrorHound(f"could not execute driver: {error}") from error

    if contains_credential(stdout_bytes, credential_forms) or contains_credential(
        stderr_bytes, credential_forms
    ):
        raise RuntimeErrorHound("driver output contained allowlisted credential material")
    if failure == "output" or len(stdout_bytes) + len(stderr_bytes) > MAX_DRIVER_OUTPUT_BYTES:
        raise RuntimeErrorHound("driver output size limit exceeded")

    try:
        stdout = stdout_bytes.decode("utf-8")
        stderr = stderr_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeErrorHound("driver output must be UTF-8") from error

    diagnostic = _diagnostic(stderr)
    if failure == "timeout":
        suffix = f"; stderr: {diagnostic}" if diagnostic else ""
        raise RuntimeErrorHound(f"driver timed out{suffix}")
    if returncode != 0:
        suffix = f"; stderr: {diagnostic}" if diagnostic else ""
        raise RuntimeErrorHound(
            f"driver exited with status {returncode}{suffix}"
        )

    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as error:
        suffix = f"; stderr: {diagnostic}" if diagnostic else ""
        raise RuntimeErrorHound(
            f"driver stdout must contain exactly one JSON value{suffix}"
        ) from error
    try:
        return validate_response(response)
    except ContractError as error:
        suffix = f"; stderr: {diagnostic}" if diagnostic else ""
        raise RuntimeErrorHound(f"invalid driver response: {error}{suffix}") from error


def repo_fingerprint(repo: str | Path) -> dict[str, Any]:
    root = _git_root(repo)
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    integrity = _git_integrity_state(root)
    if not integrity.startswith("0:"):
        raise RuntimeErrorHound("repository Git object integrity check failed")
    staged = _git(root, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv")
    unstaged = _git(root, "diff", "--binary", "--no-ext-diff", "--no-textconv")
    untracked = {
        path: _path_hash(root / path)
        for path in _listed_paths(root, "--others", "--exclude-standard")
    }
    tracked = {
        path: _path_hash(root / path) if (root / path).exists() or (root / path).is_symlink() else "missing"
        for path in _listed_paths(root, "--cached")
    }
    value = {
        "head": head,
        "index_state_sha256": _git_index_state(root),
        "refs_state_sha256": _git_refs_state(root),
        "git_integrity": integrity,
        "git_sensitive_state_sha256": _git_sensitive_state(root),
        "staged_diff_sha256": hashlib.sha256(staged).hexdigest(),
        "unstaged_diff_sha256": hashlib.sha256(unstaged).hexdigest(),
        "untracked": untracked,
        "tracked": tracked,
    }
    value["fingerprint_sha256"] = canonical_hash(value)
    return value


def capture_driver_environment(
    manifest: Mapping[str, Any],
    source: Mapping[str, str] | None = None,
    *,
    operation: str | None = None,
) -> dict[str, str]:
    """Freeze the allowlisted environment values that will reach a driver."""

    environment = os.environ if source is None else source
    if not isinstance(environment, Mapping):
        raise RuntimeErrorHound("driver environment source must be a mapping")
    selected: dict[str, str] = {}
    for name in _driver_environment_names(manifest, operation):
        if name not in environment:
            continue
        value = environment[name]
        if not isinstance(value, str):
            raise RuntimeErrorHound(f"driver environment {name} must be a string")
        selected[name] = value
    return _validate_driver_environment(manifest, selected, operation=operation)


def driver_environment_fingerprint(
    manifest: Mapping[str, Any],
    environment: Mapping[str, str],
    *,
    operation: str | None = None,
) -> str:
    """Bind exported values without placing their cleartext in a plan."""

    selected = _validate_driver_environment(
        manifest, environment, operation=operation
    )
    names = _driver_environment_names(manifest, operation)
    state = {
        "system_path_sha256": hashlib.sha256(os.fsencode(os.defpath)).hexdigest(),
        "variables": [
            {
                "name": name,
                "present": name in selected,
                **(
                    {"value_sha256": hashlib.sha256(selected[name].encode("utf-8")).hexdigest()}
                    if name in selected
                    else {}
                ),
            }
            for name in names
        ],
    }
    return canonical_hash(state)


def _validate_driver_environment(
    manifest: Mapping[str, Any],
    environment: Mapping[str, str],
    *,
    operation: str | None = None,
) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise RuntimeErrorHound("driver environment must be a mapping")
    allowed = set(_driver_environment_names(manifest, operation))
    if any(
        not isinstance(name, str)
        or name not in allowed
        or not isinstance(value, str)
        for name, value in environment.items()
    ):
        raise RuntimeErrorHound("driver environment does not match its allowlist")
    return dict(environment)


def _driver_environment_names(
    manifest: Mapping[str, Any], operation: str | None
) -> list[str]:
    names = set(manifest.get("env_allowlist", []))
    if operation is not None:
        capability = manifest.get("capabilities", {}).get(operation, {})
        names.update(capability.get("env_allowlist", []))
    return sorted(names)


def snapshot_repo(
    repo: str | Path,
    *,
    ignored_snapshot_excludes: Iterable[str] = (),
) -> dict[str, str]:
    root = _git_root(repo)
    snapshot: dict[str, str] = {}
    paths = set(_listed_paths(root, "--cached", "--others", "--exclude-standard"))
    excluded = tuple(
        PurePosixPath(value.replace("\\", "/"))
        for value in ignored_snapshot_excludes
    )
    paths.update(
        relative
        for relative in _listed_paths(
            root, "--others", "--ignored", "--exclude-standard"
        )
        if not _path_is_within_any(PurePosixPath(relative), excluded)
    )
    for relative in sorted(paths):
        path = root / relative
        if path.exists() or path.is_symlink():
            snapshot[relative] = _path_hash(path)
    snapshot[".git/hound-index-state"] = _git_index_state(root)
    snapshot[".git/hound-refs-state"] = _git_refs_state(root)
    snapshot[".git/hound-integrity-state"] = _git_integrity_state(root)
    snapshot[".git/hound-sensitive-state"] = _git_sensitive_state(root)
    return snapshot


def _path_is_within_any(
    path: PurePosixPath, prefixes: Iterable[PurePosixPath]
) -> bool:
    return any(path == prefix or prefix in path.parents for prefix in prefixes)


def changed_paths(
    before: Mapping[str, str], after: Mapping[str, str]
) -> list[str]:
    return sorted(
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )


def paths_within_scopes(
    repo: str | Path, changed: Iterable[str], scopes: Iterable[str]
) -> tuple[bool, list[str]]:
    root = Path(repo).resolve()
    resolved_scopes = [
        resolved
        for scope in scopes
        if (resolved := _safe_repo_path(root, scope)) is not None
        and resolved.is_relative_to(root)
    ]
    violations: list[str] = []
    for relative in sorted(set(changed)):
        resolved = _safe_repo_path(root, relative)
        if (
            resolved is None
            or not resolved.is_relative_to(root)
            or not any(
                resolved == scope or resolved.is_relative_to(scope)
                for scope in resolved_scopes
            )
        ):
            violations.append(relative)
    return not violations, violations


def write_bytes_create_only(path: str | Path, payload: bytes) -> None:
    """Atomically publish complete bytes without replacing an existing path."""

    destination = Path(path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise RuntimeErrorHound(f"cannot create {destination}: {error}") from error
    temporary = _write_temporary(destination, payload)
    try:
        os.link(temporary, destination)
        _fsync_directory(destination.parent)
    except FileExistsError:
        raise
    except OSError as error:
        raise RuntimeErrorHound(f"cannot create {destination}: {error}") from error
    finally:
        temporary.unlink(missing_ok=True)


def write_json_create_only(path: str | Path, obj: Any) -> None:
    destination = Path(path)
    try:
        write_bytes_create_only(destination, _json_bytes(obj))
    except FileExistsError as error:
        raise RuntimeErrorHound(f"{destination} already exists") from error


def write_json_atomic(path: str | Path, obj: Any) -> None:
    destination = Path(path)
    payload = _json_bytes(obj)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = _write_temporary(destination, payload)
    try:
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except OSError as error:
        raise RuntimeErrorHound(f"cannot replace {destination}: {error}") from error
    finally:
        temporary.unlink(missing_ok=True)


def _git_root(repo: str | Path) -> Path:
    candidate = Path(repo).resolve()
    output = _git(candidate, "rev-parse", "--show-toplevel")
    root = Path(output.decode("utf-8").strip()).resolve()
    if root != candidate:
        raise RuntimeErrorHound(
            f"declared owner repository must equal its Git root: {candidate} != {root}"
        )
    return root


def _git(repo: Path, *arguments: str) -> bytes:
    returncode, stdout, stderr = _run_git(repo, *arguments)
    if returncode:
        raise RuntimeErrorHound(
            f"git {' '.join(arguments)} failed: {_diagnostic(stderr)}"
        )
    return stdout


def _git_index_state(repo: Path) -> str:
    state = (
        _git(repo, "ls-files", "--stage", "-z")
        + b"\0"
        + _git(repo, "ls-files", "-v", "-z")
    )
    return hashlib.sha256(state).hexdigest()


def _git_refs_state(repo: Path) -> str:
    head_path = _git_path(repo, "HEAD")
    refs = _git(
        repo,
        "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(symref)",
    )
    return canonical_hash(
        {
            "refs_sha256": hashlib.sha256(refs).hexdigest(),
            "head": _path_hash(head_path),
            "control": _git_control_state(repo),
        }
    )


def _git_control_state(repo: Path) -> str:
    """Hash Git state that can change repository behavior without moving a ref."""

    git_dir = _git_directory(repo, "--absolute-git-dir")
    common_dir = _git_directory(repo, "--git-common-dir")
    excluded = (
        "HEAD",
        "config",
        "config.worktree",
        "hooks",
        "hound-execute.lock",
        "index",
        "info/exclude",
        "modules",
        "objects",
        "packed-refs",
        "refs",
        "worktrees",
    )
    trees = {"git_dir": _path_tree_hash(git_dir, excluded=excluded)}
    if common_dir != git_dir:
        trees["common_dir"] = _path_tree_hash(common_dir, excluded=excluded)
    trees["object_info"] = _path_tree_hash(common_dir / "objects" / "info")
    return canonical_hash(trees)


def _git_directory(repo: Path, argument: str) -> Path:
    try:
        value = _git(repo, "rev-parse", argument).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimeErrorHound("Git directory path is not UTF-8") from error
    if not value or any(ord(character) < 32 for character in value):
        raise RuntimeErrorHound("Git directory path is malformed")
    path = Path(value)
    return (path if path.is_absolute() else repo / path).resolve(strict=False)


def _git_integrity_state(repo: Path) -> str:
    return _git_probe(repo, "fsck", "--no-dangling")


def _git_sensitive_state(repo: Path) -> str:
    """Hash effective Git configuration, excludes, and the active hook tree."""

    effective_config = _git(repo, "config", "--null", "--show-origin", "--list")
    config = _git_path(repo, "config")
    worktree_config = _git_path(repo, "config.worktree")
    exclude = _git_path(repo, "info/exclude")
    returncode, hooks_output, _ = _run_git(
        repo, "config", "--path", "--get", "core.hooksPath"
    )
    if returncode == 0:
        try:
            hooks_text = hooks_output.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise RuntimeErrorHound("Git hooks path is not UTF-8") from error
        if not hooks_text or any(ord(character) < 32 for character in hooks_text):
            raise RuntimeErrorHound("Git hooks path is malformed")
        hooks = Path(hooks_text)
        if not hooks.is_absolute():
            hooks = repo / hooks
        hooks = hooks.resolve(strict=False)
    elif returncode == 1:
        hooks = _git_path(repo, "hooks")
    else:
        raise RuntimeErrorHound("could not resolve Git hooks path")
    state = {
        "effective_config_sha256": hashlib.sha256(effective_config).hexdigest(),
        "config": _path_tree_hash(config),
        "worktree_config": _path_tree_hash(worktree_config),
        "exclude": _path_tree_hash(exclude),
        "hooks_path_sha256": hashlib.sha256(os.fsencode(hooks)).hexdigest(),
        "hooks": _path_tree_hash(hooks),
    }
    return canonical_hash(state)


def _git_path(repo: Path, name: str) -> Path:
    try:
        value = _git(repo, "rev-parse", "--git-path", name).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimeErrorHound(f"Git path {name!r} is not UTF-8") from error
    if not value or any(ord(character) < 32 for character in value):
        raise RuntimeErrorHound(f"Git path {name!r} is malformed")
    path = Path(value)
    return (path if path.is_absolute() else repo / path).resolve(strict=False)


def _path_tree_hash(path: Path, *, excluded: Iterable[str] = ()) -> str:
    if path.is_symlink() or path.is_file():
        return canonical_hash({"kind": "file", "sha256": _path_hash(path)})
    if not path.exists():
        return canonical_hash({"kind": "missing"})
    if not path.is_dir():
        raise RuntimeErrorHound(f"cannot hash non-file metadata path {path}")
    excluded_paths = tuple(PurePosixPath(value) for value in excluded)
    entries: dict[str, str] = {
        ".": f"directory:{stat.S_IMODE(path.lstat().st_mode):o}"
    }
    pending = [path]
    try:
        while pending:
            directory = pending.pop()
            for child in sorted(directory.iterdir(), key=lambda item: item.name):
                relative = child.relative_to(path).as_posix()
                if _path_is_within_any(PurePosixPath(relative), excluded_paths):
                    continue
                child_state = child.lstat()
                if stat.S_ISDIR(child_state.st_mode):
                    entries[relative] = (
                        f"directory:{stat.S_IMODE(child_state.st_mode):o}"
                    )
                    pending.append(child)
                elif stat.S_ISREG(child_state.st_mode) or stat.S_ISLNK(child_state.st_mode):
                    entries[relative] = _path_hash(child)
                else:
                    raise RuntimeErrorHound(f"cannot hash Git metadata path {child}")
    except OSError as error:
        raise RuntimeErrorHound(f"cannot hash Git metadata tree {path}: {error}") from error
    return canonical_hash({"kind": "directory", "entries": entries})


def _git_probe(repo: Path, *arguments: str) -> str:
    returncode, stdout, stderr = _run_git(repo, *arguments)
    details = {
        "returncode": returncode,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    return f"{returncode}:{canonical_hash(details)}"


def _run_git(repo: Path, *arguments: str) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            [_GIT_EXECUTABLE, *arguments],
            cwd=repo,
            env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
            shell=False,
        )
    except OSError as error:
        raise RuntimeErrorHound(f"could not execute git: {error}") from error
    try:
        stdout, stderr, failure = _collect_process_output(
            process,
            GIT_COMMAND_TIMEOUT_SECONDS,
            MAX_GIT_OUTPUT_BYTES,
        )
    finally:
        if process.poll() is None:
            _terminate_driver_group(process)
        else:
            _kill_lingering_driver_group(process)
        _close_driver_pipes(process)
    command = " ".join(arguments)
    if failure == "timeout":
        raise RuntimeErrorHound(f"git {command} timed out")
    if failure == "output":
        raise RuntimeErrorHound(f"git {command} output size limit exceeded")
    if process.returncode is None:  # pragma: no cover - cleanup invariant
        raise RuntimeErrorHound(f"git {command} did not terminate")
    return process.returncode, stdout, stderr


def _listed_paths(repo: Path, *arguments: str) -> list[str]:
    raw = _git(repo, "ls-files", "-z", *arguments)
    try:
        paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeDecodeError as error:
        raise RuntimeErrorHound("repository contains a non-UTF-8 path") from error
    return sorted(paths)


def _path_hash(path: Path) -> str:
    try:
        path_state = path.lstat()
        mode = stat.S_IMODE(path_state.st_mode)
        if stat.S_ISLNK(path_state.st_mode):
            content = f"symlink\0{mode:o}\0".encode() + os.fsencode(os.readlink(path))
            return hashlib.sha256(content).hexdigest()
        if stat.S_ISREG(path_state.st_mode):
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened_state = os.fstat(descriptor)
                if not stat.S_ISREG(opened_state.st_mode):
                    raise RuntimeErrorHound(
                        f"cannot hash non-file repository path {path}"
                    )
                digest = hashlib.sha256()
                digest.update(
                    f"file\0{stat.S_IMODE(opened_state.st_mode):o}\0".encode()
                )
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                return digest.hexdigest()
            finally:
                os.close(descriptor)
        else:
            raise RuntimeErrorHound(f"cannot hash non-file repository path {path}")
    except OSError as error:
        raise RuntimeErrorHound(f"cannot hash repository path {path}: {error}") from error


def _safe_repo_path(root: Path, value: str) -> Path | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    posix = PurePosixPath(value.replace("\\", "/"))
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts:
        return None
    try:
        return (root / posix).resolve(strict=False)
    except OSError:
        return None


def _json_bytes(obj: Any) -> bytes:
    try:
        return (canonical_json(obj) + "\n").encode("utf-8")
    except ContractError as error:
        raise RuntimeErrorHound(f"invalid JSON document: {error}") from error


def _write_temporary(destination: Path, payload: bytes) -> Path:
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return Path(name)
    except OSError as error:
        raise RuntimeErrorHound(f"cannot stage JSON for {destination}: {error}") from error


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _collect_driver_output(
    process: subprocess.Popen[bytes], timeout: float
) -> tuple[bytes, bytes, str | None]:
    """Drain stdout/stderr through bounded pipes under one wall-clock deadline."""

    return _collect_process_output(process, timeout, MAX_DRIVER_OUTPUT_BYTES)


def _collect_process_output(
    process: subprocess.Popen[bytes], timeout: float, max_output_bytes: int
) -> tuple[bytes, bytes, str | None]:
    """Drain stdout/stderr without exceeding a combined in-memory byte bound."""

    if process.stdout is None or process.stderr is None:  # pragma: no cover - invariant
        raise RuntimeErrorHound("subprocess output pipes are unavailable")
    buffers = {
        process.stdout.fileno(): bytearray(),
        process.stderr.fileno(): bytearray(),
    }
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    failure: str | None = None
    try:
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            if not selector.get_map():
                try:
                    process.wait(timeout=min(0.05, remaining))
                except subprocess.TimeoutExpired:
                    pass
                continue
            for key, _ in selector.select(timeout=min(0.05, remaining)):
                total = sum(len(value) for value in buffers.values())
                capacity = max_output_bytes + 1 - total
                if capacity <= 0:
                    failure = "output"
                    break
                chunk = os.read(key.fd, min(64 * 1024, capacity))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.fd].extend(chunk)
                if sum(len(value) for value in buffers.values()) > max_output_bytes:
                    failure = "output"
                    break
            if failure is not None:
                break
    finally:
        selector.close()
    return (
        bytes(buffers[process.stdout.fileno()]),
        bytes(buffers[process.stderr.fileno()]),
        failure,
    )


def _close_driver_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def _terminate_driver_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired as error:
        raise RuntimeErrorHound("could not terminate timed-out driver") from error


def _kill_lingering_driver_group(process: subprocess.Popen[bytes]) -> None:
    if os.name != "posix":
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _diagnostic(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = value.strip()
    return value if len(value) <= 4096 else value[:4093] + "..."


def _credential_forms(
    names: Iterable[str], environment: Mapping[str, str]
) -> tuple[str, ...]:
    forms: set[str] = set()
    for name in names:
        value = environment.get(name, "")
        if not value:
            continue
        forms.update(credential_forms(value))
    return tuple(item for item in forms if item)
