"""Staging-only observations for the Slice 3A evidence generator.

The tests are the observers: this module deliberately has no knowledge of
retained evidence and is inert unless the generator provides a private capture
directory.  A fragment is published with ``link(2)`` so a duplicate producer
can never overwrite an earlier observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any


_VARIABLE = "HOUND_SLICE3A_CAPTURE_DIR"
_TOKEN_VARIABLE = "HOUND_SLICE3A_CAPTURE_TOKEN"
_MARKER = ".hound-slice3a-capture-owner.json"
_NODE = re.compile(r"^(tests/[A-Za-z0-9_./-]+\.py::[^ ]+?)(?: \([^)]*\))?$")


def _json_value(value: object) -> Any:
    """Reject Python-only values before they can become ambiguous JSON."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    decoded = json.loads(encoded)
    if type(decoded) not in (dict, list, str, int, float, bool, type(None)):
        raise AssertionError("capture contains a non-JSON scalar")
    return decoded


def _capture_directory() -> Path | None:
    raw = os.environ.get(_VARIABLE)
    if raw is None:
        return None
    directory = Path(raw)
    if not directory.is_absolute() or not directory.exists() or directory.is_symlink():
        raise AssertionError("Slice 3A capture directory is unsafe")
    for ancestor in reversed((directory, *directory.parents)):
        if ancestor.is_symlink():
            raise AssertionError("Slice 3A capture path has a symlinked ancestor")
    resolved = directory.resolve(strict=True)
    retained = Path(__file__).parent / "evidence" / "slice3a"
    if resolved == retained.resolve() or retained.resolve() in resolved.parents:
        raise AssertionError("Slice 3A capture must never target retained evidence")
    info = resolved.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise AssertionError("Slice 3A capture directory is not generator-private")
    marker = resolved / _MARKER
    if marker.is_symlink() or not marker.is_file():
        raise AssertionError("Slice 3A capture directory is not generator-owned")
    try:
        owner = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError("invalid Slice 3A capture owner marker") from error
    if type(owner) is not dict or set(owner) != {"schema", "pid", "token"}:
        raise AssertionError("invalid Slice 3A capture owner marker")
    token = os.environ.get(_TOKEN_VARIABLE)
    if owner["schema"] != "houndd.slice3a.capture-owner.v1" or type(owner["pid"]) is not int or type(owner["token"]) is not str or len(owner["token"]) != 64 or type(token) is not str or not secrets.compare_digest(owner["token"], token):
        raise AssertionError("invalid Slice 3A capture owner marker")
    return resolved


def capture(observation: str, value: object) -> None:
    """Publish one canonical observation for the current test/parameter node."""
    directory = _capture_directory()
    if directory is None:
        return
    current = os.environ.get("PYTEST_CURRENT_TEST", "")
    matched = _NODE.fullmatch(current)
    if matched is None:
        raise AssertionError("Slice 3A capture requires a canonical pytest node id")
    node_id = matched.group(1)
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", observation):
        raise AssertionError("invalid Slice 3A observation name")
    fragment = {"schema_version": "houndd.slice3a.capture.v1", "node_id": node_id, "observation": observation, "value": _json_value(value)}
    encoded = (json.dumps(fragment, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    name = hashlib.sha256(f"{node_id}\0{observation}".encode("utf-8")).hexdigest() + ".json"
    target = directory / name
    temporary = directory / ("." + name + ".tmp")
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.write(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, target, follow_symlinks=False)
    except FileExistsError as error:
        raise AssertionError(f"duplicate Slice 3A capture fragment: {node_id} / {observation}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def inventory(root: Path) -> dict[str, object]:
    """Return the complete lstat inventory used for state-preservation claims."""
    root = root.resolve(strict=True)
    entries: list[dict[str, object]] = []
    for path in (root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())):
        info = path.lstat()
        kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "regular" if stat.S_ISREG(info.st_mode) else "other"
        entry: dict[str, object] = {"path": "." if path == root else path.relative_to(root).as_posix(), "kind": kind, "dev": info.st_dev, "ino": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink, "uid": info.st_uid, "gid": info.st_gid, "rdev": info.st_rdev, "size": info.st_size, "blocks": info.st_blocks, "blksize": info.st_blksize, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
        if kind == "symlink":
            entry["symlink_target"] = os.readlink(path)
        elif kind == "regular":
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(entry)
    return {"root": os.fspath(root), "entries": entries}


def descriptor_inventory() -> list[dict[str, object]]:
    """A stable, typed view of this process's open descriptors on Linux."""
    directory = Path("/proc/self/fd")
    if not directory.is_dir():
        raise AssertionError("Slice 3A FD evidence requires procfs")
    result: list[dict[str, object]] = []
    for path in sorted(directory.iterdir(), key=lambda item: int(item.name)):
        try:
            result.append({"fd": int(path.name), "target": os.readlink(path)})
        except FileNotFoundError:  # procfs races with the directory scanner itself
            continue
    return result
