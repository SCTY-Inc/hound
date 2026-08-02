from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import stat
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

from houndd import commit, phi
from houndd.commit import (
    COMMIT_REQUEST_SCHEMA,
    COMMIT_RESPONSE_SCHEMA,
    MAX_SOURCE_BYTES,
    MAX_WIRE_BODY_BYTES,
    AVAILABLE_ROUTE_BINDINGS,
    CommitContractError,
    CommitRequest,
    CommitResponse,
    NormalizedSource,
    Producer,
    RouteBinding,
    SourceDeclaration,
    SourceError,
    canonical_commit_request,
    normalize_source,
    parse_commit_request,
    resolve_route,
    validate_commit_response,
)
from houndd.phi import (
    PHI_MANIFEST_SCHEMA,
    PhiManifestError,
    PhiScanner,
    load_phi_manifest,
)


def _source_bytes(data: bytes) -> dict[str, object]:
    return {
        "kind": "bytes",
        "body_base64": __import__("base64").b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_length": len(data),
    }


def _request(source: dict[str, object], *, operation: str = "ingest.file") -> dict[str, object]:
    payload: dict[str, object]
    if operation == "ingest.file":
        payload = {"source": source, "media_type": "application/octet-stream"}
    else:
        payload = {"record_id": "legacy-1", "source": source}
    return {
        "schema_version": COMMIT_REQUEST_SCHEMA,
        "request_id": "req-1",
        "idempotency_key": "idem-1",
        "producer": {"owner_id": "owner", "capability": operation, "run_id": "run"},
        "requested_access": "workspace",
        "policy_id": "policy",
        "operation": {"name": operation, "payload": payload},
    }


def _manifest_bytes(*entries: dict[str, str]) -> bytes:
    return json.dumps(
        {"schema_version": PHI_MANIFEST_SCHEMA, "entries": list(entries)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _manifest_entry(digest: str) -> dict[str, str]:
    return {"sha256": digest, "media_type": "application/octet-stream", "encoding": "identity"}


def test_routes_are_exact_and_only_two_slice_3c1_bindings_are_available() -> None:
    assert {binding.operation for binding in AVAILABLE_ROUTE_BINDINGS} == {"ingest.file", "import.record"}
    assert resolve_route("POST", "/v1/ingest/file").available is True
    assert resolve_route("POST", "/v1/import-record").available is True
    with pytest.raises(CommitContractError):
        resolve_route("post", "/v1/ingest/file")
    with pytest.raises(CommitContractError):
        resolve_route("POST", "/v1/ingest/file?x=1")


def test_route_must_be_the_exact_available_fixed_binding_everywhere() -> None:
    route = resolve_route("POST", "/v1/ingest/file")
    request = _request(_source_bytes(b"bound"))
    parsed = parse_commit_request(request, route)
    forged = RouteBinding("POST", "/v1/ingest/file", "ingest.file", "ingest.file", True)
    other = resolve_route("POST", "/v1/import-record")
    for candidate in (forged, other):
        with pytest.raises(CommitContractError):
            parse_commit_request(request, candidate)
        with pytest.raises(CommitContractError):
            canonical_commit_request(parsed, candidate)


def test_commit_request_is_strict_and_binds_operation_capability() -> None:
    request = parse_commit_request(_request(_source_bytes(b"hello")), resolve_route("POST", "/v1/ingest/file"))
    assert request.operation == "ingest.file"
    assert request.producer.capability == "ingest.file"
    with pytest.raises(CommitContractError):
        parse_commit_request(
            {**_request(_source_bytes(b"hello")), "extra": 1},
            resolve_route("POST", "/v1/ingest/file"),
        )
    with pytest.raises(CommitContractError):
        parse_commit_request(
            {**_request(_source_bytes(b"hello")), "producer": {"owner_id": "owner", "capability": "import.record", "run_id": "run"}},
            resolve_route("POST", "/v1/ingest/file"),
        )


def test_source_normalization_removes_transport_and_path_is_held_nofollow(tmp_path: Path) -> None:
    body = b"stable bytes"
    inline = normalize_source(_source_bytes(body))
    assert isinstance(inline, NormalizedSource)
    assert inline.identity == {"sha256": hashlib.sha256(body).hexdigest(), "byte_length": len(body)}
    assert inline.data == body
    path = tmp_path / "source.bin"
    path.write_bytes(body)
    held = normalize_source({"kind": "path", "path": str(path), "sha256": inline.sha256, "byte_length": len(body)})
    assert held.identity == inline.identity
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(CommitContractError):
        normalize_source({"kind": "path", "path": str(link), "sha256": inline.sha256, "byte_length": len(body)})


def test_source_mismatch_and_subtype_attacks_fail_closed() -> None:
    data = b"hello"
    source = _source_bytes(data)
    source["byte_length"] = 4
    with pytest.raises(CommitContractError):
        normalize_source(source)
    class EvilDict(dict):
        pass
    with pytest.raises(CommitContractError):
        normalize_source(EvilDict(_source_bytes(data)))


def test_direct_models_reject_nested_hostile_subtypes_and_are_deeply_immutable() -> None:
    class EvilStr(str):
        pass

    class EvilDict(dict):
        pass

    with pytest.raises(TypeError):
        Producer(EvilStr("owner"), "ingest.file", "run")
    with pytest.raises(TypeError):
        SourceDeclaration("bytes", hashlib.sha256(b"").hexdigest(), 0, body_base64=EvilStr(""))
    parsed = parse_commit_request(_request(_source_bytes(b"immutable")), resolve_route("POST", "/v1/ingest/file"))
    with pytest.raises(TypeError):
        parsed.payload["media_type"] = "changed"  # type: ignore[index]
    response = CommitResponse.from_value(
        {
            "schema_version": COMMIT_RESPONSE_SCHEMA,
            "request_id": "req-1",
            "ok": False,
            "outcome": "invalid",
            "record_ids": [],
            "entry_ids": [],
            "usage": {"requests": 0, "bytes": 0, "cost": 0},
            "error": {"code": "source_refused", "retryable": False, "message": "source refused"},
        }
    )
    with pytest.raises(TypeError):
        response.usage["bytes"] = 1  # type: ignore[index]
    assert isinstance(parsed.payload, MappingProxyType)


def test_canonical_identity_ignores_source_kind_path_and_base64(tmp_path: Path) -> None:
    body = b"same"
    digest = hashlib.sha256(body).hexdigest()
    path = tmp_path / "same.bin"
    path.write_bytes(body)
    route = resolve_route("POST", "/v1/ingest/file")
    inline = parse_commit_request(_request(_source_bytes(body)), route)
    path_request = parse_commit_request(
        _request({"kind": "path", "path": str(path), "sha256": digest, "byte_length": len(body)}), route
    )
    assert canonical_commit_request(inline, route) == canonical_commit_request(path_request, route)


def test_canonicalization_cannot_rebind_a_normalized_source() -> None:
    body = b"declared"
    route = resolve_route("POST", "/v1/ingest/file")
    request = parse_commit_request(_request(_source_bytes(body)), route)
    replacement = NormalizedSource(hashlib.sha256(b"other").hexdigest(), 5, b"other")
    with pytest.raises(CommitContractError):
        canonical_commit_request(request, route, replacement)


@pytest.mark.parametrize("primitive", ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
def test_missing_required_path_primitive_fails_closed(primitive: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(target)
    path = link if primitive == "O_NOFOLLOW" else target
    monkeypatch.delattr(commit.os, primitive, raising=False)
    with pytest.raises(SourceError):
        normalize_source({"kind": "path", "path": str(path), "sha256": hashlib.sha256(b"safe").hexdigest(), "byte_length": 4})


def _fifo_normalization_child(path: str, digest: str, queue: multiprocessing.queues.Queue[bool]) -> None:
    try:
        normalize_source({"kind": "path", "path": path, "sha256": digest, "byte_length": 0})
    except SourceError:
        queue.put(True)
    else:
        queue.put(False)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO")
def test_path_fifo_never_blocks_and_fails_closed(tmp_path: Path) -> None:
    fifo = tmp_path / "source.fifo"
    os.mkfifo(fifo, 0o600)
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    child = context.Process(target=_fifo_normalization_child, args=(str(fifo), hashlib.sha256(b"").hexdigest(), queue))
    child.start()
    child.join(1)
    if child.is_alive():
        child.terminate()
        child.join()
        pytest.fail("SOURCE FIFO open blocked")
    assert child.exitcode == 0 and queue.get(timeout=1) is True


def test_path_post_read_mode_race_and_growth_fail_closed(tmp_path: Path) -> None:
    body = b"safe"
    path = tmp_path / "source"
    path.write_bytes(body)
    declaration = {"kind": "path", "path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byte_length": len(body)}
    read = commit.os.read
    changed = False

    def change_mode(fd: int, size: int) -> bytes:
        nonlocal changed
        if not changed:
            os.chmod(path, 0)
            changed = True
        return read(fd, size)

    with patch.object(commit.os, "read", change_mode), pytest.raises(SourceError):
        normalize_source(declaration)
    os.chmod(path, 0o600)
    changed = False

    def grow(fd: int, size: int) -> bytes:
        nonlocal changed
        if not changed:
            with path.open("ab") as handle:
                handle.write(b"!")
            changed = True
        return read(fd, size)

    with patch.object(commit.os, "read", grow), pytest.raises(SourceError):
        normalize_source(declaration)

    read_started = False
    fstat = commit.os.fstat

    def mark_read(fd: int, size: int) -> bytes:
        nonlocal read_started
        read_started = True
        return read(fd, size)

    def change_owner_after_read(fd: int) -> os.stat_result:
        info = fstat(fd)
        if read_started and stat.S_ISREG(info.st_mode):
            values = list(info)
            values[4] = info.st_uid + 1
            return os.stat_result(values)
        return info

    with patch.object(commit.os, "read", mark_read), patch.object(commit.os, "fstat", change_owner_after_read), pytest.raises(SourceError):
        normalize_source(declaration)


def test_path_current_binding_replacement_fails_closed(tmp_path: Path) -> None:
    body = b"safe"
    path = tmp_path / "source"
    replacement = tmp_path / "replacement"
    path.write_bytes(body)
    replacement.write_bytes(body)
    declaration = {"kind": "path", "path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byte_length": len(body)}
    read = commit.os.read
    swapped = False

    def replace_name(fd: int, size: int) -> bytes:
        nonlocal swapped
        if not swapped:
            os.replace(replacement, path)
            swapped = True
        return read(fd, size)

    with patch.object(commit.os, "read", replace_name), pytest.raises(SourceError):
        normalize_source(declaration)


def test_path_binding_and_held_descriptor_fail_after_fork(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "source"
    path.write_bytes(b"safe")
    calls = iter((100, 101))
    monkeypatch.setattr(commit.os, "getpid", lambda: next(calls))
    with pytest.raises(SourceError):
        normalize_source({"kind": "path", "path": str(path), "sha256": hashlib.sha256(b"safe").hexdigest(), "byte_length": 4})


def test_phi_manifest_is_canonical_private_and_scanner_is_frozen(tmp_path: Path) -> None:
    service = tmp_path / "service"
    service.mkdir(mode=0o700)
    data = b"clear"
    digest = hashlib.sha256(data).hexdigest()
    manifest_path = service / "phi-clear.json"
    manifest_path.write_bytes(
        json.dumps(
            {"schema_version": PHI_MANIFEST_SCHEMA, "entries": [{"sha256": digest, "media_type": "application/octet-stream", "encoding": "identity"}]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    manifest_path.chmod(0o600)
    scanner = PhiScanner(load_phi_manifest(manifest_path))
    assert scanner.scan(data, "application/octet-stream", "identity", "ingest.file") == "clear"
    manifest_path.write_bytes(b"not canonical")
    assert scanner.scan(data, "application/octet-stream", "identity", "ingest.file") == "clear"
    assert scanner.scan(b"different", "application/octet-stream", "identity", "ingest.file") == "suspected"
    with pytest.raises(PhiManifestError):
        load_phi_manifest(manifest_path)


def test_manifest_replacement_growth_and_held_descriptor_fork_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = tmp_path / "service"
    service.mkdir(mode=0o700)
    manifest_path = service / "phi-clear.json"
    first = "a" * 64
    second = "b" * 64
    manifest_path.write_bytes(_manifest_bytes(_manifest_entry(first)))
    manifest_path.chmod(0o600)
    replacement = service / "replacement"
    replacement.write_bytes(_manifest_bytes(_manifest_entry(second)))
    replacement.chmod(0o600)
    read_bytes = Path.read_bytes
    read = phi.os.read
    swapped = False

    def swap() -> None:
        nonlocal swapped
        if not swapped:
            os.replace(replacement, manifest_path)
            swapped = True

    def path_read_bytes(self: Path) -> bytes:
        if self == manifest_path:
            swap()
        return read_bytes(self)

    def fd_read(fd: int, size: int) -> bytes:
        swap()
        return read(fd, size)

    with patch.object(Path, "read_bytes", path_read_bytes), patch.object(phi.os, "read", fd_read), pytest.raises(PhiManifestError):
        load_phi_manifest(manifest_path)
    manifest_path.write_bytes(_manifest_bytes(_manifest_entry(first)))
    manifest_path.chmod(0o600)
    read = phi.os.read
    grew = False

    def grow(fd: int, size: int) -> bytes:
        nonlocal grew
        if not grew:
            with manifest_path.open("ab") as handle:
                handle.write(b" ")
            grew = True
        return read(fd, size)

    with patch.object(phi.os, "read", grow), pytest.raises(PhiManifestError):
        load_phi_manifest(manifest_path)
    manifest_path.write_bytes(_manifest_bytes(_manifest_entry(first)))
    manifest_path.chmod(0o600)
    read_started = False
    fstat = phi.os.fstat
    read = phi.os.read

    def mark_read(fd: int, size: int) -> bytes:
        nonlocal read_started
        read_started = True
        return read(fd, size)

    def change_owner_after_read(fd: int) -> os.stat_result:
        info = fstat(fd)
        if read_started and stat.S_ISREG(info.st_mode):
            values = list(info)
            values[4] = info.st_uid + 1
            return os.stat_result(values)
        return info

    with patch.object(phi.os, "read", mark_read), patch.object(phi.os, "fstat", change_owner_after_read), pytest.raises(PhiManifestError):
        load_phi_manifest(manifest_path)
    manifest_path.write_bytes(_manifest_bytes(_manifest_entry(first)))
    manifest_path.chmod(0o600)
    pids = iter((100, 101))
    monkeypatch.setattr(phi.os, "getpid", lambda: next(pids))
    with pytest.raises(PhiManifestError):
        load_phi_manifest(manifest_path)


def test_phi_manifest_rejects_wrong_mode_order_duplicates_and_unsupported_subtypes(tmp_path: Path) -> None:
    service = tmp_path / "service"
    service.mkdir(mode=0o700)
    path = service / "phi-clear.json"
    entry = {"sha256": "0" * 64, "media_type": "application/octet-stream", "encoding": "identity"}
    path.write_text(json.dumps({"schema_version": PHI_MANIFEST_SCHEMA, "entries": [entry, entry]}, separators=(",", ":")))
    path.chmod(0o600)
    with pytest.raises(PhiManifestError):
        load_phi_manifest(path)
    path.chmod(0o644)
    with pytest.raises(PhiManifestError):
        load_phi_manifest(path)


def test_commit_response_is_exact_and_source_details_never_appear() -> None:
    response = {
        "schema_version": COMMIT_RESPONSE_SCHEMA,
        "request_id": "req-1",
        "ok": True,
        "outcome": "completed",
        "record_ids": ["a"],
        "entry_ids": ["b"],
        "usage": {"requests": 0, "bytes": 5, "cost": 0},
    }
    assert validate_commit_response(response) == response
    with pytest.raises(CommitContractError):
        validate_commit_response({**response, "result": "secret"})
    with pytest.raises(CommitContractError):
        validate_commit_response(
            {
                **response,
                "ok": False,
                "outcome": "invalid",
                "error": {"code": "source_refused", "retryable": False, "message": "/secret/path body_base64=QUJD"},
            }
        )
    with pytest.raises(CommitContractError):
        validate_commit_response({**response, "error": {"code": "source_refused", "retryable": False, "message": "source refused"}})


def test_canonical_base64_and_exact_encoded_and_decoded_boundaries() -> None:
    empty = _source_bytes(b"")
    one = _source_bytes(b"x")
    assert normalize_source(empty).data == b""
    assert normalize_source(one).data == b"x"
    noncanonical = dict(one)
    noncanonical["body_base64"] = "eA==\n"
    with pytest.raises(SourceError):
        normalize_source(noncanonical)
    data = b"x" * (((MAX_WIRE_BODY_BYTES // 4) * 3))
    request = _request(_source_bytes(data))
    while len(commit.canonical_bytes(request)) > MAX_WIRE_BODY_BYTES:
        data = data[:-3]
        request = _request(_source_bytes(data))
    assert len(commit.canonical_bytes(request)) <= MAX_WIRE_BODY_BYTES
    parse_commit_request(request, resolve_route("POST", "/v1/ingest/file"))
    oversized = _request(_source_bytes(data + b"xxx"))
    assert len(commit.canonical_bytes(oversized)) > MAX_WIRE_BODY_BYTES
    with pytest.raises(CommitContractError):
        parse_commit_request(oversized, resolve_route("POST", "/v1/ingest/file"))
    sixteen_mib = b"z" * MAX_SOURCE_BYTES
    assert normalize_source(_source_bytes(sixteen_mib)).byte_length == MAX_SOURCE_BYTES
    with pytest.raises(CommitContractError):
        normalize_source(_source_bytes(sixteen_mib + b"z"))
