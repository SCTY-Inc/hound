"""Slice 3C2 must recover stores written by the 3C1-era daemon."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from houndd import HounddStore
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.commit import normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitRuntime
from houndd.contracts import canonical_bytes
from houndd.verify import verify_store


def _imported_store(tmp_path: Path, data: bytes) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    digest = hashlib.sha256(data).hexdigest()
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request({
        "schema_version": "houndd.commit-request.v1",
        "request_id": "compat-req",
        "idempotency_key": "compat-key",
        "producer": {"owner_id": "writer", "capability": "import.record", "run_id": "run"},
        "requested_access": "public",
        "policy_id": "compat-policy",
        "operation": {"name": "import.record", "payload": {
            "record_id": "legacy-compat-record",
            "source": {"kind": "bytes", "body_base64": base64.b64encode(data).decode("ascii"), "sha256": digest, "byte_length": len(data)},
        }},
    }, route)
    source = normalize_source(request.source.to_wire())
    tiers = frozenset({"public"})
    scope = PrincipalScope(
        principal=AuthenticatedPrincipal("linux-uid:1000"),
        readable_tiers=tiers,
        permitted_event_selectors=(EventSelector("compat-policy", ProducerSelector("writer", None, None), tiers),),
    )
    runtime = CommitRuntime(root)
    response = runtime.execute(request, route, principal="linux-uid:1000", access="public", source=source, scanner_clear=True, scope=scope)
    assert response["outcome"] == "completed"
    return root


def test_recover_rebuilds_projection_over_a_completed_import(tmp_path: Path) -> None:
    """The projection rebuild must not demand a blob for legacy import bytes."""

    root = _imported_store(tmp_path, b"compat projection body\n")
    (root / "index.sqlite").unlink(missing_ok=True)
    store = HounddStore(root)
    try:
        store.recover()
        assert store.verify()["valid"] is True
    finally:
        store.close()
    assert verify_store(root)["valid"] is True


def test_runtime_accepts_a_pre_3c2_open_marker_without_usage(tmp_path: Path) -> None:
    """Finalized 3C1-era markers lack ``usage`` and must stay loadable."""

    root = _imported_store(tmp_path, b"compat marker body\n")
    open_dir = root / "commit3c1" / "open"
    names = sorted(os.listdir(open_dir))
    assert len(names) == 1
    marker_path = open_dir / names[0]
    marker = json.loads(marker_path.read_bytes())
    marker.pop("usage")
    marker_path.write_bytes(canonical_bytes(marker))
    # Construction exercises inventory validation; reconcile must also accept
    # the legacy marker and leave the finalized attempt untouched.
    assert CommitRuntime(root).reconcile() == []
