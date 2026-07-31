"""HSP-14: legacy byte/hash preservation, index rebuild, and relocation evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from pathlib import Path

from houndd import HounddStore, make_journal_envelope


def test_hsp14_legacy_bytes_ids_and_hashes_survive_rebuild_and_relocation(tmp_path) -> None:
    fixture = json.loads((Path(__file__).parent / "fixtures" / "hsp14_legacy_record.json").read_text())
    data = base64.b64decode(fixture["bytes_base64"])
    assert hashlib.sha256(data).hexdigest() == fixture["sha256"]
    root = tmp_path / "original"
    store = HounddStore(root)
    reference = store.mirror_legacy(fixture["record_id"], data, expected_sha256=fixture["sha256"])
    assert reference.record_id == fixture["record_id"]
    assert store.records.read(fixture["record_id"]) == data
    assert store.records.verify_record(fixture["record_id"]) is True

    blob = store.records.blob(data)
    envelope = make_journal_envelope(
        sequence=0,
        appended_at="2026-07-31T00:00:00Z",
        producer={"owner_id": "legacy", "capability": "import", "run_id": "run"},
        artifact={"kind": "import", "schema": "legacy.record.v1", "record_id": reference.record_id, "hash": reference.content_sha256, "authorized_uri": "houndd://legacy/legacy-record-01"},
        lineage={"relation": "none", "record_id": reference.record_id, "lead_id": "none"},
        source={"provider": "legacy", "native_id": reference.record_id, "canonical_url": "none"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access="workspace",
        policy_id="legacy-policy",
        dedupe={"object_key": "legacy-record-01", "content_sha256": blob},
        usage={"bytes": len(data)},
    )
    store.journal.append(envelope)
    store.rebuild_index()
    before = store.projection.rows()
    relocated = tmp_path / "relocated"
    shutil.copytree(root, relocated)
    restored = HounddStore(relocated)
    restored.projection.delete()
    restored.rebuild_index()
    assert restored.records.read(fixture["record_id"]) == data
    assert restored.records.verify_record(fixture["record_id"]) is True
    assert restored.projection.rows() == before
    assert restored.verify()["valid"] is True
