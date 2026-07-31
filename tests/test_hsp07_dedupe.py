"""HSP-07: occurrence identity, shared blobs, revisions, and concurrency evidence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from houndd import HounddStore


def _request(key: str, run_id: str, url: str = "https://example.test/item") -> dict[str, object]:
    return {
        "schema_version": "houndd.request.v1",
        "request_id": f"request-{key}",
        "idempotency_key": key,
        "producer": {"owner_id": "owner", "capability": "capture", "run_id": run_id},
        "requested_access": "public",
        "policy_id": "policy",
        "operation": {"name": "capture", "payload": {"url": url}},
    }


def _commit(store: HounddStore, key: str, run_id: str, body: str = "same", object_key: str = "same-object") -> dict[str, object]:
    return store.begin(_request(key, run_id), principal=f"peer:{run_id}", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "body": body},
        blob=body.encode(),
        context={
            "object_key": object_key,
            "source": {"provider": run_id, "native_id": run_id, "canonical_url": "https://example.test/item"},
        },
    )


def test_hsp07_equal_blob_occurrences_are_distinct_events_and_concurrent_keys_are_safe(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(_commit, store, f"key-{index}", f"run-{index}") for index in range(6)]
        responses = [future.result() for future in futures]
    assert len({response["entry_ids"][0] for response in responses}) == 6
    assert len({response["record_ids"][0] for response in responses}) == 6
    assert len(store.records.blobs.digests()) == 1
    assert len(store.journal.entries()) == 6
    store.rebuild_index()
    assert store.verify()["valid"] is True


def test_hsp07_object_key_groups_revisions_without_url_destruction(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    first = _commit(store, "one", "run-one", "revision-one", "object-1")
    second = _commit(store, "two", "run-two", "revision-two", "object-1")
    entries = store.journal.entries()
    assert first["entry_ids"][0] != second["entry_ids"][0]
    assert entries[0]["source"]["canonical_url"] == entries[1]["source"]["canonical_url"]
    assert entries[0]["dedupe"]["object_key"] == entries[1]["dedupe"]["object_key"] == "object-1"
    assert {entry["artifact"]["record_id"] for entry in entries} == {first["record_ids"][0], second["record_ids"][0]}
    store.rebuild_index()
    assert store.verify()["valid"] is True
