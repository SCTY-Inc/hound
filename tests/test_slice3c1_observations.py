"""Live observation producer for the isolated Slice 3C1 evidence run."""

from __future__ import annotations

from houndd.contracts import canonical_bytes
from houndd.service import MAX_FRAME_BYTES, WIRE_VERSION


OBSERVATION_NODE = "tests/test_slice3c1_observations.py::test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner"
NODE_ID_PROPERTY = "hound.slice3c1.nodeid"
OBSERVATION_PROPERTY = "hound.slice3c1.observation"
OBSERVATION = {
    "schema_version": "houndd.slice3c1.live-observations.v1",
    "named_tests": [OBSERVATION_NODE],
    "producer": {
        "node_id": OBSERVATION_NODE,
        "classname": "tests.test_slice3c1_observations",
        "name": "test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner",
    },
    "wire": {"version": WIRE_VERSION, "encoded_json_limit": MAX_FRAME_BYTES},
}
OBSERVATION_JSON = canonical_bytes(OBSERVATION).decode("utf-8")


def pytest_collection_modifyitems(items) -> None:
    for item in items:
        item.user_properties.append((NODE_ID_PROPERTY, item.nodeid))
        if item.nodeid == OBSERVATION_NODE:
            item.user_properties.append((OBSERVATION_PROPERTY, OBSERVATION_JSON))


def test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner() -> None:
    assert OBSERVATION_JSON == canonical_bytes(OBSERVATION).decode("utf-8")
