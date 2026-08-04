from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import migration.consumer_inventory as consumer_inventory
from migration.policy_generator import (
    DEFAULT_INVENTORY_PATH,
    DEFAULT_OVERLAY_PATH,
    KNOWN_CAPABILITIES,
    PolicyGeneratorError,
    _derive_review_selectors,
    _lane_grants,
    generate_policy,
    generate_policy_bytes,
    load_default_inputs,
    load_overlay,
    validate_overlay,
)
from houndd import access
from houndd.contracts import canonical_bytes
from houndd.service import load_frozen_policy


ROOT = Path(__file__).parents[1]
OVERLAY = json.loads(DEFAULT_OVERLAY_PATH.read_text())


def _inputs() -> tuple[dict, dict]:
    return load_default_inputs()


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "migration/check_policy.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


# --- determinism -------------------------------------------------------


def test_generate_policy_is_deterministic_within_process() -> None:
    inventory, overlay = _inputs()
    first = generate_policy_bytes(inventory, overlay)
    second = generate_policy_bytes(inventory, overlay)
    assert first == second


def test_generate_policy_is_deterministic_across_processes() -> None:
    """A fresh interpreter randomizes PYTHONHASHSEED by default; if any set
    iteration leaked into the output order the two emits would disagree."""

    results = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", "from migration.policy_generator import load_default_inputs, generate_policy_bytes; import sys; sys.stdout.buffer.write(generate_policy_bytes(*load_default_inputs()))"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
        results.append(proc.stdout)
    assert results[0] == results[1]
    assert len(results[0]) > 0


def test_lane_grants_are_independent_of_consumer_order() -> None:
    """The full generate_policy() path is pinned to one canonical row order
    by consumer_inventory's baseline-closure digest (by design -- see
    test_adding_a_target_op_propagates_to_the_generated_rules for why that
    pin can't be bypassed here), so order-independence is proven at the
    derivation seam generate_policy() calls into."""

    inventory, _overlay = _inputs()
    reordered = copy.deepcopy(inventory)
    reordered["consumers"] = list(reversed(reordered["consumers"]))
    assert _lane_grants(inventory) == _lane_grants(reordered)
    assert _derive_review_selectors(inventory, "acquisition_lane_owner_target_ops") == _derive_review_selectors(
        reordered, "acquisition_lane_owner_target_ops"
    )


# --- loader acceptance ---------------------------------------------------


def test_generated_policy_loads_via_houndd_access() -> None:
    inventory, overlay = _inputs()
    policy = generate_policy(inventory, overlay)  # generate_policy already round-trips via houndd.access internally
    rules = tuple(
        access.PolicyRule(
            subject=rule["subject"],
            claim_selector=access.ProducerSelector(**rule["claim_selector"]),
            policy_id=rule["policy_id"],
            event_producer_selectors=tuple(access.ProducerSelector(**s) for s in rule["event_producer_selectors"]),
            readable_tiers=frozenset(rule["readable_tiers"]),
            allowed_output_tiers=frozenset(rule["allowed_output_tiers"]),
        )
        for rule in policy["rules"]
    )
    bundle = access.PolicyBundle(rules)
    assert len(bundle.rules) == len(policy["rules"])


def test_generated_policy_loads_via_houndd_service_frozen_loader(tmp_path: Path) -> None:
    """Round-trip through the real daemon loader: private dirs, 0600 file,
    canonical-JSON-on-disk -- the exact contract load_frozen_policy enforces."""

    inventory, overlay = _inputs()
    data = generate_policy_bytes(inventory, overlay)

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    service = state / "service"
    service.mkdir(mode=0o700)
    policy_path = service / "policy.json"
    policy_path.write_bytes(data)
    policy_path.chmod(0o600)

    frozen = load_frozen_policy(state)
    try:
        assert len(frozen.bundle.rules) == len(json.loads(data)["rules"])
    finally:
        os.close(frozen.policy_fd)
        frozen.service_root.close()


# --- drift detection -----------------------------------------------------


def test_check_policy_verify_passes_against_self_emitted_file(tmp_path: Path) -> None:
    emitted = tmp_path / "policy.json"
    result = _cli("--emit", str(emitted))
    assert result.returncode == 0, result.stderr
    result = _cli("--verify", str(emitted))
    assert result.returncode == 0, result.stderr
    assert "valid" in result.stdout


def test_check_policy_verify_fails_on_mutated_file(tmp_path: Path) -> None:
    emitted = tmp_path / "policy.json"
    assert _cli("--emit", str(emitted)).returncode == 0
    policy = json.loads(emitted.read_text())
    # Drop one rule -- simulates a hand edit or a lane that regressed.
    policy["rules"].pop()
    emitted.write_text(json.dumps(policy))

    result = _cli("--verify", str(emitted))
    assert result.returncode == 1
    assert "does not byte-match" in result.stderr
    assert "MISSING FROM TARGET" in result.stderr


def test_check_policy_verify_reports_changed_producer_selectors(tmp_path: Path) -> None:
    """The exact 71/105 shape: same rule key, stale selector list."""

    emitted = tmp_path / "policy.json"
    assert _cli("--emit", str(emitted)).returncode == 0
    policy = json.loads(emitted.read_text())
    for rule in policy["rules"]:
        if rule["claim_selector"]["owner_id"] == "workpad-review":
            rule["event_producer_selectors"] = rule["event_producer_selectors"][:2]
    emitted.write_text(json.dumps(policy))

    result = _cli("--verify", str(emitted))
    assert result.returncode == 1
    assert "CHANGED IN TARGET" in result.stderr
    assert "workpad-review" in result.stderr


def test_check_policy_emit_refuses_the_live_state_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    target = fake_home / ".local" / "state" / "hound" / "discovery" / "service" / "policy.json"
    target.parent.mkdir(parents=True)

    env = dict(os.environ)
    env["HOME"] = str(fake_home)
    env.pop("XDG_STATE_HOME", None)
    result = subprocess.run(
        [sys.executable, "migration/check_policy.py", "--emit", str(target)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert "refusing to write under the live houndd state root" in result.stderr
    assert not target.exists()


# --- inventory-change propagation ----------------------------------------


def test_adding_a_target_op_propagates_to_the_generated_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory, overlay = _inputs()
    mutated = copy.deepcopy(inventory)
    lane = next(row for row in mutated["consumers"] if row["id"] == "benefits-radar")
    assert "ingest.file" not in lane["target_ops"]
    lane["target_ops"].append("ingest.file")
    digest = hashlib.sha256(json.dumps(mutated["consumers"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    monkeypatch.setattr(consumer_inventory, "CANONICAL_ROW_DIGEST", digest)

    before = {(o, c) for o, c in _lane_grants(inventory)}
    after = {(o, c) for o, c in _lane_grants(mutated)}
    assert ("gc-benefits", "ingest.file") not in before
    assert ("gc-benefits", "ingest.file") in after

    policy = generate_policy(mutated, overlay)
    grant = next(
        rule
        for rule in policy["rules"]
        if rule["claim_selector"] == {"owner_id": "gc-benefits", "capability": "ingest.file", "run_id": None}
    )
    assert grant["event_producer_selectors"] == [{"owner_id": "gc-benefits", "capability": None, "run_id": None}]


def test_new_acquisition_lane_owner_propagates_into_review_surface_selectors() -> None:
    inventory, _overlay = _inputs()
    selectors = _derive_review_selectors(inventory, "acquisition_lane_owner_target_ops")
    # civic-policy-radar (owner gc-web since the M3 owner correction) is an
    # acquisition lane in the checked-in inventory; wiki's ops must appear in
    # the derived review set without anyone having hand-listed the owner.
    assert {"owner_id": "gc-wiki", "capability": "ingest.search", "run_id": None} in selectors
    assert {"owner_id": "gc-wiki", "capability": "ingest.url", "run_id": None} in selectors


# --- overlay closure -------------------------------------------------------


def test_overlay_rejects_unknown_top_level_field() -> None:
    mutated = copy.deepcopy(OVERLAY)
    mutated["unexpected_field"] = True
    errors = validate_overlay(mutated)
    assert any("unknown fields" in error for error in errors)
    with pytest.raises(PolicyGeneratorError):
        generate_policy(_inputs()[0], mutated)


def test_overlay_rejects_unknown_operator_field() -> None:
    mutated = copy.deepcopy(OVERLAY)
    mutated["operator"]["extra"] = "nope"
    errors = validate_overlay(mutated)
    assert any("unknown fields" in error for error in errors)


def test_overlay_rejects_unknown_review_surface_field() -> None:
    mutated = copy.deepcopy(OVERLAY)
    mutated["review_surfaces"][0]["extra"] = "nope"
    errors = validate_overlay(mutated)
    assert any("unknown fields" in error for error in errors)


def test_overlay_rejects_unknown_capability() -> None:
    mutated = copy.deepcopy(OVERLAY)
    mutated["operator"]["own_producer_capabilities"].append("not.a.capability")
    errors = validate_overlay(mutated)
    assert any("unknown capability" in error for error in errors)


def test_overlay_rejects_unknown_selector_source() -> None:
    mutated = copy.deepcopy(OVERLAY)
    mutated["review_surfaces"][0]["producer_selector_source"] = "hand_enumerated"
    errors = validate_overlay(mutated)
    assert any("derivation rule" in error for error in errors)


def test_overlay_rejects_capability_overlap_between_own_and_wildcard() -> None:
    mutated = copy.deepcopy(OVERLAY)
    mutated["operator"]["wildcard_producer_capabilities"].append(mutated["operator"]["own_producer_capabilities"][0])
    errors = validate_overlay(mutated)
    assert any("overlap" in error for error in errors)


def test_checked_in_overlay_is_valid() -> None:
    assert validate_overlay(OVERLAY) == []


def test_known_capabilities_matches_houndd_route_surface() -> None:
    # Every capability the overlay/generator may name must be one the daemon
    # actually recognises: the six commit routes plus the three read ops.
    assert KNOWN_CAPABILITIES == frozenset(
        {"ingest.search", "ingest.url", "ingest.file", "ingest.media", "transcribe", "import.record", "journal.query", "record.get", "journal.get"}
    )


# --- no dropped live grants (regression pin for today's incident) --------


def test_generated_policy_is_a_strict_superset_of_the_checked_in_snapshot() -> None:
    """Frozen copy of the live policy.json captured 2026-08-04 (see
    docs/policy-generation.md); every grant it contains must still be
    produced, or explicitly accounted for in the overlay -- never silently
    dropped."""

    live = json.loads((Path(__file__).parent / "fixtures" / "live-policy-2026-08-04.json").read_text())
    inventory, overlay = _inputs()
    generated = generate_policy(inventory, overlay)

    def key(rule: dict) -> tuple:
        cs = rule["claim_selector"]
        return (cs["owner_id"], cs["capability"], cs["run_id"])

    live_keys = {key(rule) for rule in live["rules"]}
    generated_keys = {key(rule) for rule in generated["rules"]}
    assert live_keys <= generated_keys, live_keys - generated_keys
