"""Generate ``houndd.policy.v1`` from the consumer inventory plus a small overlay.

The live operator policy (``${state}/service/policy.json``) used to be hand
maintained: 28 rules mechanically re-deriving what
``migration/consumer-inventory.v1.json`` already declares (owner x
target_ops), plus a hand-enumerated producer-selector list for the
Workpad review surface that silently lagged every new lane cutover. Both
classes of bug -- rules drifting from the inventory, and a review selector
list going stale -- are eliminated by generation instead of hand editing.

This module is pure: it takes the already-loaded inventory and overlay
documents and returns a policy dict (or its canonical bytes). It never opens
the live state root and never writes anything -- ``check_policy.py`` owns the
CLI surface, and the operator owns moving an emitted file into place.

Everything the inventory already knows (lane owners and their target_ops)
must be *derived*, not re-typed, in ``policy_overlay.v1.json``. The overlay
only declares the two things the inventory cannot: the operator's own broad
grants, and which review surfaces exist plus which derivation rule builds
their producer-selector list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from houndd import access
from houndd.contracts import canonical_bytes

from migration.consumer_inventory import OPS, InventoryError, load_inventory, validate_inventory


class PolicyGeneratorError(ValueError):
    """The inventory, overlay, or generated policy is malformed or unsafe."""


# Every capability a generated rule may name. ``OPS`` is the inventory's
# write/journal.query vocabulary (see consumer_inventory.OPS); ``record.get``
# and ``journal.get`` are operator-only meta reads that no consumer row ever
# declares as a target_op, so they are not in OPS and only reachable through
# the overlay's operator grants.
KNOWN_CAPABILITIES = OPS | frozenset({"record.get", "journal.get"})

# The set of supported review-surface producer-selector derivation rules.
# "acquisition_lane_owner_target_ops" = one selector per (owner, target_op)
# pair across every inventory consumer whose kind is "acquisition" -- this is
# the rule that was previously hand-enumerated and went stale.
SELECTOR_SOURCES = frozenset({"acquisition_lane_owner_target_ops"})

DEFAULT_INVENTORY_PATH = Path(__file__).with_name("consumer-inventory.v1.json")
DEFAULT_OVERLAY_PATH = Path(__file__).with_name("policy_overlay.v1.json")

MAX_OVERLAY_BYTES = 65_536


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyGeneratorError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_overlay(path: Path = DEFAULT_OVERLAY_PATH) -> dict[str, Any]:
    """Load and validate the checked-in overlay document."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PolicyGeneratorError(f"cannot read overlay {path}: {error}") from error
    if len(raw) > MAX_OVERLAY_BYTES:
        raise PolicyGeneratorError(f"overlay {path} exceeds {MAX_OVERLAY_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, ValueError) as error:
        raise PolicyGeneratorError(f"cannot parse overlay {path}: {error}") from error
    errors = validate_overlay(value)
    if errors:
        raise PolicyGeneratorError("; ".join(errors))
    return value


def _check_object_fields(value: object, label: str, fields: frozenset[str], errors: list[str]) -> bool:
    if type(value) is not dict:
        errors.append(f"{label} must be an object")
        return False
    actual = set(value)
    missing = fields - actual
    extra = actual - fields
    if missing:
        errors.append(f"{label} missing fields: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unknown fields: {', '.join(sorted(extra))}")
    return not missing and not extra


def _check_capability_list(value: object, label: str, errors: list[str]) -> None:
    if type(value) is not list:
        errors.append(f"{label} must be a list")
        return
    seen: set[str] = set()
    for item in value:
        if type(item) is not str or item not in KNOWN_CAPABILITIES:
            errors.append(f"{label} contains an unknown capability: {item!r}")
        elif item in seen:
            errors.append(f"{label} contains a duplicate capability: {item}")
        else:
            seen.add(item)


def validate_overlay(overlay: object) -> list[str]:
    """Return every overlay error; closure-strict like consumer_inventory's validator."""

    errors: list[str] = []
    top_fields = frozenset({"schema_version", "subject", "policy_id", "readable_tiers", "allowed_output_tiers", "operator", "review_surfaces"})
    if not _check_object_fields(overlay, "overlay", top_fields, errors):
        return errors
    assert isinstance(overlay, dict)
    if overlay["schema_version"] != "hound.migration.policy-overlay.v1":
        errors.append("overlay.schema_version is not the canonical version")
    for key in ("subject", "policy_id"):
        if type(overlay[key]) is not str or not overlay[key]:
            errors.append(f"overlay.{key} must be a non-empty string")
    for key in ("readable_tiers", "allowed_output_tiers"):
        if overlay[key] != ["public"]:
            errors.append(f'overlay.{key} must be exactly ["public"]')

    operator = overlay["operator"]
    operator_fields = frozenset({"owner_id", "own_producer_capabilities", "wildcard_producer_capabilities"})
    if _check_object_fields(operator, "overlay.operator", operator_fields, errors):
        if type(operator["owner_id"]) is not str or not operator["owner_id"]:
            errors.append("overlay.operator.owner_id must be a non-empty string")
        for key in ("own_producer_capabilities", "wildcard_producer_capabilities"):
            _check_capability_list(operator.get(key), f"overlay.operator.{key}", errors)
        own = set(operator.get("own_producer_capabilities", []))
        wildcard = set(operator.get("wildcard_producer_capabilities", []))
        overlap = own & wildcard
        if overlap:
            errors.append(f"overlay.operator capability lists overlap: {', '.join(sorted(overlap))}")
        if not own and not wildcard:
            errors.append("overlay.operator must declare at least one capability")

    review_surfaces = overlay["review_surfaces"]
    if type(review_surfaces) is not list:
        errors.append("overlay.review_surfaces must be a list")
    else:
        seen: set[tuple[Any, Any, Any]] = set()
        surface_fields = frozenset({"owner_id", "run_id", "capability", "producer_selector_source"})
        for index, surface in enumerate(review_surfaces):
            label = f"overlay.review_surfaces[{index}]"
            if not _check_object_fields(surface, label, surface_fields, errors):
                continue
            if type(surface["owner_id"]) is not str or not surface["owner_id"]:
                errors.append(f"{label}.owner_id must be a non-empty string")
            if type(surface["run_id"]) is not str or not surface["run_id"]:
                errors.append(f"{label}.run_id must be a non-empty string")
            if surface["capability"] not in KNOWN_CAPABILITIES:
                errors.append(f"{label}.capability is not a known houndd capability")
            if surface["producer_selector_source"] not in SELECTOR_SOURCES:
                errors.append(f"{label}.producer_selector_source is not a known derivation rule")
            key = (surface.get("owner_id"), surface.get("run_id"), surface.get("capability"))
            if key in seen:
                errors.append(f"{label} duplicates an earlier review surface grant")
            seen.add(key)
    return errors


def _own_selector(owner: str) -> dict[str, str | None]:
    return {"owner_id": owner, "capability": None, "run_id": None}


def _wildcard_selector() -> dict[str, str | None]:
    return {"owner_id": None, "capability": None, "run_id": None}


def _rule(
    *,
    subject: str,
    owner: str,
    capability: str,
    run_id: str | None,
    producer_selectors: list[dict[str, str | None]],
    policy_id: str,
    readable_tiers: list[str],
    allowed_output_tiers: list[str],
) -> dict[str, Any]:
    return {
        "subject": subject,
        "claim_selector": {"owner_id": owner, "capability": capability, "run_id": run_id},
        "policy_id": policy_id,
        "event_producer_selectors": sorted(producer_selectors, key=canonical_bytes),
        "readable_tiers": list(readable_tiers),
        "allowed_output_tiers": list(allowed_output_tiers),
    }


def _lane_grants(inventory: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every (owner, capability) pair every inventory lane declares.

    Acquisition lanes additionally receive ``record.get`` and
    ``journal.query`` -- the established grant shape a lane needs to both
    ingest and read back its own provenance -- mirroring what the four
    already-live acquisition lanes (gc-benefits/gc-web/gc-wiki/gc-intel) show
    in the current hand-maintained policy.
    """

    grants: dict[tuple[str, str], None] = {}
    for consumer in inventory["consumers"]:
        owner = consumer["owner"]
        capabilities = set(consumer["target_ops"])
        if consumer["kind"] == "acquisition":
            capabilities |= {"record.get", "journal.query"}
        for capability in capabilities:
            grants[(owner, capability)] = None
    return sorted(grants)


def _derive_review_selectors(inventory: Mapping[str, Any], source: str) -> list[dict[str, str | None]]:
    if source != "acquisition_lane_owner_target_ops":
        raise PolicyGeneratorError(f"unknown producer_selector_source: {source}")
    selectors: dict[tuple[str, str], dict[str, str | None]] = {}
    for consumer in inventory["consumers"]:
        if consumer["kind"] != "acquisition":
            continue
        owner = consumer["owner"]
        for capability in consumer["target_ops"]:
            selectors[(owner, capability)] = {"owner_id": owner, "capability": capability, "run_id": None}
    return [selectors[key] for key in sorted(selectors)]


def _prove_loadable(policy: Mapping[str, Any]) -> None:
    """Round-trip the generated dict through houndd's own policy primitives."""

    try:
        rules = tuple(
            access.PolicyRule(
                subject=rule["subject"],
                claim_selector=access.ProducerSelector(**rule["claim_selector"]),
                policy_id=rule["policy_id"],
                event_producer_selectors=tuple(access.ProducerSelector(**selector) for selector in rule["event_producer_selectors"]),
                readable_tiers=frozenset(rule["readable_tiers"]),
                allowed_output_tiers=frozenset(rule["allowed_output_tiers"]),
            )
            for rule in policy["rules"]
        )
        bundle = access.PolicyBundle(rules)
    except access.AccessPolicyError as error:
        raise PolicyGeneratorError(f"generated policy failed houndd.access validation: {error}") from error
    if len(bundle.rules) != len(rules):
        raise PolicyGeneratorError("generated policy contains duplicate rules under houndd.access canonicalization")


def generate_policy(inventory: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Pure inventory + overlay -> complete ``houndd.policy.v1`` dict.

    Raises ``PolicyGeneratorError`` if either input is invalid, or if the
    generated policy would fail houndd's own loader.
    """

    inventory_errors = validate_inventory(inventory)
    if inventory_errors:
        raise PolicyGeneratorError("; ".join(inventory_errors))
    overlay_errors = validate_overlay(overlay)
    if overlay_errors:
        raise PolicyGeneratorError("; ".join(overlay_errors))

    subject = overlay["subject"]
    policy_id = overlay["policy_id"]
    readable_tiers = overlay["readable_tiers"]
    allowed_output_tiers = overlay["allowed_output_tiers"]

    rules_by_key: dict[bytes, dict[str, Any]] = {}

    def add(rule: dict[str, Any]) -> None:
        rules_by_key[canonical_bytes(rule)] = rule

    for owner, capability in _lane_grants(inventory):
        add(
            _rule(
                subject=subject,
                owner=owner,
                capability=capability,
                run_id=None,
                producer_selectors=[_own_selector(owner)],
                policy_id=policy_id,
                readable_tiers=readable_tiers,
                allowed_output_tiers=allowed_output_tiers,
            )
        )

    operator = overlay["operator"]
    operator_owner = operator["owner_id"]
    for capability in operator["own_producer_capabilities"]:
        add(
            _rule(
                subject=subject,
                owner=operator_owner,
                capability=capability,
                run_id=None,
                producer_selectors=[_own_selector(operator_owner)],
                policy_id=policy_id,
                readable_tiers=readable_tiers,
                allowed_output_tiers=allowed_output_tiers,
            )
        )
    for capability in operator["wildcard_producer_capabilities"]:
        add(
            _rule(
                subject=subject,
                owner=operator_owner,
                capability=capability,
                run_id=None,
                producer_selectors=[_wildcard_selector()],
                policy_id=policy_id,
                readable_tiers=readable_tiers,
                allowed_output_tiers=allowed_output_tiers,
            )
        )

    for surface in overlay["review_surfaces"]:
        selectors = _derive_review_selectors(inventory, surface["producer_selector_source"])
        add(
            _rule(
                subject=subject,
                owner=surface["owner_id"],
                capability=surface["capability"],
                run_id=surface["run_id"],
                producer_selectors=selectors,
                policy_id=policy_id,
                readable_tiers=readable_tiers,
                allowed_output_tiers=allowed_output_tiers,
            )
        )

    ordered = [rules_by_key[key] for key in sorted(rules_by_key)]
    policy = {"schema_version": "houndd.policy.v1", "rules": ordered}
    _prove_loadable(policy)
    return policy


def generate_policy_bytes(inventory: Mapping[str, Any], overlay: Mapping[str, Any]) -> bytes:
    return canonical_bytes(generate_policy(inventory, overlay))


def load_default_inputs(
    manifest_path: Path = DEFAULT_INVENTORY_PATH, overlay_path: Path = DEFAULT_OVERLAY_PATH
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        inventory = load_inventory(manifest_path)
    except InventoryError as error:
        raise PolicyGeneratorError(f"cannot load inventory {manifest_path}: {error}") from error
    overlay = load_overlay(overlay_path)
    return inventory, overlay


__all__ = [
    "KNOWN_CAPABILITIES",
    "SELECTOR_SOURCES",
    "DEFAULT_INVENTORY_PATH",
    "DEFAULT_OVERLAY_PATH",
    "PolicyGeneratorError",
    "generate_policy",
    "generate_policy_bytes",
    "load_default_inputs",
    "load_overlay",
    "validate_overlay",
]
