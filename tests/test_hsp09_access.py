"""HSP-09: pure access-policy and authenticated-principal primitives."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from houndd.access import (
    AccessPolicyError,
    AccessRefusal,
    AuthenticatedPrincipal,
    EffectiveAccess,
    PolicyBundle,
    PolicyRule,
    ProducerClaim,
    ProducerSelector,
    authorize_event_header,
    resolve_effective_access,
    resolve_scope,
)


def _rule(
    *,
    subject: str = "peer:1000",
    claim_owner: str = "query-owner",
    policy_id: str = "policy-a",
    event_owner: str = "event-owner",
    readable_tiers: frozenset[str] = frozenset({"public", "workspace"}),
    allowed_output_tiers: frozenset[str] = frozenset({"workspace", "restricted"}),
) -> PolicyRule:
    return PolicyRule(
        subject=subject,
        claim_selector=ProducerSelector(owner_id=claim_owner, capability="journal.query"),
        policy_id=policy_id,
        event_producer_selectors=(ProducerSelector(owner_id=event_owner, capability="capture"),),
        readable_tiers=readable_tiers,
        allowed_output_tiers=allowed_output_tiers,
    )


def _event(*, access: str, policy_id: str, owner_id: str) -> dict[str, object]:
    return {
        "access": access,
        "policy_id": policy_id,
        "producer": {"owner_id": owner_id, "capability": "capture", "run_id": "event-run"},
        "protected": "must-not-be-inspected",
    }


def test_hsp09_principal_is_transport_identity_and_producer_claim_is_not() -> None:
    actual = AuthenticatedPrincipal("peer:1000")
    attacker = AuthenticatedPrincipal("peer:2000")
    claim = ProducerClaim("query-owner", "journal.query", "request-run")
    bundle = PolicyBundle((_rule(),))

    scope = resolve_scope(bundle, actual, claim)
    assert scope is not None
    assert scope.principal is actual
    assert scope.principal.subject == "peer:1000"
    assert resolve_scope(bundle, attacker, claim) is None
    assert actual != claim

    with pytest.raises(FrozenInstanceError):
        claim.owner_id = "forged"  # type: ignore[misc]
    with pytest.raises(TypeError):
        ProducerClaim(  # type: ignore[call-arg]
            owner_id="query-owner",
            capability="journal.query",
            run_id="run",
            subject="peer:1000",
        )


def test_hsp09_scope_resolution_fails_closed_for_unpermitted_claims_and_raw_values() -> None:
    bundle = PolicyBundle((_rule(),))
    principal = AuthenticatedPrincipal("peer:1000")

    assert resolve_scope(bundle, principal, ProducerClaim("other", "journal.query", "run")) is None
    assert resolve_scope(bundle, principal, ProducerClaim("query-owner", "other", "run")) is None
    assert resolve_scope(bundle, principal, {"owner_id": "query-owner"}) is None  # type: ignore[arg-type]
    assert resolve_scope(bundle, "peer:1000", ProducerClaim("query-owner", "journal.query", "run")) is None  # type: ignore[arg-type]


def test_hsp09_event_authorization_uses_explicit_tiers_and_paired_selectors() -> None:
    rules = (
        _rule(policy_id="policy-a", event_owner="owner-a", readable_tiers=frozenset({"public"})),
        _rule(policy_id="policy-b", event_owner="owner-b", readable_tiers=frozenset({"restricted"})),
    )
    scope = resolve_scope(
        PolicyBundle(rules),
        AuthenticatedPrincipal("peer:1000"),
        ProducerClaim("query-owner", "journal.query", "run"),
    )
    assert scope is not None
    assert scope.readable_tiers == frozenset({"public", "restricted"})
    assert scope.permitted_policy_ids == frozenset({"policy-a", "policy-b"})

    assert authorize_event_header(scope, _event(access="public", policy_id="policy-a", owner_id="owner-a"))
    assert authorize_event_header(scope, _event(access="restricted", policy_id="policy-b", owner_id="owner-b"))
    assert not authorize_event_header(scope, _event(access="restricted", policy_id="policy-a", owner_id="owner-a"))
    assert not authorize_event_header(scope, _event(access="public", policy_id="policy-b", owner_id="owner-b"))
    assert not authorize_event_header(scope, _event(access="public", policy_id="policy-a", owner_id="owner-b"))
    assert not authorize_event_header(scope, _event(access="workspace", policy_id="policy-a", owner_id="owner-a"))


def test_hsp09_authorization_inspects_only_the_event_header() -> None:
    class ObservedEvent(dict[str, object]):
        inspected: list[str]

        def __init__(self, value: dict[str, object]) -> None:
            super().__init__(value)
            self.inspected = []

        def __getitem__(self, key: str) -> object:
            self.inspected.append(key)
            if key == "protected":
                raise AssertionError("protected event data was inspected")
            return super().__getitem__(key)

    scope = resolve_scope(
        PolicyBundle((_rule(),)),
        AuthenticatedPrincipal("peer:1000"),
        ProducerClaim("query-owner", "journal.query", "run"),
    )
    assert scope is not None
    event = ObservedEvent(_event(access="public", policy_id="policy-a", owner_id="event-owner"))

    assert authorize_event_header(scope, event)
    assert set(event.inspected) == {"access", "policy_id", "producer"}


@pytest.mark.parametrize(
    "event",
    [
        {},
        {"access": "unknown", "policy_id": "policy-a", "producer": {}},
        {"access": "public", "policy_id": "", "producer": {}},
        {
            "access": "public",
            "policy_id": "policy-a",
            "producer": {"owner_id": "event-owner", "capability": "capture", "run_id": "run", "subject": "forged"},
        },
        {"access": "public", "policy_id": "policy-a", "producer": None},
    ],
)
def test_hsp09_malformed_event_headers_are_non_authorized(event: dict[str, object]) -> None:
    scope = resolve_scope(
        PolicyBundle((_rule(),)),
        AuthenticatedPrincipal("peer:1000"),
        ProducerClaim("query-owner", "journal.query", "run"),
    )
    assert scope is not None
    assert not authorize_event_header(scope, event)


def test_hsp09_policy_bundle_is_immutable_canonical_and_order_independent() -> None:
    first = _rule()
    second = _rule(policy_id="policy-b", event_owner="other-owner")
    source = [second, first, first]
    left = PolicyBundle(source)
    right = PolicyBundle((first, second))

    source.clear()
    assert left.rules == right.rules
    assert left.bundle_hash == right.bundle_hash
    assert len(left.bundle_hash) == 64
    assert set(left.bundle_hash) <= set("0123456789abcdef")
    assert left.bundle_hash != PolicyBundle((
        _rule(allowed_output_tiers=frozenset({"restricted"})),
        second,
    )).bundle_hash

    with pytest.raises(FrozenInstanceError):
        first.policy_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        left.rules = ()  # type: ignore[misc]


@pytest.mark.parametrize("tier", ["PUBLIC", "private", "", None, 1])
def test_hsp09_policy_tiers_use_only_the_exact_visibility_vocabulary(tier: object) -> None:
    with pytest.raises(AccessPolicyError):
        _rule(readable_tiers=frozenset({tier}))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("requested", "allowed", "expected", "clamped"),
    [
        ("public", frozenset({"public", "restricted"}), "public", False),
        ("workspace", frozenset({"workspace"}), "workspace", False),
        ("restricted", frozenset({"restricted"}), "restricted", False),
        (None, frozenset({"restricted"}), "restricted", True),
        ("uncertain", frozenset({"restricted"}), "restricted", True),
        ("public", frozenset({"workspace", "restricted"}), "restricted", True),
        ("workspace", frozenset({"public", "restricted"}), "restricted", True),
    ],
)
def test_hsp09_effective_access_keeps_exact_or_clamps_to_restricted(
    requested: object,
    allowed: frozenset[str],
    expected: str,
    clamped: bool,
) -> None:
    decision = resolve_effective_access(_rule(allowed_output_tiers=allowed), requested)
    assert decision == EffectiveAccess(expected, clamped=clamped)


@pytest.mark.parametrize(
    ("requested", "allowed"),
    [
        (None, frozenset()),
        ("restricted", frozenset({"public"})),
        ("workspace", frozenset({"public"})),
        ("public", frozenset({"workspace"})),
        ([], frozenset({"public", "workspace"})),
    ],
)
def test_hsp09_effective_access_refuses_when_safe_restricted_output_is_not_allowed(
    requested: object,
    allowed: frozenset[str],
) -> None:
    decision = resolve_effective_access(_rule(allowed_output_tiers=allowed), requested)
    assert decision == AccessRefusal(
        code="access_not_permitted",
        message="requested access cannot be granted safely",
    )


def test_hsp09_validated_structures_reject_empty_and_wrong_typed_identity_values() -> None:
    with pytest.raises(AccessPolicyError):
        AuthenticatedPrincipal("")
    with pytest.raises(AccessPolicyError):
        ProducerClaim("owner", "capability", None)  # type: ignore[arg-type]
    with pytest.raises(AccessPolicyError):
        ProducerSelector(owner_id=3)  # type: ignore[arg-type]
    with pytest.raises(AccessPolicyError):
        PolicyBundle((object(),))  # type: ignore[arg-type]


def test_hsp09_all_policy_identity_text_must_be_valid_utf8() -> None:
    invalid = "\ud800"
    constructors = (
        lambda: AuthenticatedPrincipal(invalid),
        lambda: ProducerClaim(invalid, "capability", "run"),
        lambda: ProducerSelector(owner_id=invalid),
        lambda: _rule(subject=invalid),
        lambda: _rule(policy_id=invalid),
        lambda: AccessRefusal(code=invalid),
    )

    for construct in constructors:
        with pytest.raises(AccessPolicyError):
            construct()
