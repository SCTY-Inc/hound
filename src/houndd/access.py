"""HSP-09: pure authenticated-principal and access-policy primitives."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


ACCESS_TIERS = frozenset({"public", "workspace", "restricted"})


class AccessPolicyError(ValueError):
    """An access-policy value is malformed or unsafe."""


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AccessPolicyError(f"{label} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise AccessPolicyError(f"{label} must contain valid Unicode") from error
    return value


def _tier_set(value: object, label: str) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise AccessPolicyError(f"{label} must be a set of access tiers")
    try:
        tiers = frozenset(value)
    except TypeError as error:
        raise AccessPolicyError(f"{label} must be a set of access tiers") from error
    if any(not isinstance(tier, str) or tier not in ACCESS_TIERS for tier in tiers):
        raise AccessPolicyError(f"{label} contains an unsupported access tier")
    return tiers


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Opaque identity created by the authenticated transport boundary."""

    subject: str

    def __post_init__(self) -> None:
        _text(self.subject, "principal.subject")


@dataclass(frozen=True, slots=True)
class ProducerClaim:
    """Untrusted request-envelope claim; never an authenticated identity."""

    owner_id: str
    capability: str
    run_id: str

    def __post_init__(self) -> None:
        _text(self.owner_id, "producer.owner_id")
        _text(self.capability, "producer.capability")
        _text(self.run_id, "producer.run_id")


@dataclass(frozen=True, slots=True)
class ProducerSelector:
    """An explicit producer selector; ``None`` is a policy-authored wildcard."""

    owner_id: str | None = None
    capability: str | None = None
    run_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("owner_id", "capability", "run_id"):
            value = getattr(self, name)
            if value is not None:
                _text(value, f"producer selector.{name}")

    def matches(self, claim: ProducerClaim) -> bool:
        if not isinstance(claim, ProducerClaim):
            return False
        return all(
            selected is None or selected == getattr(claim, name)
            for name, selected in (
                ("owner_id", self.owner_id),
                ("capability", self.capability),
                ("run_id", self.run_id),
            )
        )


def _selector_value(selector: ProducerSelector) -> dict[str, str | None]:
    return {
        "owner_id": selector.owner_id,
        "capability": selector.capability,
        "run_id": selector.run_id,
    }


def _selector_tuple(value: object, label: str) -> tuple[ProducerSelector, ...]:
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise AccessPolicyError(f"{label} must be a collection of producer selectors")
    selectors = tuple(value)
    if any(not isinstance(selector, ProducerSelector) for selector in selectors):
        raise AccessPolicyError(f"{label} must contain only producer selectors")
    by_value = {_canonical_bytes(_selector_value(selector)): selector for selector in selectors}
    return tuple(by_value[key] for key in sorted(by_value))


@dataclass(frozen=True, slots=True)
class EventSelector:
    """A policy/producer/tier grant kept paired to avoid cross-rule widening."""

    policy_id: str
    producer_selector: ProducerSelector
    readable_tiers: frozenset[str]

    def __post_init__(self) -> None:
        _text(self.policy_id, "event selector.policy_id")
        if not isinstance(self.producer_selector, ProducerSelector):
            raise AccessPolicyError("event selector.producer_selector is invalid")
        object.__setattr__(
            self,
            "readable_tiers",
            _tier_set(self.readable_tiers, "event selector.readable_tiers"),
        )

    def permits(self, access: str, policy_id: str, producer: ProducerClaim) -> bool:
        return (
            policy_id == self.policy_id
            and access in self.readable_tiers
            and self.producer_selector.matches(producer)
        )


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One immutable caller-claim mapping and its explicit access grants."""

    subject: str
    claim_selector: ProducerSelector
    policy_id: str
    event_producer_selectors: tuple[ProducerSelector, ...]
    readable_tiers: frozenset[str]
    allowed_output_tiers: frozenset[str]

    def __post_init__(self) -> None:
        _text(self.subject, "policy rule.subject")
        if not isinstance(self.claim_selector, ProducerSelector):
            raise AccessPolicyError("policy rule.claim_selector is invalid")
        _text(self.policy_id, "policy rule.policy_id")
        object.__setattr__(
            self,
            "event_producer_selectors",
            _selector_tuple(self.event_producer_selectors, "policy rule.event_producer_selectors"),
        )
        object.__setattr__(
            self,
            "readable_tiers",
            _tier_set(self.readable_tiers, "policy rule.readable_tiers"),
        )
        object.__setattr__(
            self,
            "allowed_output_tiers",
            _tier_set(self.allowed_output_tiers, "policy rule.allowed_output_tiers"),
        )


def _rule_value(rule: PolicyRule) -> dict[str, Any]:
    return {
        "subject": rule.subject,
        "claim_selector": _selector_value(rule.claim_selector),
        "policy_id": rule.policy_id,
        "event_producer_selectors": [
            _selector_value(selector) for selector in rule.event_producer_selectors
        ],
        "readable_tiers": sorted(rule.readable_tiers),
        "allowed_output_tiers": sorted(rule.allowed_output_tiers),
    }


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """Canonical, in-memory-only policy snapshot."""

    rules: tuple[PolicyRule, ...]
    bundle_hash: str = field(init=False)

    def __post_init__(self) -> None:
        if isinstance(self.rules, (str, bytes, Mapping)) or not isinstance(self.rules, Iterable):
            raise AccessPolicyError("policy bundle.rules must be a collection of policy rules")
        rules = tuple(self.rules)
        if any(not isinstance(rule, PolicyRule) for rule in rules):
            raise AccessPolicyError("policy bundle.rules must contain only policy rules")
        by_value = {_canonical_bytes(_rule_value(rule)): rule for rule in rules}
        canonical_rules = tuple(by_value[key] for key in sorted(by_value))
        body = {
            "schema_version": "houndd.policy-bundle.v1",
            "rules": [_rule_value(rule) for rule in canonical_rules],
        }
        object.__setattr__(self, "rules", canonical_rules)
        object.__setattr__(self, "bundle_hash", hashlib.sha256(_canonical_bytes(body)).hexdigest())


def _event_selector_value(selector: EventSelector) -> dict[str, Any]:
    return {
        "policy_id": selector.policy_id,
        "producer_selector": _selector_value(selector.producer_selector),
        "readable_tiers": sorted(selector.readable_tiers),
    }


def _event_selector_tuple(value: object) -> tuple[EventSelector, ...]:
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise AccessPolicyError("scope.permitted_event_selectors must be a collection")
    selectors = tuple(value)
    if any(not isinstance(selector, EventSelector) for selector in selectors):
        raise AccessPolicyError("scope.permitted_event_selectors contains an invalid selector")
    by_value = {_canonical_bytes(_event_selector_value(selector)): selector for selector in selectors}
    return tuple(by_value[key] for key in sorted(by_value))


@dataclass(frozen=True, slots=True)
class PrincipalScope:
    """Resolved read scope for exactly one authenticated principal."""

    principal: AuthenticatedPrincipal
    readable_tiers: frozenset[str]
    permitted_event_selectors: tuple[EventSelector, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.principal, AuthenticatedPrincipal):
            raise AccessPolicyError("scope.principal must be authenticated")
        readable_tiers = _tier_set(self.readable_tiers, "scope.readable_tiers")
        selectors = _event_selector_tuple(self.permitted_event_selectors)
        if any(not selector.readable_tiers <= readable_tiers for selector in selectors):
            raise AccessPolicyError("scope event tiers must be included in scope.readable_tiers")
        object.__setattr__(self, "readable_tiers", readable_tiers)
        object.__setattr__(self, "permitted_event_selectors", selectors)

    @property
    def permitted_policy_ids(self) -> frozenset[str]:
        return frozenset(selector.policy_id for selector in self.permitted_event_selectors)

    @property
    def permitted_producer_selectors(self) -> tuple[ProducerSelector, ...]:
        selectors = (selector.producer_selector for selector in self.permitted_event_selectors)
        return _selector_tuple(tuple(selectors), "scope.permitted_producer_selectors")


@dataclass(frozen=True, slots=True)
class EffectiveAccess:
    """A safely resolved access tier for a future ingestion transaction."""

    access: str
    clamped: bool = False

    def __post_init__(self) -> None:
        if self.access not in ACCESS_TIERS:
            raise AccessPolicyError("effective access is not a supported tier")
        if not isinstance(self.clamped, bool):
            raise AccessPolicyError("effective access.clamped must be boolean")


@dataclass(frozen=True, slots=True)
class AccessRefusal:
    """Clear internal refusal when no policy-permitted safe output exists."""

    code: str = "access_not_permitted"
    message: str = "requested access cannot be granted safely"

    def __post_init__(self) -> None:
        _text(self.code, "access refusal.code")
        _text(self.message, "access refusal.message")


def resolve_scope(
    bundle: PolicyBundle,
    authenticated_principal: AuthenticatedPrincipal,
    producer_claim: ProducerClaim,
) -> PrincipalScope | None:
    """Resolve policy from transport identity plus a separate untrusted claim."""

    if not isinstance(bundle, PolicyBundle):
        return None
    if not isinstance(authenticated_principal, AuthenticatedPrincipal):
        return None
    if not isinstance(producer_claim, ProducerClaim):
        return None
    matching = tuple(
        rule
        for rule in bundle.rules
        if rule.subject == authenticated_principal.subject
        and rule.claim_selector.matches(producer_claim)
    )
    if not matching:
        return None
    event_selectors = tuple(
        EventSelector(rule.policy_id, producer_selector, rule.readable_tiers)
        for rule in matching
        for producer_selector in rule.event_producer_selectors
    )
    return PrincipalScope(
        principal=authenticated_principal,
        readable_tiers=frozenset(
            tier for rule in matching for tier in rule.readable_tiers
        ),
        permitted_event_selectors=event_selectors,
    )


def _event_producer(value: object) -> ProducerClaim | None:
    if isinstance(value, ProducerClaim):
        return value
    if not isinstance(value, Mapping):
        return None
    try:
        if set(value.keys()) != {"owner_id", "capability", "run_id"}:
            return None
        return ProducerClaim(
            owner_id=value["owner_id"],
            capability=value["capability"],
            run_id=value["run_id"],
        )
    except (AccessPolicyError, KeyError, TypeError):
        return None


def authorize_event_header(scope: PrincipalScope, event: Mapping[str, object]) -> bool:
    """Authorize from only ``access``, ``policy_id``, and ``producer``."""

    if not isinstance(scope, PrincipalScope) or not isinstance(event, Mapping):
        return False
    try:
        access = event["access"]
        policy_id = event["policy_id"]
        producer_value = event["producer"]
    except (KeyError, TypeError):
        return False
    if not isinstance(access, str) or access not in ACCESS_TIERS:
        return False
    if not isinstance(policy_id, str) or not policy_id:
        return False
    producer = _event_producer(producer_value)
    if producer is None or access not in scope.readable_tiers:
        return False
    return any(
        selector.permits(access, policy_id, producer)
        for selector in scope.permitted_event_selectors
    )


def resolve_effective_access(
    rule: PolicyRule,
    requested_access: object = None,
) -> EffectiveAccess | AccessRefusal:
    """Keep an allowed request exact, otherwise clamp only to restricted."""

    if not isinstance(rule, PolicyRule):
        raise AccessPolicyError("effective access requires a policy rule")
    uncertain = not isinstance(requested_access, str) or requested_access not in ACCESS_TIERS
    candidate = "restricted" if uncertain else requested_access
    if candidate in rule.allowed_output_tiers:
        return EffectiveAccess(candidate, clamped=uncertain)
    if "restricted" in rule.allowed_output_tiers:
        return EffectiveAccess("restricted", clamped=True)
    return AccessRefusal()


def resolve_commit_access(
    rule: PolicyRule,
    requested_access: object,
) -> EffectiveAccess | AccessRefusal:
    """Resolve durable output access without exceeding its disclosure ceiling."""

    if type(rule) is not PolicyRule:
        raise AccessPolicyError("commit access requires a policy rule")
    if type(requested_access) is not str or requested_access not in ACCESS_TIERS:
        return AccessRefusal()
    allowed_output_tiers = rule.allowed_output_tiers
    if type(allowed_output_tiers) is not frozenset:
        return AccessRefusal()
    sanitized_allowed_output_tiers = frozenset(
        tier for tier in allowed_output_tiers if type(tier) is str and tier in ACCESS_TIERS
    )
    if len(sanitized_allowed_output_tiers) != len(allowed_output_tiers):
        return AccessRefusal()
    ceilings = {
        "public": frozenset({"public"}),
        "workspace": frozenset({"public", "workspace"}),
        "restricted": frozenset({"public", "workspace", "restricted"}),
    }
    permitted = sanitized_allowed_output_tiers & ceilings[requested_access]
    for tier in ("restricted", "workspace", "public"):
        if tier in permitted:
            return EffectiveAccess(tier, clamped=tier != requested_access)
    return AccessRefusal()


__all__ = [
    "ACCESS_TIERS",
    "AccessPolicyError",
    "AccessRefusal",
    "AuthenticatedPrincipal",
    "EffectiveAccess",
    "EventSelector",
    "PolicyBundle",
    "PolicyRule",
    "PrincipalScope",
    "ProducerClaim",
    "ProducerSelector",
    "authorize_event_header",
    "resolve_commit_access",
    "resolve_effective_access",
    "resolve_scope",
]
