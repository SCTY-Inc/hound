"""HSP-08/09: immutable, access-scoped query provenance artifacts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .access import ACCESS_TIERS, PrincipalScope, ProducerClaim, authorize_event_header
from .contracts import canonical_hash


class ProvenanceError(ValueError):
    """A provenance artifact or derived projection is unsafe."""


_ARTIFACT_KINDS = frozenset({"lane", "topic", "entity"})
_ANNOTATION_KINDS = frozenset({"topic", "entity"})
_HEX = frozenset("0123456789abcdef")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProvenanceError(f"{label} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise ProvenanceError(f"{label} must contain valid Unicode") from error
    return value


def _digest(value: object, label: str) -> str:
    value = _text(value, label)
    if len(value) != 64 or any(character not in _HEX for character in value):
        raise ProvenanceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _producer_value(producer: ProducerClaim) -> dict[str, str]:
    return {
        "owner_id": producer.owner_id,
        "capability": producer.capability,
        "run_id": producer.run_id,
    }


def _scope_value(scope: PrincipalScope) -> dict[str, Any]:
    return {
        "principal": scope.principal.subject,
        "readable_tiers": sorted(scope.readable_tiers),
        "permitted_event_selectors": [
            {
                "policy_id": selector.policy_id,
                "producer": {
                    "owner_id": selector.producer_selector.owner_id,
                    "capability": selector.producer_selector.capability,
                    "run_id": selector.producer_selector.run_id,
                },
                "readable_tiers": sorted(selector.readable_tiers),
            }
            for selector in scope.permitted_event_selectors
        ],
    }


@dataclass(frozen=True, slots=True)
class AnnotationHeader:
    """The authorization and target-semantics header of an owner annotation."""

    access: str
    policy_id: str
    producer: ProducerClaim

    def __post_init__(self) -> None:
        if self.access not in ACCESS_TIERS:
            raise ProvenanceError("annotation access is not a supported access tier")
        _text(self.policy_id, "annotation policy_id")
        if not isinstance(self.producer, ProducerClaim):
            raise ProvenanceError("annotation producer must be a ProducerClaim")

    @property
    def event_header(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "access": self.access,
                "policy_id": self.policy_id,
                "producer": _producer_value(self.producer),
            }
        )

    def is_authorized(self, scope: PrincipalScope) -> bool:
        return authorize_event_header(scope, self.event_header)

    @property
    def canonical(self) -> dict[str, Any]:
        return {
            "access": self.access,
            "policy_id": self.policy_id,
            "producer": _producer_value(self.producer),
        }


@dataclass(frozen=True, slots=True)
class LaneRule:
    """A content-addressed deterministic lane derivation rule."""

    policy_id: str
    owner_id: str
    capability: str
    lane: str
    source: str
    provenance_id: str = field(init=False)
    kind: str = field(default="lane", init=False)

    def __init__(
        self,
        policy_id: str,
        owner_id: str,
        capability: str,
        lane: str,
        *,
        source: str,
    ) -> None:
        object.__setattr__(self, "policy_id", _text(policy_id, "lane rule.policy_id"))
        object.__setattr__(self, "owner_id", _text(owner_id, "lane rule.owner_id"))
        object.__setattr__(self, "capability", _text(capability, "lane rule.capability"))
        object.__setattr__(self, "lane", _text(lane, "lane rule.lane"))
        object.__setattr__(self, "source", _text(source, "lane rule.source"))
        object.__setattr__(self, "kind", "lane")
        object.__setattr__(self, "provenance_id", canonical_hash(self._body()))

    def _body(self) -> dict[str, str]:
        return {
            "schema_version": "houndd.provenance.v1",
            "kind": "lane",
            "policy_id": self.policy_id,
            "owner_id": self.owner_id,
            "capability": self.capability,
            "lane": self.lane,
            "source": self.source,
        }

    @property
    def artifact_id(self) -> str:
        return self.provenance_id

    def matches(self, event: Mapping[str, object]) -> bool:
        producer = event["producer"]
        return (
            event["policy_id"] == self.policy_id
            and isinstance(producer, Mapping)
            and producer.get("owner_id") == self.owner_id
            and producer.get("capability") == self.capability
        )

    def verify(self) -> None:
        if self.kind != "lane" or self.provenance_id != canonical_hash(self._body()):
            raise ProvenanceError("lane rule digest does not match its immutable body")


@dataclass(frozen=True, slots=True)
class OwnerAnnotation:
    """A content-addressed topic/entity value bound to one event header."""

    kind: str
    entry_id: str
    value: str
    header: AnnotationHeader
    source: str
    provenance_id: str = field(init=False)

    def __init__(
        self,
        kind: str,
        entry_id: str,
        value: str,
        header: AnnotationHeader,
        *,
        source: str,
    ) -> None:
        if kind not in _ANNOTATION_KINDS:
            raise ProvenanceError("owner annotation kind must be exactly 'topic' or 'entity'")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "entry_id", _digest(entry_id, "annotation entry_id"))
        object.__setattr__(self, "value", _text(value, "annotation value"))
        if not isinstance(header, AnnotationHeader):
            raise ProvenanceError("annotation header must be an AnnotationHeader")
        object.__setattr__(self, "header", header)
        object.__setattr__(self, "source", _text(source, "annotation source"))
        object.__setattr__(self, "provenance_id", canonical_hash(self._body()))

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": "houndd.provenance.v1",
            "kind": self.kind,
            "entry_id": self.entry_id,
            "value": self.value,
            "header": self.header.canonical,
            "source": self.source,
        }

    @property
    def artifact_id(self) -> str:
        return self.provenance_id

    def verify(self) -> None:
        if self.kind not in _ANNOTATION_KINDS or self.provenance_id != canonical_hash(self._body()):
            raise ProvenanceError("owner annotation digest does not match its immutable body")

    def matches_target(self, event: Mapping[str, object]) -> bool:
        try:
            entry_id = _digest(event["entry_id"], "event entry_id")
            policy_id = _text(event["policy_id"], "event policy_id")
            producer = event["producer"]
            if not isinstance(producer, Mapping) or set(producer) != {"owner_id", "capability", "run_id"}:
                raise ProvenanceError("event producer is invalid")
            producer_value = {
                field: _text(producer[field], f"event producer.{field}")
                for field in ("owner_id", "capability", "run_id")
            }
        except (KeyError, TypeError) as error:
            raise ProvenanceError("event annotation target is invalid") from error
        return (
            self.entry_id == entry_id
            and self.header.policy_id == policy_id
            and _producer_value(self.header.producer) == producer_value
        )


@dataclass(frozen=True, slots=True)
class ProvenanceValue:
    """One derived value with its exact artifact source and identity."""

    value: str
    source: str
    provenance_id: str

    def __post_init__(self) -> None:
        _text(self.value, "provenance value")
        _text(self.source, "provenance source")
        _digest(self.provenance_id, "provenance ID")


@dataclass(frozen=True, slots=True)
class EventProvenance:
    """The authorized lane and owner annotations for a canonical event."""

    lane: ProvenanceValue | None
    topics: tuple[ProvenanceValue, ...]
    entities: tuple[ProvenanceValue, ...]

    def __post_init__(self) -> None:
        if self.lane is not None and not isinstance(self.lane, ProvenanceValue):
            raise ProvenanceError("event provenance lane is invalid")
        for label in ("topics", "entities"):
            values = getattr(self, label)
            if not isinstance(values, tuple) or any(not isinstance(value, ProvenanceValue) for value in values):
                raise ProvenanceError(f"event provenance {label} is invalid")
            object.__setattr__(self, label, tuple(sorted(values, key=lambda value: (value.value, value.source, value.provenance_id))))


class ProvenanceProjection:
    """Immutable provenance indexed only in process memory for one query snapshot."""

    __slots__ = ("lane_rules", "owner_annotations", "_rules", "_annotations", "_sealed")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("provenance projection is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        lane_rules: Iterable[LaneRule] = (),
        owner_annotations: Iterable[OwnerAnnotation] = (),
    ) -> None:
        try:
            rules = tuple(lane_rules)
            annotations = tuple(owner_annotations)
        except TypeError as error:
            raise ProvenanceError("provenance artifacts must be iterable") from error
        if any(not isinstance(rule, LaneRule) for rule in rules):
            raise ProvenanceError("provenance lane rules must be LaneRule artifacts")
        if any(not isinstance(annotation, OwnerAnnotation) for annotation in annotations):
            raise ProvenanceError("provenance annotations must be OwnerAnnotation artifacts")
        artifact_ids = [artifact.provenance_id for artifact in (*rules, *annotations)]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ProvenanceError("provenance artifacts contain a duplicate content address")
        for rule in rules:
            rule.verify()
        for annotation in annotations:
            annotation.verify()

        rule_map: dict[tuple[str, str, str], LaneRule] = {}
        for rule in sorted(rules, key=lambda item: item.provenance_id):
            key = (rule.policy_id, rule.owner_id, rule.capability)
            if key in rule_map:
                raise ProvenanceError("conflicting lane rules fail closed")
            rule_map[key] = rule
        annotation_map: dict[tuple[str, str], list[OwnerAnnotation]] = {}
        for annotation in annotations:
            annotation_map.setdefault((annotation.entry_id, annotation.kind), []).append(annotation)
        frozen_annotations = {
            key: tuple(sorted(value, key=lambda item: (item.value, item.source, item.provenance_id)))
            for key, value in annotation_map.items()
        }
        self.lane_rules = tuple(sorted(rules, key=lambda item: item.provenance_id))
        self.owner_annotations = tuple(sorted(annotations, key=lambda item: item.provenance_id))
        self._rules = MappingProxyType(rule_map)
        self._annotations = MappingProxyType(frozen_annotations)
        self._sealed = True

    @staticmethod
    def _entry_id(event: Mapping[str, object]) -> str:
        try:
            return _digest(event["entry_id"], "event entry_id")
        except (KeyError, TypeError) as error:
            raise ProvenanceError("authorized event has no valid entry ID") from error

    @staticmethod
    def _rule_key(event: Mapping[str, object]) -> tuple[str, str, str]:
        try:
            policy_id = _text(event["policy_id"], "event policy_id")
            producer = event["producer"]
            if not isinstance(producer, Mapping):
                raise ProvenanceError("event producer is invalid")
            return (
                policy_id,
                _text(producer["owner_id"], "event producer.owner_id"),
                _text(producer["capability"], "event producer.capability"),
            )
        except (KeyError, TypeError) as error:
            raise ProvenanceError("event producer is invalid") from error

    def _authorized_values(self, scope: PrincipalScope, event: Mapping[str, object], kind: str) -> tuple[ProvenanceValue, ...]:
        entry_id = self._entry_id(event)
        values: list[ProvenanceValue] = []
        for annotation in self._annotations.get((entry_id, kind), ()):
            if not annotation.header.is_authorized(scope):
                continue
            if not annotation.matches_target(event):
                raise ProvenanceError("owner annotation target does not match its authorized event")
            values.append(ProvenanceValue(annotation.value, annotation.source, annotation.provenance_id))
        return tuple(values)

    def project(self, scope: PrincipalScope, event: Mapping[str, object]) -> EventProvenance:
        """Resolve only after the event header has independently authorized."""

        if not isinstance(scope, PrincipalScope) or not isinstance(event, Mapping):
            raise ProvenanceError("provenance projection requires a scope and canonical event mapping")
        if not authorize_event_header(scope, event):
            raise ProvenanceError("event provenance is not authorized")
        rule = self._rules.get(self._rule_key(event))
        lane = None if rule is None else ProvenanceValue(rule.lane, rule.source, rule.provenance_id)
        return EventProvenance(
            lane=lane,
            topics=self._authorized_values(scope, event, "topic"),
            entities=self._authorized_values(scope, event, "entity"),
        )

    resolve = project

    def access_scoped_context_hashes(
        self,
        scope: PrincipalScope,
        events: Iterable[Mapping[str, object]],
    ) -> tuple[str, ...]:
        """Build append-stable journal-prefix commitments in one linear pass."""

        if not isinstance(scope, PrincipalScope):
            raise ProvenanceError("context hashing requires a PrincipalScope")
        try:
            iterable = tuple(events)
        except TypeError as error:
            raise ProvenanceError("context events must be iterable") from error
        previous = canonical_hash(
            {
                "schema_version": "houndd.provenance-context-chain.v2",
                "scope": _scope_value(scope),
            }
        )
        prefixes: list[str] = []
        for event in iterable:
            if not isinstance(event, Mapping):
                raise ProvenanceError("context event is not a mapping")
            if not authorize_event_header(scope, event):
                prefixes.append(previous)
                continue
            provenance = self.project(scope, event)
            visible = (
                {
                    "entry_id": self._entry_id(event),
                    "lane": None if provenance.lane is None else {
                        "value": provenance.lane.value,
                        "source": provenance.lane.source,
                        "provenance_id": provenance.lane.provenance_id,
                    },
                    "topics": [
                        {"value": value.value, "source": value.source, "provenance_id": value.provenance_id}
                        for value in provenance.topics
                    ],
                    "entities": [
                        {"value": value.value, "source": value.source, "provenance_id": value.provenance_id}
                        for value in provenance.entities
                    ],
                }
            )
            previous = canonical_hash(
                {
                    "schema_version": "houndd.provenance-context-chain.v2",
                    "previous": previous,
                    "visible": visible,
                }
            )
            prefixes.append(previous)
        return tuple(prefixes)

    def access_scoped_context_hash(self, scope: PrincipalScope, events: Iterable[Mapping[str, object]]) -> str:
        """Return the final append-stable context commitment for these events."""

        prefixes = self.access_scoped_context_hashes(scope, events)
        if prefixes:
            return prefixes[-1]
        return canonical_hash(
            {
                "schema_version": "houndd.provenance-context-chain.v2",
                "scope": _scope_value(scope),
            }
        )

    context_hash = access_scoped_context_hash


__all__ = [
    "AnnotationHeader",
    "EventProvenance",
    "LaneRule",
    "OwnerAnnotation",
    "ProvenanceError",
    "ProvenanceProjection",
    "ProvenanceValue",
]
