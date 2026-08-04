"""Pure inventory validation and static baseline scanning.

This module intentionally has no Hound service imports and performs no writes or
network access.  It is usable from a copied Hound checkout.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tokenize
from typing import Any, Mapping
import unicodedata


class InventoryError(ValueError):
    """Raised when a manifest or indicator catalog cannot be loaded."""


STAGES = ("freeze_contracts", "import_mirror", "shadow", "migrated", "retired")
OPS = frozenset(
    {
        "ingest.search",
        "ingest.url",
        "ingest.file",
        "ingest.media",
        "transcribe",
        "journal.query",
        "import.record",
    }
)
KINDS = frozenset({"acquisition", "partial_read_client", "consumer_only"})
STATUSES = frozenset({"legacy_path_active", "blocked_contract", "baseline", "shadow", "migrated", "retired"})
EXCLUSIONS = frozenset({"tests", "history", "local_retrieval", "health", "deploy", "publish"})
EXCLUSION_ORDER = ["tests", "history", "local_retrieval", "health", "deploy", "publish"]
PAIRING_RULES = {
    "outbound_transport_requires": ["same_provider_indicator"],
    "evidence_artifact_requires": ["same_provider_indicator"],
    "evidence_artifact_absence": ["hound_id", "record_id", "artifact_id"],
}
ENTRY_FIELDS = frozenset(
    {
        "id",
        "kind",
        "owner",
        "cadence_category",
        "cadence_authority",
        "contract_ref",
        "scan_roots",
        "legacy_paths",
        "target_ops",
        "blocked_reason",
        "wave",
        "stage",
        "status",
        "credential_boundary",
        "evidence",
        "approval_ref",
    }
)
EVIDENCE_FIELDS = frozenset(
    {
        "baseline_scan",
        "stage_ledger",
        "parity",
        "static_no_direct_provider",
        "credential_unset",
        "unix_socket",
        "recovery_drill",
        "full_cycle",
        "legacy_absent",
    }
)
CATALOG_ENTRY_FIELDS = frozenset({"id", "category", "provider", "match"})
CATALOG_CATEGORIES = frozenset(
    {"credential_name", "endpoint", "sdk_import", "client", "outbound_transport", "prompt_skill_acquisition", "evidence_artifact"}
)
MATCH_FIELDS = frozenset({"kind", "value"})
MATCH_KINDS = frozenset({"literal", "token"})
MAX_SCAN_BYTES = 1_048_576
MAX_LINE_BYTES = 16_384
CANONICAL_ROW_DIGEST = "82b634972b4decdfb2055a92776e5434c0991549c5a3cddafd7bd5915a5682fe"
CANONICAL_CATALOG_DIGEST = "c319e49bae8dc4450a904e44fe08b397a93be1778cd0fbde6ef85b66323b6ca4"
MAX_CATALOG_BYTES = 65_536
MAX_INVENTORY_BYTES = 1_048_576
MAX_INDICATORS = 128
MAX_SCAN_ENTRIES = 100_000
MAX_JSON_NESTING = 256
MAX_JSON_NODES = 10_000


def _exact(value: object, expected: type, label: str, errors: list[str]) -> bool:
    if type(value) is not expected:
        errors.append(f"{label} must be exact builtin type {expected.__name__}")
        return False
    return True


def _object(value: object, label: str, fields: frozenset[str], errors: list[str]) -> bool:
    if not _exact(value, dict, label, errors):
        return False
    actual: set[str] = set()
    keys_ok = True
    for key in value:
        if _exact(key, str, f"{label} key", errors):
            actual.add(key)
        else:
            keys_ok = False
    missing = fields - actual
    extra = actual - fields
    if missing:
        errors.append(f"{label} missing fields: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} field closure violated: {', '.join(sorted(extra))}")
    return keys_ok and not missing and not extra


def _exact_string_list(value: object, label: str, errors: list[str]) -> bool:
    if not _exact(value, list, label, errors):
        return False
    valid = True
    for index, item in enumerate(value):
        if not _exact(item, str, f"{label}[{index}]", errors):
            valid = False
    return valid


def _exact_json_graph(value: object) -> bool:
    if type(value) in {str, int, bool, type(None)}:
        return True
    if type(value) is list:
        return all(_exact_json_graph(item) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _exact_json_graph(item) for key, item in value.items())
    return False


def _has_path_control(value: str) -> bool:
    return any(unicodedata.category(char).startswith("C") for char in value)


def _path_ok(path: object, label: str, errors: list[str]) -> bool:
    if not _exact(path, str, label, errors):
        return False
    if not path:
        errors.append(f"{label} must be a non-empty single path")
        return False
    if _has_path_control(path):
        errors.append(f"{label} contains control characters")
        return False
    if any(char in path for char in "*?[]"):
        errors.append(f"{label} uses a broad/glob path")
        return False
    if Path(path).is_absolute():
        errors.append(f"{label} must be workspace-relative")
        return False
    parts = Path(path).parts
    if not parts or any(part in {".", ".."} for part in parts) or path in {"/", ".", ".."}:
        errors.append(f"{label} is broad or not bounded")
        return False
    return True


def _validate_evidence(value: object, label: str, errors: list[str]) -> None:
    if not _object(value, label, EVIDENCE_FIELDS, errors):
        return
    pointers: dict[str, str] = {}
    for key, pointer in value.items():
        if pointer is not None and not _exact(pointer, str, f"{label}.{key}", errors):
            continue
        if type(pointer) is str:
            _path_ok(pointer, f"{label}.{key}", errors)
        if type(pointer) is str:
            if pointer in pointers:
                errors.append(f"{label} contains duplicate evidence path: {pointer}")
            pointers[pointer] = key


def _forbidden_manifest_values(value: object, label: str, errors: list[str]) -> None:
    if type(value) is str:
        if re.search(r"(?i)\b(?:cron|systemd\s+timer|oncalendar|ontimer|schedule\s*=)", value) or re.fullmatch(r"\s*[0-9*/,-]+(?:\s+[0-9*/,-]+){4}\s*", value):
            errors.append(f"{label} contains timer/cron truth")
        if re.search(r"(?i)(?:api[_-]?key|access[_-]?token|bearer|secret)\s*[:=]\s*(?!null\b)[A-Za-z0-9_\-/.]{4,}", value) or re.search(r"(?:sk-|ghp_|AIza)[A-Za-z0-9_-]{8,}", value):
            errors.append(f"{label} contains secret material")
    elif type(value) is dict:
        for key, child in value.items():
            _forbidden_manifest_values(child, f"{label}.{key}", errors)
    elif type(value) is list:
        for index, child in enumerate(value):
            _forbidden_manifest_values(child, f"{label}[{index}]", errors)


def validate_catalog(catalog: object) -> list[str]:
    errors: list[str] = []
    _forbidden_manifest_values(catalog, "catalog", errors)
    if not _object(catalog, "catalog", frozenset({"schema_version", "pairing_rules", "indicators"}), errors):
        return errors
    schema_ok = _exact(catalog["schema_version"], str, "catalog.schema_version", errors)
    if schema_ok and catalog["schema_version"] != "hound.migration.provider-indicators.v1":
        errors.append("catalog.schema_version is not the versioned provider catalog")
    if _object(catalog["pairing_rules"], "catalog.pairing_rules", frozenset(PAIRING_RULES), errors):
        pairing_ok = True
        for key, rule in catalog["pairing_rules"].items():
            _exact(key, str, "catalog.pairing_rules key", errors)
            if type(rule) is list:
                for index, value in enumerate(rule):
                    if not _exact(value, str, f"catalog.pairing_rules.{key}[{index}]", errors):
                        pairing_ok = False
            elif not _exact(rule, list, f"catalog.pairing_rules.{key}", errors):
                pairing_ok = False
        if pairing_ok and catalog["pairing_rules"] != PAIRING_RULES:
            errors.append("catalog.pairing_rules is not the exact provider-pairing contract")
    if _exact(catalog["indicators"], list, "catalog.indicators", errors):
        seen: set[str] = set()
        for index, entry in enumerate(catalog["indicators"]):
            label = f"catalog.indicators[{index}]"
            if not _object(entry, label, CATALOG_ENTRY_FIELDS, errors):
                continue
            for key in ("id", "category", "provider"):
                _exact(entry[key], str, f"{label}.{key}", errors)
            if _object(entry["match"], f"{label}.match", MATCH_FIELDS, errors):
                kind_ok = _exact(entry["match"]["kind"], str, f"{label}.match.kind", errors)
                value_ok = _exact(entry["match"]["value"], str, f"{label}.match.value", errors)
                if kind_ok and entry["match"]["kind"] not in MATCH_KINDS:
                    errors.append(f"{label}.match.kind must be literal or token")
                if value_ok and not entry["match"]["value"]:
                    errors.append(f"{label}.match.value must be non-empty")
            if type(entry["id"]) is str:
                if not entry["id"]:
                    errors.append(f"{label}.id must be non-empty")
                if entry["id"] in seen:
                    errors.append(f"duplicate catalog indicator id: {entry['id']}")
                seen.add(entry["id"])
            if type(entry["category"]) is str and (not entry["category"] or entry["category"] not in CATALOG_CATEGORIES):
                errors.append(f"unknown catalog category: {entry['category']}")
            if type(entry["provider"]) is str and (not entry["provider"] or entry["provider"].lower() in {"provider", "paired", "browser", "generic"}):
                errors.append(f"catalog indicator {entry['id']} has a generic provider")
            if type(entry["match"]) is dict and type(entry["match"].get("value")) is str and entry["match"]["value"].lower() in {"http", "https", "http://", "https://"}:
                errors.append(f"catalog indicator {entry['id']} is a blanket HTTP pattern")
            for field in ("id", "provider"):
                if type(entry[field]) is str and (not entry[field] or len(entry[field]) > 128 or any(ord(c) < 32 for c in entry[field])):
                    errors.append(f"{label}.{field} is unbounded or contains control characters")
            if type(entry["match"]) is dict and type(entry["match"].get("value")) is str and (len(entry["match"]["value"]) > 256 or any(ord(c) < 32 for c in entry["match"]["value"])):
                errors.append(f"{label}.match.value is unbounded or contains control characters")
        if len(catalog["indicators"]) > MAX_INDICATORS:
            errors.append("catalog.indicators exceeds maximum size")
        if not errors and hashlib.sha256(json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != CANONICAL_CATALOG_DIGEST:
            errors.append("catalog must match the exact approved provider indicator set")
    return errors


def validate_inventory(inventory: object, *, require_paths: bool = False, workspace: Path | None = None) -> list[str]:
    """Return all manifest errors; no error is suppressed as a baseline."""

    errors: list[str] = []
    _forbidden_manifest_values(inventory, "inventory", errors)
    top_fields = frozenset({"schema_version", "stage_order", "allowed_kinds", "allowed_statuses", "allowed_exclusions", "adapter_allowlist", "consumers"})
    if not _object(inventory, "inventory", top_fields, errors):
        return errors
    schema_ok = _exact(inventory["schema_version"], str, "inventory.schema_version", errors)
    if schema_ok and inventory["schema_version"] != "hound.migration.consumer-inventory.v1":
        errors.append("inventory.schema_version is not the canonical version")
    collections = {
        key: _exact(inventory[key], expected, f"inventory.{key}", errors)
        for key, expected in (
            ("stage_order", list),
            ("allowed_kinds", list),
            ("allowed_statuses", list),
            ("allowed_exclusions", list),
            ("adapter_allowlist", list),
            ("consumers", list),
        )
    }
    string_collections: dict[str, bool] = {}
    for key in ("stage_order", "allowed_kinds", "allowed_statuses", "allowed_exclusions", "adapter_allowlist"):
        string_collections[key] = collections[key] and _exact_string_list(inventory[key], f"inventory.{key}", errors)
    if string_collections["stage_order"] and inventory["stage_order"] != list(STAGES):
        errors.append("stage_order must preserve the exact migration order")
    if string_collections["allowed_exclusions"] and inventory["allowed_exclusions"] != EXCLUSION_ORDER:
        errors.append("allowed_exclusions must be the exact HSP-18 exclusion set")
    if string_collections["allowed_kinds"] and set(inventory["allowed_kinds"]) != KINDS:
        errors.append("allowed_kinds is not exact")
    if string_collections["allowed_statuses"] and set(inventory["allowed_statuses"]) != STATUSES:
        errors.append("allowed_statuses is not exact")
    exact_adapters = ["repos/hound/src/hound_web_adapters/exa.py", "repos/hound/src/hound_web_adapters/firecrawl.py", "repos/hound/src/hound_web_adapters/camofox.py", "repos/hound/src/hound_web_adapters/_http.py"]
    if string_collections["adapter_allowlist"] and inventory["adapter_allowlist"] != exact_adapters:
        errors.append("adapter_allowlist must be the exact four adapter files")

    consumers = inventory["consumers"]
    if not collections["consumers"]:
        return errors
    # Owner decisions 2026-08-04 (GOALIE D1/D3/D4): benefits-legacy dropped
    # from scope; gmail-newsletters-attachments and helm-external-ingestion
    # deferred — re-entry is a new owner decision, not an edit here.
    expected_ids = {
        "pulse", "benefits-radar", "wiki-refresh", "intel-refresh", "civic-policy-radar",
        "radar-curation", "manual-web", "manual-x", "youtube-transcription",
        "signal-daily", "workpad-intake-ledger", "gc-gtm-crm",
    }
    seen: set[str] = set()
    stage_status = {
        "freeze_contracts": frozenset({"legacy_path_active", "blocked_contract", "baseline"}),
        "import_mirror": frozenset({"baseline"}),
        "shadow": frozenset({"shadow"}),
        "migrated": frozenset({"migrated"}),
        "retired": frozenset({"retired"}),
    }
    staged_items: list[tuple[dict[str, Any], int]] = []
    for index, item in enumerate(consumers):
        label = f"consumers[{index}]"
        if not _object(item, label, ENTRY_FIELDS, errors):
            continue
        identifier = item["id"]
        if not _exact(identifier, str, f"{label}.id", errors):
            continue
        if identifier in seen:
            errors.append(f"duplicate consumer id: {identifier}")
        seen.add(identifier)
        for key in ("kind", "owner", "cadence_category", "cadence_authority", "contract_ref", "credential_boundary", "stage", "status"):
            _exact(item[key], str, f"{label}.{key}", errors)
            if type(item[key]) is str and not item[key]:
                errors.append(f"{label}.{key} must be non-empty")
        if type(item["contract_ref"]) is str and ("/" in item["contract_ref"] or _has_path_control(item["contract_ref"])):
            _path_ok(item["contract_ref"], f"{label}.contract_ref", errors)
        if type(item["kind"]) is str and item["kind"] not in KINDS:
            errors.append(f"{label}.kind is not allowed")
        target_ops = item["target_ops"] if type(item["target_ops"]) is list else None
        if identifier == "workpad-intake-ledger":
            if type(item["kind"]) is not str or type(item["credential_boundary"]) is not str or target_ops is None or item["kind"] != "partial_read_client" or target_ops != ["journal.query"] or item["credential_boundary"] != "no_provider_credentials_or_bypass":
                errors.append(f"{label} must remain the restricted partial journal-read consumer")
        if identifier == "gc-gtm-crm":
            if type(item["kind"]) is not str or type(item["credential_boundary"]) is not str or target_ops is None or item["kind"] != "consumer_only" or target_ops != ["journal.query"] or item["credential_boundary"] != "no_provider_credentials_or_bypass":
                errors.append(f"{label} must remain the restricted journal-only CRM consumer")
        if type(item["stage"]) is str and item["stage"] not in STAGES:
            errors.append(f"{label}.stage is not allowed")
        if type(item["status"]) is str and item["status"] not in STATUSES:
            errors.append(f"{label}.status is not allowed")
        # Stages advance with the stage ledger (2026-08-04 replan): a row's
        # status must belong to its stage, evidence may only be named at or
        # past the stage that requires it, and approval_ref exists only from
        # migrated onward (HSP-22 — the ledger walk verifies the binding).
        stage = item["stage"] if type(item["stage"]) is str else None
        stage_statuses = {
            "freeze_contracts": {"legacy_path_active", "blocked_contract", "baseline"},
            "import_mirror": {"baseline"},
            "shadow": {"shadow"},
            "migrated": {"migrated"},
            "retired": {"retired"},
        }
        if stage in stage_statuses and type(item["status"]) is str and item["status"] not in stage_statuses[stage]:
            errors.append(f"{label}.status does not belong to its stage")
        if stage == "freeze_contracts":
            if type(item.get("evidence")) is dict and any(pointer is not None for pointer in item["evidence"].values()):
                errors.append(f"{label}.evidence must be null before import_mirror")
        if stage in {"freeze_contracts", "import_mirror", "shadow", None}:
            if item["approval_ref"] is not None:
                errors.append(f"{label}.approval_ref exists only from migrated onward")
        elif item["approval_ref"] is not None and not _exact(item["approval_ref"], str, f"{label}.approval_ref", errors):
            pass
        _exact(item["blocked_reason"], (str if item["blocked_reason"] is not None else type(None)), f"{label}.blocked_reason", errors)
        if type(item["wave"]) is not int or item["wave"] < 2:
            errors.append(f"{label}.wave must be an integer migration wave")
        for key in ("scan_roots", "legacy_paths", "target_ops"):
            if _exact(item[key], list, f"{label}.{key}", errors):
                values = item[key]
                if len(values) != len(set(values)) if all(type(v) is str for v in values) else True:
                    errors.append(f"{label}.{key} contains duplicate paths/values")
                list_paths: set[str] = set()
                for path_index, path in enumerate(values):
                    if key != "target_ops":
                        _path_ok(path, f"{label}.{key}[{path_index}]", errors)
                        if type(path) is str:
                            if path in list_paths:
                                errors.append(f"{label} contains duplicate path: {path}")
                            list_paths.add(path)
                    elif not _exact(path, str, f"{label}.target_ops[{path_index}]", errors) or path not in OPS:
                        errors.append(f"{label} has unknown target operation: {path}")
        if type(item["target_ops"]) is list and not item["target_ops"] and not item["blocked_reason"]:
            errors.append(f"{label} needs target_ops or blocked_reason")
        evidence = item["evidence"] if type(item["evidence"]) is dict else {}
        if type(item["stage"]) is str and item["stage"] == "migrated":
            required = ("static_no_direct_provider", "credential_unset", "unix_socket", "recovery_drill", "full_cycle")
            for key in required:
                if type(evidence.get(key)) is not str:
                    errors.append(f"{label}.evidence.{key} is required for migrated stage")
        if type(item["stage"]) is str and item["stage"] == "retired":
            for key in ("static_no_direct_provider", "credential_unset", "unix_socket", "recovery_drill", "full_cycle", "legacy_absent"):
                if type(evidence.get(key)) is not str:
                    errors.append(f"{label}.evidence.{key} is required for retired stage")
        _validate_evidence(item["evidence"], f"{label}.evidence", errors)
        if type(item["stage"]) is str and type(item["status"]) is str:
            if item["status"] not in stage_status.get(item["stage"], frozenset()):
                errors.append(f"{label} has invalid stage/status combination")
            if item["status"] == "blocked_contract" and item["stage"] != "freeze_contracts":
                errors.append(f"{label} blocked_contract cannot advance")
            if item["stage"] == "shadow":
                if identifier not in {"pulse", "benefits-radar"}:
                    errors.append(f"{label} shadow is limited to Pulse and Benefits radar")
                if type(evidence.get("parity")) is not str:
                    errors.append(f"{label}.evidence.parity is required for shadow")
            if item["stage"] in {"migrated", "retired"} and item["kind"] == "acquisition":
                if item["credential_boundary"] != "provider_credentials_owned_only_by_houndd_after_cutover":
                    errors.append(f"{label} migrated acquisition has an invalid credential boundary")
            staged_items.append((item, STAGES.index(item["stage"]) if item["stage"] in STAGES else -1))
        if workspace is not None and require_paths:
            for key in ("scan_roots", "legacy_paths"):
                if type(item[key]) is not list:
                    continue
                for path in item[key]:
                    candidate = Path(path) if Path(path).is_absolute() else workspace / path
                    problem = _path_problem(candidate, workspace)
                    if problem:
                        errors.append(f"{label}.{key} path does not exist or is unsafe ({problem}) in workspace: {path}")
                    elif key == "scan_roots" and not candidate.is_file() and not candidate.is_dir():
                        errors.append(f"{label}.scan_roots path is not a file or directory: {path}")
                    elif key == "legacy_paths" and not candidate.is_file():
                        errors.append(f"{label}.legacy_paths path is not a file: {path}")
            contract = item["contract_ref"]
            if type(contract) is str and "/" in contract:
                candidate = Path(contract) if Path(contract).is_absolute() else workspace / contract
                problem = _path_problem(candidate, workspace)
                if problem or not candidate.is_file():
                    errors.append(f"{label}.contract_ref path {problem or 'not a file'} in workspace: {contract}")
            if type(item["evidence"]) is dict:
                for evidence_key, pointer in item["evidence"].items():
                    if type(pointer) is str:
                        candidate = workspace / pointer
                        problem = _path_problem(candidate, workspace)
                        if problem or not candidate.is_file():
                            errors.append(f"{label}.evidence.{evidence_key} path {problem or 'not a file'} in workspace: {pointer}")
    missing = expected_ids - seen
    extra = seen - expected_ids
    if missing:
        errors.append(f"consumer ID set missing: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"consumer ID set has unexpected IDs: {', '.join(sorted(extra))}")
    if len(consumers) != len(expected_ids):
        errors.append(f"consumer ID set must contain exactly {len(expected_ids)} entries")
    if _exact_json_graph(consumers):
        closure = [item for item in consumers if type(item) is dict]
        digest = hashlib.sha256(json.dumps(closure, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != CANONICAL_ROW_DIGEST:
            errors.append("consumer rows must match the exact canonical closure")
    else:
        errors.append("consumer rows must match the exact canonical closure")
    for item, stage_index in staged_items:
        if stage_index <= 0:
            continue
        for prior, prior_index in staged_items:
            if prior["wave"] < item["wave"] and prior_index < stage_index:
                errors.append(f"{item['id']} cannot advance wave {item['wave']} past prior wave {prior['id']}")
    return errors


def _json_text_problem(text: str) -> str | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for char in text:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == '"':
            quote = char
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                return "JSON nesting exceeds maximum depth"
        elif char in "]}":
            depth -= 1
    return None


def _json_graph_problem(value: object) -> str | None:
    nodes = 0
    pending = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            return "JSON exceeds maximum node count"
        if depth > MAX_JSON_NESTING:
            return "JSON nesting exceeds maximum depth"
        if type(current) is dict:
            pending.extend((child, depth + 1) for child in current.values())
        elif type(current) is list:
            pending.extend((child, depth + 1) for child in current)
    return None


def load_inventory(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_INVENTORY_BYTES:
            raise InventoryError(f"inventory exceeds {MAX_INVENTORY_BYTES} bytes")
        text = raw.decode("utf-8")
        if problem := _json_text_problem(text):
            raise InventoryError(f"cannot load inventory {path}: {problem}")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except RecursionError as exc:
        raise InventoryError(f"cannot load inventory {path}: JSON nesting exceeds maximum depth") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot load inventory {path}: {exc}") from exc
    if problem := _json_graph_problem(value):
        raise InventoryError(f"cannot load inventory {path}: {problem}")
    if type(value) is not dict:
        raise InventoryError("inventory JSON must be an object")
    return value


def load_catalog(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_CATALOG_BYTES:
            raise InventoryError(f"provider catalog exceeds {MAX_CATALOG_BYTES} bytes")
        text = raw.decode("utf-8")
        if problem := _json_text_problem(text):
            raise InventoryError(f"cannot load provider catalog {path}: {problem}")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except RecursionError as exc:
        raise InventoryError(f"cannot load provider catalog {path}: JSON nesting exceeds maximum depth") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot load provider catalog {path}: {exc}") from exc
    if problem := _json_graph_problem(value):
        raise InventoryError(f"cannot load provider catalog {path}: {problem}")
    if type(value) is not dict:
        raise InventoryError("provider catalog JSON must be an object")
    errors = validate_catalog(value)
    if errors:
        raise InventoryError("; ".join(errors))
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class ScanResult:
    findings: list[dict[str, Any]]
    baseline_findings: list[dict[str, Any]]
    failures: list[str]
    coverage: list[dict[str, Any]]


_UNKNOWN_CREDENTIAL = re.compile(r"\b[A-Z][A-Z0-9_]*(?:API_KEY|ACCESS_TOKEN|BEARER_TOKEN|SECRET_KEY)\b")
_UNKNOWN_TOKEN = re.compile(r"\b[A-Z][A-Z0-9_]*_TOKEN\b")
_LOCAL_TOKEN_PARTS = frozenset({"CANCEL", "CONTINUATION", "CSRF", "CURSOR", "FORM", "LOCAL", "NEXT", "PAGE", "PAGINATION", "PREV", "PROCESS", "REQUEST", "SESSION", "STATE", "WORKFLOW"})
_UNKNOWN_IMPORT = re.compile(r"\b(?:import|from)\s+(?P<candidate>[A-Za-z_][\w.]*(?:provider|client|sdk|api)[\w.]*)\b", re.I)
_UNKNOWN_CLIENT = re.compile(r"\b(?P<candidate>[A-Z][A-Za-z0-9]*?(?:Client|SDK|Api|Service)|[A-Za-z_]\w*\.(?:Client|SDK|Api|Service))\b")
_UNKNOWN_ENDPOINT = re.compile(r"\b(?P<candidate>[A-Z][A-Z0-9_]*(?:ENDPOINT|BASE_URL|API_URL)|[a-z][a-z0-9_]*(?:endpoint|base_url|api_url))\s*[:=]\s*['\"]?https?://", re.I)
# A raw provider URL passed directly to a requests transport is provider
# specific when it uses the conventional ``api.<provider>`` host form. Keep
# this deliberately narrow: arbitrary URLs and generic transports stay out.
_TRANSPORT_CALL = re.compile(r"\b(?:(?:requests|httpx)\.(?:get|post|put|patch|delete|request)|urllib\.request\.urlopen)\s*\(", re.I)
_RAW_API_HOST = re.compile(r'''['"]https?://(?P<candidate>api\.[a-z0-9-]+\.[a-z]{2,})(?:[/:?'"]|$)''', re.I)
_TRANSPORT_METHODS = frozenset({"get", "post", "put", "patch", "delete", "request"})
MAX_TRANSPORT_ALIASES = 32
MAX_TRANSPORT_CALLS = 32
MAX_TRANSPORT_ASSIGNMENTS = 32
MAX_TRANSPORT_CALL_BYTES = 16_384
MAX_PYTHON_TRANSPORT_TOKENS = 32_768
_PYTHON_TRANSPORT_CONSTRUCTORS = frozenset({"requests.Session", "httpx.Client", "httpx.AsyncClient", "urllib.request.build_opener"})
_PYTHON_TRANSPORT_IMPORTS = frozenset({"Session", "Client", "AsyncClient", "build_opener", "urlopen", "Request"})
_RAW_API_HOST_VALUE = re.compile(r"^https?://(?P<candidate>api\.[a-z0-9-]+\.[a-z]{2,})(?:[/:?]|$)", re.I)


def _normalise_transport_aliases(text: str) -> tuple[str, str | None]:
    """Expand only supported import aliases without treating arbitrary calls as HTTP."""

    module_aliases: dict[str, str] = {}
    call_aliases: dict[str, str] = {}
    for match in re.finditer(r"(?m)^\s*import\s+(requests|httpx|urllib\.request)\s+as\s+([A-Za-z_]\w*)\b", text):
        module, alias = match.groups()
        module_aliases[alias] = module
    for match in re.finditer(r"(?m)^\s*from\s+(requests|httpx|urllib\.request)\s+import\s+([^\n#]+)", text):
        module, imports = match.groups()
        for item in imports.split(","):
            parts = item.strip().split()
            if not parts:
                continue
            imported = parts[0]
            alias = parts[2] if len(parts) == 3 and parts[1] == "as" else imported
            supported = (module in {"requests", "httpx"} and imported in _TRANSPORT_METHODS) or (module == "urllib.request" and imported == "urlopen")
            if supported:
                call_aliases[alias] = f"{module}.{imported}"
    if len(module_aliases) + len(call_aliases) > MAX_TRANSPORT_ALIASES:
        return text, f"transport aliases exceeds {MAX_TRANSPORT_ALIASES}"
    normalised = text
    if module_aliases:
        aliases = "|".join(re.escape(alias) for alias in sorted(module_aliases, key=len, reverse=True))
        normalised = re.sub(rf"\b(?P<alias>{aliases})\.", lambda match: f"{module_aliases[match.group('alias')]}.", normalised)
    if call_aliases:
        aliases = "|".join(re.escape(alias) for alias in sorted(call_aliases, key=len, reverse=True))
        normalised = re.sub(rf"(?<![.\w])(?P<alias>{aliases})(?=\s*\()", lambda match: call_aliases[match.group("alias")], normalised)
    return normalised, None


def _text_transport_api_hosts(text: str) -> tuple[dict[int, set[str]], dict[int, set[str]], str | None]:
    """Return literal API-host candidates keyed to their bounded call's line."""

    source, problem = _normalise_transport_aliases(text)
    if problem:
        return {}, {}, problem
    candidates: dict[int, set[str]] = {}
    for count, match in enumerate(_TRANSPORT_CALL.finditer(source), 1):
        if count > MAX_TRANSPORT_CALLS:
            return {}, {}, f"transport calls exceeds {MAX_TRANSPORT_CALLS}"
        start = match.end()
        limit = min(len(source), start + MAX_TRANSPORT_CALL_BYTES)
        depth = 1
        quote: str | None = None
        escaped = False
        end = limit
        closed = False
        for index in range(start, limit):
            char = source[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = index
                    closed = True
                    break
        if not closed and limit < len(source):
            return {}, {}, f"transport call exceeds {MAX_TRANSPORT_CALL_BYTES} bytes"
        line_number = source.count("\n", 0, match.start()) + 1
        for host in _RAW_API_HOST.finditer(source[start:end]):
            candidates.setdefault(line_number, set()).add(host.group("candidate"))
    return candidates, {}, None


def _python_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[int, set[str]], str | None]:
    aliases: dict[str, str] = {}
    declarations: dict[int, set[str]] = {}

    def add(imported: ast.alias, canonical: str, line: int) -> None:
        alias = imported.asname or imported.name
        aliases[alias] = canonical
        declarations.setdefault(getattr(imported, "lineno", line), set()).update({alias, imported.name})

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name in {"requests", "httpx", "urllib.request"} and imported.asname:
                    add(imported, imported.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            if module == "urllib":
                for imported in node.names:
                    if imported.name == "request":
                        add(imported, "urllib.request", node.lineno)
            elif module in {"requests", "httpx", "urllib.request"}:
                for imported in node.names:
                    if imported.name in _TRANSPORT_METHODS or imported.name in _PYTHON_TRANSPORT_IMPORTS:
                        add(imported, f"{module}.{imported.name}", node.lineno)
        if len(aliases) > MAX_TRANSPORT_ALIASES:
            return {}, {}, f"transport aliases exceeds {MAX_TRANSPORT_ALIASES}"
    return aliases, declarations, None


def _python_origin(node: ast.AST, aliases: Mapping[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id if node.id in {"requests", "httpx", "urllib"} else None)
    if isinstance(node, ast.Attribute):
        parent = _python_origin(node.value, aliases)
        return None if parent is None else f"{parent}.{node.attr}"
    if isinstance(node, ast.Call):
        origin = _python_origin(node.func, aliases)
        return f"{origin}()" if origin in _PYTHON_TRANSPORT_CONSTRUCTORS else None
    return None


def _python_spelled_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_spelled_name(node.value)
        return None if parent is None else f"{parent}.{node.attr}"
    return None


def _python_transport_call(origin: str | None) -> bool:
    if origin in {f"requests.{method}" for method in _TRANSPORT_METHODS} | {f"httpx.{method}" for method in _TRANSPORT_METHODS} | {"urllib.request.urlopen"}:
        return True
    if origin is None:
        return False
    if origin.startswith(("requests.Session().", "httpx.Client().", "httpx.AsyncClient().")):
        return origin.rsplit(".", 1)[-1] in _TRANSPORT_METHODS
    return origin == "urllib.request.build_opener().open"


def _python_transport_api_hosts(text: str) -> tuple[dict[int, set[str]], dict[int, set[str]], str | None]:
    try:
        token_count = 0
        for token_count, _token in enumerate(tokenize.generate_tokens(io.StringIO(text).readline), 1):
            if token_count > MAX_PYTHON_TRANSPORT_TOKENS:
                return {}, {}, f"python transport tokens exceeds {MAX_PYTHON_TRANSPORT_TOKENS}"
        tree = ast.parse(text)
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return {}, {}, "python transport parse error"
    aliases, trusted_names, problem = _python_aliases(tree)
    if problem:
        return {}, {}, problem
    candidates: dict[int, set[str]] = {}
    origins = dict(aliases)
    invalidated: set[str] = set()
    assignments = 0
    calls = 0

    def bind(target: ast.Name, value: ast.AST, line: int) -> str | None:
        nonlocal assignments
        origin = _python_origin(value, origins)
        if origin in {f"{constructor}()" for constructor in _PYTHON_TRANSPORT_CONSTRUCTORS}:
            assignments += 1
            if assignments > MAX_TRANSPORT_ASSIGNMENTS:
                return f"transport assignments exceeds {MAX_TRANSPORT_ASSIGNMENTS}"
            origins[target.id] = origin
            invalidated.discard(target.id)
            bound_names = {target.id, origin[:-2], origin[:-2].rsplit(".", 1)[-1]}
            if isinstance(value, ast.Call):
                if spelled := _python_spelled_name(value.func):
                    bound_names.add(spelled)
            bound_names.update(child.id for child in ast.walk(value) if isinstance(child, ast.Name) and child.id in origins)
            trusted_names.setdefault(line, set()).update(bound_names)
        elif target.id in origins:
            assignments += 1
            if assignments > MAX_TRANSPORT_ASSIGNMENTS:
                return f"transport assignments exceeds {MAX_TRANSPORT_ASSIGNMENTS}"
            origins.pop(target.id, None)
            invalidated.add(target.id)
        return None

    events = sorted(
        (node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.With, ast.AsyncWith, ast.Call))),
        key=lambda node: (node.lineno, node.col_offset, 0 if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.With, ast.AsyncWith)) else 1),
    )
    for node in events:
        target: ast.Name | None = None
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target, value = node.target, node.value
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            if node.target.id in origins:
                assignments += 1
                if assignments > MAX_TRANSPORT_ASSIGNMENTS:
                    return {}, {}, f"transport assignments exceeds {MAX_TRANSPORT_ASSIGNMENTS}"
                origins.pop(node.target.id, None)
                invalidated.add(node.target.id)
            continue
        if target is not None and value is not None:
            if problem := bind(target, value, node.lineno):
                return {}, {}, problem
            continue
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name):
                    if problem := bind(item.optional_vars, item.context_expr, node.lineno):
                        return {}, {}, problem
            continue
        origin = _python_origin(node.func, origins) if isinstance(node, ast.Call) else None
        stale_transport = (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in invalidated
            and node.func.attr in _TRANSPORT_METHODS
        )
        if not isinstance(node, ast.Call) or not (_python_transport_call(origin) or stale_transport):
            continue
        calls += 1
        if calls > MAX_TRANSPORT_CALLS:
            return {}, {}, f"transport calls exceeds {MAX_TRANSPORT_CALLS}"
        call_names = {child.id for child in ast.walk(node.func) if isinstance(child, ast.Name) and child.id in origins}
        if call_names:
            trusted_names.setdefault(node.lineno, set()).update(call_names)
        for child in ast.walk(node):
            if not isinstance(child, ast.Constant) or type(child.value) is not str:
                continue
            match = _RAW_API_HOST_VALUE.match(child.value)
            if match:
                candidates.setdefault(node.lineno, set()).add(match.group("candidate"))
    return candidates, trusted_names, None


def _transport_api_hosts(text: str, *, python: bool) -> tuple[dict[int, set[str]], dict[int, set[str]], str | None]:
    if python:
        return _python_transport_api_hosts(text)
    return _text_transport_api_hosts(text)


def _provider_unknown_candidates(
    text: str, raw_api_hosts: set[str] | None = None, trusted_transport_names: set[str] | None = None
) -> list[str]:
    candidates: list[str] = []
    trusted = trusted_transport_names or set()

    def add(value: str) -> None:
        if value not in candidates:
            candidates.append(value)

    for match in _UNKNOWN_CREDENTIAL.finditer(text):
        if match.group(0) not in trusted:
            add(match.group(0))
    for match in _UNKNOWN_TOKEN.finditer(text):
        stem = match.group(0).split("_")[:-1]
        if match.group(0) not in trusted and (not stem or not set(stem) <= _LOCAL_TOKEN_PARTS):
            add(match.group(0))
    for pattern in (_UNKNOWN_IMPORT, _UNKNOWN_CLIENT, _UNKNOWN_ENDPOINT):
        for match in pattern.finditer(text):
            candidate = match.group("candidate")
            if candidate not in trusted:
                add(candidate)
    for host in raw_api_hosts or set():
        add(host)
    return candidates


def _known_provider_indicator(indicator: Mapping[str, Any], candidate: str) -> bool:
    return indicator["category"] not in {"outbound_transport", "evidence_artifact"} and _matches(indicator, candidate)


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _excluded(path: Path) -> bool:
    return any(part in EXCLUSIONS for part in path.parts)


def _resolved_manifest_path(value: str, workspace: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else workspace / path


def _matches(indicator: Mapping[str, Any], text: str) -> bool:
    match = indicator["match"]
    if match["kind"] == "literal":
        return match["value"] in text
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(match["value"]) + r"(?![A-Za-z0-9_])", text) is not None


def _path_problem(path: Path, workspace: Path) -> str | None:
    if _has_path_control(str(path)):
        return "contains control characters"
    workspace = workspace.resolve()
    raw = path if path.is_absolute() else workspace / path
    lexical = Path(raw.anchor)
    for part in raw.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            if lexical != Path(raw.anchor):
                lexical = lexical.parent
            continue
        lexical /= part
    if not _under(lexical, workspace):
        return "escapes workspace"
    current = lexical
    while current != workspace:
        try:
            current.lstat()
        except OSError:
            return "missing or unreadable"
        if current.is_symlink():
            return "uses symlink"
        if current.parent == current:
            return "escapes workspace"
        current = current.parent
    try:
        resolved = lexical.resolve(strict=True)
    except OSError:
        return "missing or unreadable"
    if not _under(resolved, workspace):
        return "escapes workspace"
    return None


def _scan_candidates(root: Path, workspace: Path, failures: list[str]) -> list[Path]:
    """Walk a declared root explicitly so unreadable directories cannot vanish."""

    if root.is_file():
        return [root]
    candidates: list[Path] = []
    pending = [root]
    entries_seen = 0
    while pending:
        directory = pending.pop()
        relative_directory = directory.relative_to(workspace)
        try:
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    if entries_seen >= MAX_SCAN_ENTRIES:
                        failures.append(f"scan directory {relative_directory}: exceeds {MAX_SCAN_ENTRIES} entries")
                        return candidates
                    entries_seen += 1
                    entries.append(entry)
        except OSError:
            failures.append(f"scan directory {relative_directory}: unreadable")
            continue
        for entry in sorted(entries, key=lambda entry: entry.name):
            path = Path(entry.path)
            problem = _path_problem(path, workspace)
            if problem:
                failures.append(f"scan file {path.relative_to(workspace)}: {problem}")
                continue
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            else:
                candidates.append(path)
    return candidates


def scan_workspace(inventory: Mapping[str, Any], catalog: Mapping[str, Any], workspace: Path) -> ScanResult:
    """Scan only bounded roots present in *workspace* and never mutate it."""

    errors = validate_inventory(inventory)
    errors.extend(validate_catalog(catalog))
    if errors:
        return ScanResult([], [], errors, [])
    return _scan_workspace(inventory, catalog, workspace)


def _scan_workspace(inventory: Mapping[str, Any], catalog: Mapping[str, Any], workspace: Path) -> ScanResult:
    """Internal scanner for isolated parser fixtures after contract validation."""

    workspace = workspace.resolve()
    findings: list[dict[str, Any]] = []
    baseline: list[dict[str, Any]] = []
    failures: list[str] = []
    coverage: list[dict[str, Any]] = []
    for consumer in inventory["consumers"]:
        legacy = {_resolved_manifest_path(path, workspace).resolve() for path in consumer["legacy_paths"]}
        roots: list[Path] = []
        for raw_root in consumer["scan_roots"]:
            requested = _resolved_manifest_path(raw_root, workspace)
            problem = _path_problem(requested, workspace)
            if problem:
                failures.append(f"scan root {raw_root}: {problem}")
                continue
            root = requested.resolve()
            if root.is_file() or root.is_dir():
                roots.append(root)
            else:
                failures.append(f"scan root {raw_root}: not a file or directory")
        seen_files: set[Path] = set()
        for root in roots:
            for path in _scan_candidates(root, workspace, failures):
                if path in seen_files:
                    continue
                if _excluded(path.relative_to(workspace)):
                    failures.append(f"scan file {path.relative_to(workspace)}: declared exclusion")
                    continue
                problem = _path_problem(path, workspace)
                if problem:
                    failures.append(f"scan file {path.relative_to(workspace)}: {problem}")
                    continue
                if path.is_dir():
                    continue
                if not path.is_file():
                    failures.append(f"scan file {path.relative_to(workspace)}: not a regular file")
                    continue
                seen_files.add(path)
                relative = path.relative_to(workspace)
                if any(relative == Path(allow) for allow in inventory["adapter_allowlist"]):
                    continue
                try:
                    size = path.stat().st_size
                    if size > MAX_SCAN_BYTES:
                        failures.append(f"scan file {relative}: oversize ({size} bytes)")
                        continue
                    text = path.read_bytes().decode("utf-8")
                except OSError as exc:
                    failures.append(f"scan file {relative}: unreadable: {exc}")
                    continue
                except UnicodeDecodeError:
                    failures.append(f"scan file {relative}: non-UTF-8")
                    continue
                lines = text.splitlines()
                if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in lines):
                    failures.append(f"scan file {relative}: line exceeds {MAX_LINE_BYTES} bytes")
                    continue
                coverage.append({"consumer_id": consumer["id"], "scan_root": str(root.relative_to(workspace)), "path": str(relative), "bytes": size, "lines": len(lines)})
                raw_endpoint_lines, trusted_transport_names, transport_problem = _transport_api_hosts(
                    text, python=path.suffix in {".py", ".pyw"}
                )
                if transport_problem:
                    failures.append(f"scan file {relative}: {transport_problem}")
                    continue
                provider_lines: dict[str, set[int]] = {}
                for line_number, line in enumerate(lines, 1):
                    for indicator in catalog["indicators"]:
                        if indicator["category"] not in {"outbound_transport", "evidence_artifact"} and _matches(indicator, line):
                            provider_lines.setdefault(indicator["provider"], set()).add(line_number)
                for line_number, line in enumerate(lines, 1):
                    known = []
                    for indicator in catalog["indicators"]:
                        if _matches(indicator, line):
                            if indicator["category"] in {"outbound_transport", "evidence_artifact"}:
                                continue
                            known.append(indicator)
                    # Transport is meaningful only when paired with a provider
                    # indicator in the same bounded file, never by itself.
                    for indicator in catalog["indicators"]:
                        paired = provider_lines.get(indicator["provider"], set())
                        if indicator["category"] == "outbound_transport" and any(abs(line_number - provider_line) <= 2 for provider_line in paired) and _matches(indicator, line):
                            known.append(indicator)
                        if indicator["category"] == "evidence_artifact" and any(abs(line_number - provider_line) <= 2 for provider_line in paired) and _matches(indicator, line):
                            known.append(indicator)
                    unknown = [
                        candidate
                        for candidate in _provider_unknown_candidates(
                            line, raw_endpoint_lines.get(line_number), trusted_transport_names.get(line_number)
                        )
                        if not any(_known_provider_indicator(indicator, candidate) for indicator in catalog["indicators"])
                    ]
                    for indicator in known:
                        if indicator["category"] == "evidence_artifact" and re.search(r"(?i)\b(?:hound_id|record_id|artifact_id)\b", line):
                            continue
                        finding = {"consumer_id": consumer["id"], "path": str(relative), "line": line_number, "indicator_id": indicator["id"], "category": indicator["category"], "baseline": path in legacy}
                        findings.append(finding)
                        if path in legacy and consumer["stage"] not in {"migrated", "retired"}:
                            baseline.append(finding)
                        else:
                            location = "migrated consumer" if consumer["stage"] in {"migrated", "retired"} else "outside legacy_paths"
                            failures.append(f"direct-provider indicator in {location}: {relative}:{line_number} ({indicator['id']})")
                    if unknown:
                        failures.append(f"unclassified provider-specific indicator: {relative}:{line_number}")
    return ScanResult(findings, baseline, failures, coverage)
