"""Thin source lifecycle composed from immutable web records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .contracts import load_manifest
from .evidence import EvidenceError
from .orchestrator import HoundError, invoke_read
from .web import run_web, verify_web_run


DISCOVERY_SPEC_SCHEMA = "hound.source.discovery-spec.v2"
DISCOVERY_SCHEMA = "hound.source.discovery.v2"
CAPTURE_INPUT_SCHEMA = "hound.source.capture.input.v2"
CAPTURE_SPEC_SCHEMA = "hound.source.capture-spec.v2"
CAPTURE_SET_SCHEMA = "hound.source.capture-set.v2"
MAX_SOURCE_REQUESTS = 32
MAX_SOURCE_LEADS = 1_000
MAX_SOURCE_CAPTURES = 30
MAX_SOURCE_BYTES = 64 * 1024 * 1024

WebRunner = Callable[..., dict[str, Any]]


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _strict(value: dict[str, Any], required: set[str], optional: set[str], label: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing fields {sorted(missing)!r}")
        if unknown:
            details.append(f"unknown fields {sorted(unknown)!r}")
        raise EvidenceError(f"{label} has {' and '.join(details)}")


def _integer(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise EvidenceError(f"{label} must be an integer from 1 through {maximum}")
    return value


def _manifest_context(manifest_path: str | Path) -> tuple[Path, dict[str, Any], Path, Path]:
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    source = manifest.get("source")
    if not isinstance(source, dict) or source.get("schema_version") != "hound.source.v2":
        raise HoundError("driver does not declare hound.source.v2 composition", exit_code=2)
    repo = (path.parent / manifest["owner"]["repo"]).resolve()
    return path, manifest, repo, repo / ".hound" / "web"


def _adapter_path(path: Path, manifest: dict[str, Any], alias: object) -> Path:
    if not isinstance(alias, str):
        raise EvidenceError("source adapter alias must be a string")
    adapters = manifest["source"]["adapters"]
    locator = adapters.get(alias)
    if not isinstance(locator, str):
        raise EvidenceError(f"source adapter alias is not declared: {alias!r}")
    adapter = (path.parent / locator).resolve()
    load_manifest(adapter)
    return adapter


def _limits(value: object) -> dict[str, int]:
    limits = _object(value, "source limits")
    _strict(limits, {"max_requests", "max_leads", "max_bytes"}, set(), "source limits")
    return {
        "max_requests": _integer(
            limits["max_requests"], "source limits.max_requests", maximum=MAX_SOURCE_REQUESTS
        ),
        "max_leads": _integer(
            limits["max_leads"], "source limits.max_leads", maximum=MAX_SOURCE_LEADS
        ),
        "max_bytes": _integer(
            limits["max_bytes"], "source limits.max_bytes", maximum=MAX_SOURCE_BYTES
        ),
    }


def _discovery_spec(response: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not response.get("ok") or response.get("outcome") != "completed":
        raise HoundError("source discovery driver did not complete")
    spec = _object(response.get("data"), "source discovery spec")
    _strict(spec, {"schema_version", "searches", "limits"}, set(), "source discovery spec")
    if spec["schema_version"] != DISCOVERY_SPEC_SCHEMA:
        raise EvidenceError("source discovery spec has an unsupported schema version")
    searches = spec["searches"]
    if not isinstance(searches, list) or not searches:
        raise EvidenceError("source discovery searches must be a non-empty array")
    limits = _limits(spec["limits"])
    if len(searches) > limits["max_requests"]:
        raise EvidenceError("source discovery max_requests exceeded")
    validated: list[dict[str, Any]] = []
    for raw in searches:
        search = _object(raw, "source search")
        _strict(search, {"adapter", "input"}, set(), "source search")
        if not isinstance(search["input"], dict):
            raise EvidenceError("source search input must be an object")
        validated.append({"adapter": search["adapter"], "input": search["input"]})
    return validated, limits


def _record_output(root: Path, record_id: str, operation: str) -> dict[str, Any]:
    record = root / record_id
    verification = verify_web_run(record)
    if not verification["valid"]:
        raise EvidenceError(f"source {operation} record is invalid: {record_id}")
    try:
        descriptor = json.loads((record / "record.json").read_text(encoding="utf-8"))
        output = json.loads((record / "output.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise EvidenceError(f"source {operation} record is unreadable: {record_id}") from None
    if descriptor.get("operation") != operation or descriptor.get("outcome") != "completed":
        raise EvidenceError(f"source record is not a completed {operation}: {record_id}")
    return output


def _validate_discovery(root: Path, value: object) -> dict[str, Any]:
    discovery = _object(value, "source discovery")
    _strict(
        discovery,
        {"schema_version", "records", "leads", "usage"},
        set(),
        "source discovery",
    )
    if discovery["schema_version"] != DISCOVERY_SCHEMA:
        raise EvidenceError("source discovery has an unsupported schema version")
    records = discovery["records"]
    leads = discovery["leads"]
    if not isinstance(records, list) or not isinstance(leads, list):
        raise EvidenceError("source discovery records and leads must be arrays")
    if len(records) != len(set(records)):
        raise EvidenceError("source discovery contains duplicate record IDs")
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    byte_count = 0
    for record_id in records:
        if not isinstance(record_id, str):
            raise EvidenceError("source discovery record IDs must be strings")
        output = _record_output(root, record_id, "search")
        byte_count += (root / record_id / "raw.bin").stat().st_size
        for lead in output.get("leads", []):
            if not isinstance(lead, dict) or not isinstance(lead.get("lead_id"), str):
                raise EvidenceError("source search record contains an invalid lead")
            key = (record_id, lead["lead_id"])
            if key in expected:
                raise EvidenceError("source search record contains duplicate lead IDs")
            expected[key] = lead
    normalized: list[dict[str, Any]] = []
    for raw in leads:
        reference = _object(raw, "source lead reference")
        _strict(reference, {"record_id", "lead_id", "lead"}, set(), "source lead reference")
        match = expected.get((reference["record_id"], reference["lead_id"]))
        if match is None or match != reference["lead"]:
            raise EvidenceError("source lead reference does not match its search record")
        normalized.append(reference)
    normalized_keys = [(reference["record_id"], reference["lead_id"]) for reference in normalized]
    if len(normalized_keys) != len(set(normalized_keys)) or set(expected) != set(normalized_keys):
        raise EvidenceError("source discovery omits or duplicates search-record leads")
    usage = _object(discovery["usage"], "source discovery usage")
    _strict(usage, {"requests", "leads", "bytes"}, set(), "source discovery usage")
    if usage != {"requests": len(records), "leads": len(leads), "bytes": byte_count}:
        raise EvidenceError("source discovery usage does not match its records")
    return discovery


def discover_sources(
    manifest_path: str | Path,
    payload: dict[str, Any],
    *,
    as_of: str | None = None,
    web_runner: WebRunner = run_web,
) -> dict[str, Any]:
    """Run owner-declared searches through explicit adapter manifests."""

    path, manifest, _, record_root = _manifest_context(manifest_path)
    response = invoke_read(path, "source.discover", payload, as_of=as_of)
    searches, limits = _discovery_spec(response)
    records: list[str] = []
    leads: list[dict[str, Any]] = []
    byte_count = 0
    diagnostics: list[str] = []
    for index, search in enumerate(searches, start=1):
        adapter = _adapter_path(path, manifest, search["adapter"])
        result = web_runner(
            adapter,
            "search",
            search["input"],
            record_root=record_root,
            as_of=as_of,
        )
        if not result.get("ok"):
            diagnostics.append(f"search {index} failed: {result.get('error', 'adapter failed')}")
            continue
        record_id = result["record_id"]
        output = _record_output(record_root, record_id, "search")
        records.append(record_id)
        byte_count += (record_root / record_id / "raw.bin").stat().st_size
        for lead in output["leads"]:
            leads.append({"record_id": record_id, "lead_id": lead["lead_id"], "lead": lead})
        if len(leads) > limits["max_leads"]:
            raise EvidenceError("source discovery max_leads exceeded")
        if byte_count > limits["max_bytes"]:
            raise EvidenceError("source discovery max_bytes exceeded")
    if not records:
        raise EvidenceError("all source discovery searches failed")
    discovery = {
        "schema_version": DISCOVERY_SCHEMA,
        "records": records,
        "leads": leads,
        "usage": {"requests": len(records), "leads": len(leads), "bytes": byte_count},
    }
    return {
        **response,
        "data_schema": DISCOVERY_SCHEMA,
        "data": discovery,
        "proofs": [
            *response.get("proofs", []),
            {"kind": "web-records", "passed": True, "count": len(records)},
        ],
        "diagnostics": [*response.get("diagnostics", []), *diagnostics],
    }


def _capture_spec(response: dict[str, Any]) -> list[dict[str, Any]]:
    if not response.get("ok") or response.get("outcome") != "completed":
        raise HoundError("source capture driver did not complete")
    spec = _object(response.get("data"), "source capture spec")
    _strict(spec, {"schema_version", "captures"}, set(), "source capture spec")
    if spec["schema_version"] != CAPTURE_SPEC_SCHEMA:
        raise EvidenceError("source capture spec has an unsupported schema version")
    captures = spec["captures"]
    if not isinstance(captures, list):
        raise EvidenceError("source capture requests must be an array")
    if len(captures) > MAX_SOURCE_CAPTURES:
        raise EvidenceError(f"source capture count exceeds {MAX_SOURCE_CAPTURES}")
    validated: list[dict[str, Any]] = []
    for raw in captures:
        capture = _object(raw, "source capture request")
        _strict(
            capture,
            {"search_record_id", "lead_id", "adapter"},
            {"max_pages"},
            "source capture request",
        )
        normalized = {
            "search_record_id": capture["search_record_id"],
            "lead_id": capture["lead_id"],
            "adapter": capture["adapter"],
        }
        if "max_pages" in capture:
            normalized["max_pages"] = capture["max_pages"]
        validated.append(normalized)
    selections = [(capture["search_record_id"], capture["lead_id"]) for capture in validated]
    if len(selections) != len(set(selections)):
        raise EvidenceError("source capture requests contain duplicate lead references")
    return validated


def capture_sources(
    manifest_path: str | Path,
    payload: dict[str, Any],
    *,
    as_of: str | None = None,
    web_runner: WebRunner = run_web,
) -> dict[str, Any]:
    """Extract exact owner-selected discovery leads through explicit adapters."""

    path, manifest, _, record_root = _manifest_context(manifest_path)
    value = _object(payload, "source capture input")
    _strict(
        value,
        {"schema_version", "discovery"},
        {"owner_input"},
        "source capture input",
    )
    if "owner_input" in value and not isinstance(value["owner_input"], dict):
        raise EvidenceError("source capture owner_input must be an object")
    if value["schema_version"] != CAPTURE_INPUT_SCHEMA:
        raise EvidenceError("source capture input has an unsupported schema version")
    discovery = _validate_discovery(record_root, value["discovery"])
    response = invoke_read(path, "source.capture", payload, as_of=as_of)
    captures = _capture_spec(response)
    references = {
        (reference["record_id"], reference["lead_id"]): reference
        for reference in discovery["leads"]
    }
    completed: list[dict[str, str]] = []
    diagnostics: list[str] = []
    for index, capture in enumerate(captures, start=1):
        reference = references.get((capture["search_record_id"], capture["lead_id"]))
        if reference is None:
            raise EvidenceError("source capture selected a lead absent from discovery")
        lead = reference["lead"]
        adapter = _adapter_path(path, manifest, capture["adapter"])
        extract_input: dict[str, Any] = {
            "url": lead["url"],
            "lineage": {
                "kind": "search",
                "record_id": reference["record_id"],
                "lead_id": reference["lead_id"],
            },
        }
        if "max_pages" in capture:
            extract_input["max_pages"] = capture["max_pages"]
        result = web_runner(
            adapter,
            "extract",
            extract_input,
            record_root=record_root,
            as_of=as_of,
        )
        if not result.get("ok"):
            diagnostics.append(f"capture {index} failed: {result.get('error', 'adapter failed')}")
            continue
        completed.append(
            {
                "lead_id": reference["lead_id"],
                "search_record_id": reference["record_id"],
                "extract_record_id": result["record_id"],
            }
        )
    if captures and not completed:
        raise EvidenceError("all source capture extracts failed")
    capture_set = {"schema_version": CAPTURE_SET_SCHEMA, "captures": completed}
    return {
        **response,
        "data_schema": CAPTURE_SET_SCHEMA,
        "data": capture_set,
        "proofs": [
            *response.get("proofs", []),
            {"kind": "web-records", "passed": True, "count": len(completed)},
        ],
        "diagnostics": [*response.get("diagnostics", []), *diagnostics],
    }


def _verified_capture_set(root: Path, value: object) -> dict[str, Any]:
    capture_set = _object(value, "source capture set")
    _strict(capture_set, {"schema_version", "captures"}, set(), "source capture set")
    if capture_set["schema_version"] != CAPTURE_SET_SCHEMA:
        raise EvidenceError("source capture set has an unsupported schema version")
    captures = capture_set["captures"]
    if not isinstance(captures, list):
        raise EvidenceError("source capture set captures must be an array")
    verified: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in captures:
        reference = _object(raw, "source capture reference")
        _strict(
            reference,
            {"lead_id", "search_record_id", "extract_record_id"},
            set(),
            "source capture reference",
        )
        key = (
            reference["search_record_id"],
            reference["lead_id"],
            reference["extract_record_id"],
        )
        if key in seen:
            raise EvidenceError("source capture set contains duplicate references")
        seen.add(key)
        search_output = _record_output(root, reference["search_record_id"], "search")
        extract_output = _record_output(root, reference["extract_record_id"], "extract")
        matches = [
            lead for lead in search_output["leads"] if lead.get("lead_id") == reference["lead_id"]
        ]
        if len(matches) != 1:
            raise EvidenceError("source capture lead does not match its search record")
        try:
            extract_request = json.loads(
                (root / reference["extract_record_id"] / "request.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            raise EvidenceError("source capture extract request is unreadable") from None
        expected_lineage = {
            "kind": "search",
            "record_id": reference["search_record_id"],
            "lead_id": reference["lead_id"],
        }
        if extract_request.get("input", {}).get("lineage") != expected_lineage:
            raise EvidenceError("source capture extract lineage does not match")
        verified.append(
            {
                **reference,
                "capture_id": reference["extract_record_id"],
                "lead": matches[0],
                "documents": extract_output["documents"],
            }
        )
    return {"schema_version": CAPTURE_SET_SCHEMA, "captures": verified}


def inspect_sources(
    manifest_path: str | Path,
    payload: dict[str, Any],
    *,
    as_of: str | None = None,
) -> dict[str, Any]:
    """Verify every referenced search and extract record before interpretation."""

    path, _, _, record_root = _manifest_context(manifest_path)
    value = _object(payload, "source inspect input")
    _strict(value, {"capture_set"}, {"owner_input"}, "source inspect input")
    if "owner_input" in value and not isinstance(value["owner_input"], dict):
        raise EvidenceError("source inspect owner_input must be an object")
    verified = _verified_capture_set(record_root, value["capture_set"])
    return invoke_read(
        path,
        "source.inspect",
        {**payload, "capture_set": verified},
        as_of=as_of,
    )


__all__ = ["capture_sources", "discover_sources", "inspect_sources"]
