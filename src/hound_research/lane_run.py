"""Stateless lane manifest runner: submit search/url entries through houndd.

A lane manifest is strict JSON declaring one or more search queries and/or
URL extractions to submit through the Slice 3C commit boundary. Each entry
gets a deterministic idempotency key derived from the lane, the UTC date,
and the entry's own canonical content, so re-running the same manifest on
the same day replays houndd's finalized results instead of duplicating work.
This runner keeps no state of its own and never retries.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any, Sequence

from houndd.commit import resolve_route
from houndd.contracts import canonical_hash
from houndd.service import WIRE_VERSION

from .commit_client import CommitClientError, exchange, exit_code
from .evidence import EvidenceError, validate_public_url

LANE_MANIFEST_SCHEMA = "hound.lane-manifest.v1"
_REQUESTED_ACCESS = {"public", "workspace", "restricted"}
_MANIFEST_REQUIRED = {"schema_version", "lane", "owner_id", "run_id", "policy_id", "requested_access"}
_MANIFEST_OPTIONAL = {"socket", "searches", "urls"}


class LaneRunError(RuntimeError):
    """A lane manifest or its entries do not satisfy the strict contract."""

    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LaneRunError(message, exit_code=2)


def _text(value: Any, label: str) -> str:
    _require(type(value) is str and value != "", f"{label} must be a non-empty string")
    return value


def _default_socket() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    _require(bool(runtime) and os.path.isabs(runtime), "XDG_RUNTIME_DIR must be an absolute path, or the manifest must supply socket")
    return Path(runtime) / "hound" / "houndd.sock"


def _search_entry(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"query", "limit"}, "each searches[] entry must have exactly query and limit")
    query = _text(value["query"], "searches[].query")
    limit = value["limit"]
    _require(type(limit) is int and not isinstance(limit, bool), "searches[].limit must be an integer")
    return {"kind": "search", "query": query, "limit": max(1, min(50, limit))}


def _url_entry(value: Any) -> dict[str, Any]:
    _require(type(value) is dict, "each urls[] entry must be an object")
    keys = set(value)
    _require(keys in ({"url"}, {"url", "max_pages"}), "each urls[] entry must have url and optional max_pages")
    try:
        url = validate_public_url(value["url"], "urls[].url")
    except EvidenceError as error:
        raise LaneRunError(str(error), exit_code=2) from error
    entry: dict[str, Any] = {"kind": "url", "url": url}
    if "max_pages" in value:
        max_pages = value["max_pages"]
        _require(type(max_pages) is int and not isinstance(max_pages, bool) and 2 <= max_pages <= 20, "urls[].max_pages must be an integer 2..20")
        entry["max_pages"] = max_pages
    return entry


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise LaneRunError(f"cannot read manifest: {error}", exit_code=2) from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise LaneRunError(f"manifest is not valid JSON: {error}", exit_code=2) from error
    _require(type(value) is dict, "manifest must be a JSON object")
    keys = set(value)
    unknown = keys - _MANIFEST_REQUIRED - _MANIFEST_OPTIONAL
    missing = _MANIFEST_REQUIRED - keys
    _require(not unknown, f"manifest has unknown fields {sorted(unknown)!r}")
    _require(not missing, f"manifest is missing fields {sorted(missing)!r}")
    _require(value["schema_version"] == LANE_MANIFEST_SCHEMA, "manifest schema_version must be hound.lane-manifest.v1")

    lane = _text(value["lane"], "lane")
    owner_id = _text(value["owner_id"], "owner_id")
    run_id = _text(value["run_id"], "run_id")
    policy_id = _text(value["policy_id"], "policy_id")
    requested_access = value["requested_access"]
    _require(requested_access in _REQUESTED_ACCESS, "requested_access must be public, workspace, or restricted")

    if "socket" in value:
        socket_path = Path(_text(value["socket"], "socket"))
        _require(socket_path.is_absolute(), "socket must be an absolute path")
    else:
        socket_path = _default_socket()

    searches = value.get("searches", [])
    urls = value.get("urls", [])
    _require(type(searches) is list, "searches must be an array")
    _require(type(urls) is list, "urls must be an array")
    entries = [_search_entry(item) for item in searches] + [_url_entry(item) for item in urls]
    _require(bool(entries), "manifest must declare at least one searches[] or urls[] entry")

    return {
        "lane": lane,
        "owner_id": owner_id,
        "run_id": run_id,
        "policy_id": policy_id,
        "requested_access": requested_access,
        "socket": socket_path,
        "entries": entries,
    }


def idempotency_key(lane: str, today: str, entry: dict[str, Any]) -> str:
    """Deterministic replay key: same lane, day, and entry content -> same key."""

    digest = canonical_hash(entry)
    return f"lane:{lane}:{today}:{digest[:12]}"


def _request(manifest: dict[str, Any], entry: dict[str, Any], *, today: str, request_id: str) -> dict[str, Any]:
    if entry["kind"] == "search":
        path = "/v1/ingest/search"
        operation = "ingest.search"
        payload: dict[str, Any] = {"query": entry["query"], "limit": entry["limit"]}
    else:
        path = "/v1/ingest/url"
        operation = "ingest.url"
        payload = {"url": entry["url"], "lineage": {"kind": "direct"}}
        if "max_pages" in entry:
            payload["max_pages"] = entry["max_pages"]
    resolve_route("POST", path)  # confirms the raw path/operation stay bound to the frozen table
    body = {
        "schema_version": "houndd.commit-request.v1",
        "request_id": request_id,
        "idempotency_key": idempotency_key(manifest["lane"], today, entry),
        "producer": {"owner_id": manifest["owner_id"], "capability": operation, "run_id": manifest["run_id"]},
        "requested_access": manifest["requested_access"],
        "policy_id": manifest["policy_id"],
        "operation": {"name": operation, "payload": payload},
    }
    return {"wire_version": WIRE_VERSION, "method": "POST", "path": path, "body": body}


def _emit(value: dict[str, Any], *, stream: Any = None) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), file=stream or sys.stdout)


def run(manifest_path: Path, *, now: datetime | None = None) -> int:
    manifest = load_manifest(manifest_path)
    today = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    worst_exit = 0
    for index, entry in enumerate(manifest["entries"]):
        request_id = f"lane-run:{manifest['lane']}:{today}:{index}"
        request = _request(manifest, entry, today=today, request_id=request_id)
        try:
            response = exchange(manifest["socket"], request)
            body = response["body"]
            summary = {
                "entry": entry,
                "outcome": body["outcome"],
                "ok": body["ok"],
                "record_ids": body["record_ids"],
                "entry_ids": body["entry_ids"],
            }
            code = exit_code(response)
        except CommitClientError as error:
            summary = {"entry": entry, "outcome": "unavailable", "ok": False, "record_ids": [], "entry_ids": [], "error": str(error)}
            code = 5
        _emit(summary)
        worst_exit = max(worst_exit, code)
    _emit({
        "schema_version": "hound.lane-run.summary.v1",
        "lane": manifest["lane"],
        "entries": len(manifest["entries"]),
        "exit_code": worst_exit,
    })
    return worst_exit


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hound-lane-run", description="Submit one lane manifest of search/url entries through houndd")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        return run(args.manifest.resolve())
    except LaneRunError as error:
        _emit({"schema_version": "hound.error.v1", "error": str(error)}, stream=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        _emit({"schema_version": "hound.error.v1", "error": "interrupted"}, stream=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
