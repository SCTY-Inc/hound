"""Read new houndd journal entries once, idempotently, and resume across restarts.

This is the reference pattern every lane migrating onto Hound copies: a
producer-agnostic reader that pages through ``journal.query`` with an opaque
cursor, applies each event exactly once to its own idempotent output, and
persists its cursor to a small per-lane state file with an atomic write. See
``docs/how-to-consume.md`` for the replay discipline this module implements.

The wire exchange and response validation live in ``hound_client``, the
shared strict client every houndd consumer builds on; this module only adapts
its typed ``journal_query`` result into the small dict/exception shape the
rest of this file (and its callers) already expect.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from hound_client import (
    HounddClient,
    HounddClientError,
    HounddJournalCursorRejectedError,
)

DEFAULT_LIMIT = 50


class ConsumerError(RuntimeError):
    """The journal could not be read, or its response violated the read contract."""


class CursorRejectedError(ConsumerError):
    """houndd could no longer recover the persisted cursor.

    The caller has no partial-resume option here: the only correct response
    is to resnapshot from the start (a fresh cursorless query) and let
    idempotent processing absorb any re-delivered entries.
    """


def query_journal(
    socket_path: Path,
    *,
    owner_id: str,
    policy_id: str,
    run_id: str,
    request_id: str,
    cursor: str | None,
    limit: int = DEFAULT_LIMIT,
    requested_access: str = "workspace",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Exchange one ``journal.query`` request and return its response body.

    Raises ``CursorRejectedError`` for a rejected cursor and ``ConsumerError``
    for every other transport or contract fault.
    """

    client = HounddClient(
        socket_path,
        owner_id=owner_id,
        policy_id=policy_id,
        requested_access=requested_access,
        read_timeout=max(1, int(timeout)),
    )
    try:
        entries, next_cursor = client.journal_query(
            cursor=cursor,
            limit=limit,
            run_id=run_id,
            request_id=request_id,
        )
    except HounddJournalCursorRejectedError as error:
        raise CursorRejectedError(str(error)) from error
    except HounddClientError as error:
        raise ConsumerError(str(error)) from error
    return {"result": entries, "cursor": next_cursor}


def load_state(state_path: Path) -> dict[str, Any]:
    """Read the persisted per-lane cursor state, or the initial state if absent."""

    if not state_path.exists():
        return {"cursor": None}
    return json.loads(state_path.read_text(encoding="utf-8"))


def save_state_atomic(state_path: Path, state: dict[str, Any]) -> None:
    """Persist cursor state via temp-file-then-rename so a crash mid-write cannot corrupt it."""

    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_name(f".{state_path.name}.tmp-{os.getpid()}")
    tmp_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, state_path)


def load_processed_entry_ids(output_path: Path) -> set[str]:
    if not output_path.exists():
        return set()
    processed: set[str] = set()
    with output_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                processed.add(json.loads(line)["entry_id"])
    return processed


def process_entries_idempotent(entries: list[dict[str, Any]], output_path: Path) -> int:
    """Apply each event to the lane's own output exactly once, in delivery order.

    A re-delivered ``entry_id`` (at-least-once redelivery after a crash, or a
    resnapshot following an exhausted or rejected cursor) is a documented,
    silent no-op here. Swap this ledger for the lane's real idempotent sink --
    an upsert keyed by ``entry_id``, a dedup table, whatever it already uses.
    """

    processed = load_processed_entry_ids(output_path)
    new_count = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for entry in entries:
            entry_id = entry["entry_id"]
            if entry_id in processed:
                continue
            handle.write(json.dumps({"entry_id": entry_id, "artifact": entry.get("artifact", {})}, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            processed.add(entry_id)
            new_count += 1
    return new_count


def run_once(
    socket_path: Path,
    state_path: Path,
    output_path: Path,
    *,
    owner_id: str,
    policy_id: str,
    run_id: str,
    limit: int = DEFAULT_LIMIT,
    requested_access: str = "workspace",
    request_id: str | None = None,
) -> int:
    """Read and process one page of new journal entries, then persist the cursor.

    Order matters: entries are processed (idempotently) *before* the cursor is
    persisted. A crash between the two steps leaves the old cursor in place,
    so the next run re-fetches the same page -- at-least-once delivery that
    idempotent processing turns into exactly-once effects. Returns the number
    of entries newly applied (redelivered entries do not count).
    """

    state = load_state(state_path)
    cursor = state.get("cursor")
    base_request_id = request_id or f"{owner_id}-consumer-{os.getpid()}"
    try:
        body = query_journal(
            socket_path,
            owner_id=owner_id,
            policy_id=policy_id,
            run_id=run_id,
            request_id=base_request_id,
            cursor=cursor,
            limit=limit,
            requested_access=requested_access,
        )
    except CursorRejectedError:
        body = query_journal(
            socket_path,
            owner_id=owner_id,
            policy_id=policy_id,
            run_id=run_id,
            request_id=f"{base_request_id}-resnapshot",
            cursor=None,
            limit=limit,
            requested_access=requested_access,
        )

    new_count = process_entries_idempotent(body["result"], output_path)
    state["cursor"] = body.get("cursor")
    save_state_atomic(state_path, state)
    return new_count


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process one page of new houndd journal entries")
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--state-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--requested-access", default="workspace", choices=("public", "workspace", "restricted"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        new_count = run_once(
            args.socket,
            args.state_file,
            args.output,
            owner_id=args.owner_id,
            policy_id=args.policy_id,
            run_id=args.run_id,
            limit=args.limit,
            requested_access=args.requested_access,
        )
    except ConsumerError as error:
        print(f"consumer: {error}", file=sys.stderr)
        return 1
    print(f"consumer: processed {new_count} new entry(ies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
