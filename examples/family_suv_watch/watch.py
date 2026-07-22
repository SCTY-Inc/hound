"""Compose Hound web primitives into a small, approval-safe vehicle watch."""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from hound_cli.evidence import EvidenceError, validate_public_url
from hound_cli.web import run_web


WebRunner = Callable[..., dict[str, Any]]
MAX_SEARCHES = 5
MAX_CANDIDATES = 20
UNDER_MARKET_THRESHOLD = 0.15


def _config(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("watch config must be an object")
    required = {
        "queries",
        "models",
        "search_adapter",
        "extract_adapter",
        "record_root",
        "database",
        "alerts",
        "review_queue",
    }
    if set(value) != required:
        raise ValueError("watch config has missing or unknown fields")
    queries = value["queries"]
    models = value["models"]
    if (
        not isinstance(queries, list)
        or not 1 <= len(queries) <= MAX_SEARCHES
        or any(not isinstance(query, str) or not query.strip() for query in queries)
    ):
        raise ValueError(f"watch config queries must contain 1 through {MAX_SEARCHES} strings")
    if (
        not isinstance(models, list)
        or not models
        or any(not isinstance(model, str) or not model.strip() for model in models)
    ):
        raise ValueError("watch config models must be a non-empty string list")
    for field in required - {"queries", "models"}:
        if not isinstance(value[field], str) or not value[field]:
            raise ValueError(f"watch config {field} must be a path string")
    return dict(value)


def _database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path)
    database.executescript(
        """
        pragma foreign_keys = on;
        create table if not exists listings (
            listing_id text primary key,
            source_url text not null unique,
            year integer not null,
            make text not null,
            model text not null,
            trim text not null,
            price integer not null,
            mileage integer not null,
            location text not null,
            content_sha256 text not null,
            extract_record_id text not null,
            first_seen text not null,
            last_seen text not null,
            market_value real,
            under_market_pct real
        );
        create table if not exists observations (
            listing_id text not null references listings(listing_id),
            content_sha256 text not null,
            observed_at text not null,
            price integer not null,
            mileage integer not null,
            extract_record_id text not null,
            primary key (listing_id, content_sha256)
        );
        create table if not exists alerts (
            listing_id text not null references listings(listing_id),
            content_sha256 text not null,
            created_at text not null,
            payload_json text not null,
            primary key (listing_id, content_sha256)
        );
        """
    )
    return database


def _vehicle(document: object, lead: Mapping[str, object], allowed: set[str]) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("url") != lead.get("url"):
        raise ValueError("extraction did not return the direct candidate URL")
    metadata = document.get("metadata")
    vehicle = metadata.get("vehicle") if isinstance(metadata, dict) else None
    if not isinstance(vehicle, dict):
        raise ValueError("missing verified vehicle metadata")
    required = {
        "listing_id",
        "year",
        "make",
        "model",
        "trim",
        "price",
        "mileage",
        "location",
        "title_verified",
        "history_url",
        "recalls_checked",
    }
    if set(vehicle) != required:
        raise ValueError("missing verified vehicle metadata")
    if vehicle["title_verified"] is not True or vehicle["recalls_checked"] is not True:
        raise ValueError("title, history, or recalls are not verified")
    try:
        history_url = validate_public_url(vehicle["history_url"], "vehicle history_url")
        source_url = validate_public_url(document["url"], "vehicle source_url")
    except EvidenceError as error:
        raise ValueError(str(error)) from error
    for field in ("listing_id", "make", "model", "trim", "location"):
        if not isinstance(vehicle[field], str) or not vehicle[field].strip():
            raise ValueError(f"vehicle {field} is invalid")
    for field in ("year", "price", "mileage"):
        if (
            isinstance(vehicle[field], bool)
            or not isinstance(vehicle[field], int)
            or vehicle[field] <= 0
        ):
            raise ValueError(f"vehicle {field} is invalid")
    if f"{vehicle['make']} {vehicle['model']}" not in allowed:
        raise ValueError("vehicle is outside the configured model set")
    markdown_sha256 = document.get("markdown_sha256")
    if not isinstance(markdown_sha256, str) or len(markdown_sha256) != 64:
        raise ValueError("vehicle extraction has no content hash")
    return {
        **vehicle,
        "history_url": history_url,
        "source_url": source_url,
        "content_sha256": markdown_sha256,
    }


def _upsert(
    database: sqlite3.Connection,
    vehicle: dict[str, Any],
    *,
    record_id: str,
    observed_at: str,
) -> bool:
    previous = database.execute(
        "select content_sha256, price, mileage from listings where listing_id = ?",
        (vehicle["listing_id"],),
    ).fetchone()
    changed = previous is None or tuple(previous) != (
        vehicle["content_sha256"],
        vehicle["price"],
        vehicle["mileage"],
    )
    first_seen = (
        observed_at
        if previous is None
        else database.execute(
            "select first_seen from listings where listing_id = ?", (vehicle["listing_id"],)
        ).fetchone()[0]
    )
    database.execute(
        """
        insert into listings (
            listing_id, source_url, year, make, model, trim, price, mileage,
            location, content_sha256, extract_record_id, first_seen, last_seen
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(listing_id) do update set
            source_url = excluded.source_url,
            year = excluded.year,
            make = excluded.make,
            model = excluded.model,
            trim = excluded.trim,
            price = excluded.price,
            mileage = excluded.mileage,
            location = excluded.location,
            content_sha256 = excluded.content_sha256,
            extract_record_id = excluded.extract_record_id,
            last_seen = excluded.last_seen
        """,
        (
            vehicle["listing_id"],
            vehicle["source_url"],
            vehicle["year"],
            vehicle["make"],
            vehicle["model"],
            vehicle["trim"],
            vehicle["price"],
            vehicle["mileage"],
            vehicle["location"],
            vehicle["content_sha256"],
            record_id,
            first_seen,
            observed_at,
        ),
    )
    database.execute(
        """
        insert or ignore into observations (
            listing_id, content_sha256, observed_at, price, mileage, extract_record_id
        ) values (?, ?, ?, ?, ?, ?)
        """,
        (
            vehicle["listing_id"],
            vehicle["content_sha256"],
            observed_at,
            vehicle["price"],
            vehicle["mileage"],
            record_id,
        ),
    )
    return changed


def _value_listings(database: sqlite3.Connection) -> None:
    rows = database.execute("select listing_id, make, model, price from listings").fetchall()
    groups: dict[tuple[str, str], list[int]] = {}
    for _, make, model, price in rows:
        groups.setdefault((make, model), []).append(price)
    for listing_id, make, model, price in rows:
        prices = groups[(make, model)]
        if len(prices) < 3:
            database.execute(
                "update listings set market_value = null, under_market_pct = null "
                "where listing_id = ?",
                (listing_id,),
            )
            continue
        market_value = float(statistics.median(prices))
        under_market = max(0.0, (market_value - price) / market_value)
        database.execute(
            "update listings set market_value = ?, under_market_pct = ? where listing_id = ?",
            (market_value, under_market, listing_id),
        )


def _alert_payload(row: sqlite3.Row) -> dict[str, object]:
    title = (
        f"{row['year']} {row['make']} {row['model']} — "
        f"{row['under_market_pct']:.0%} below comparables"
    )
    return {
        "embeds": [
            {
                "title": title,
                "url": row["source_url"],
                "description": "Verified public dealer listing; seller contact remains manual.",
                "fields": [
                    {"name": "Asking", "value": f"${row['price']:,.0f}", "inline": True},
                    {
                        "name": "Comparable median",
                        "value": f"${row['market_value']:,.0f}",
                        "inline": True,
                    },
                    {"name": "Mileage", "value": f"{row['mileage']:,}", "inline": True},
                    {"name": "Location", "value": row["location"], "inline": True},
                ],
                "footer": {"text": f"Hound extract record {row['extract_record_id']}"},
            }
        ]
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_watch(
    config: object,
    *,
    web_runner: WebRunner = run_web,
    now: str,
) -> dict[str, Any]:
    settings = _config(config)
    allowed = set(settings["models"])
    record_root = Path(settings["record_root"])
    diagnostics: list[str] = []
    leads_by_url: dict[str, dict[str, Any]] = {}
    for query in settings["queries"]:
        result = web_runner(
            Path(settings["search_adapter"]),
            "search",
            {"query": query, "limit": 10},
            record_root=record_root,
            as_of=now,
        )
        if not result.get("ok"):
            diagnostics.append(str(result.get("error", "search failed")))
            continue
        for lead in result.get("data", {}).get("leads", []):
            if isinstance(lead, dict) and isinstance(lead.get("url"), str):
                leads_by_url.setdefault(lead["url"], lead)
            if len(leads_by_url) >= MAX_CANDIDATES:
                break

    review: list[dict[str, str]] = []
    changed_ids: set[str] = set()
    verified = 0
    database = _database(Path(settings["database"]))
    database.row_factory = sqlite3.Row
    try:
        for lead in list(leads_by_url.values())[:MAX_CANDIDATES]:
            result = web_runner(
                Path(settings["extract_adapter"]),
                "extract",
                {
                    "url": lead["url"],
                    "lineage": {
                        "kind": "search",
                        "record_id": lead["search_record_id"],
                        "lead_id": lead["lead_id"],
                    },
                },
                record_root=record_root,
                as_of=now,
            )
            if not result.get("ok"):
                review.append(
                    {
                        "url": str(lead["url"]),
                        "title": str(lead.get("title", "Untitled candidate")),
                        "reason": str(result.get("error", "static extraction failed")),
                    }
                )
                continue
            documents = result.get("data", {}).get("documents", [])
            try:
                if not isinstance(documents, list) or len(documents) != 1:
                    raise ValueError("single-page extraction did not return one document")
                vehicle = _vehicle(documents[0], lead, allowed)
            except ValueError as error:
                review.append(
                    {
                        "url": str(lead["url"]),
                        "title": str(lead.get("title", "Untitled candidate")),
                        "reason": str(error),
                    }
                )
                continue
            verified += 1
            if _upsert(
                database,
                vehicle,
                record_id=str(result["record_id"]),
                observed_at=now,
            ):
                changed_ids.add(vehicle["listing_id"])
        _value_listings(database)

        alerts: list[dict[str, object]] = []
        for listing_id in sorted(changed_ids):
            row = database.execute(
                "select * from listings where listing_id = ?", (listing_id,)
            ).fetchone()
            if row["under_market_pct"] is None or row["under_market_pct"] < UNDER_MARKET_THRESHOLD:
                continue
            payload = _alert_payload(row)
            cursor = database.execute(
                """
                insert or ignore into alerts (listing_id, content_sha256, created_at, payload_json)
                values (?, ?, ?, ?)
                """,
                (listing_id, row["content_sha256"], now, json.dumps(payload, sort_keys=True)),
            )
            if cursor.rowcount:
                alerts.append(payload)
        database.commit()
    finally:
        database.close()

    _write_json(Path(settings["alerts"]), alerts)
    _write_json(Path(settings["review_queue"]), review)
    return {
        "searches": len(settings["queries"]),
        "candidates": len(leads_by_url),
        "verified": verified,
        "new_or_changed": len(changed_ids),
        "alerts": len(alerts),
        "browser_review": len(review),
        "diagnostics": diagnostics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one bounded family SUV watch cycle")
    parser.add_argument("--config", required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for field in (
        "search_adapter",
        "extract_adapter",
        "record_root",
        "database",
        "alerts",
        "review_queue",
    ):
        path = Path(config[field])
        config[field] = str(path if path.is_absolute() else config_path.parent / path)
    print(json.dumps(run_watch(config, now=args.as_of), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
