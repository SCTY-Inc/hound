from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from examples.family_suv_watch.watch import run_watch


def _lead(url: str, title: str) -> dict[str, object]:
    return {
        "lead_id": hashlib.sha256(url.encode()).hexdigest(),
        "search_record_id": "a" * 64,
        "schema_version": "hound.lead.v1",
        "evidence_status": "not-evidence",
        "provider": "exa",
        "query": "used Lexus GX 460 Long Island dealer",
        "url": url,
        "title": title,
        "metadata": {"rank": 1},
    }


def _document(url: str, listing_id: str, price: int) -> dict[str, object]:
    markdown = f"# 2020 Lexus GX 460\nPrice: ${price:,}\nMileage: 45,000"
    return {
        "url": url,
        "markdown": markdown,
        "markdown_sha256": hashlib.sha256(markdown.encode()).hexdigest(),
        "links": [f"{url}/history"],
        "metadata": {
            "vehicle": {
                "listing_id": listing_id,
                "year": 2020,
                "make": "Lexus",
                "model": "GX 460",
                "trim": "Premium",
                "price": price,
                "mileage": 45_000,
                "location": "Long Island, NY",
                "title_verified": True,
                "history_url": f"{url}/history",
                "recalls_checked": True,
            }
        },
    }


def _config(tmp_path: Path) -> dict[str, object]:
    return {
        "queries": ["used Lexus GX 460 Long Island dealer"],
        "models": ["Lexus GX 460"],
        "search_adapter": "search-driver.json",
        "extract_adapter": "extract-driver.json",
        "record_root": str(tmp_path / "records"),
        "database": str(tmp_path / "listings.sqlite3"),
        "alerts": str(tmp_path / "discord-alerts.json"),
        "review_queue": str(tmp_path / "browser-review.json"),
    }


def _runner(listings: list[dict[str, object]]):
    leads = [_lead(str(item["url"]), f"Listing {index}") for index, item in enumerate(listings)]
    documents = {str(item["url"]): item for item in listings}

    def run(
        adapter: object,
        verb: str,
        payload: dict[str, object],
        *,
        record_root: object,
        as_of: object = None,
    ) -> dict[str, Any]:
        if verb == "search":
            return {
                "ok": True,
                "outcome": "completed",
                "record_id": "search-record",
                "data": {
                    "schema_version": "hound.web.search.v1",
                    "trust": "untrusted",
                    "evidence_status": "not-evidence",
                    "leads": leads,
                },
            }
        document = documents[str(payload["url"])]
        vehicle = document["metadata"].get("vehicle", {})
        return {
            "ok": True,
            "outcome": "completed",
            "record_id": f"extract-{vehicle.get('listing_id', 'unknown')}",
            "data": {
                "schema_version": "hound.web.extract.v1",
                "trust": "untrusted",
                "evidence_class": "provider-derived",
                "documents": [document],
            },
        }

    return run


def test_family_suv_watch_dedupes_values_and_emits_only_new_under_market_alerts(
    tmp_path: Path,
) -> None:
    listings = [
        _document("https://dealer.example.test/gx-a", "gx-a", 31_000),
        _document("https://dealer.example.test/gx-b", "gx-b", 32_000),
        _document("https://dealer.example.test/gx-c", "gx-c", 33_000),
        _document("https://dealer.example.test/gx-deal", "gx-deal", 24_000),
    ]
    config = _config(tmp_path)

    first = run_watch(config, web_runner=_runner(listings), now="2026-07-21T12:00:00Z")
    first_alerts = json.loads(Path(config["alerts"]).read_text(encoding="utf-8"))
    second = run_watch(config, web_runner=_runner(listings), now="2026-07-22T12:00:00Z")

    assert first == {
        "searches": 1,
        "candidates": 4,
        "verified": 4,
        "new_or_changed": 4,
        "alerts": 1,
        "browser_review": 0,
        "diagnostics": [],
    }
    assert len(first_alerts) == 1
    assert first_alerts[0]["embeds"][0]["url"] == "https://dealer.example.test/gx-deal"
    assert "extract-gx-deal" in first_alerts[0]["embeds"][0]["footer"]["text"]
    assert second["new_or_changed"] == 0
    assert second["alerts"] == 0
    alerts = json.loads(Path(config["alerts"]).read_text(encoding="utf-8"))
    assert alerts == []
    with sqlite3.connect(config["database"]) as database:
        assert database.execute("select count(*) from listings").fetchone()[0] == 4
        deal = database.execute(
            "select market_value, under_market_pct from listings where listing_id = 'gx-deal'"
        ).fetchone()
        assert deal[0] == 31_500
        assert deal[1] >= 0.15
        assert database.execute("select count(*) from alerts").fetchone()[0] == 1


def test_family_suv_watch_queues_unverified_pages_for_manual_browser_review(
    tmp_path: Path,
) -> None:
    weak = _document("https://dealer.example.test/inventory", "gx-weak", 22_000)
    weak["metadata"] = {"title": "Inventory results"}
    config = _config(tmp_path)

    result = run_watch(config, web_runner=_runner([weak]), now="2026-07-21T12:00:00Z")

    assert result["verified"] == 0
    assert result["alerts"] == 0
    assert result["browser_review"] == 1
    review = json.loads(Path(config["review_queue"]).read_text(encoding="utf-8"))
    assert review == [
        {
            "reason": "missing verified vehicle metadata",
            "title": "Listing 0",
            "url": "https://dealer.example.test/inventory",
        }
    ]


def test_family_suv_watch_fails_safe_when_search_is_unavailable(tmp_path: Path) -> None:
    config = _config(tmp_path)

    def failed_search(*args: object, **kwargs: object) -> dict[str, object]:
        return {"ok": False, "outcome": "failed", "error": "search timed out"}

    result = run_watch(config, web_runner=failed_search, now="2026-07-21T12:00:00Z")

    assert result["candidates"] == 0
    assert result["alerts"] == 0
    assert result["diagnostics"] == ["search timed out"]
