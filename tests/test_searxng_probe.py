from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).parents[1]
PROBE = ROOT / "ops" / "searxng" / "probe.py"


def load_probe() -> Any:
    spec = importlib.util.spec_from_file_location("searxng_probe", PROBE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load_probe()


def test_every_probe_query_is_domain_appropriate() -> None:
    """Each engine either names its own probes or inherits them from a category
    it actually declares, so no engine is judged on a foreign query."""
    for name, queries in probe.ENGINE_QUERIES.items():
        assert queries, f"{name} has no probe queries"
        assert len(queries) >= 3, f"{name} needs at least three probes"
    for category, queries in probe.CATEGORY_QUERIES.items():
        assert len(queries) >= 3, f"{category} needs at least three probes"


def test_queries_fall_back_to_the_first_declared_category() -> None:
    assert probe.queries_for("github", ["it", "repos"], 3) == probe.ENGINE_QUERIES["github"]
    # `bing news` names no override, so it inherits the news probes.
    assert probe.queries_for("bing news", ["news"], 2) == probe.CATEGORY_QUERIES["news"][:2]
    # An unknown engine in an unknown category still gets probed, not skipped.
    assert probe.queries_for("mystery", ["nonexistent"], 2) == probe.GENERIC_QUERIES[:2]


def test_queries_cycle_when_more_probes_than_queries_are_requested() -> None:
    pool = probe.CATEGORY_QUERIES["news"]
    assert probe.queries_for("bing news", ["news"], 5) == [pool[i % len(pool)] for i in range(5)]


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        (["leads", "leads", "leads"], "responsive"),
        (["leads", "zero", "leads"], "query-dependent"),
        (["zero", "zero", "zero"], "no-leads"),
        (["blocked", "blocked", "blocked"], "blocked"),
        # One probe returning zero is not an outage; one probe blocked is.
        (["leads", "leads", "blocked"], "blocked"),
        (["zero", "blocked", "zero"], "blocked"),
    ],
)
def test_verdict_follows_the_documented_status_vocabulary(
    outcomes: list[str], expected: str
) -> None:
    assert probe.verdict(outcomes) == expected


def test_an_intermittent_route_is_never_reported_as_responsive() -> None:
    """The google cse shape: answers most probes, rate-limits on one. It cannot
    be a sole source, so it must not classify as responsive."""
    assert probe.verdict(["leads", "leads", "blocked"]) == "blocked"


def test_domains_are_deduplicated_and_lowercased() -> None:
    results = [
        {"url": "https://Example.com/a"},
        {"url": "https://example.com/b"},
        {"url": "https://other.org/c"},
        {"url": None},
        "not-a-dict",
    ]
    assert probe.domains(results) == ["example.com", "other.org"]


def test_responders_reports_engines_that_produced_results() -> None:
    results = [
        {"url": "https://a.test", "engines": ["github", "gitlab"]},
        {"url": "https://b.test", "engines": ["github"]},
        {"url": "https://c.test"},
    ]
    assert probe.responders(results) == ["github", "gitlab"]


def test_failures_are_keyed_by_casefolded_engine_name() -> None:
    payload = {"unresponsive_engines": [["Google CSE", "Too many requests"], ["bad"], 7]}
    assert probe.failures(payload) == {"google cse": "Too many requests"}


def test_budget_is_a_hard_ceiling() -> None:
    budget = probe.Budget(2)
    budget.take()
    budget.take()
    with pytest.raises(SystemExit):
        budget.take()


def test_credential_map_covers_the_engines_this_overlay_adds() -> None:
    assert probe.CREDENTIALS["exa web"] == ("EXA_API_KEY", True)
    assert probe.CREDENTIALS["exa publications"] == ("EXA_API_KEY", True)
    # federal register is a keyless json_engine route.
    assert "federal register" not in probe.CREDENTIALS


def test_tab_categories_match_the_pinned_image() -> None:
    """Only these ten categories restrict dispatch to default-enabled engines;
    every other category reaches engines /config reports as disabled."""
    assert probe.TAB_CATEGORIES == {
        "general",
        "images",
        "videos",
        "news",
        "map",
        "music",
        "it",
        "science",
        "files",
        "social media",
    }


def test_inventory_renders_one_row_per_engine() -> None:
    config = {
        "engines": [
            {"name": "exa web", "shortcut": "exaw", "categories": ["general"], "enabled": True},
            {"name": "yandex", "shortcut": "yd", "categories": ["general"], "enabled": False},
        ]
    }
    table = probe.inventory(config).splitlines()
    assert len(table) == 4  # header, separator, two engines
    assert "`EXA_API_KEY` (required)" in table[2]
    assert table[2].endswith("| yes | `EXA_API_KEY` (required) |")
    assert table[3].endswith("| no | none |")
