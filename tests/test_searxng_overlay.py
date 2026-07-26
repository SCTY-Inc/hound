from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]
SETTINGS = ROOT / "examples" / "searxng" / "settings.yml"


def test_overlay_uses_upstream_defaults_and_enables_json() -> None:
    settings = yaml.safe_load(SETTINGS.read_text(encoding="utf-8"))

    assert settings["use_default_settings"] is True
    assert "json" in settings["search"]["formats"]


def test_example_overlay_carries_the_reviewed_arxiv_timeout() -> None:
    """The 2026-07-23 pressure test found arXiv failing on the upstream three
    second timeout. The operational overlay raised it to fifteen; the example an
    operator copies must not ship the known-broken value."""
    example = yaml.safe_load(SETTINGS.read_text(encoding="utf-8"))
    operational = yaml.safe_load(
        (ROOT / "ops" / "searxng" / "settings.yml").read_text(encoding="utf-8")
    )
    engines = {engine["name"]: engine for engine in example["engines"]}
    reviewed = {engine["name"]: engine for engine in operational["engines"]}

    assert engines["arxiv"] == {"name": "arxiv", "disabled": False, "timeout": 15}
    assert engines["arxiv"] == reviewed["arxiv"]


def test_federal_register_is_a_native_government_search_engine() -> None:
    settings = yaml.safe_load(SETTINGS.read_text(encoding="utf-8"))
    engines = {engine["name"]: engine for engine in settings["engines"]}
    engine = engines["federal register"]

    assert engine == {
        "name": "federal register",
        "engine": "json_engine",
        "shortcut": "fr",
        "categories": ["government", "news"],
        "disabled": False,
        "paging": True,
        "search_url": (
            "https://www.federalregister.gov/api/v1/documents.json"
            "?per_page=20&page={pageno}&conditions%5Bterm%5D={query}"
        ),
        "results_query": "results",
        "url_query": "html_url",
        "title_query": "title",
        "content_query": "excerpts",
        "content_html_to_text": True,
        "timeout": 10,
    }


def test_exa_is_a_credential_free_publications_engine_definition() -> None:
    settings = yaml.safe_load(SETTINGS.read_text(encoding="utf-8"))
    engines = {engine["name"]: engine for engine in settings["engines"]}

    assert engines["exa publications"] == {
        "name": "exa publications",
        "engine": "exa",
        "shortcut": "exap",
        "categories": ["science", "scientific publications"],
        "disabled": False,
        "results_per_page": 16,
        "timeout": 15,
    }
    assert engines["exa web"] == {
        "name": "exa web",
        "engine": "exa",
        "shortcut": "exaw",
        "categories": ["general", "web"],
        "disabled": False,
        "search_category": "",
        "results_per_page": 16,
        "timeout": 15,
    }
    assert "EXA_API_KEY" not in SETTINGS.read_text(encoding="utf-8")
