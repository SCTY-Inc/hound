from __future__ import annotations

import importlib.util
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).parents[1]
ENGINE = ROOT / "examples" / "searxng" / "exa.py"


class FakeEngineResults:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.types = SimpleNamespace(MainResult=lambda **value: value)

    def add(self, result: dict[str, Any]) -> None:
        self.items.append(result)


class FakeSearxEngineAPIException(Exception):
    pass


def load_engine(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    searx = ModuleType("searx")
    exceptions = ModuleType("searx.exceptions")
    result_types = ModuleType("searx.result_types")
    utils = ModuleType("searx.utils")
    exceptions.SearxEngineAPIException = FakeSearxEngineAPIException
    result_types.EngineResults = FakeEngineResults
    utils.html_to_text = lambda value: value.strip()
    monkeypatch.setitem(sys.modules, "searx", searx)
    monkeypatch.setitem(sys.modules, "searx.exceptions", exceptions)
    monkeypatch.setitem(sys.modules, "searx.result_types", result_types)
    monkeypatch.setitem(sys.modules, "searx.utils", utils)

    spec = importlib.util.spec_from_file_location("test_exa_engine", ENGINE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exa_engine_requires_service_owned_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    engine = load_engine(monkeypatch)

    with pytest.raises(FakeSearxEngineAPIException, match="EXA_API_KEY is required"):
        engine.init({})


def test_exa_engine_builds_bounded_publication_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXA_API_KEY", "test-secret")
    engine = load_engine(monkeypatch)
    engine.init({})
    params: dict[str, Any] = {
        "headers": {},
        "pageno": 1,
        "time_range": "month",
    }

    engine.request("caregiving intervention outcomes", params)

    assert params["url"] == "https://api.exa.ai/search"
    assert params["method"] == "POST"
    assert params["headers"] == {
        "x-api-key": "test-secret",
        "Content-Type": "application/json",
    }
    assert params["json"]["query"] == "caregiving intervention outcomes"
    assert params["json"]["category"] == "publication"
    assert params["json"]["type"] == "auto"
    assert params["json"]["numResults"] == 16
    assert params["json"]["contents"]["highlights"]["maxCharacters"] == 1_000
    assert params["json"]["startPublishedDate"].endswith("Z")


def test_exa_engine_builds_uncategorized_web_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXA_API_KEY", "test-secret")
    engine = load_engine(monkeypatch)
    engine.init({"search_category": ""})
    params: dict[str, Any] = {
        "headers": {},
        "pageno": 1,
        "time_range": "year",
    }

    engine.request("new state caregiver benefit", params)

    assert params["json"]["query"] == "new state caregiver benefit"
    assert "category" not in params["json"]
    assert params["json"]["type"] == "auto"
    assert params["json"]["numResults"] == 16
    assert params["json"]["startPublishedDate"].endswith("Z")


def test_exa_engine_normalizes_publication_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = load_engine(monkeypatch)
    response = SimpleNamespace(
        json=lambda: {
            "results": [
                {
                    "url": "https://doi.org/10.1000/example",
                    "title": " Care outcomes ",
                    "author": " Researcher ",
                    "publishedDate": "2026-07-01T00:00:00Z",
                    "highlights": ["First finding.", "Second finding."],
                }
            ]
        }
    )

    output = engine.response(response)

    assert output.items == [
        {
            "url": "https://doi.org/10.1000/example",
            "title": "Care outcomes",
            "content": "First finding. Second finding.",
            "publishedDate": datetime.fromisoformat("2026-07-01T00:00:00+00:00"),
            "author": "Researcher",
        }
    ]
