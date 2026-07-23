import json
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_searxng_service_is_pinned_and_loopback_only() -> None:
    service = (ROOT / "ops/systemd/hound-searxng.service").read_text(encoding="utf-8")

    assert "127.0.0.1:8888:8080" in service
    assert "ghcr.io/searxng/searxng@sha256:" in service
    assert ":latest" not in service
    assert "--pull never" in service
    assert 'openssl rand -hex 32' in service
    assert '--env SEARXNG_SECRET ' in service
    assert '--env SEARXNG_SECRET=' not in service
    assert "EnvironmentFile=%h/.env" in service
    assert "--env EXA_API_KEY " in service
    assert "--env EXA_API_KEY=" not in service
    assert (
        "--volume %h/.config/hound/searxng-exa.py:"
        "/usr/local/searxng/searx/engines/exa.py:ro"
    ) in service


def test_operational_overlay_enables_pulse_routes_and_json() -> None:
    settings = yaml.safe_load(
        (ROOT / "ops/searxng/settings.yml").read_text(encoding="utf-8")
    )
    engines = {engine["name"]: engine for engine in settings["engines"]}

    assert settings["use_default_settings"] is True
    assert "json" in settings["search"]["formats"]
    assert engines["arxiv"] == {
        "name": "arxiv",
        "disabled": False,
        "timeout": 15,
    }
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
    assert engines["federal register"]["disabled"] is False


def test_searxng_adapter_excludes_only_build_outputs_from_owner_snapshots() -> None:
    manifest = json.loads(
        (ROOT / "adapters/searxng/hound-driver.json").read_text(encoding="utf-8")
    )

    assert manifest["ignored_snapshot_excludes"] == [
        ".pytest_cache",
        "dist",
        "examples/__pycache__",
        "examples/family_suv_watch/__pycache__",
        "examples/searxng/__pycache__",
        "tests/__pycache__",
    ]
