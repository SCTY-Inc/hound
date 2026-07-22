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


def test_operational_overlay_enables_pulse_routes_and_json() -> None:
    settings = yaml.safe_load(
        (ROOT / "ops/searxng/settings.yml").read_text(encoding="utf-8")
    )
    engines = {engine["name"]: engine for engine in settings["engines"]}

    assert settings["use_default_settings"] is True
    assert "json" in settings["search"]["formats"]
    assert engines["arxiv"]["disabled"] is False
    assert engines["federal register"]["disabled"] is False
