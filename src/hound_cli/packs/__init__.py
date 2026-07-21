"""Built-in source packs exposed through Hound's provider contract."""

from __future__ import annotations

PACKS = {
    "web": ("exa", "firecrawl"),
    "scholarly": ("arxiv",),
}


def provider_pack(provider: str) -> str | None:
    for pack, providers in PACKS.items():
        if provider in providers:
            return pack
    return None


__all__ = ["PACKS", "provider_pack"]
