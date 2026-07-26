#!/usr/bin/env python3
"""Re-runnable read-only probe of the Hound SearXNG overlay.

Classifies every default-enabled engine with domain-appropriate queries and
records the reachable engine set behind every category. Standard library only,
matching the zero-dependency runtime of this repository.

The harness is read-only against every corpus: it issues HTTP GET requests to
the SearXNG endpoint and writes nothing except the report file the operator
names with --out. Total requests are bounded by --max-requests.

Usage:

    SEARXNG_ENDPOINT=http://127.0.0.1:8888 python3 ops/searxng/probe.py \
        --out /tmp/searxng-probe.json

    # narrow re-check of a single route
    python3 ops/searxng/probe.py --engines 'google cse,exa web' --probes 5

Status vocabulary matches docs/searxng-sources.md:

  responsive       every probe returned leads and no probe reported a failure
  query-dependent  no failures, but at least one probe returned zero leads
  no-leads         no failures and no probe returned a lead
  blocked          at least one probe reported an upstream failure; a route that
                   fails intermittently is still blocked for routing purposes,
                   because it cannot be a sole source

"Leads" means entries in the SearXNG `results` array, because that is the only
array src/hound_web_adapters/searxng.py converts into Hound leads. Engines that
answer through `answers` or `infoboxes` instead are counted separately and
flagged `answer_only`: they work in SearXNG and are invisible to Hound.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any

DEFAULT_ENDPOINT = "http://127.0.0.1:8888"
USER_AGENT = "hound-searxng-probe/0.3"

# Queries chosen so that each engine is asked something inside its own domain.
# A caregiver policy query proves nothing about `docker hub`, so every engine
# either names its own probes here or inherits them from its first category.
ENGINE_QUERIES: dict[str, list[str]] = {
    "arch linux wiki": ["systemd", "pacman", "kernel module"],
    "artic": ["monet", "japanese woodblock print", "portrait"],
    "arxiv": ["transformer attention", "quantum error correction", "caregiver burden"],
    "askubuntu": ["apt broken packages", "grub rescue", "wifi driver"],
    "bandcamp": ["ambient", "jazz trio", "shoegaze"],
    "bt4g": ["ubuntu", "debian iso", "blender"],
    "chefkoch": ["kuchen", "kartoffelsuppe", "brot backen"],
    "currency": ["1 USD in EUR", "100 GBP to USD", "50 EUR in JPY"],
    "deviantart": ["dragon art", "landscape painting", "character design"],
    "devicons": ["github", "python", "docker"],
    "dictzone": ["house", "water", "book"],
    "docker hub": ["nginx", "postgres", "redis"],
    "etymonline": ["serendipity", "quarantine", "salary"],
    "federal register": [
        "home and community based services",
        "medicare advantage",
        "clean air",
    ],
    "genius": ["bohemian rhapsody", "hallelujah", "imagine"],
    "gentoo": ["portage", "kernel", "systemd"],
    "github": ["kubernetes operator", "async runtime", "static site generator"],
    "hoogle": ["foldr", "Maybe", "map"],
    "lemmy communities": ["selfhosted", "privacy", "linux"],
    "lemmy users": ["linux", "privacy", "tech"],
    "lingva": ["house", "water", "book"],
    "lucide": ["home", "user", "search"],
    "mankier": ["grep", "systemctl", "ssh"],
    "mastodon hashtags": ["opensource", "privacy", "linux"],
    "mastodon users": ["linux", "security", "developer"],
    "mdn": ["fetch api", "flexbox", "promise"],
    "mymemory translated": ["house", "water", "book"],
    "openairedatasets": ["caregiver burden", "air quality", "dementia"],
    "openairepublications": ["caregiver burden", "air quality", "dementia"],
    "openstreetmap": ["Berlin", "Boston City Hall", "Paris"],
    "pdbe": ["hemoglobin", "lysozyme", "insulin"],
    "photon": ["Berlin", "Boston", "Paris"],
    "pubmed": ["caregiver burden intervention", "dementia care", "hypertension"],
    "pypi": ["requests", "numpy", "httpx"],
    "radio browser": ["jazz", "bbc", "classical"],
    "stackoverflow": ["python asyncio", "git merge conflict", "css flexbox"],
    "superuser": ["ssh tunnel", "windows path variable", "flush dns cache"],
    "wikicommons.audio": ["piano", "bird song", "bell"],
    "wikicommons.files": ["map", "diagram", "poster"],
    "wikicommons.images": ["moon", "cat", "eiffel tower"],
    "wikicommons.videos": ["earth", "volcano", "train"],
    "wikidata": ["Medicaid", "Berlin", "Ada Lovelace"],
    "wikipedia": ["Medicaid", "Caregiver", "Berlin"],
    "wiktionary": ["water", "house", "serendipity"],
    "wordnik": ["serendipity", "ubiquitous", "ephemeral"],
    "wttr.in": ["Boston", "Berlin", "Paris"],
}

# Fallback probes, selected by the engine's first declared category.
CATEGORY_QUERIES: dict[str, list[str]] = {
    "currency": ["1 USD in EUR", "100 GBP to USD", "50 EUR in JPY"],
    "define": ["serendipity", "ubiquitous", "ephemeral"],
    "dictionaries": ["water", "house", "serendipity"],
    "files": ["ubuntu", "debian", "blender"],
    "general": [
        "medicaid home care waiver",
        "direct care workforce shortage",
        "climate adaptation planning",
    ],
    "government": [
        "home and community based services",
        "medicare advantage",
        "clean air",
    ],
    "icons": ["home", "user", "search"],
    "images": ["golden gate bridge", "red fox", "mountain sunrise"],
    "it": ["python asyncio", "docker compose", "git rebase"],
    "lyrics": ["bohemian rhapsody", "hallelujah", "imagine"],
    "map": ["Berlin", "Boston", "Paris"],
    "music": ["jazz trio", "ambient", "piano sonata"],
    "news": ["medicaid policy", "home care workforce", "federal budget"],
    "other": ["recipe", "weather", "dictionary"],
    "packages": ["nginx", "requests", "redis"],
    "q&a": ["python asyncio", "git merge conflict", "css flexbox"],
    "radio": ["jazz", "bbc", "classical"],
    "repos": ["kubernetes operator", "async runtime", "static site generator"],
    "science": ["caregiver burden intervention", "dementia care", "air quality"],
    "scientific publications": [
        "caregiver burden intervention",
        "dementia care",
        "air quality",
    ],
    "social media": ["opensource", "privacy", "linux"],
    "software wikis": ["systemd", "kernel", "package manager"],
    "translate": ["house", "water", "book"],
    "videos": ["python tutorial", "caregiver support", "guitar lesson"],
    "weather": ["Boston", "Berlin", "Paris"],
    "web": [
        "medicaid home care waiver",
        "direct care workforce shortage",
        "climate adaptation planning",
    ],
    "wikimedia": ["Medicaid", "Berlin", "election"],
}

GENERIC_QUERIES = ["open source", "public health", "climate"]

# Engines carrying a credential field in the pinned SearXNG image, plus the two
# engines this overlay adds. "required" means the engine cannot run without it.
# Everything not listed here runs keyless, so the disabled majority is not
# gated behind a purchase. Re-derive with:
#   docker exec hound-searxng cat /usr/local/searxng/searx/settings.yml
CREDENTIALS: dict[str, tuple[str, bool]] = {
    "exa web": ("EXA_API_KEY", True),
    "exa publications": ("EXA_API_KEY", True),
    "iqiyi": ("api_key", True),
    "mymemory translated": ("api_key", False),
    "semantic scholar": ("api_client_id", False),
}

# SearXNG queries only the default-enabled engines for a tab category, but
# queries every engine carrying a non-tab category regardless of its disabled
# flag. Source: categories_as_tabs in the image's settings.yml.
TAB_CATEGORIES = frozenset(
    {
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
)


def inventory(config: dict[str, Any]) -> str:
    """Markdown table of every engine in the running configuration."""
    rows = ["| Engine | Shortcut | Categories | Enabled | Credential |", "| --- | --- | --- | --- | --- |"]
    for engine in sorted(config["engines"], key=lambda item: item["name"]):
        name = engine["name"]
        key, required = CREDENTIALS.get(name, ("", False))
        if not key:
            credential = "none"
        else:
            credential = f"`{key}` ({'required' if required else 'optional'})"
        rows.append(
            f"| `{name}` | `{engine.get('shortcut', '')}` "
            f"| {', '.join(engine.get('categories', [])) or '—'} "
            f"| {'yes' if engine.get('enabled') else 'no'} | {credential} |"
        )
    return "\n".join(rows)


class Budget:
    """Hard ceiling on outbound requests, so a re-run stays bounded."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def take(self) -> None:
        if self.used >= self.limit:
            raise SystemExit(f"probe budget exhausted after {self.used} requests")
        self.used += 1


def fetch(url: str, budget: Budget, timeout: float) -> tuple[int, bytes]:
    budget.take()
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise SystemExit(f"SearXNG endpoint unreachable: {url}: {error}") from error


def search(
    base: str,
    query: str,
    budget: Budget,
    timeout: float,
    *,
    engine: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """One bounded, single-page JSON search. Explicit engines use bang syntax,
    exactly as src/hound_web_adapters/searxng.py builds them."""
    parameters: dict[str, str] = {"format": "json", "pageno": "1"}
    if engine is not None:
        parameters["q"] = f"!{engine.replace(' ', '_')} {query}"
    else:
        parameters["q"] = query
    if category is not None:
        parameters["categories"] = category
    url = f"{base}/search?{urllib.parse.urlencode(parameters)}"
    status, body = fetch(url, budget, timeout)
    if status != 200:
        return {"transport_error": f"HTTP {status}", "results": [], "unresponsive_engines": []}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {"transport_error": "non-JSON body", "results": [], "unresponsive_engines": []}
    if not isinstance(payload, dict):
        return {"transport_error": "non-object body", "results": [], "unresponsive_engines": []}
    return payload


def domains(results: list[Any]) -> list[str]:
    found: list[str] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        host = urllib.parse.urlparse(url).netloc.lower()
        if host and host not in found:
            found.append(host)
    return found


def responders(results: list[Any]) -> list[str]:
    found: set[str] = set()
    for item in results:
        if isinstance(item, dict) and isinstance(item.get("engines"), list):
            found.update(name for name in item["engines"] if isinstance(name, str))
    return sorted(found)


def failures(payload: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}
    for entry in payload.get("unresponsive_engines") or []:
        if isinstance(entry, list) and len(entry) == 2:
            found[str(entry[0]).casefold()] = str(entry[1])
    return found


def queries_for(name: str, categories: list[str], count: int) -> list[str]:
    pool = ENGINE_QUERIES.get(name)
    if pool is None:
        for category in categories:
            if category in CATEGORY_QUERIES:
                pool = CATEGORY_QUERIES[category]
                break
    if pool is None:
        pool = GENERIC_QUERIES
    if count <= len(pool):
        return pool[:count]
    return [pool[index % len(pool)] for index in range(count)]


def verdict(outcomes: list[str]) -> str:
    tally = Counter(outcomes)
    if tally["blocked"]:
        # An intermittently failing route still cannot be a sole source.
        return "blocked"
    if tally["leads"] == len(outcomes):
        return "responsive"
    if tally["leads"]:
        return "query-dependent"
    return "no-leads"


def probe_engines(
    base: str,
    engines: list[dict[str, Any]],
    budget: Budget,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for position, engine in enumerate(engines, start=1):
        name = engine["name"]
        probes: list[dict[str, Any]] = []
        for query in queries_for(name, engine.get("categories", []), args.probes):
            payload = search(base, query, budget, args.timeout, engine=name)
            failed = failures(payload)
            results = payload.get("results") or []
            # Hound only converts `results` into leads. `answers` and
            # `infoboxes` are real SearXNG output the adapter discards.
            side = len(payload.get("answers") or []) + len(payload.get("infoboxes") or [])
            error = payload.get("transport_error") or failed.get(name.casefold())
            if error:
                outcome = "blocked"
            elif results:
                outcome = "leads"
            else:
                outcome = "zero"
            probes.append(
                {
                    "query": query,
                    "outcome": outcome,
                    "leads": len(results),
                    "answers_and_infoboxes": side,
                    "distinct_domains": len(domains(results)),
                    "error": error,
                }
            )
            time.sleep(args.delay)
        status = verdict([probe["outcome"] for probe in probes])
        intermittent = status == "blocked" and any(p["outcome"] == "leads" for p in probes)
        side_total = max(p["answers_and_infoboxes"] for p in probes)
        entry = {
            "engine": name,
            "shortcut": engine.get("shortcut"),
            "categories": engine.get("categories", []),
            "status": status,
            "intermittent": intermittent,
            # True when SearXNG answered but Hound would see nothing.
            "answer_only": status == "no-leads" and side_total > 0,
            "max_leads": max(p["leads"] for p in probes),
            "max_answers_and_infoboxes": side_total,
            "max_distinct_domains": max(p["distinct_domains"] for p in probes),
            "errors": sorted({p["error"] for p in probes if p["error"]}),
            "probes": probes,
        }
        report.append(entry)
        flag = " INTERMITTENT" if intermittent else ""
        if entry["answer_only"]:
            flag = " ANSWER-ONLY (invisible to Hound)"
        print(
            f"[{position}/{len(engines)}] {name:28s} {status:15s}"
            f" leads<={entry['max_leads']:<3d}{flag}",
            file=sys.stderr,
            flush=True,
        )
    return report


def probe_categories(
    base: str,
    categories: list[str],
    enabled: set[str],
    budget: Budget,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for category in categories:
        query = CATEGORY_QUERIES.get(category, GENERIC_QUERIES)[0]
        payload = search(base, query, budget, args.timeout, category=category)
        results = payload.get("results") or []
        seen = responders(results)
        failed = sorted(failures(payload))
        reached = sorted(set(seen) | set(failed))
        beyond = sorted(name for name in reached if name.casefold() not in enabled)
        report.append(
            {
                "category": category,
                "tab_category": category in TAB_CATEGORIES,
                "query": query,
                "leads": len(results),
                "responding_engines": seen,
                "unresponsive_engines": failed,
                "engines_beyond_default_enabled": beyond,
            }
        )
        kind = "tab " if category in TAB_CATEGORIES else "sub "
        print(
            f"[category {kind}] {category:26s} leads={len(results):<4d}"
            f" reached={len(reached):<3d} beyond-enabled={len(beyond)}",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(args.delay)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("SEARXNG_ENDPOINT", DEFAULT_ENDPOINT))
    parser.add_argument("--probes", type=int, default=3, help="probes per engine (default 3)")
    parser.add_argument("--delay", type=float, default=1.5, help="seconds between requests")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--max-requests", type=int, default=400)
    parser.add_argument("--engines", help="comma-separated subset of engine names")
    parser.add_argument("--skip-categories", action="store_true")
    parser.add_argument("--skip-engines", action="store_true")
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="print the engine inventory as markdown and exit without probing",
    )
    parser.add_argument("--out", help="write the JSON report here")
    args = parser.parse_args()

    base = args.endpoint.rstrip("/")
    budget = Budget(args.max_requests)

    status, body = fetch(f"{base}/config", budget, args.timeout)
    if status != 200:
        raise SystemExit(f"SearXNG /config returned HTTP {status}")
    config = json.loads(body)
    identity = hashlib.sha256(body).hexdigest()

    all_engines = config["engines"]
    enabled = [engine for engine in all_engines if engine.get("enabled")]
    enabled_names = {engine["name"].casefold() for engine in enabled}

    if args.inventory:
        print(f"<!-- SearXNG config identity {identity} -->")
        print(f"<!-- {len(all_engines)} engines, {len(enabled)} enabled -->\n")
        print(inventory(config))
        return 0

    selected = enabled
    if args.engines:
        wanted = {name.strip().casefold() for name in args.engines.split(",") if name.strip()}
        selected = [engine for engine in enabled if engine["name"].casefold() in wanted]
        missing = wanted - {engine["name"].casefold() for engine in selected}
        if missing:
            raise SystemExit(f"not enabled in this configuration: {sorted(missing)}")

    print(
        f"config identity {identity}\n"
        f"{len(all_engines)} engines, {len(enabled)} enabled, "
        f"probing {len(selected)} with {args.probes} queries each",
        file=sys.stderr,
        flush=True,
    )

    engine_report = [] if args.skip_engines else probe_engines(base, selected, budget, args)
    category_report: list[dict[str, Any]] = []
    if not args.skip_categories:
        category_report = probe_categories(
            base, config.get("categories", []), enabled_names, budget, args
        )

    tally = Counter(entry["status"] for entry in engine_report)
    report = {
        "schema_version": "hound.searxng.probe.v1",
        "endpoint": base,
        "config_sha256": identity,
        "searxng_version": config.get("version"),
        "engine_totals": {"all": len(all_engines), "enabled": len(enabled)},
        "probes_per_engine": args.probes,
        "requests_made": budget.used,
        "summary": dict(sorted(tally.items())),
        "answer_only_engines": sorted(
            entry["engine"] for entry in engine_report if entry["answer_only"]
        ),
        "intermittent_engines": sorted(
            entry["engine"] for entry in engine_report if entry["intermittent"]
        ),
        "engines": engine_report,
        "categories": category_report,
    }

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        print(f"\nwrote {args.out} ({budget.used} requests)", file=sys.stderr)
    else:
        print(text)
    print(f"summary: {dict(sorted(tally.items()))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
