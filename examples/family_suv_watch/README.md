# Run the family SUV watch

<!-- Diátaxis: how-to -->

This example proves that Hound's three web primitives compose into a useful
owner workflow without putting scheduling, valuation, browser policy, or Discord
inside the kernel.

The cycle performs at most five SearXNG searches, deduplicates candidate URLs,
asks Firecrawl to extract each selected detail page, stores verified observations
in SQLite, values groups with at least three comparable asking prices, and emits
Discord webhook payloads only for new or changed listings at least 15% below the
comparable median.

## Configure services

Run a trusted SearXNG instance with JSON output enabled, then export its URL and
the hosted Firecrawl credential:

```bash
export SEARXNG_ENDPOINT=http://127.0.0.1:8080
export FIRECRAWL_API_KEY=...
```

Review `config.json` before running. Paths are resolved relative to that file.
The example deliberately has no Facebook Marketplace credentials, KBB scraper,
seller messaging, negotiation, booking, deposit, or automatic browser fallback.

## Run one cycle

```bash
uv run python examples/family_suv_watch/watch.py \
  --config examples/family_suv_watch/config.json \
  --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Outputs live under `examples/family_suv_watch/.hound/`:

- `web/`: immutable Hound provenance records;
- `listings.sqlite3`: listings, observations, and alert dedupe;
- `discord-alerts.json`: Discord-ready payloads created by this run;
- `browser-review.json`: URLs that need an explicit human/agent decision before
  using Camofox.

The workflow admits a listing only when the extracted document is the direct
candidate URL and its metadata contains a complete, verified `vehicle` object
with title, history, and recall checks. Ordinary Firecrawl output will often lack
that domain-specific object; those pages go to review rather than being guessed
from prose. A real owner adapter can derive the object from reviewed dealer
schemas without changing Hound.

## Schedule externally

Hound does not contain a scheduler. Use the operating system, for example 8:30
AM Eastern with cron on a host configured for `America/New_York`:

```cron
30 8 * * * cd /path/to/hound && uv run python examples/family_suv_watch/watch.py --config examples/family_suv_watch/config.json --as-of "$(date -u +\%Y-\%m-\%dT\%H:\%M:\%SZ)"
```

Sending `discord-alerts.json` is also an owner-side effect. Review or deliver it
through the existing Discord workflow; Hound's record ID remains in every alert.

## Escalate to Camofox explicitly

When `browser-review.json` contains a public URL whose static extraction failed,
open it deliberately rather than enabling hidden fallback:

```bash
uv run hound-research interact \
  --adapter adapters/camofox/hound-driver.json \
  --record-root examples/family_suv_watch/.hound/web \
  --json '{"action":"open","url":"https://dealer.example/vehicle"}'
```

Use the returned session and tab IDs for `snapshot` and any required bounded
action, capture the evidence, then call `close`. Anonymous disposable sessions
are the only mode in this example.
