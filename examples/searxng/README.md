# SearXNG discovery overlay

<!-- Diátaxis: how-to -->

This overlay extends an unmodified, pinned upstream SearXNG image. It enables
JSON output for Hound, adds the official Federal Register API as a native
search engine, and mounts Exa as the `exa web` and `exa publications` engines.
Exa remains behind SearXNG: Hound sees ordinary search leads and never receives
its API key.

Set `EXA_API_KEY`, then run the reviewed image loopback-only:

```bash
SEARXNG_SECRET="$(openssl rand -hex 32)" docker run --rm --name hound-searxng \
  -p 127.0.0.1:8080:8080 \
  -e SEARXNG_SECRET \
  -e EXA_API_KEY \
  -v "$PWD/examples/searxng/settings.yml:/etc/searxng/settings.yml:ro" \
  -v "$PWD/examples/searxng/exa.py:/usr/local/searxng/searx/engines/exa.py:ro" \
  ghcr.io/searxng/searxng@sha256:419d2915279be335146a440fd0ad25c657738dde7046387c0d5592cb6aa472d2
```

Confirm the reviewed engines and query Exa through Hound:

```bash
curl -fsS http://127.0.0.1:8080/config | jq \
  '.engines[]
  | select(
      .name == "federal register"
      or .name == "exa web"
      or .name == "exa publications"
    )'

SEARXNG_ENDPOINT=http://127.0.0.1:8080 hound search \
  --adapter adapters/searxng/hound-driver.json \
  --json '{
    "query":"caregiving intervention outcomes",
    "limit":10,
    "options":{"engines":["exa publications"],"time_range":"month","max_pages":1}
  }'
```

Use `exa web` for broad web discovery and `exa publications` for scholarly
material. Both routes use the same service-owned credential, but only the
publication route supplies Exa's explicit publication category.

Add a settings-only `json_engine` when an API is search-shaped and returns
stable public URLs without a secret header. A credentialed custom engine reads
its credential from the separately operated SearXNG environment, not from
Hound or `settings.yml`. Keep authoritative datasets, exhaustive pagination,
and domain records in owner adapters instead of flattening them into search
results. Consult the dated
[SearXNG source map](../../docs/searxng-sources.md) before selecting a route for
a recurring workflow.
