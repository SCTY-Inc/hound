# SearXNG discovery overlay

<!-- Diátaxis: how-to -->

This overlay extends an unmodified, pinned upstream SearXNG image. It enables
JSON output for Hound and adds the official Federal Register API as a native
search engine in the `government` and `news` categories.

Run it loopback-only and replace the digest with the reviewed release:

```bash
SEARXNG_SECRET="$(openssl rand -hex 32)" docker run --rm --name hound-searxng \
  -p 127.0.0.1:8080:8080 \
  -e SEARXNG_SECRET \
  -v "$PWD/examples/searxng/settings.yml:/etc/searxng/settings.yml:ro" \
  ghcr.io/searxng/searxng@sha256:419d2915279be335146a440fd0ad25c657738dde7046387c0d5592cb6aa472d2
```

Confirm the engine and query it through Hound:

```bash
curl -fsS http://127.0.0.1:8080/config | jq \
  '.engines[] | select(.name == "federal register")'

SEARXNG_ENDPOINT=http://127.0.0.1:8080 hound search \
  --adapter adapters/searxng/hound-driver.json \
  --json '{
    "query":"family caregiver benefits",
    "limit":10,
    "options":{"engines":["federal register"],"max_pages":1}
  }'
```

Add a settings-only `json_engine` when an API is search-shaped and returns
stable public URLs. Keep authoritative datasets, exhaustive pagination, and
domain records in owner adapters instead of flattening them into search results.
