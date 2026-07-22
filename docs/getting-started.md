# Get started with Hound

Diátaxis: how-to

This guide installs Hound from source and runs the included read-only example
driver.

## Prerequisites

Install Git, Python 3.12 or newer, and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/).

## Clone and verify Hound

```bash
git clone https://github.com/SCTY-Inc/hound.git
cd hound
uv sync --locked
uv run hound --version
uv run pytest -q
```

To install the CLI independently of the checkout:

```bash
uv tool install git+https://github.com/SCTY-Inc/hound.git
hound --version
```

## Run the example driver

A Hound manifest locates its owner repository, declares literal driver argv, and
allowlists each capability. First validate the manifest and protocol handshake:

```bash
uv run hound driver check \
  --driver examples/status/hound-driver.json
```

Then invoke the declared read capability:

```bash
uv run hound invoke \
  --driver examples/status/hound-driver.json \
  --operation corpus.status \
  --input examples/status/request.json
```

Both commands emit one compact JSON object on stdout. The status response echoes
the example request through the repository-owned driver.

## Check the web adapters

The first-party adapters are ordinary Hound drivers and can be checked without
calling their services:

```bash
uv run hound driver check --driver adapters/searxng/hound-driver.json
uv run hound driver check --driver adapters/firecrawl/hound-driver.json
uv run hound driver check --driver adapters/camofox/hound-driver.json
```

Run the [versioned SearXNG overlay](../examples/searxng/README.md), or use a
trusted instance whose JSON format is enabled:

```bash
export SEARXNG_ENDPOINT=http://127.0.0.1:8080
uv run hound search \
  --adapter adapters/searxng/hound-driver.json \
  --json '{
    "query":"family caregiver benefits",
    "limit":5,
    "options":{"engines":["federal register"],"max_pages":1}
  }'
```

Use either `engines` or `categories`. SearXNG options also support `language`,
`time_range` (`day`, `month`, or `year`), `safesearch` (`0` through `2`), and
bounded `max_pages` (`1` through `5`). Pass routing through `options`; the
adapter rejects SearXNG bang, language-prefix, and timeout syntax hidden inside
the query. Hound checks `/config` before search so a missing or disabled route
fails visibly.

The command returns compact leads and writes the exact adapter response plus its
request, adapter identity, hashes, and normalized output under `.hound/web/`.
Use `hound extract` only after selecting a known URL. Use `hound interact` only
when static extraction cannot operate the page.

## Use the composed source lifecycle

An owner can preserve the discovery-to-evidence handoff by declaring the three
source read capabilities plus one top-level `hound.source.v2` adapter map. Run
them in order:

```bash
hound source discover --driver research/hound-driver.json --input request.json \
  > /tmp/discovery-response.json
jq '{schema_version:"hound.source.capture.input.v2", discovery:.data, owner_input:{}}' \
  /tmp/discovery-response.json > /tmp/capture-input.json
hound source capture --driver research/hound-driver.json \
  --input /tmp/capture-input.json > /tmp/capture-response.json
jq '{capture_set:.data}' /tmp/capture-response.json > /tmp/inspect-input.json
hound source inspect --driver research/hound-driver.json \
  --input /tmp/inspect-input.json
```

Replace the empty `owner_input` when the owner driver needs ranking or selection
parameters. Discovery creates immutable search records and exact lead IDs.
Capture extracts only owner-selected record/lead references through the named
adapter. Inspect verifies both parent and extract records before the owner
interprets them. Direct `hound extract` calls must declare
`lineage:{"kind":"direct"}`; discovered URLs use search record and lead IDs
instead.
See [Protocol v1](protocol.md) for the exact versioned payloads.

## Add a driver to an owner repository

1. Put a `hound.driver.v1` manifest and a JSON stdin/stdout driver in the owner
   Git repository.
2. Set `owner.repo` relative to the manifest directory so it resolves to the
   exact Git root.
3. Declare only the capabilities, environment variables, and write scopes the
   driver needs.
4. Run `hound driver check --driver <manifest>`.
5. Use `hound invoke --operation <name>` for reads. Use `hound plan`, review the
   saved file, then `hound execute` for writes.

The complete wire contract is in [Protocol v1](protocol.md). Read the
[security model](security-model.md) before enabling writes, adapter credentials,
or browser interaction.
