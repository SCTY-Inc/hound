# Hound

<!-- Diátaxis: explanation -->

**Make research automation prove what it read, what it plans to change, and what
it changed.**

Hound is a CLI execution layer for research agents and data pipelines that
search, extract, interact with the web, and update Git repositories. It runs
replaceable adapters through one constrained protocol, stores source material
with provenance and lineage, requires deterministic plans before writes, rejects
drift after review, and leaves verifiable records.

## The problem

A research script is easy to trust while one person runs it by hand. The risk
changes when it runs repeatedly, calls external providers, and writes into a
knowledge base, dataset, report, or published edition.

You need concrete answers to questions such as:

- Which source bytes support this output?
- Did the workflow treat search results as leads or as evidence?
- What files will change before the write happens?
- Did the request, repository, driver, or environment change after review?
- Did the driver touch anything outside its declared scope?
- Can someone else verify the run without trusting the agent's explanation?

Most agent scripts answer those questions with logs and convention. Hound makes
them part of the execution contract.

## How Hound fits

Your repository owns the domain decisions. A small **driver** decides what to
search, what evidence to keep, how to interpret it, and what the repository
should contain.

Hound owns the risky mechanics around that driver:

```text
request
  → owner driver defines the operation
  → Hound searches for leads and records provider responses
  → selected URLs are extracted; browser interaction is explicit and last
  → owner driver proposes repository changes
  → Hound creates a content-bound plan
  → a person approves that exact plan when required
  → Hound executes, checks scope, and records the run
  → anyone with the records can run hound verify
```

The manifest between them declares literal driver commands, capabilities,
credentials, timeouts, approval gates, and write scopes. Drivers communicate
with Hound through versioned JSON on stdin and stdout, so they can be written in
Python, TypeScript, or any other executable language.

## Where people use it

Hound fits recurring workflows where source quality and repository integrity
matter:

- competitor and market monitoring;
- policy, benefits, or resource-database updates;
- evidence-backed knowledge base maintenance;
- research digests and time-bounded publications;
- agent-run ETL that needs a human approval boundary.

It is most useful when the output becomes durable state rather than a disposable
chat response.

## Try it in two minutes

Hound requires Python 3.12 or newer, Git, and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone https://github.com/SCTY-Inc/hound.git
cd hound
uv sync --locked

uv run hound driver check \
  --driver examples/status/hound-driver.json

uv run hound invoke \
  --driver examples/status/hound-driver.json \
  --operation corpus.status \
  --input examples/status/request.json
```

The bundled example is a read-only owner driver. The first command validates its
manifest and protocol handshake. The second runs a declared capability and
returns one compact JSON response.

Install the command independently with:

```bash
uv tool install git+https://github.com/SCTY-Inc/hound.git
hound --version
```

## Run a guarded write

Write capabilities always plan first. The plan binds the input, cutoff date,
Hound version and source, driver manifest, allowlisted environment, repository
state, expected writes, and declared scopes.

```bash
# 1. Create the plan. Nothing is written to the owner repository.
hound plan \
  --driver research/hound-driver.json \
  --operation corpus.apply \
  --input research/request.json \
  --as-of 2026-07-21 \
  --output /tmp/hound-plan.json

# 2. Review that file, then approve its exact plan ID and write scope.
hound approve \
  --plan /tmp/hound-plan.json \
  --reviewer operator@example.com \
  --output /tmp/hound-approval.json

# 3. Execute. Hound replans first and rejects any drift.
hound execute \
  --driver research/hound-driver.json \
  --plan /tmp/hound-plan.json \
  --approval /tmp/hound-approval.json \
  | tee /tmp/hound-result.json

# 4. Independently verify the immutable run record.
hound verify "$(jq -r .run_dir /tmp/hound-result.json)"
```

Read capabilities execute directly. Existing owner drivers may use the composed
source lifecycle:

```text
source discover → source capture → source inspect
```

`discover` executes only owner-declared search adapters and returns immutable
search-record/lead references. `capture` extracts exact selected references
through an explicit adapter. `inspect` verifies every referenced search and
extract record before owner interpretation. Drivers opt in once with a
`hound.source.v2` adapter map. There is no provider registry or hidden fallback.

The lower-level web adapter surface remains explicit:

```text
search → extract → interact only when required
```

## Web adapters

Hound's first adapters use the same reviewed driver protocol as external ones:

- **Search — SearXNG:** federated candidate discovery with explicit engine or
  category routing, language, time range, safe search, and bounded paging.
  Suggestions, corrections, configuration identity, and unresponsive engines
  remain visible. Results are leads, never evidence.
- **Extract — Firecrawl:** known-URL markdown and metadata. One-page scrape is
  normal; a crawl requires an explicit page cap no greater than 20.
- **Interact — Camofox:** anonymous disposable browser actions for JavaScript or
  page interaction that static extraction cannot handle.

Each command receives an explicit adapter manifest. Hound never silently chooses
or escalates providers. Exact provider responses, normalized output, adapter Git
identity, requests, hashes, and failures are stored in immutable web run records.
A transformed markdown document or browser snapshot is labeled
`provider-derived`; it is not misrepresented as raw origin bytes. The
[upstream SearXNG overlay](examples/searxng/README.md) demonstrates first-class
government discovery through the Federal Register API without maintaining a
fork.

## What Hound enforces

- **Evidence boundary:** discovery results are marked as leads. Verified captures
  bind raw bytes to source URL, provider, retrieval time, media type, and hashes.
- **Credential boundary:** adapters receive only manifest-allowlisted
  environment variables, and Hound rejects credential material in their output.
- **Review boundary:** approvals bind to one deterministic plan and write-scope
  hash. Repository or environment drift invalidates the plan.
- **Mutation boundary:** check, read, and planning calls fail if the driver
  changes the owner repository. Executions detect out-of-scope writes.
- **Audit boundary:** each execution creates a strict, create-only run record
  that `hound verify` can check independently.

## What Hound does not build

- No giant browse tool: call `search`, `extract`, and `interact` explicitly.
- No automatic `search → extract → interact` escalation: compose those calls in
  the owner driver, source lifecycle, or shell.
- No scheduler, database, valuation logic, or notifier: use files, SQLite, cron,
  and the destination's existing delivery tool.
- No provider lifecycle manager: run pinned services with Docker, systemd, or
  tmux.
- No MCP in core: a harness may wrap the three CLI verbs without privileged
  access.
- No authenticated browser state in the first adapters: Camofox sessions are
  anonymous and disposable.
- No prompt-injection or network-sandbox claim Hound cannot enforce: outputs are
  labeled untrusted; model context and network isolation belong to their actual
  owning layers.

## Trust model

Hound runs reviewed owner drivers. It does not sandbox untrusted plugins.
Write-scope enforcement is a checked postcondition: Hound detects and records an
out-of-scope mutation, but it does not automatically roll the repository back.
Linux provides the strongest detached-process containment.

Read the [security model](docs/security-model.md) before enabling writes or
adapter credentials.

## Commands

```text
hound driver check
hound invoke
hound plan
hound approve
hound execute
hound verify
hound source discover|capture|inspect
hound search
hound extract
hound interact
hound capture store|verify
```

## Documentation

- [Vision](VISION.md)
- [Getting started](docs/getting-started.md)
- [Protocol v1 reference](docs/protocol.md)
- [Security model](docs/security-model.md)
- [Local development](docs/development.md)
- [Security policy](SECURITY.md)
- [SearXNG discovery overlay](examples/searxng/README.md)
- [Family SUV watch example](examples/family_suv_watch/README.md)

Hound is pre-1.0. Wire formats are versioned; the Python package API is not yet
stable. The distribution is `evidence-hound`, and the installed command is
`hound`.

## License

Copyright © 2026 SCTY. Hound is proprietary and publicly available for
inspection. See [LICENSE.md](LICENSE.md).
