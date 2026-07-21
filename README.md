# Hound

<!-- Diátaxis: explanation -->

**Make research automation prove what it read, what it plans to change, and what
it changed.**

Hound is a CLI execution layer for research agents and data pipelines that read
from the web and update a Git repository. It isolates provider credentials,
stores source material with provenance, requires deterministic plans before
writes, rejects drift after review, and leaves a verifiable run record.

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
  → Hound discovers and captures sources
  → owner driver proposes repository changes
  → Hound creates a content-bound plan
  → a person approves that exact plan when required
  → Hound executes, checks scope, and records the run
  → anyone with the records can run hound run verify
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

uv run hound corpus status \
  --driver examples/status/hound-driver.json \
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
hound corpus apply \
  --driver research/hound-driver.json \
  --input research/request.json \
  --as-of 2026-07-21 \
  --plan-out /tmp/hound-plan.json

# 2. Review that file, then approve its exact plan ID and write scope.
hound approval create \
  --plan /tmp/hound-plan.json \
  --reviewer operator@example.com \
  --output /tmp/hound-approval.json

# 3. Execute. Hound replans first and rejects any drift.
hound corpus apply \
  --driver research/hound-driver.json \
  --execute /tmp/hound-plan.json \
  --approval /tmp/hound-approval.json \
  | tee /tmp/hound-result.json

# 4. Independently verify the immutable run record.
hound run verify "$(jq -r .run_dir /tmp/hound-result.json)"
```

Read capabilities execute directly. Standard source drivers can also use the
composed `source discover → capture → inspect` lifecycle, which keeps search
leads separate from immutable, verified source material.

## Built-in source packs

Hound ships two credential-isolated source packs behind one provider contract:

- **Web:** Exa search and contents, Firecrawl search and passive scrape, and
  origin-page capture with direct fetching plus Scrapling extraction before a
  Firecrawl fallback.
- **Scholarly:** arXiv Atom API search without a credential. Results are marked
  as academic preprints so the owner driver can apply its own evidence policy.

Drivers opt into kernel composition by declaring `"composition":
"hound.source.v1"` on all three source capabilities. The owner driver still
chooses queries, capture modes, and interpretation; Hound owns transport,
budgets, immutable capture storage, and verification.

## What Hound enforces

- **Evidence boundary:** discovery results are marked as leads. Verified captures
  bind raw bytes to source URL, provider, retrieval time, media type, and hashes.
- **Credential boundary:** Exa and Firecrawl credentials stay inside Hound's
  transport. Owner drivers receive only explicitly allowlisted environment
  variables.
- **Review boundary:** approvals bind to one deterministic plan and write-scope
  hash. Repository or environment drift invalidates the plan.
- **Mutation boundary:** check, read, and planning calls fail if the driver
  changes the owner repository. Executions detect out-of-scope writes.
- **Audit boundary:** each execution creates a strict, create-only run record
  that `hound run verify` can check independently.

## Trust model

Hound runs reviewed owner drivers. It does not sandbox untrusted plugins.
Write-scope enforcement is a checked postcondition: Hound detects and records an
out-of-scope mutation, but it does not automatically roll the repository back.
Linux provides the strongest detached-process containment.

Read the [security model](docs/security-model.md) before enabling writes or
provider credentials.

## Commands

```text
hound driver check
hound provider run
hound capture store|verify
hound source discover|capture|inspect
hound corpus status|propose|apply|project
hound edition build|publish|replay
hound approval create
hound run verify
```

## Documentation

- [Getting started](docs/getting-started.md)
- [Protocol v1 reference](docs/protocol.md)
- [Security model](docs/security-model.md)
- [Local development](docs/development.md)
- [Security policy](SECURITY.md)

Hound is pre-1.0. Wire formats are versioned; the Python package API is not yet
stable. The distribution is `evidence-hound`, and the installed command is
`hound`.

## License

Copyright © 2026 SCTY. Hound is proprietary and publicly available for
inspection. See [LICENSE.md](LICENSE.md).
