# Hound

**Delegate a Git-repository capability without delegating the proof.**

Hound is a small, language-neutral execution primitive for agents. An owner
repository exposes named capabilities through a reviewed executable driver.
Hound invokes reads without mutation and makes writes pass through a
deterministic plan, optional human approval, drift checks, exact effect checks,
and a portable verification record.

Hound does not know whether a capability migrates configuration, generates
code, updates a dataset, or publishes an artifact. The owner driver owns that
meaning.

## Why it exists

An agent transcript is not an execution boundary. For a consequential
repository operation, a maintainer needs concrete answers:

- Which manifest, driver, input, environment, and Git state did the plan bind?
- What exact file effects did the reviewer authorize?
- Did anything drift after review?
- Did the driver touch an undeclared path or produce different bytes?
- Can the result be checked later without trusting the agent's explanation?

Hound turns those questions into one lifecycle:

```text
driver check
invoke read capability → receipt
plan write capability → deterministic expected effects
approve exact plan → human witness
execute unchanged plan → checked effects + immutable record
verify record
```

## Fit

Hound is useful when an executable capability acts on durable state in a Git
repository and the operation deserves stronger evidence than logs.

Good fits include configuration migration, code generation, repository ETL,
knowledge maintenance, release preparation, and agent-run maintenance. A
disposable chat answer or a script whose effects do not need review or proof
usually does not need Hound.

Drivers use versioned JSON on stdin and stdout and may be written in any
language. The manifest declares literal argv, capabilities, timeouts,
allowlisted environment names, write scopes, and approval gates.

## Try a read capability

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
  --operation status.read \
  --input examples/status/request.json \
  | tee /tmp/hound-invoke.json

uv run hound verify /tmp/hound-invoke.json
```

Install the command independently with:

```bash
uv tool install git+https://github.com/SCTY-Inc/hound.git
hound --version
```

## Guard a write

```bash
hound plan \
  --driver hound-driver.json \
  --operation config.migrate \
  --input request.json \
  --as-of 2026-07-27 \
  --output /tmp/hound-plan.json

hound approve \
  --plan /tmp/hound-plan.json \
  --reviewer operator@example.com \
  --output /tmp/hound-approval.json

hound execute \
  --driver hound-driver.json \
  --plan /tmp/hound-plan.json \
  --approval /tmp/hound-approval.json \
  | tee /tmp/hound-result.json

hound verify "$(jq -r .run_dir /tmp/hound-result.json)"
```

A strong plan uses `expected_effects`:

```json
{
  "expected_effects": [
    {
      "path": "config.json",
      "mode": "0644",
      "before_sha256": "…",
      "after_sha256": "…"
    }
  ]
}
```

Creation has a null before hash, update has both hashes, and deletion has a
null after hash and mode. Hashes cover exact regular-file bytes; `mode` is the
final four-digit POSIX permission mode. Hound checks the before hash while
planning and the after hash and mode following execution. Existing pre-0.4
drivers may return `expected_writes` paths as a
compatibility contract; new drivers should use exact effects.

The golden evaluator in
[`tests/golden/config_migration`](tests/golden/config_migration) demonstrates a
complete non-domain-specific driver in under 70 lines.

## What Hound enforces

- **Capability boundary:** only manifest-declared operations run through a
  literal argv process and strict JSON protocol.
- **Read boundary:** check, read, and plan modes fail if the driver mutates the
  protected owner repository.
- **Credential boundary:** a driver receives only allowlisted environment
  values; credential material is rejected from persisted output.
- **Review boundary:** an approval binds one exact plan, operation, and scope.
- **Drift boundary:** changed kernel, manifest, environment, input, plan, Git
  control state, or repository bytes invalidate execution.
- **Effect boundary:** writes outside declared scopes or approved paths fail;
  exact-effect plans also bind resulting bytes.
- **Record boundary:** an execution emits a create-only, hash-indexed record
  that remains verifiable after being copied.

## Trust model

Hound runs reviewed drivers. It does not sandbox untrusted plugins. Write-scope
and effect enforcement are checked postconditions: Hound detects and records a
violation but does not roll the repository back.

Hound strongly observes local filesystem effects. A driver may perform network
or third-party effects, but Hound does not label those verified unless a
separate capability supplies independently checkable evidence.

Approval records are local human witnesses, not digital signatures. Authenticity
requires an external digest anchor controlled outside the owner filesystem.
Read the [security model](docs/security-model.md) before enabling writes.

## Optional research extension

Research acquisition is one client of the primitive, not the product
definition. The separately named `hound-research` command contains source,
web, and capture record workflows:

```text
hound-research source discover|capture|inspect
hound-research search|extract|interact
hound-research capture store|verify
hound-research verify
```

First-party Exa, SearXNG, Firecrawl, and Camofox adapters live outside
`hound_cli`, so their code does not alter guarded-write kernel identity.
Existing manifests with top-level `source` metadata remain compatible; new
extensions belong under generic manifest `extensions` metadata.

## What Hound refuses

- No scheduler, retry service, notifier, or workflow DAG engine.
- No provider registry, hidden fallback, or automatic escalation.
- No corpus, editorial, publication, or other owner-domain semantics.
- No global lineage database, dashboard, or artifact manager.
- No in-process sandbox or claims about effects Hound cannot observe.
- No signature or public-attestation system in the kernel.

## Core commands

```text
hound driver check
hound invoke
hound plan
hound approve
hound execute
hound verify
```

## Documentation

- [Vision](VISION.md)
- [Getting started](docs/getting-started.md)
- [Protocol reference](docs/protocol.md)
- [Security model](docs/security-model.md)
- [Local development](docs/development.md)

Hound is pre-1.0. Driver interfaces may still change, but emitted record
verification is a permanent compatibility commitment. The distribution is
`evidence-hound`; the core command is `hound`.

## License

Copyright © 2026 SCTY. Hound is proprietary and publicly available for
inspection. See [LICENSE.md](LICENSE.md).
