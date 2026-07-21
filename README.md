# Hound

Diátaxis: explanation

Hound is a Python command-line kernel for bounded research and evidence
operations. It gives trusted, repository-owned drivers one consistent execution
boundary for provider transport, immutable captures, deterministic plans,
approval binding, write-scope checks, and verifiable run records.

Hound is deliberately domain-neutral. An owner repository keeps its own schemas,
source policy, reconciliation rules, quality gates, and canonical writes; Hound
owns the mechanics that make those operations bounded and auditable.

## What Hound provides

- Strict, versioned JSON contracts for drivers, providers, plans, approvals,
  captures, and run records.
- Read operations that reject repository mutations.
- Write operations that plan first, bind approvals to exact inputs and scopes,
  reject drift, and record immutable execution evidence.
- Credential-isolated Exa and Firecrawl transport with positive request
  allowlists and bounded responses.
- A composed `source discover → capture → inspect` lifecycle that keeps leads
  separate from verified evidence.
- Repository fingerprinting, process cleanup, timeout enforcement, and
  independent run verification.

Hound drivers are trusted owner code, not untrusted plugins. Write-scope checking
is a verified postcondition, not a filesystem sandbox. See the
[security model](docs/security-model.md) before running a driver.

## Command model

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

- [Get started](docs/getting-started.md) — install Hound and run the example
  driver.
- [Protocol v1](docs/protocol.md) — driver, provider, evidence, plan, approval,
  and run-record contracts.
- [Security model](docs/security-model.md) — trust boundaries, guarantees, and
  residual risks.
- [Development](docs/development.md) — test and build the package locally.
- [Security policy](SECURITY.md) — privately report a vulnerability.

Hound requires Python 3.12 or newer and Git. Linux provides the strongest
process-containment guarantees.

## Status

Hound is pre-1.0. Wire formats are explicitly versioned, but the Python package
API is not yet stable. The command-line distribution is `evidence-hound`; the
installed command is `hound`.

## License

Copyright © 2026 SCTY. Hound is currently proprietary and publicly available for
inspection. See [LICENSE.md](LICENSE.md).
