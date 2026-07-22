# Hound vision

<!-- Diátaxis: explanation -->

## Purpose

Hound is the trustworthy front door for discovery, extraction, and bounded web
interaction across many projects.

Different subjects call for different search engines, databases, APIs, crawlers,
extraction tools, and—only when static access fails—real browsers. Without a shared boundary, every project must rebuild
those integrations and decide for itself how to preserve source identity,
credentials, raw material, transformations, and audit records. The result is
provider lock-in, duplicated plumbing, and durable outputs whose evidence trail
is difficult to prove.

Hound lets each project compose the providers best suited to its domain while
receiving the same provenance, lineage, safety, and review guarantees. Search,
extraction, and interaction remain separate authorities rather than collapsing
into one opaque browsing tool.

## Promise

A project can change or combine discovery and extraction providers without
changing its downstream evidence model.

Every admitted piece of evidence should remain traceable from the originating
request, through the adapter and retrieved source bytes, through each extraction
or transformation, to the durable output it supports. When Hound permits a
repository change, the evidence, decision, approval, and resulting write should
form one verifiable chain.

## Who Hound serves

Hound serves maintainers and operators of recurring research, intelligence,
data, knowledge, and publishing workflows. They need to use heterogeneous
sources across multiple repositories without trusting one provider, one model,
or one project's conventions to preserve the record.

Owner projects remain the domain experts. They decide what to search, which
sources matter, how evidence should be interpreted, and what their repositories
should contain. Hound provides the common execution and evidence boundary around
those decisions.

## Governing beliefs

- **Composition over provider allegiance.** Search, extraction, and interaction
  capabilities should be selected for the subject and replaced without
  redesigning the workflow.
- **Stable envelopes, replaceable adapters.** Hound owns the versioned contracts,
  bounds, identities, and lineage records. Adapters own provider-specific
  transport and normalization.
- **Discovery is not evidence.** Search results, snippets, rankings, and model
  suggestions are leads until selected source material is captured and verified.
- **Extraction and interaction are recorded transformations.** Derived text,
  structured data, snapshots, screenshots, and browser state observations must
  remain bound to the available source or provider bytes, method, attempts,
  actions, and adapter identity that produced them.
- **Domain policy belongs to the owner.** Hound must not become the hidden owner
  of relevance, editorial judgment, reconciliation, or publication decisions.
- **Credentials and effects are explicit.** Adapters receive only declared
  authority. Reads are bounded; writes are planned, scoped, reviewable, and
  verifiable.
- **Partial failure stays visible.** Fallbacks, missing sources, provider errors,
  and degraded extraction must remain part of the record rather than being
  smoothed into apparent success.
- **The kernel stays small.** Hound should add durable primitives and remove
  repeated decision sites, not accumulate a bespoke pipeline for every domain.

## Product shape

Hound presents one consistent lifecycle across projects:

```text
search → select → extract → interact only when required → inspect → apply → verify
```

Projects compose trusted adapters through explicit capabilities. A search
adapter may federate many engines, query a specialist database, inspect a local
corpus, or call a commercial API. An extraction adapter may fetch an origin
page, parse a document, call a structured endpoint, or derive normalized
content. An interaction adapter may operate a disposable browser session when
JavaScript or explicit page actions are unavoidable. These implementations may
differ, but their outputs cross the same Hound contracts.

Hound records the request and adapter identity, enforces budgets and credential
boundaries, distinguishes leads from evidence, preserves immutable captures and
transformation lineage, and verifies the handoff into owner logic. When a
workflow writes durable state, Hound binds that state transition to a
content-specific plan and run record.

Adapters are trusted, explicitly installed capabilities—not arbitrary code
silently selected by a prompt. Hound verifies their boundaries; it does not
pretend to sandbox untrusted providers or owner drivers.

## Direction of travel

Hound should evolve toward:

- one versioned adapter contract and explicit manifests shared across projects;
- independently reusable search, extraction, and interaction capabilities;
- adapter packages that evolve without changing guarded-write kernel identity;
- complete lineage across raw capture, derived representations, interpretation,
  and durable writes;
- portable run records that can be inspected and verified outside the producing
  project; and
- explicit composition and fallback behavior rather than provider-specific
  orchestration hidden in project scripts.

The measure of progress is not the number of providers bundled into Hound. It is
how easily a project can choose the right providers while retaining one coherent
evidence and execution contract.

## Observable success

Hound is succeeding when:

- a new adapter can serve multiple owner projects without changing the kernel;
- a project can replace a provider without rewriting its evidence pipeline;
- every durable claim or data change can be traced to verified source material
  and the transformations that produced it;
- provider and extraction failures are diagnosable from the run record alone;
- owner repositories contain domain policy rather than duplicated acquisition
  and provenance machinery; and
- operators can review and verify what happened without trusting an agent's
  narrative.

## Document boundary

This vision defines Hound's enduring promise and decision principles. Current
providers, commands, schemas, file layouts, deployment choices, and implementation
milestones belong in the README, protocol reference, architecture notes, and
roadmap. They may change while this promise remains stable.
