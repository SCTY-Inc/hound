# Hound vision

<!-- Diátaxis: explanation -->

## Purpose

Hound is a Git-native, plan-bound capability runner for agents.

An agent can invoke almost any executable, but a consequential operation needs
better answers than a transcript can provide: Which reviewed capability ran?
What repository state and input did it see? What exact effect was authorized?
Did anything drift before execution? What actually changed? Can the record be
checked later without trusting the agent's account?

Hound makes those answers part of one small execution contract.

## Promise

**A maintainer can delegate a repository operation while retaining a verifiable
boundary around what ran, what was approved, and what changed.**

Owner repositories keep their domain logic. A language-neutral driver declares
named read and write capabilities and speaks versioned JSON. Hound invokes
reads without repository mutation, binds writes into deterministic plans,
requires an exact human witness when declared, rejects drift, checks resulting
effects, and emits portable verification records.

Hound is intentionally specific to capabilities operating on a Git workspace.
It is general across domains, not universal across every execution substrate.

## Governing beliefs

- **The owner owns meaning.** Relevance, transformation, quality, and business
  policy stay in the repository driver. The kernel understands capabilities and
  effects, not the domain.
- **Review must bind content.** Approval of a verb or path is weaker than
  approval of exact input, repository state, plan, scope, and expected file
  effects.
- **Drift invalidates authority.** A changed driver, manifest, environment,
  repository, input, or plan requires a new plan and, when gated, a new witness.
- **Receipts outlive runtimes.** Emitted records are a durable product contract.
  New Hound versions must continue to verify historical records.
- **Failure is evidence.** Driver diagnostics, partial effects, mismatches, and
  failed checks remain visible rather than being compressed into apparent
  success.
- **Trust claims stay narrow.** Drivers are reviewed code, not sandboxed
  plugins. Filesystem effects are checked postconditions. Hound does not claim
  to enforce external effects it cannot independently observe.
- **The kernel earns every line.** A new domain should require a small driver,
  not a kernel concept.

## Product shape

The durable surface is:

```text
driver check
invoke read capability → receipt
plan write capability → deterministic expected effects
approve exact plan → human witness
execute unchanged plan → checked effects + immutable record
verify record
```

Research, web acquisition, publishing, migrations, code generation, and other
workflows may build on this lifecycle. They are extensions or owner
capabilities, not identities Hound must absorb. GiveCare is a demanding proving
ground for the primitive, not its product definition.

## Refusals

Hound will not become:

- a scheduler, retry service, notifier, or workflow DAG engine;
- a provider registry, automatic fallback system, or general browser platform;
- an owner of corpus, editorial, publication, or other domain semantics;
- a global lineage database, dashboard, or artifact-management service;
- an in-process sandbox for untrusted code;
- a signature or public-attestation system; or
- an authority that labels unobservable network or third-party effects safe.

Those systems may call Hound, wrap it, or consume its records. They do not
belong in the kernel.

## Observable success

Hound is succeeding when:

- a meaningful new domain works through a small driver with no kernel change;
- a reviewer can see exact expected file effects before authorizing a write;
- drift, mismatched bytes, and driver failures produce specific diagnostics;
- a copied historical record verifies on future Hound versions;
- extension and provider changes do not alter guarded-write kernel identity;
- owner repositories delete duplicated planning and receipt machinery; and
- kernel production code and domain vocabulary trend downward while evaluator
  coverage grows.

## Document boundary

This vision governs the enduring product boundary. Commands, schemas, file
layouts, extension packages, provider choices, and migration instructions
belong in the README and protocol documentation.
