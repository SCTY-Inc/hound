# Approval seams: receipts, decisions, outcomes

Explanation of the E4 record formats (HSP-10, HSP-22) — how human approval
binds to evidence without hound ever owning an approval database or the
ledger growing a write path.

## The three-record distinction

Approval involves three facts that are routinely conflated and must never be:

1. **Gate receipt** — *a gate existed, over exactly these contents.*
   `hound.approval.gate-receipt.v1`: `{schema_version, gate_id, lane,
   subject, requested_at, queue_ref}` where `subject` names the exact
   thing awaiting judgment — a plan ID plus the content hashes of every
   record/artifact it covers. Content-addressed and immutable: the
   receipt's own hash is what everything downstream binds to. `queue_ref`
   points at the gate's native human surface (the approval queue page);
   the receipt never carries the content itself.

2. **Decision** — *what the human said.*
   `hound.approval.decision.v1`: `{schema_version, gate_id, decision:
   approve|reject, decided_by, decided_at, receipt_hash, evidence_refs}`.
   Appended to `migration/approvals/decisions.jsonl`, which is
   **audit-only and hash-chained** in the stage-ledger pattern (each entry
   binds sha256 over the prior entry hash + its body). Nothing reads
   decisions.jsonl to decide anything at runtime — decisions land as the
   gate's native artifact per the approval-queue contract; this log is
   the tamper-evident audit trail, not a control plane.

3. **Outcome** — *what the system then did.* The lane's own artifact
   (an applied corpus plan, a stage-ledger `migrated` entry, a publish
   witness). An outcome claiming approval must reference the decision's
   chain hash; a decision must reference the exact receipt hash. A gate
   receipt without a decision is an open gate; a decision without an
   outcome is an unexecuted approval — both are legal states the checker
   reports rather than repairs.

## Annotations

Review annotations (`plus`, `amplify`) are append-only records binding
`{record_hash, annotation, author, at}` — never edited, never deleted.
An annotation is testimony about a specific content hash; changing the
content produces a different hash and therefore requires new testimony.

## The per-lane cutover gate (HSP-22)

The E2 stage ledger already refuses a `migrated` transition without an
`approval_ref`. E4 gives that field a verifiable target: it must name a
decision entry whose receipt's `subject` covers the lane's evidence set
(the five migrated-stage evidence pointers). The checker walks
stage-ledger → decision → receipt → evidence hashes and fails on any
broken link.

## What the checker rejects (`migration/check_approvals.py`, to build)

- decisions.jsonl chain break (tamper, splice, truncation)
- a decision whose `receipt_hash` matches no receipt
- a receipt whose subject hashes don't resolve to real artifacts
- an outcome (stage-ledger `approval_ref`) naming a missing/rejecting decision
- an edited annotation (hash mismatch against its append-time record)

## Boundaries (unchanged)

Hound holds no approval state at runtime and the intake ledger stays
read-only: Workpad may *render* receipts and decisions next to ledger
rows and link out via `queue_ref`, but the approve action always happens
on the gate's native surface, and the ledger never grows a button that
writes.
