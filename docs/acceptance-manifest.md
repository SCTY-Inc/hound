# The acceptance manifest

<!-- Diátaxis: reference -->

`migration/acceptance.v1.json` is the machine-readable claim sheet for
VISION.md's HSP acceptance table. It holds exactly 22 rows, one per HSP-01
through HSP-22, and for each row it names the tests, evidence, and commands
that prove it -- or says plainly what is still missing.

`migration/check_acceptance.py` is the gate that keeps the sheet honest. CI
runs it as the acceptance command:

```bash
uv run python migration/check_acceptance.py --run-tests
```

Without `--run-tests` it validates the manifest only, and is fast enough to
run on every edit.

## What the checker enforces

| Rule | Failure it prevents |
|---|---|
| Closed shape, exactly 22 rows ordered HSP-01..HSP-22 | a row quietly deleted, duplicated, reordered, or given an escape-hatch field |
| Every named artifact resolves on disk; a named evidence directory exists and is not empty | a claim pointing at a file or bundle that was never written |
| One artifact, one owning row | the same test counted as proof for two rows |
| Every in-scope proof artifact is owned by some row | orphan evidence: a suite or bundle nothing claims, so nothing notices when it rots |
| `supporting` must name another row's artifact | a row inflating its own evidence by re-listing it |
| `complete` requires proving tests, asserted behavior, and an empty `missing` | an unproven claim |
| `partial` and `open` require a nonempty `missing` | a row that admits it is incomplete without saying how |
| `summary` counts must equal the rows | a headline number drifting from the body |
| A row's pytest command may only run tests that row owns | a command borrowing another row's green |
| `vision_line` must point at that row in VISION.md | the manifest and the contract silently diverging |
| A non-CI command must carry `ci_reason` | a command excluded from the gate with no stated reason |

## Row fields

| Field | Meaning |
|---|---|
| `id`, `vision_line` | the HSP row and the VISION.md line that defines it |
| `status` | `complete`, `partial`, or `open` |
| `claim` | the row's contract, condensed |
| `tests`, `evidence` | artifacts this row **owns**; ownership is one-to-one |
| `supporting` | artifacts another row owns that also bear on this row |
| `commands` | `{command, ci}`; `ci: false` requires a `ci_reason` |
| `assertions` | what the artifacts actually assert |
| `missing` | what is not proven; required unless `status` is `complete` |
| `deviations` | accepted departures from the VISION text, with the reason |

## Traceability scope

The globs must end in `**/*`, never `**`. `Path.glob` treats `**` as directories
only, so `migration/evidence/**` matches zero files: the orphan check goes
vacuous while the manifest still reports valid.
`test_the_traceability_scope_actually_matches_the_evidence_trees` guards this.

One-to-one traceability is enforced over **proof artifacts** -- test files,
evidence bundles, sealed slice manifests, migration checkers and their data
files -- not over `src/`. The exclusion is deliberate and recorded in the
manifest's `traceability_scope.src_exclusion_reason`: the sealed slice
manifests already assign the same module to different rows
(`src/houndd/journal.py` is HSP-05 in `tests/acceptance_slice1.json` and
HSP-20 in `tests/acceptance_slice3a.json`), because a module genuinely serves
several rows. Picking one owner per module would be an invention. The residual
gap is carried in HSP-21's own `missing` list rather than papered over.

## What `--run-tests` runs

1. The manifest's `test_command` once -- the whole suite, which covers every
   cited pytest suite in the rows.
2. Every CI-safe (`ci: true`) non-pytest command the rows name -- currently
   the consumer-inventory schema gate and the stage-ledger gate.

Commands marked `ci: false` are not run: they need the real atum workspace
(`--workspace /home/deploy`) or inputs that do not exist yet, and their output
is retained under `migration/evidence/` instead. Each one states why in
`ci_reason`.

Output streams live, so a failing suite reads the same in CI as it does
locally. The checker exits nonzero if the manifest fails validation or any
command it ran did.

## Related

- `tests/test_acceptance_manifest.py` -- the adversarial tests for this gate.
- `tests/acceptance_slice*.json` -- per-slice sealed manifests, bound to a
  commit by digest. This manifest names artifacts by path, not by digest, so
  it detects a missing or unclaimed artifact but not a silently edited one.
- `docs/approval-seams.md` -- the approval records HSP-10 and HSP-22 rest on.
