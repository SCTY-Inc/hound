# How to regenerate and apply the operator policy

<!-- Diátaxis: how-to -->

`${state}/service/policy.json` used to be hand edited: 28 rules that only
re-typed what `migration/consumer-inventory.v1.json` already declares (lane
owner x target_ops), plus a hand-enumerated producer-selector list for the
Workpad review surface that silently fell behind every new lane cutover. Both
failure modes -- rules drifting from the inventory, and a review selector list
going stale -- are eliminated by generating the file instead. This page is the
operator's apply flow for that generator.

The generator (`migration/policy_generator.py`) and its CLI
(`migration/check_policy.py`) never touch the live state root. They read the
checked-in inventory and overlay, and only ever write to a path you choose.
Moving the emitted file into place and restarting `houndd` stays a manual,
reviewed step.

## Prerequisites

- `uv sync --locked` in a `repos/hound` checkout.
- Read access to `migration/consumer-inventory.v1.json` and
  `migration/policy_overlay.v1.json` (both checked in).

## Check whether the live policy has drifted

```bash
cp ~/.local/state/hound/discovery/service/policy.json /tmp/live-policy.json
uv run python migration/check_policy.py --verify /tmp/live-policy.json
```

Exit 0 and `valid` means the live file is byte-identical to what the
inventory + overlay would generate today. Exit 1 prints one of three drift
shapes:

- `MISSING FROM TARGET` -- a rule the inventory/overlay declare that the live
  file doesn't have (e.g. a lane's grant was never added after cutover).
- `UNEXPECTED IN TARGET` -- a rule in the live file with no inventory/overlay
  basis (a hand grant that needs to move into the overlay, or be removed).
- `CHANGED IN TARGET` -- same `(owner_id, capability, run_id)` key, different
  producer selectors (the Workpad-review staleness shape).

Add `--json` for a machine-readable report with the full selector diff.

## Generate a candidate policy

```bash
uv run python migration/check_policy.py --emit /tmp/policy.json
```

This regenerates from `migration/consumer-inventory.v1.json` and
`migration/policy_overlay.v1.json` (override with `--manifest`/`--overlay` to
generate from a different pair, e.g. a branch under review) and writes
canonical bytes to `/tmp/policy.json`. The tool refuses to write under the
live houndd state root (`$XDG_STATE_HOME/hound` or the `~/.local/state/hound`
default) -- you always emit to a scratch path first.

Diff it against the live file to see exactly what would change:

```bash
uv run python migration/check_policy.py --verify /tmp/policy.json --json | python3 -m json.tool
```

(If this now says `valid`, the candidate matches the running policy and
there's nothing to apply.)

## Apply it

This is the one step the tool deliberately does not do for you.

```bash
install -m 0600 /tmp/policy.json ~/.local/state/hound/discovery/service/policy.json
systemctl --user restart houndd   # or the current service management path
```

`houndd` freezes the policy file's fingerprint at startup
(`load_frozen_policy`/`_assert_frozen` in `src/houndd/service.py`) and refuses
any request once it detects the file changed underneath it, so a restart is
required -- an in-place edit alone will not take effect.

## What the generator will and won't do for you

- **Every inventory lane gets a grant**, not just the ones currently wired to
  real provider credentials. `migration/consumer-inventory.v1.json` freezes
  every row's `stage` at `freeze_contracts` by design (see
  `consumer_inventory.py`'s canonical-closure digest); actual per-lane
  cutover progress lives in the stage ledger, not this file. So `--emit`
  produces the *complete* target policy for every declared lane, and it is
  the operator's call -- informed by which lanes are actually live -- whether
  and when to apply it. Applying early only pre-authorizes a capability; it
  does not wire credentials or start traffic.
- **The overlay is the only place hand-declared grants belong.** Today that's
  the operator (`ali`)'s broad own/wildcard grants and the Workpad review
  surface. If a new non-inventory principal needs a standing grant, add it to
  `migration/policy_overlay.v1.json`, not to a future hand edit of
  `policy.json`.
- **`--verify` is the CI-shaped invariant.** Run it against a copy of the live
  file (never the live file's actual path, to keep this read-only with
  respect to the daemon) as a gate before any policy change ships.

## Related

- `migration/policy_overlay.v1.json` -- the overlay document itself.
- `migration/policy_generator.py` -- the pure generation function
  (`generate_policy`) and overlay validator (`validate_overlay`).
- `tests/test_policy_generator.py` -- determinism, both loader round-trips
  (`houndd.access` and the real `houndd.service.load_frozen_policy`), drift
  detection, inventory-change propagation, and overlay closure.
- `src/houndd/access.py`, `src/houndd/service.py` -- the policy primitives
  and the frozen-per-lifetime loader this generator's output must satisfy.
