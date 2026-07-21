# Hound security model

Diátaxis: explanation

Hound makes trusted repository operations bounded and auditable. It does not turn
an untrusted program into a safe plugin.

## Trust boundary

The owner Git repository is the read trust boundary, and the owner driver is
trusted code. Hound intentionally does not accept narrower `read_scopes` because
a path list would not enforce filesystem confinement. Use an isolated account,
container, or dedicated repository when repo-wide read access is unacceptable.

Write scopes are checked postconditions, not an operating-system sandbox. Hound
detects and records an out-of-scope mutation as a failed run; it does not
promise automatic rollback.

## Plan and execution binding

A write plan binds the Hound version and source hash, canonical manifest,
operation input and cutoff date, allowlisted environment digest, Git HEAD and
working state, expected writes, and declared scopes. Execution repeats planning
and rejects any drift. Human approval, when required, is bound to the exact plan
ID and write-scope hash.

Read, check, and planning calls snapshot the owner repository before and after
the driver invocation and fail if the driver mutates it. Execution records the
manifest, plan, request, approval, result, and strict hash index in a create-only
run directory. `hound run verify` independently checks those records and their
cross-document bindings.

Approval files, capture IDs, and run indexes are local workflow witnesses, not
digital signatures. An attacker who can coherently rewrite all local records can
rewrite those witnesses. Anchor the returned record digest in an external ledger
when adversarial tamper evidence is required.

## Credentials and providers

Drivers receive a fixed system `PATH` plus only the environment variables
allowlisted globally and for the selected capability. Environment values are not
stored in cleartext, though their combined digest can reveal low-entropy values
through guessing.

Provider credentials stay inside Hound's Exa and Firecrawl transports. Positive
field allowlists reject credential-shaped parameters and active browser
features. Search responses are leads marked `not-evidence`; only immutable,
verified captures cross the evidence boundary.

Provider response bytes and caller wall time are bounded. A timed-out standard
library network worker may continue until the short-lived Hound process exits,
so Hound is not designed as a persistent in-process provider service.

## Process and repository containment

On Linux, a kernel-owned supervisor acts as a child subreaper, terminates process
groups and detached descendants, and receives a parent-death signal. Repository
postconditions cover working files, modes, ignored files, Git index and refs,
effective Git configuration and hooks, and reachable-object integrity.

Other platforms retain direct process-group cleanup but do not provide the same
detached-descendant containment. Use operating-system isolation when that
property matters.
