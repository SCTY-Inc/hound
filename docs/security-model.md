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
working state, exact expected file bytes and POSIX modes, and declared scopes.
Execution repeats planning and rejects any drift. Human approval, when required,
is bound to the exact plan ID and write-scope hash. Legacy drivers may still use
path-only `expected_writes`, which provides weaker postcondition evidence.

Read, check, and planning calls snapshot the owner repository before and after
the driver invocation and fail if the driver mutates it. `hound invoke` returns
a self-hashed receipt binding the request, response, manifest, repository,
environment, and kernel; a saved invocation JSON is independently checkable
with `hound verify`. Execution records the manifest, plan, request, approval,
result, and strict hash index in a create-only run directory. `hound verify`
also checks those records and their cross-document bindings.

Approval files, capture IDs, and run indexes are local workflow witnesses, not
digital signatures. An attacker who can coherently rewrite all local records can
rewrite those witnesses. Anchor the returned record digest in an external ledger
when adversarial tamper evidence is required.

## Credentials and adapters

Drivers receive a fixed system `PATH` plus only the environment variables
allowlisted globally and for the selected capability. Environment values are not
stored in cleartext, though their combined digest can reveal low-entropy values
through guessing.

Hound has no provider registry or credential-file loader. Web adapters are
reviewed driver executables and receive only the environment variables
allowlisted for their one capability. Source owners select aliases declared in
the owner manifest; input cannot supply an executable, service endpoint,
credential, header, or proxy.

The runtime freezes each adapter invocation once; its kernel-owned receipt binds
the exact executed manifest, repository state, allowlisted environment, response,
and cleanup proof. Web records persist that receipt rather than independently
fingerprinting mutable state.

Hound scans stdout, stderr, and recursively decoded adapter attachments for
credential-like allowlisted values before accepting or persisting a response.
Public service configuration uses environment names ending in `_ENDPOINT`; its
value may appear in request provenance and must be a credential-free HTTP root
URL with no path, query, fragment, or user information.
SearXNG custom-engine credentials belong to the separately operated SearXNG
service and are never Hound search input.

Agent-supplied targets must be public HTTP(S) URLs. Literal loopback, private,
link-local, malformed, credential-bearing, and ambiguous secret-parameter URLs
are rejected. Operator-configured adapter service endpoints may be loopback
because they are outside owner input. Redirect behavior belongs to each reviewed
adapter and must preserve the same target policy. URL parsing cannot prevent DNS
rebinding or constrain a browser's network; real private-network exclusion
requires container or host egress controls.

Search responses are leads marked `not-evidence`. SearXNG records its exact
`/config` and page responses, engine attribution, and unresponsive-engine
errors, but none of those turns a result into evidence. Firecrawl markdown and
Camofox snapshots are `provider-derived`: Hound stores the exact provider
response and derivation hashes but does not claim those transformations are raw
origin bytes. A separate origin capture is required when owner policy needs that
stronger evidence class. Failed extraction never promotes a search snippet.

Camofox is restricted to anonymous open, snapshot, click, type-without-submit,
scroll, and close actions. Hound does not expose cookie import, arbitrary
JavaScript, selectors, coordinates, proxy controls, or persistent profiles. A
record-root lock enforces a 30-action and five-minute session budget; close
remains available for cleanup. The operator must run Camofox loopback-only with
access-key authentication, persistence disabled, and telemetry disabled.

Every web result is labeled `untrusted`. Hound can preserve that label and keep
bytes out of its own control fields; it cannot guarantee that another model
harness will not concatenate web content into instructions. That boundary must
be enforced by the calling harness rather than claimed as an in-process
sandbox.

Adapter response bytes, request counts, and caller wall time are bounded. Hound
is not designed as a persistent in-process adapter service.

## Process and repository containment

On Linux, a kernel-owned supervisor acts as a child subreaper, terminates process
groups and detached descendants, and receives a parent-death signal. Repository
postconditions cover working files, modes, ignored files, Git index and refs,
effective Git configuration and hooks, and reachable-object integrity.

Other platforms retain direct process-group cleanup but do not provide the same
detached-descendant containment. Use operating-system isolation when that
property matters.
