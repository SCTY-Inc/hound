# Security policy

Diátaxis: reference

## Supported version

Security fixes are applied to the latest release on the default branch.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
**Security → Advisories → Report a vulnerability** flow so the report and any
proof of concept remain private.

Include the affected command or protocol boundary, Hound version, operating
system, reproduction steps, expected behavior, and observed behavior. Remove
live credentials and private source material from all artifacts.

Hound processes trusted owner drivers. Reports that require a malicious driver
to escape declared write scopes are still useful when they show that Hound
fails to detect or record the mutation; reports that assume drivers are
untrusted plugins are outside the current threat model.
