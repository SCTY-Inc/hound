# pulse: static no-direct-provider evidence
The E1 consolidated no-bypass matrix
(repos/hound/migration/evidence/e1/no-bypass-matrix.json, 2026-08-05) records
static_scan_clean_for_lane_code=true and
real_ownership_violations_in_five_cutover_repos_lane_code=0, with the
inventory scan (repos/hound/migration/evidence/e1/no-bypass-scan.json) at
acquisition_bypass_findings_after=0. Cutover commit gc-web 6fb4ac9 deleted the
direct-provider acquisition path; in repos/givecare/gc-web the strings
EXA_API_KEY/FIRECRAWL/exa-js survive only inside tests, and there only as
negative assertions that guard the cutover
(packages/pulse-pipeline/tests/architecture-regression.test.ts:51,87 and
tests/lane-orchestration.test.ts:80-81 assert the lane source does *not*
contain them) plus two provider-name fixtures
(tests_py/test_pulse_acquire.py:240, tests/pulse-lane-exit-contract.test.ts:219).

Residuals, stated rather than suppressed: the E3 repo-wide scan
(repos/hound/migration/evidence/e3/ownership-scan-givecare.json) still reports
code-severity indicator hits under pulse paths — Deepgram credentials and
endpoint in packages/pulse-pipeline/pipeline/run-audio.ts:319,320,344 and
scripts/pulse-lane.sh:954,958; Cloudflare R2 credentials in run-audio.ts:326,
332,685 and pulse-lane.sh:670,698,1000,1026; a Discord credential in
pipeline/notify.ts:14; and Playwright hits in
apps/web-pulse/.github-workflows-example.yml:47,58 and
apps/web-pulse/tsconfig.eslint.json:8. None sit on the acquisition path: the
Deepgram calls are text-to-speech synthesis against api.deepgram.com/v1/speak
(output direction, not ingestion), Cloudflare is R2 upload/publish, Discord is
notification, and the Playwright entries are browser end-to-end accessibility
test config. The E1 matrix classifies exactly this set as bounded and
non-acquisition (consumer_owned_tts, consumer_owned_publication,
consumer_owned_terminal_status), and HSP-18 excludes tests and publish/deploy
from the no-bypass scan. Ali's decision D12 (2026-08-05, GOALIE.md) settles
their disposition: it scopes the "provider credentials exist only inside
houndd" acceptance sentence to migrated GiveCare lane *acquisition*, which is
the boundary these residuals sit outside. D12's named allowlist
(migration/domain-ownership-allowlist.v1.json, docs/credential-exceptions.md)
holds gc-benefits entries only — no gc-web path is allowlisted, and none is
claimed here; these hits stay visible in the E3 capability dump by design.

Scope: lane driver + repo verified 2026-08-05; sibling pipelines covered by the
owner exception-list decision.
