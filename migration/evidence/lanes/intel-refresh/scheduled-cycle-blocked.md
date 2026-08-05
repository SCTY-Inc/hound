# intel-refresh: scheduled-cycle blocker

Acceptance run `thr_ctbgqgpxna` returned `REFRESH_FAILED` before acquisition
because the scheduled environment had Hound `0.5.0`, outside the required
`0.4.x` range. This is a runtime compatibility failure, not evidence of an
acquisition bypass or a completed scheduled cycle.

Keep the formal stage at `import_mirror`. The current consumer ref
`7de92fa7ed8698ecbd5545e2cb79ba7642bee008` is not a migrated-stage proof.
The upcoming consumer repair must land before the scheduled cycle is rerun.
