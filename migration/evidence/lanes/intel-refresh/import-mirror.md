# intel-refresh: import-mirror evidence

The lane is operationally live on houndd after the c782f49 cutover. The
current consumer main ref is 7de92fa7ed8698ecbd5545e2cb79ba7642bee008
(`fix(intel): read canonical Hound URL records`). It reads canonical Hound
URL records and does not reacquire through a provider. The formal stage stays
`import_mirror` until the retained scheduled-cycle and Ali approval gates are
complete; this evidence does not promote the lane to `migrated`.
