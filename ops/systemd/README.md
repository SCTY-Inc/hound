# How to run houndd under systemd (user unit)

This directory ships one user-scoped systemd unit for `houndd`:

- `houndd.service` — the daemon, always-on, enabled directly.

It assumes `houndd` is already on `PATH` (installed via `uv tool install`
or equivalent, e.g. `~/.local/bin/houndd`) and that provider credentials
live in `~/.config/hound/houndd.env` (`EXA_API_KEY`, `FIRECRAWL_API_KEY`).

## Install

```sh
mkdir -p ~/.config/systemd/user
cp ops/systemd/houndd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now houndd.service
```

## Verify

```sh
systemd-analyze --user verify ~/.config/systemd/user/houndd.service
systemctl --user status houndd.service
hound-research journal query --socket "$XDG_RUNTIME_DIR/hound/houndd.sock" \
  --owner-id <reader> --run-id <run> --policy-id <policy> --requested-access workspace --limit 1
```

## Migrating from a hand-managed unit

If `houndd.service` is already hand-installed directly under
`~/.config/systemd/user/` with its own `env.conf`/`memory.conf` drop-ins
(the state before this directory existed), switch over like this:

```sh
# 1. Install the repo unit over the hand-managed one.
cp ops/systemd/houndd.service ~/.config/systemd/user/

# 2. Drop the old unit's drop-ins; their settings (env file, memory caps)
#    are already folded into the repo unit.
rm -rf ~/.config/systemd/user/houndd.service.d

# 3. Reload and restart. houndd.service keeps binding the exact same
#    socket and state paths (StateDirectory=hound -> ~/.local/state/hound,
#    RuntimeDirectory=hound -> $XDG_RUNTIME_DIR/hound), so existing
#    consumers need no reconfiguration.
systemctl --user daemon-reload
systemctl --user restart houndd.service
systemctl --user status houndd.service
```

## Why not socket activation

`houndd` binds its own socket at startup (`service.py`'s `_bind`): it opens
a private descriptor, then publishes it at the final path with
`renameat2(..., RENAME_NOREPLACE)` — an atomic rename that deliberately
**refuses to overwrite an existing file** at that path. This is a real
security property (it stops a symlink/pre-created-file race from handing a
client a hijacked socket), but it means `houndd` never reads
`LISTEN_FDS`/`sd_listen_fds()` and cannot accept an already-bound listening
socket handed to it by systemd. Pointing a plain `ListenStream=` socket
unit at the daemon's path makes every activation attempt crash-loop with
exit code 5 (`ServiceError: socket path is already occupied`) — proved
live during GOALIE B8.

A trigger-only approximation (socket unit owns the path, `ExecStartPre`
clears systemd's file so houndd can rebind it) was built and proved during
B8, but it necessarily drops the one connection that causes each cold
start. Hound's consumers fail closed rather than blindly retry (that is
the lane contract), so a dropped first connection becomes a false lane
failure. With the daemon idling around 14M RSS, on-demand start saves
nothing worth that cost — hence always-on.

Genuine zero-dropped-connection activation would require `houndd` itself to
call `sd_listen_fds()` and reuse an inherited descriptor instead of doing
its own `RENAME_NOREPLACE` bind. If on-demand start ever matters, that is
the change to make — in `houndd.cli`/`service.py`, not here.

## Sandboxing notes

- `ProtectHome=read-only` alone would make `~/.local/state/hound` (where the
  journal, blob store, and policy live) unwritable and break the daemon on
  first run. `StateDirectory=hound` and `RuntimeDirectory=hound` are
  automatically exempted from `ProtectHome=`/`ProtectSystem=strict`
  (`systemd.exec(5)`: these directives imply `BindPaths=` for their target),
  so the daemon gets read-only access to the rest of `$HOME` plus a writable
  state directory, with no broader carve-out.
- `RestrictAddressFamilies=` keeps `AF_INET`/`AF_INET6` open alongside
  `AF_UNIX` because `houndd` hosts the live Exa/Firecrawl adapters, which
  make outbound HTTPS requests from inside the daemon process.
- `MemoryHigh=384M` / `MemoryMax=512M` match the values already in use on
  this host's memory-guardrailed slices; adjust both together if the
  daemon's working set changes.

## Testing changes to this unit

Never edit the production `houndd.service` in place to experiment. Copy the
file under a different unit name (e.g. `houndd-mytest.service`), point its
`ExecStart` at a scratch state dir and scratch socket path,
`systemd-analyze --user verify` it, exercise a round trip, then
`systemctl --user disable --now` and delete the copy.
