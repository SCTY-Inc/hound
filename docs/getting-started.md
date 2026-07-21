# Get started with Hound

Diátaxis: how-to

This guide installs Hound from source and runs the included read-only example
driver.

## Prerequisites

Install Git, Python 3.12 or newer, and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/).

## Clone and verify Hound

```bash
git clone https://github.com/SCTY-Inc/hound.git
cd hound
uv sync --locked
uv run hound --version
uv run pytest -q
```

To install the CLI independently of the checkout:

```bash
uv tool install git+https://github.com/SCTY-Inc/hound.git
hound --version
```

## Run the example driver

A Hound manifest locates its owner repository, declares literal driver argv, and
allowlists each capability. First validate the manifest and protocol handshake:

```bash
uv run hound driver check \
  --driver examples/status/hound-driver.json
```

Then invoke the declared read capability:

```bash
uv run hound corpus status \
  --driver examples/status/hound-driver.json \
  --input examples/status/request.json
```

Both commands emit one compact JSON object on stdout. The status response echoes
the example request through the repository-owned driver.

## Add a driver to an owner repository

1. Put a `hound.driver.v1` manifest and a JSON stdin/stdout driver in the owner
   Git repository.
2. Set `owner.repo` relative to the manifest directory so it resolves to the
   exact Git root.
3. Declare only the capabilities, environment variables, and write scopes the
   driver needs.
4. Run `hound driver check --driver <manifest>`.
5. Invoke read capabilities directly. For a write capability, create and inspect
   a deterministic plan before executing it.

The complete wire contract is in [Protocol v1](protocol.md). Read the
[security model](security-model.md) before enabling writes or provider
credentials.
