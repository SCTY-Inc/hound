# Develop Hound locally

Diátaxis: how-to

## Set up the environment

```bash
git clone https://github.com/SCTY-Inc/hound.git
cd hound
uv sync --locked
```

Refresh the operator-installed command after source changes, including when the
package version has not changed:

```bash
uv tool install --force --refresh-package evidence-hound .
```

Hound's kernel and first-party adapter bundle use the Python standard library.
Pytest is the development dependency. Exa is called directly over HTTPS;
Firecrawl and Camofox remain separate services rather than package dependencies.

## Run the verification gate

```bash
uv run pytest -q
uv build
```

After building, verify the installed artifact rather than only the editable
checkout:

```bash
uv venv /tmp/hound-smoke
uv pip install --python /tmp/hound-smoke/bin/python dist/*.whl
/tmp/hound-smoke/bin/hound --version
/tmp/hound-smoke/bin/hound --help
```

The wheel and source distribution must contain the kernel beneath
`src/hound_cli`, optional research records beneath `src/hound_research`, and
provider implementations beneath `src/hound_web_adapters`. Guarded-write kernel
identity intentionally excludes both extension packages.

## Change a protocol boundary

1. Add or update a failing contract or CLI test.
2. Implement the smallest versioned contract change.
3. Update [Protocol v1](protocol.md) and any affected example.
4. Run the full verification gate and artifact smoke test.

Do not silently widen adapter fields, driver environment access, write scopes,
or mutation permissions. New trust boundaries require explicit documentation
and negative tests.
