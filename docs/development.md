# Develop Hound locally

Diátaxis: how-to

## Set up the environment

```bash
git clone https://github.com/SCTY-Inc/hound.git
cd hound
uv sync --locked
```

Hound uses only the Python standard library at runtime. Pytest is the development
dependency.

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

The wheel and source distribution must contain every module beneath
`src/hound_cli`, including modules imported by the console entry point.

## Change a protocol boundary

1. Add or update a failing contract or CLI test.
2. Implement the smallest versioned contract change.
3. Update [Protocol v1](protocol.md) and any affected example.
4. Run the full verification gate and artifact smoke test.

Do not silently widen provider fields, driver environment access, write scopes,
or mutation permissions. New trust boundaries require explicit documentation
and negative tests.
