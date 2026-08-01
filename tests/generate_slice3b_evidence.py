"""Generate an unretained Slice 3B candidate from an isolated source commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid
from xml.etree import ElementTree


ROOT = Path(__file__).parents[1]
CORE_TESTS = (
    "tests/test_slice3b_service.py",
    "tests/test_slice3b_hostile.py",
    "tests/test_slice3b_observations.py",
    "tests/test_slice3b_evidence.py",
)
TESTS = (*CORE_TESTS, "tests/test_slice3b_final_evidence_integrity.py")
SELECTIONS = {"core": CORE_TESTS, "retained": TESTS}
OBSERVATION_NODE = "tests/test_slice3b_observations.py::test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner"
OBSERVATION_TESTCASE = (
    "tests.test_slice3b_observations",
    "test_slice3b_live_observations_are_emitted_only_for_the_evidence_runner",
)
NODE_ID_PROPERTY = "hound.slice3b.nodeid"
OBSERVATION_PROPERTY = "hound.slice3b.observation"
ARTIFACTS = frozenset({"run-manifest.json", "slice3b-collection.json", "slice3b-pytest.xml", "observations.json"})
SOURCE_FIXED = frozenset({"pyproject.toml", "uv.lock", "README.md", "LICENSE.md", "tests/acceptance_slice3b.json"})
PYTEST_ENVIRONMENT = {
    "HOUND_SLICE3B_UV": "/home/deploy/.local/bin/uv",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONPATH": "src",
    "TMPDIR": "/tmp",
    "UV_CACHE_DIR": "/tmp/hound-slice3b-evidence-uv-cache",
}
REMOVED_PYTEST_ENVIRONMENT = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")
_HEX = re.compile(r"[0-9a-f]{40}\Z")
_COLLECTION_SUMMARY = re.compile(r"([0-9]+) tests? collected in .+\Z")


class EvidenceError(ValueError):
    pass


def _trusted_git() -> str:
    try:
        executable = shutil.which("git", path=os.defpath)
        if executable is None:
            raise EvidenceError("trusted Git executable is unavailable")
        return os.fspath(Path(executable).resolve(strict=True))
    except OSError as error:
        raise EvidenceError("trusted Git executable is unavailable") from error


def _git_fingerprint(executable: str) -> str:
    try:
        return hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    except OSError as error:
        raise EvidenceError("trusted Git executable is unavailable") from error


GIT_EXECUTABLE = _trusted_git()
GIT_SHA256 = _git_fingerprint(GIT_EXECUTABLE)
GIT_ENVIRONMENT = {
    "PATH": os.defpath,
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "0",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
}
OBSERVATION = {"schema_version": "houndd.slice3b.live-observations.v1", "named_tests": [OBSERVATION_NODE], "producer": {"node_id": OBSERVATION_NODE, "classname": OBSERVATION_TESTCASE[0], "name": OBSERVATION_TESTCASE[1]}, "wire": {"version": "houndd.uds.v1", "encoded_json_limit": 1_048_576}}
OBSERVATION_JSON = json.dumps(OBSERVATION, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _git(repository: Path, *args: str) -> str:
    try:
        return subprocess.check_output(_git_argv(*args), cwd=repository, env=GIT_ENVIRONMENT, text=True).strip()
    except OSError as error:
        raise EvidenceError("trusted Git invocation failed") from error


def _git_bytes(repository: Path, spec: str) -> bytes:
    try:
        return subprocess.check_output(_git_argv("show", spec), cwd=repository, env=GIT_ENVIRONMENT)
    except OSError as error:
        raise EvidenceError("trusted Git invocation failed") from error


def _git_argv(*args: str) -> list[str]:
    if _git_fingerprint(GIT_EXECUTABLE) != GIT_SHA256:
        raise EvidenceError("trusted Git executable changed after resolution")
    return [GIT_EXECUTABLE, *args]


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _exact_nonnegative_int(value: object, label: str, *, exact: int | None = None) -> int:
    if type(value) is not int or value < 0:
        raise EvidenceError(f"{label} must be an exact nonnegative integer")
    if exact is not None and value != exact:
        raise EvidenceError(f"{label} is invalid")
    return value


def _decimal_counter(value: object, label: str) -> int:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise EvidenceError(f"{label} is not a canonical decimal counter")
    return int(value)


def _selection(name: str) -> tuple[str, ...]:
    if type(name) is not str or name not in SELECTIONS:
        raise EvidenceError("evidence test selection is invalid")
    return SELECTIONS[name]


def _git_identity() -> dict[str, str]:
    return {"executable": GIT_EXECUTABLE, "sha256": GIT_SHA256}


def source_paths(repository: Path, commit: str) -> tuple[str, ...]:
    """Derive the complete executable source/test closure from one Git tree."""

    try:
        raw = subprocess.check_output(_git_argv("ls-tree", "-r", "-z", "--full-tree", commit), cwd=repository, env=GIT_ENVIRONMENT)
    except OSError as error:
        raise EvidenceError("trusted Git invocation failed") from error
    tracked_regular: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path_bytes = record.split(b"\t", 1)
        mode, kind, _blob = metadata.split(b" ", 2)
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("source path is not valid UTF-8") from error
        selected_target = path.startswith("src/") or (path.startswith("tests/") and path.endswith(".py")) or path in SOURCE_FIXED
        regular = kind == b"blob" and mode in {b"100644", b"100755"}
        if selected_target and not regular:
            raise ValueError(f"non-regular source target: {path}")
        if regular:
            tracked_regular.add(path)
    missing = SOURCE_FIXED - tracked_regular
    if missing:
        raise ValueError(f"source dependency set is incomplete: {sorted(missing)!r}")
    selected = SOURCE_FIXED | {path for path in tracked_regular if path.startswith("src/") or (path.startswith("tests/") and path.endswith(".py"))}
    return tuple(sorted(selected))


def _junit_results(junit: Path) -> tuple[list[str], bytes]:
    root = ElementTree.parse(junit).getroot()
    nodes: list[str] = []
    observed_property: str | None = None
    for case in root.iter("testcase"):
        identity = (case.attrib.get("classname"), case.attrib.get("name"))
        values = [
            prop.attrib.get("value")
            for prop in case.findall("./properties/property")
            if prop.attrib.get("name") == NODE_ID_PROPERTY
        ]
        if len(values) != 1 or type(values[0]) is not str or not values[0]:
            raise RuntimeError("JUnit testcase lacks its exact pytest node ID")
        node = values[0]
        case_observation_values = [prop.attrib.get("value") for prop in case.findall("./properties/property") if prop.attrib.get("name") == OBSERVATION_PROPERTY]
        if identity == OBSERVATION_TESTCASE:
            if node != OBSERVATION_NODE or case_observation_values != [OBSERVATION_JSON] or any(case.find(outcome) is not None for outcome in ("failure", "error", "skipped")):
                raise RuntimeError("named observation testcase did not pass with its exact canonical property")
            if observed_property is not None:
                raise RuntimeError("named observation testcase is not unique")
            observed_property = case_observation_values[0]
        elif node == OBSERVATION_NODE or case_observation_values:
            raise RuntimeError("observation property was emitted by the wrong testcase")
        nodes.append(node)
    if observed_property is None:
        raise RuntimeError("named observation testcase property is missing")
    return nodes, observed_property.encode("utf-8") + b"\n"


def _run_id(value: str) -> str:
    if not value.startswith("slice3b-"):
        raise ValueError("run ID must start with slice3b-")
    suffix = value.removeprefix("slice3b-")
    try:
        parsed = uuid.UUID(suffix)
    except ValueError as error:
        raise ValueError("run ID must contain an exact UUID") from error
    if str(parsed) != suffix:
        raise ValueError("run ID UUID must use canonical spelling")
    return value


def _interpreter(python: str) -> dict[str, object]:
    probe = (
        "import json,sys;"
        "print(json.dumps({'executable':sys.executable,'implementation':sys.implementation.name,"
        "'version':list(sys.version_info[:3])},sort_keys=True))"
    )
    try:
        result = subprocess.run([python, "-I", "-c", probe], check=True, capture_output=True, text=True)
        identity = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise EvidenceError("Python interpreter identity is unavailable") from error
    if (
        type(identity) is not dict
        or set(identity) != {"executable", "implementation", "version"}
        or type(identity["executable"]) is not str
        or not os.path.isabs(identity["executable"])
        or type(identity["implementation"]) is not str
        or type(identity["version"]) is not list
        or len(identity["version"]) != 3
    ):
        raise EvidenceError("Python interpreter identity is invalid")
    for part in identity["version"]:
        _exact_nonnegative_int(part, "Python interpreter version component")
    executable = Path(identity["executable"])
    if not executable.is_file():
        raise EvidenceError("Python interpreter executable is unavailable")
    identity["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
    return identity


def _pytest_environment() -> dict[str, str]:
    return {"PATH": os.defpath, **PYTEST_ENVIRONMENT}


def _collection_argv(python: str, selection: str) -> list[str]:
    return [python, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.test_slice3b_observations", *_selection(selection), "--collect-only", "-q"]


def _run_argv(python: str, selection: str) -> list[str]:
    return [python, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.test_slice3b_observations", *_selection(selection), "--junitxml=tests/evidence/slice3b/slice3b-pytest.xml"]


def _collect(checkout: Path, python: str, selection: str) -> dict[str, object]:
    argv = _collection_argv(python, selection)
    result = subprocess.run(argv, cwd=checkout, env=_pytest_environment(), text=True, capture_output=True, check=False)
    if type(result.returncode) is not int or result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)
    tests = _selection(selection)
    prefixes = tuple(f"{path}::" for path in tests)
    raw_nodes = [line for line in result.stdout.splitlines() if line.startswith(prefixes)]
    summaries = [match for line in result.stdout.splitlines() if (match := _COLLECTION_SUMMARY.fullmatch(line))]
    if len(summaries) != 1 or _decimal_counter(summaries[0].group(1), "pytest collection count") != len(raw_nodes) or not raw_nodes:
        raise RuntimeError("pytest collection result is incomplete")
    if len(raw_nodes) != len(set(raw_nodes)):
        raise RuntimeError("pytest collection contains duplicate node IDs")
    return {
        "schema_version": "houndd.slice3b.pytest-collection.v1",
        "selection": selection,
        "argv": argv,
        "environment": {"absent": list(REMOVED_PYTEST_ENVIRONMENT), "values": _pytest_environment()},
        "exit_code": _exact_nonnegative_int(result.returncode, "pytest collection exit code", exact=0),
        "node_ids": raw_nodes,
    }


def _empty_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("evidence output must be a new absent directory")
    path.mkdir(parents=True, mode=0o700)


def generate(
    *,
    expected_commit: str,
    expected_tree: str,
    expected_thread_id: str,
    expected_run_id: str,
    evidence_dir: Path,
    python: str,
    repository: Path = ROOT,
    test_selection: str = "retained",
) -> None:
    _run_id(expected_run_id)
    if not expected_thread_id.startswith("thr_"):
        raise ValueError("BB thread ID is invalid")
    if _HEX.fullmatch(expected_commit) is None or _HEX.fullmatch(expected_tree) is None:
        raise ValueError("expected source commit/tree spelling is invalid")
    if _git(repository, "rev-parse", f"{expected_commit}^{{tree}}") != expected_tree:
        raise ValueError("expected source commit/tree binding is false")
    interpreter = _interpreter(python)
    tests = _selection(test_selection)
    _exact_nonnegative_int(OBSERVATION["wire"]["encoded_json_limit"], "observation encoded JSON limit", exact=1_048_576)
    _empty_output(evidence_dir)
    paths = source_paths(repository, expected_commit)
    with tempfile.TemporaryDirectory(prefix="hound-slice3b-source-") as temporary:
        checkout = Path(temporary) / "source"
        try:
            subprocess.run(_git_argv("clone", "--shared", "--no-checkout", str(repository), str(checkout)), env=GIT_ENVIRONMENT, check=True, capture_output=True)
            subprocess.run(_git_argv("checkout", "--detach", expected_commit), cwd=checkout, env=GIT_ENVIRONMENT, check=True, capture_output=True)
        except OSError as error:
            raise EvidenceError("trusted Git invocation failed") from error
        if _git(checkout, "rev-parse", "HEAD^{tree}") != expected_tree:
            raise ValueError("isolated checkout tree is false")
        bindings = {
            path: {
                "blob": _git(checkout, "rev-parse", f"{expected_commit}:{path}"),
                "sha256": hashlib.sha256(_git_bytes(checkout, f"{expected_commit}:{path}")).hexdigest(),
            }
            for path in paths
        }
        work_evidence = checkout / "tests" / "evidence" / "slice3b"
        work_evidence.mkdir(parents=True)
        collection_path = work_evidence / "slice3b-collection.json"
        junit = work_evidence / "slice3b-pytest.xml"
        observations = work_evidence / "observations.json"
        collection = _collect(checkout, str(interpreter["executable"]), test_selection)
        collection_bytes = _canonical_json(collection)
        collection_path.write_bytes(collection_bytes)
        argv = _run_argv(str(interpreter["executable"]), test_selection)
        result = subprocess.run(argv, cwd=checkout, env=_pytest_environment(), text=True, capture_output=True, check=False)
        if type(result.returncode) is not int or result.returncode != 0:
            raise RuntimeError(result.stdout + result.stderr)
        nodes, observation_bytes = _junit_results(junit)
        if not nodes or nodes != collection["node_ids"] or len(nodes) != len(set(nodes)):
            raise RuntimeError("executed JUnit nodes do not match immutable collection")
        observations.write_bytes(observation_bytes)
        manifest = {
            "schema_version": "houndd.slice3b.evidence.v5",
            "selection": test_selection,
            "run_id": expected_run_id,
            "bb_thread_id": expected_thread_id,
            "source": {"commit": expected_commit, "tree": expected_tree},
            "git": _git_identity(),
            "interpreter": interpreter,
            "pytest_environment": {"absent": list(REMOVED_PYTEST_ENVIRONMENT), "values": _pytest_environment()},
            "argv": argv,
            "source_files": bindings,
            "collection": {"path": collection_path.name, "sha256": hashlib.sha256(collection_bytes).hexdigest()},
            "junit": {"path": junit.name, "sha256": hashlib.sha256(junit.read_bytes()).hexdigest(), "node_ids": nodes},
            "observations": {"path": observations.name, "sha256": hashlib.sha256(observations.read_bytes()).hexdigest()},
        }
        (work_evidence / "run-manifest.json").write_bytes(_canonical_json(manifest))
        for name in ARTIFACTS:
            shutil.copyfile(work_evidence / name, evidence_dir / name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--expected-bb-thread-id", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--python", required=True)
    args = parser.parse_args()
    generate(expected_commit=args.expected_source_commit, expected_tree=args.expected_source_tree, expected_thread_id=args.expected_bb_thread_id, expected_run_id=args.expected_run_id, evidence_dir=args.evidence_dir, python=args.python)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
