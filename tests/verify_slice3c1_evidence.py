"""Independent verifier for an isolated, unretained Slice 3C1 candidate."""

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
TESTS = (
    "tests/test_slice3c1_service_authz.py",
    "tests/test_slice3c1_commit_runtime.py",
    "tests/test_slice3c1_contract_source_phi.py",
    "tests/test_slice3c1_observations.py",
    "tests/test_slice3c1_evidence.py",
)
OBSERVATION_NODE = "tests/test_slice3c1_observations.py::test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner"
OBSERVATION_TESTCASE = (
    "tests.test_slice3c1_observations",
    "test_slice3c1_live_observations_are_emitted_only_for_the_evidence_runner",
)
NODE_ID_PROPERTY = "hound.slice3c1.nodeid"
OBSERVATION_PROPERTY = "hound.slice3c1.observation"
ARTIFACTS = frozenset({"run-manifest.json", "slice3c1-collection.json", "slice3c1-pytest.xml", "observations.json"})
SOURCE_FIXED = frozenset({"pyproject.toml", "uv.lock", "README.md", "LICENSE.md", "tests/acceptance_slice3c1.json"})
PYTEST_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONPATH": "src",
    "TMPDIR": "/tmp",
    "UV_CACHE_DIR": "/tmp/hound-slice3c1-evidence-uv-cache",
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
OBSERVATION = {"schema_version": "houndd.slice3c1.live-observations.v1", "named_tests": [OBSERVATION_NODE], "producer": {"node_id": OBSERVATION_NODE, "classname": OBSERVATION_TESTCASE[0], "name": OBSERVATION_TESTCASE[1]}, "wire": {"version": "houndd.uds.v1", "encoded_json_limit": 1_048_576}}
OBSERVATION_JSON = json.dumps(OBSERVATION, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fail(message: str) -> None:
    raise EvidenceError(message)


def _bound_interpreter(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {"executable", "implementation", "version", "sha256"}:
        _fail("external Python interpreter binding is false")
    if type(value["executable"]) is not str or not os.path.isabs(value["executable"]):
        _fail("external Python interpreter binding is false")
    if type(value["implementation"]) is not str or type(value["sha256"]) is not str:
        _fail("external Python interpreter binding is false")
    version = value["version"]
    if type(version) is not list or len(version) != 3:
        _fail("external Python interpreter binding is false")
    for part in version:
        _exact_nonnegative_int(part, "Python interpreter version component")
    return value


def _exact_observation(value: object) -> None:
    if type(value) is not dict or set(value) != {"schema_version", "named_tests", "producer", "wire"}:
        _fail("typed observations are invalid or have the wrong producer")
    if value["schema_version"] != "houndd.slice3c1.live-observations.v1":
        _fail("typed observations are invalid or have the wrong producer")
    named_tests = value["named_tests"]
    if type(named_tests) is not list or named_tests != [OBSERVATION_NODE]:
        _fail("typed observations are invalid or have the wrong producer")
    producer = value["producer"]
    if type(producer) is not dict or set(producer) != {"node_id", "classname", "name"}:
        _fail("typed observations are invalid or have the wrong producer")
    if producer["node_id"] != OBSERVATION_NODE or producer["classname"] != OBSERVATION_TESTCASE[0] or producer["name"] != OBSERVATION_TESTCASE[1]:
        _fail("typed observations are invalid or have the wrong producer")
    wire = value["wire"]
    if type(wire) is not dict or set(wire) != {"version", "encoded_json_limit"} or wire["version"] != "houndd.uds.v1":
        _fail("typed observations are invalid or have the wrong producer")
    _exact_nonnegative_int(wire["encoded_json_limit"], "observation encoded JSON limit", exact=1_048_576)


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
        _fail("trusted Git executable changed after resolution")
    return [GIT_EXECUTABLE, *args]


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _exact_nonnegative_int(value: object, label: str, *, exact: int | None = None) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{label} must be an exact nonnegative integer")
    if exact is not None and value != exact:
        _fail(f"{label} is invalid")
    return value


def _decimal_counter(value: object, label: str) -> int:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        _fail(f"{label} is not a canonical decimal counter")
    return int(value)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail("JSON contains a duplicate key")
        value[key] = item
    return value


def _nonfinite(_value: str) -> object:
    _fail("JSON contains a nonfinite number")


def _load_json(path: Path, label: str) -> tuple[object, bytes]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_nonfinite)
    except (OSError, UnicodeError, ValueError) as error:
        raise EvidenceError(f"{label} is unavailable or invalid JSON") from error
    if raw != _canonical_json(value):
        _fail(f"{label} is not canonical JSON")
    return value, raw


def _git_identity() -> dict[str, str]:
    return {"executable": GIT_EXECUTABLE, "sha256": GIT_SHA256}


def _run_id(value: object) -> str:
    if type(value) is not str or not value.startswith("slice3c1-"):
        _fail("run ID is invalid")
    suffix = value.removeprefix("slice3c1-")
    try:
        parsed = uuid.UUID(suffix)
    except ValueError as error:
        raise EvidenceError("run ID is invalid") from error
    if str(parsed) != suffix:
        _fail("run ID UUID spelling is not canonical")
    return value


def _source_paths(repository: Path, commit: str) -> tuple[str, ...]:
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
            raise EvidenceError("source path is not valid UTF-8") from error
        selected_target = path.startswith("src/") or (path.startswith("tests/") and path.endswith(".py")) or path in SOURCE_FIXED
        regular = kind == b"blob" and mode in {b"100644", b"100755"}
        if selected_target and not regular:
            _fail(f"non-regular source target: {path}")
        if regular:
            tracked_regular.add(path)
    if SOURCE_FIXED - tracked_regular:
        _fail("source dependency set is incomplete")
    selected = SOURCE_FIXED | {path for path in tracked_regular if path.startswith("src/") or (path.startswith("tests/") and path.endswith(".py"))}
    return tuple(sorted(selected))


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
        raise EvidenceError("externally supplied Python interpreter is unavailable") from error
    if (
        type(identity) is not dict
        or set(identity) != {"executable", "implementation", "version"}
        or type(identity["executable"]) is not str
        or not os.path.isabs(identity["executable"])
        or type(identity["implementation"]) is not str
        or type(identity["version"]) is not list
        or len(identity["version"]) != 3
    ):
        _fail("externally supplied Python interpreter identity is invalid")
    for part in identity["version"]:
        _exact_nonnegative_int(part, "Python interpreter version component")
    executable = Path(identity["executable"])
    if not executable.is_file():
        _fail("externally supplied Python interpreter executable is unavailable")
    identity["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
    return _bound_interpreter(identity)


def _pytest_environment() -> dict[str, str]:
    return {"PATH": os.defpath, **PYTEST_ENVIRONMENT}


def _environment_binding() -> dict[str, object]:
    return {"absent": list(REMOVED_PYTEST_ENVIRONMENT), "values": _pytest_environment()}


def _collection_argv(python: str) -> list[str]:
    return [python, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.test_slice3c1_observations", *TESTS, "--collect-only", "-q"]


def _run_argv(python: str) -> list[str]:
    return [python, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.test_slice3c1_observations", *TESTS, "--junitxml=tests/evidence/slice3c1/slice3c1-pytest.xml"]


def _collect(checkout: Path, python: str) -> dict[str, object]:
    argv = _collection_argv(python)
    result = subprocess.run(argv, cwd=checkout, env=_pytest_environment(), text=True, capture_output=True, check=False)
    if type(result.returncode) is not int or result.returncode != 0:
        _fail("immutable source collection failed")
    prefixes = tuple(f"{path}::" for path in TESTS)
    raw_nodes = [line for line in result.stdout.splitlines() if line.startswith(prefixes)]
    summaries = [match for line in result.stdout.splitlines() if (match := _COLLECTION_SUMMARY.fullmatch(line))]
    if len(summaries) != 1 or _decimal_counter(summaries[0].group(1), "pytest collection count") != len(raw_nodes) or not raw_nodes:
        _fail("immutable source collection is incomplete")
    if len(raw_nodes) != len(set(raw_nodes)):
        _fail("immutable source collection contains duplicate node IDs")
    return {
        "schema_version": "houndd.slice3c1.pytest-collection.v1",
        "argv": argv,
        "environment": _environment_binding(),
        "exit_code": _exact_nonnegative_int(result.returncode, "pytest collection exit code", exact=0),
        "node_ids": raw_nodes,
    }


def _regular_inventory(evidence: Path) -> None:
    try:
        entries = tuple(evidence.rglob("*"))
    except OSError as error:
        raise EvidenceError("evidence inventory is unavailable") from error
    if evidence.is_symlink() or not evidence.is_dir():
        _fail("evidence inventory is not a regular directory")
    relative = {entry.relative_to(evidence).as_posix() for entry in entries}
    if relative != ARTIFACTS:
        _fail("evidence inventory is not exact")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            _fail("evidence inventory contains a non-regular artifact")


def _junit_results(root: ElementTree.Element) -> tuple[list[str], bytes]:
    nodes: list[str] = []
    observed_property: str | None = None
    for case in root.iter("testcase"):
        if not case.attrib.get("classname") or not case.attrib.get("name"):
            _fail("JUnit testcase identity is incomplete")
        identity = (case.attrib["classname"], case.attrib["name"])
        values = [
            prop.attrib.get("value")
            for prop in case.findall("./properties/property")
            if prop.attrib.get("name") == NODE_ID_PROPERTY
        ]
        if len(values) != 1 or type(values[0]) is not str or not values[0]:
            _fail("JUnit testcase lacks its exact pytest node ID")
        node = values[0]
        case_observation_values = [prop.attrib.get("value") for prop in case.findall("./properties/property") if prop.attrib.get("name") == OBSERVATION_PROPERTY]
        if identity == OBSERVATION_TESTCASE:
            if node != OBSERVATION_NODE or case_observation_values != [OBSERVATION_JSON]:
                _fail("named observation producer property is not exact")
            if observed_property is not None:
                _fail("named observation testcase is not unique")
            observed_property = case_observation_values[0]
        elif node == OBSERVATION_NODE or case_observation_values:
            _fail("observation property belongs to the wrong testcase")
        nodes.append(node)
    if observed_property is None:
        _fail("named observation testcase property is missing")
    return nodes, observed_property.encode("utf-8") + b"\n"


def _verify_junit(path: Path, expected_nodes: list[str]) -> tuple[list[str], bytes]:
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as error:
        raise EvidenceError("JUnit artifact is unavailable or invalid") from error
    suites = root.findall("./testsuite")
    cases = list(root.iter("testcase"))
    if root.tag != "testsuites" or len(suites) != 1 or not cases:
        _fail("JUnit suite shape is invalid")
    suite = suites[0]
    counters = {"tests": len(cases), "errors": 0, "failures": 0, "skipped": 0}
    if any(
        _decimal_counter(suite.attrib.get(name), f"JUnit {name} counter") != expected
        for name, expected in counters.items()
    ):
        _fail("JUnit suite counters are not completely passing")
    if any(case.find("failure") is not None or case.find("error") is not None or case.find("skipped") is not None for case in cases):
        _fail("JUnit records a non-passing node")
    nodes, observation_bytes = _junit_results(root)
    if nodes != expected_nodes or len(nodes) != len(set(nodes)):
        _fail("JUnit nodes differ from immutable source collection")
    return nodes, observation_bytes


def verify(
    evidence: Path,
    repository: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_thread_id: str,
    expected_run_id: str,
    expected_python: str,
) -> None:
    _regular_inventory(evidence)
    manifest, _manifest_bytes = _load_json(evidence / "run-manifest.json", "manifest")
    required = {"schema_version", "run_id", "bb_thread_id", "source", "git", "interpreter", "pytest_environment", "argv", "source_files", "collection", "junit", "observations"}
    if type(manifest) is not dict or set(manifest) != required or manifest["schema_version"] != "houndd.slice3c1.evidence.v1":
        _fail("manifest schema is not exact")
    if _run_id(manifest["run_id"]) != expected_run_id or manifest["bb_thread_id"] != expected_thread_id or type(expected_thread_id) is not str or not expected_thread_id.startswith("thr_"):
        _fail("external run/thread binding is false")
    source = manifest["source"]
    if type(source) is not dict or source != {"commit": expected_commit, "tree": expected_tree} or _HEX.fullmatch(expected_commit) is None or _HEX.fullmatch(expected_tree) is None:
        _fail("external source binding is false")
    if _git(repository, "rev-parse", f"{expected_commit}^{{tree}}") != expected_tree:
        _fail("source commit/tree binding is false")
    git = manifest["git"]
    expected_git = _git_identity()
    if type(git) is not dict or set(git) != {"executable", "sha256"} or any(type(git[key]) is not str or git[key] != expected_git[key] for key in expected_git):
        _fail("trusted Git executable binding is false")
    interpreter = _interpreter(expected_python)
    bound_interpreter = _bound_interpreter(manifest["interpreter"])
    if any(bound_interpreter[key] != interpreter[key] for key in ("executable", "implementation", "version", "sha256")):
        _fail("external Python interpreter binding is false")
    environment_binding = _environment_binding()
    if manifest["pytest_environment"] != environment_binding:
        _fail("pytest environment binding is false")
    executable = str(interpreter["executable"])
    if manifest["argv"] != _run_argv(executable):
        _fail("exact argv is invalid")
    expected_paths = _source_paths(repository, expected_commit)
    files = manifest["source_files"]
    if type(files) is not dict or tuple(files) != expected_paths:
        _fail("source file binding set is incomplete")
    for path, binding in files.items():
        if type(binding) is not dict or set(binding) != {"blob", "sha256"}:
            _fail("source file binding shape is invalid")
        raw = _git_bytes(repository, f"{expected_commit}:{path}")
        if binding["blob"] != _git(repository, "rev-parse", f"{expected_commit}:{path}") or binding["sha256"] != hashlib.sha256(raw).hexdigest():
            _fail(f"raw Git binding failed for {path}")
    collection_binding = manifest["collection"]
    collection_path = evidence / "slice3c1-collection.json"
    collection, collection_bytes = _load_json(collection_path, "collection artifact")
    if type(collection_binding) is not dict or collection_binding != {"path": collection_path.name, "sha256": hashlib.sha256(collection_bytes).hexdigest()}:
        _fail("collection artifact binding is invalid")
    if (
        type(collection) is not dict
        or set(collection) != {"schema_version", "argv", "environment", "exit_code", "node_ids"}
        or collection["schema_version"] != "houndd.slice3c1.pytest-collection.v1"
        or collection["argv"] != _collection_argv(executable)
        or collection["environment"] != environment_binding
        or _exact_nonnegative_int(collection["exit_code"], "collection exit code", exact=0) != 0
        or type(collection["node_ids"]) is not list
        or not collection["node_ids"]
        or any(type(node) is not str or not node for node in collection["node_ids"])
        or len(collection["node_ids"]) != len(set(collection["node_ids"]))
    ):
        _fail("collection artifact schema is invalid")
    with tempfile.TemporaryDirectory(prefix="hound-slice3c1-verify-") as temporary:
        checkout = Path(temporary) / "source"
        try:
            subprocess.run(_git_argv("clone", "--shared", "--no-checkout", str(repository), str(checkout)), env=GIT_ENVIRONMENT, check=True, capture_output=True)
            subprocess.run(_git_argv("checkout", "--detach", expected_commit), cwd=checkout, env=GIT_ENVIRONMENT, check=True, capture_output=True)
        except OSError as error:
            raise EvidenceError("trusted Git invocation failed") from error
        if _git(checkout, "rev-parse", "HEAD^{tree}") != expected_tree:
            _fail("isolated verification checkout tree is false")
        if _collect(checkout, executable) != collection:
            _fail("collection artifact differs from immutable source collection")
    junit = manifest["junit"]
    junit_path = evidence / "slice3c1-pytest.xml"
    if type(junit) is not dict or set(junit) != {"path", "sha256", "node_ids"} or junit["path"] != junit_path.name or junit["sha256"] != hashlib.sha256(junit_path.read_bytes()).hexdigest():
        _fail("JUnit binding is invalid")
    nodes, junit_observation_bytes = _verify_junit(junit_path, collection["node_ids"])
    if junit["node_ids"] != nodes:
        _fail("manifest JUnit nodes are incomplete")
    observations = manifest["observations"]
    observation_path = evidence / "observations.json"
    observed, observation_bytes = _load_json(observation_path, "observation payload")
    if type(observations) is not dict or observations != {"path": observation_path.name, "sha256": hashlib.sha256(observation_bytes).hexdigest()}:
        _fail("observation binding is invalid")
    _exact_observation(observed)
    if observation_bytes != junit_observation_bytes or OBSERVATION_NODE not in nodes:
        _fail("typed observations are invalid or have the wrong producer")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--expected-bb-thread-id", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-python", required=True)
    args = parser.parse_args()
    verify(args.evidence_dir, args.repository, expected_commit=args.expected_source_commit, expected_tree=args.expected_source_tree, expected_thread_id=args.expected_bb_thread_id, expected_run_id=args.expected_run_id, expected_python=args.expected_python)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
