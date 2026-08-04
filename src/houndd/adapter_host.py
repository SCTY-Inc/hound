"""Slice 3C2 adapter allowlist: the daemon's only provider-invocation seam.

The host binds an operation to exactly one callable.  It never retries, never
falls back, and never lets a caller select a provider.  Every credential it
uses comes from one frozen environment captured at service startup.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import math
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .contracts import canonical_bytes
from hound_web_adapters._http import Transport, request


ADAPTER_OPERATIONS: frozenset[str] = frozenset({"ingest.search", "ingest.url", "transcribe"})
ADAPTER_PROVIDERS: Mapping[str, str] = MappingProxyType({"ingest.search": "exa", "ingest.url": "firecrawl", "transcribe": "openai"})
# The key set is exactly the adapter operations that stage a content object,
# and each value is the media type its post-acceptance PHI scan uses.
# ``transcribe`` is absent on purpose: a transcription record is hashes and
# policy-safe provenance only, so no transcript byte is ever staged or scanned.
ADAPTER_MEDIA_TYPES: Mapping[str, str] = MappingProxyType({"ingest.search": "application/json", "ingest.url": "text/markdown"})
ADAPTER_ENV_KEYS: tuple[str, ...] = ("EXA_API_KEY", "FIRECRAWL_API_KEY", "FIRECRAWL_ENDPOINT", "OPENAI_API_KEY")
SEARCH_CONTENT_SCHEMA = "houndd.search-content.v1"
MAX_ADAPTER_CONTENT_BYTES = 16 * 1024 * 1024
MAX_TRANSCRIPT_SEGMENTS = 2_048
# A transcript is complete only when the provider's own timings account for the
# whole media it reported.  Anything short of that is durable ``partial``.
TRANSCRIPT_COVERAGE_TOLERANCE_MS = 500
_OUTCOMES = frozenset({"completed", "partial"})
_SHA256 = frozenset("0123456789abcdef")
_NO_PROVENANCE = "none"


class AdapterHostError(RuntimeError):
    """The adapter host cannot produce a usable provider result."""

    def __init__(self, message: str, *, requests: int = 0) -> None:
        super().__init__(message)
        if type(requests) is not int or requests not in {0, 1}:
            raise TypeError("adapter request count is invalid")
        self.requests = requests


class AdapterUnavailable(AdapterHostError):
    """No allowlisted adapter is bound to the operation."""


class AdapterAbstained(AdapterHostError):
    """The bound adapter declined to produce a result."""


class AdapterFailed(AdapterHostError):
    """The one provider exchange failed, was truncated, or was invalid."""


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """One adapter exchange reduced to durable, policy-safe daemon truth."""

    operation: str
    outcome: str
    content: bytes
    media_type: str
    retrieved_at: str
    requests: int
    cost: float
    leads: tuple[Mapping[str, str], ...] = ()
    # Transcription provenance the daemon derived from the one exchange.  Every
    # field here is provider- or daemon-produced; none is caller-selectable.
    # The transcript text itself is never carried here: it is hashed inside the
    # adapter and dropped, so no transcript byte can reach the commit path.
    model: str = _NO_PROVENANCE
    model_version: str = _NO_PROVENANCE
    language: str = _NO_PROVENANCE
    text_sha256: str = _NO_PROVENANCE
    text_byte_length: int = 0
    segments: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if type(self.operation) is not str or self.operation not in ADAPTER_OPERATIONS:
            raise TypeError("adapter result operation is not allowlisted")
        if type(self.outcome) is not str or self.outcome not in _OUTCOMES:
            raise TypeError("adapter result outcome is invalid")
        staging = self.operation in ADAPTER_MEDIA_TYPES
        if type(self.content) is not bytes or (bool(self.content) is not staging) or len(self.content) > MAX_ADAPTER_CONTENT_BYTES:
            raise TypeError("adapter result content is outside the bounded representation")
        if type(self.media_type) is not str or self.media_type != ADAPTER_MEDIA_TYPES.get(self.operation, _NO_PROVENANCE):
            raise TypeError("adapter result media type is unsupported")
        if type(self.retrieved_at) is not str or not self.retrieved_at:
            raise TypeError("adapter result retrieved_at is invalid")
        try:
            parsed = datetime.fromisoformat(self.retrieved_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise TypeError("adapter result retrieved_at is invalid") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise TypeError("adapter result retrieved_at is invalid")
        if type(self.requests) is not int or self.requests != 1:
            raise TypeError("adapter result request count is invalid")
        if type(self.cost) not in {int, float} or type(self.cost) is bool or not math.isfinite(self.cost) or self.cost < 0:
            raise TypeError("adapter result cost is invalid")
        if type(self.leads) is not tuple or (self.leads and self.operation != "ingest.search"):
            raise TypeError("adapter result leads are invalid")
        checked: list[Mapping[str, str]] = []
        for lead in self.leads:
            if type(lead) is not dict or set(lead) != {"url", "title", "native_id"} or any(type(value) is not str or not value for value in lead.values()):
                raise TypeError("adapter result lead fields are invalid")
            checked.append(MappingProxyType(dict(lead)))
        object.__setattr__(self, "leads", tuple(checked))
        self._check_transcript()

    def _check_transcript(self) -> None:
        """Require transcription provenance exactly where it belongs."""

        transcript = self.operation == "transcribe"
        for value in (self.model, self.model_version, self.language):
            if type(value) is not str or not value or len(value) > 128:
                raise TypeError("adapter result transcription provenance is invalid")
            if not transcript and value != _NO_PROVENANCE:
                raise TypeError("adapter result carries transcription provenance")
        if type(self.text_byte_length) is not int or self.text_byte_length < 0 or self.text_byte_length > MAX_ADAPTER_CONTENT_BYTES:
            raise TypeError("adapter result transcript length is invalid")
        if type(self.segments) is not tuple or (self.segments and not transcript):
            raise TypeError("adapter result segments are invalid")
        if not transcript:
            if self.text_sha256 != _NO_PROVENANCE or self.text_byte_length:
                raise TypeError("adapter result carries transcription provenance")
            return
        if not self.segments or len(self.segments) > MAX_TRANSCRIPT_SEGMENTS:
            raise TypeError("adapter result segments are invalid")
        if _NO_PROVENANCE in {self.model, self.model_version}:
            raise TypeError("adapter result transcription provenance is invalid")
        if type(self.text_sha256) is not str or len(self.text_sha256) != 64 or any(character not in _SHA256 for character in self.text_sha256) or not self.text_byte_length:
            raise TypeError("adapter result transcript identity is invalid")
        checked: list[Mapping[str, Any]] = []
        previous_end = 0
        for index, segment in enumerate(self.segments):
            digest = segment.get("text_sha256") if type(segment) is dict else None
            if (
                type(segment) is not dict
                or set(segment) != {"index", "start_ms", "end_ms", "text_sha256"}
                or segment["index"] != index
                or type(segment["start_ms"]) is not int
                or type(segment["end_ms"]) is not int
                or segment["start_ms"] < previous_end
                or segment["end_ms"] < segment["start_ms"]
                or type(digest) is not str
                or len(digest) != 64
                or any(character not in _SHA256 for character in digest)
            ):
                raise TypeError("adapter result segment fields are invalid")
            previous_end = segment["end_ms"]
            checked.append(MappingProxyType(dict(segment)))
        object.__setattr__(self, "segments", tuple(checked))


def _lead(value: Any) -> dict[str, str]:
    """Reduce one provider lead to the three fields the record retains."""

    url = value.get("url")
    title = value.get("title")
    metadata = value.get("metadata")
    native_id = metadata.get("providerId") if type(metadata) is dict else None
    if type(url) is not str or not url:
        raise AdapterFailed("provider lead has no URL", requests=1)
    return {
        "url": url,
        "title": title if type(title) is str and title else "none",
        "native_id": native_id if type(native_id) is str and native_id else "none",
    }


def _exa_search(
    payload: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    transport: Transport,
) -> AdapterResult:
    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.exa import search

    search_input: dict[str, Any] = {"query": payload["query"], "limit": payload["limit"]}
    if "options" in payload:
        search_input["options"] = payload["options"]
    try:
        data = search(search_input, env=env, transport=transport)
    except AdapterError as error:
        raise AdapterFailed("provider exchange failed", requests=1) from error
    except ValueError as error:
        raise AdapterFailed("provider result is invalid", requests=1) from error
    try:
        leads = [_lead(item) for item in data["output"]["leads"]]
        content = canonical_bytes({
            "schema_version": SEARCH_CONTENT_SCHEMA,
            "provider": "exa",
            "retrieved_at": data["retrieved_at"],
            "query": payload["query"],
            "limit": payload["limit"],
            "leads": data["output"]["leads"],
        })
        return AdapterResult("ingest.search", "completed", content, "application/json", data["retrieved_at"], int(data["usage"]["requests"]), 0, tuple(leads))
    except (AdapterHostError, KeyError, TypeError, ValueError) as error:
        raise AdapterFailed("provider result is invalid", requests=1) from error


def _firecrawl_extract(
    payload: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    transport: Transport,
) -> AdapterResult:
    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.firecrawl import extract

    # The daemon owns lineage; the provider request carries only the URL and
    # page bound, never the caller's declared search lineage.
    request: dict[str, Any] = {"url": payload["url"], "lineage": {"kind": "direct"}}
    if "max_pages" in payload:
        request["max_pages"] = payload["max_pages"]
    try:
        data = extract(request, env=env, transport=transport)
    except AdapterError as error:
        if error.requests == 0:
            raise AdapterAbstained("provider request is unsupported", requests=0) from error
        raise AdapterFailed("provider exchange failed", requests=1) from error
    except ValueError as error:
        raise AdapterFailed("provider result is invalid", requests=1) from error
    try:
        content = "\n\n".join(document["markdown"] for document in data["output"]["documents"]).encode("utf-8")
        if not content:
            raise AdapterAbstained("provider returned no extractable content", requests=int(data["usage"]["requests"]))
        return AdapterResult("ingest.url", "completed", content, "text/markdown", data["retrieved_at"], int(data["usage"]["requests"]), 0)
    except AdapterHostError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise AdapterFailed("provider result is invalid", requests=1) from error


def _openai_transcribe(
    payload: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    transport: Transport,
) -> AdapterResult:
    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.whisper import transcribe

    if set(payload) != {"capture_id", "audio"}:
        # The daemon resolves the capture and binds its bytes; a payload that
        # reached the provider seam without them never made a request.
        raise AdapterFailed("transcribe payload is not bound to a capture", requests=0)
    try:
        data = transcribe({"capture_id": payload["capture_id"], "audio": payload["audio"]}, env=env, transport=transport)
    except AdapterError as error:
        if error.requests == 0:
            raise AdapterAbstained("provider request is unsupported", requests=0) from error
        raise AdapterFailed("provider exchange failed", requests=1) from error
    except ValueError as error:
        raise AdapterFailed("provider result is invalid", requests=1) from error
    try:
        output = data["output"]
        text = output["text"]
        content = text.encode("utf-8")
        if not content:
            # Silence, or a provider that answered with nothing: a refusal, not
            # an empty transcript promoted to evidence.
            raise AdapterAbstained("provider returned no transcript", requests=int(data["usage"]["requests"]))
        segments = tuple(
            {
                "index": segment["index"],
                "start_ms": segment["start_ms"],
                "end_ms": segment["end_ms"],
                "text_sha256": hashlib.sha256(segment["text"].encode("utf-8")).hexdigest(),
            }
            for segment in output["segments"]
        )
        outcome = "completed" if _covers_media(output["duration_ms"], segments) else "partial"
        # The transcript is reduced to its hashes here and the text goes no
        # further: the commit path never receives a transcript byte.
        return AdapterResult(
            "transcribe",
            outcome,
            b"",
            _NO_PROVENANCE,
            data["retrieved_at"],
            int(data["usage"]["requests"]),
            0,
            (),
            model=output["model"],
            model_version=output["model_version"],
            language=output["language"],
            text_sha256=hashlib.sha256(content).hexdigest(),
            text_byte_length=len(content),
            segments=segments,
        )
    except AdapterHostError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise AdapterFailed("provider result is invalid", requests=1) from error


def _covers_media(duration_ms: object, segments: tuple[Mapping[str, Any], ...]) -> bool:
    """Prove full coverage from the provider's own timings, or report partial."""

    if type(duration_ms) is not int or duration_ms < 0 or not segments:
        return False
    tolerance = TRANSCRIPT_COVERAGE_TOLERANCE_MS
    if segments[0]["start_ms"] > tolerance or duration_ms - segments[-1]["end_ms"] > tolerance:
        return False
    return all(
        following["start_ms"] - preceding["end_ms"] <= tolerance
        for preceding, following in zip(segments, segments[1:])
    )


class AdapterHost:
    """One immutable operation -> callable allowlist."""

    __slots__ = ("_adapters",)

    def __init__(self, adapters: Mapping[str, Callable[[Mapping[str, Any]], AdapterResult]]) -> None:
        if type(adapters) is not dict or any(type(name) is not str or name not in ADAPTER_OPERATIONS or not callable(adapter) for name, adapter in adapters.items()):
            raise AdapterHostError("adapter host allowlist is invalid")
        self._adapters = MappingProxyType(dict(adapters))

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        *,
        transport: Transport = request,
    ) -> "AdapterHost":
        """Bind a production adapter only when its credential is provisioned."""

        if not isinstance(env, Mapping) or any(type(key) is not str or type(value) is not str for key, value in env.items()):
            raise AdapterHostError("adapter host environment is invalid")
        frozen = MappingProxyType({key: env[key] for key in ADAPTER_ENV_KEYS if key in env})
        adapters: dict[str, Callable[[Mapping[str, Any]], AdapterResult]] = {}
        if not callable(transport):
            raise AdapterHostError("adapter host transport is invalid")
        if frozen.get("EXA_API_KEY"):
            adapters["ingest.search"] = lambda payload: _exa_search(payload, frozen, transport=transport)
        if frozen.get("FIRECRAWL_API_KEY"):
            adapters["ingest.url"] = lambda payload: _firecrawl_extract(payload, frozen, transport=transport)
        if frozen.get("OPENAI_API_KEY"):
            adapters["transcribe"] = lambda payload: _openai_transcribe(payload, frozen, transport=transport)
        return cls(adapters)

    @property
    def operations(self) -> frozenset[str]:
        return frozenset(self._adapters)

    def invoke(self, operation: str, payload: Mapping[str, Any]) -> AdapterResult:
        """Call exactly one allowlisted adapter exactly once."""

        if type(operation) is not str or operation not in ADAPTER_OPERATIONS or not isinstance(payload, Mapping):
            raise AdapterHostError("adapter invocation inputs are invalid")
        adapter = self._adapters.get(operation)
        if adapter is None:
            raise AdapterUnavailable("no adapter is bound to the operation")
        result = adapter(payload)
        if type(result) is not AdapterResult or result.operation != operation or result.requests != 1:
            raise AdapterFailed("adapter result does not bind its operation", requests=1)
        return result


__all__ = [
    "ADAPTER_ENV_KEYS",
    "ADAPTER_MEDIA_TYPES",
    "ADAPTER_OPERATIONS",
    "ADAPTER_PROVIDERS",
    "AdapterAbstained",
    "AdapterFailed",
    "AdapterHost",
    "AdapterHostError",
    "AdapterResult",
    "AdapterUnavailable",
    "MAX_ADAPTER_CONTENT_BYTES",
    "MAX_TRANSCRIPT_SEGMENTS",
    "SEARCH_CONTENT_SCHEMA",
    "TRANSCRIPT_COVERAGE_TOLERANCE_MS",
]
