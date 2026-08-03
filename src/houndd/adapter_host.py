"""Slice 3C2 adapter allowlist: the daemon's only provider-invocation seam.

The host binds an operation to exactly one callable.  It never retries, never
falls back, and never lets a caller select a provider.  Every credential it
uses comes from one frozen environment captured at service startup.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .contracts import canonical_bytes


ADAPTER_OPERATIONS: frozenset[str] = frozenset({"ingest.search", "ingest.url"})
ADAPTER_PROVIDERS: Mapping[str, str] = MappingProxyType({"ingest.search": "exa", "ingest.url": "firecrawl"})
ADAPTER_MEDIA_TYPES: Mapping[str, str] = MappingProxyType({"ingest.search": "application/json", "ingest.url": "text/markdown"})
ADAPTER_ENV_KEYS: tuple[str, ...] = ("EXA_API_KEY", "FIRECRAWL_API_KEY", "FIRECRAWL_ENDPOINT")
SEARCH_CONTENT_SCHEMA = "houndd.search-content.v1"
MAX_ADAPTER_CONTENT_BYTES = 16 * 1024 * 1024
_OUTCOMES = frozenset({"completed", "partial"})


class AdapterHostError(RuntimeError):
    """The adapter host cannot produce a usable provider result."""

    def __init__(self, message: str, *, requests: int = 0) -> None:
        super().__init__(message)
        if type(requests) is not int or requests < 0:
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

    def __post_init__(self) -> None:
        if type(self.operation) is not str or self.operation not in ADAPTER_OPERATIONS:
            raise TypeError("adapter result operation is not allowlisted")
        if type(self.outcome) is not str or self.outcome not in _OUTCOMES:
            raise TypeError("adapter result outcome is invalid")
        if type(self.content) is not bytes or not 0 < len(self.content) <= MAX_ADAPTER_CONTENT_BYTES:
            raise TypeError("adapter result content is outside the bounded representation")
        if type(self.media_type) is not str or self.media_type != ADAPTER_MEDIA_TYPES[self.operation]:
            raise TypeError("adapter result media type is unsupported")
        if type(self.retrieved_at) is not str or not self.retrieved_at:
            raise TypeError("adapter result retrieved_at is invalid")
        if type(self.requests) is not int or not 1 <= self.requests <= 64:
            raise TypeError("adapter result request count is invalid")
        if type(self.cost) not in {int, float} or type(self.cost) is bool or self.cost < 0:
            raise TypeError("adapter result cost is invalid")
        if type(self.leads) is not tuple or (self.leads and self.operation != "ingest.search"):
            raise TypeError("adapter result leads are invalid")
        checked: list[Mapping[str, str]] = []
        for lead in self.leads:
            if type(lead) is not dict or set(lead) != {"url", "title", "native_id"} or any(type(value) is not str or not value for value in lead.values()):
                raise TypeError("adapter result lead fields are invalid")
            checked.append(MappingProxyType(dict(lead)))
        object.__setattr__(self, "leads", tuple(checked))


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


def _exa_search(payload: Mapping[str, Any], env: Mapping[str, str]) -> AdapterResult:
    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.exa import search

    try:
        data = search({"query": payload["query"], "limit": payload["limit"]}, env=env)
    except AdapterError as error:
        raise AdapterFailed("provider exchange failed", requests=max(error.requests, 1)) from error
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


def _firecrawl_extract(payload: Mapping[str, Any], env: Mapping[str, str]) -> AdapterResult:
    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.firecrawl import extract

    # The daemon owns lineage; the provider request carries only the URL and
    # page bound, never the caller's declared search lineage.
    request: dict[str, Any] = {"url": payload["url"], "lineage": {"kind": "direct"}}
    if "max_pages" in payload:
        request["max_pages"] = payload["max_pages"]
    try:
        data = extract(request, env=env)
    except AdapterError as error:
        raise AdapterFailed("provider exchange failed", requests=max(error.requests, 1)) from error
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


class AdapterHost:
    """One immutable operation -> callable allowlist."""

    __slots__ = ("_adapters",)

    def __init__(self, adapters: Mapping[str, Callable[[Mapping[str, Any]], AdapterResult]]) -> None:
        if type(adapters) is not dict or any(type(name) is not str or name not in ADAPTER_OPERATIONS or not callable(adapter) for name, adapter in adapters.items()):
            raise AdapterHostError("adapter host allowlist is invalid")
        self._adapters = MappingProxyType(dict(adapters))

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "AdapterHost":
        """Bind a production adapter only when its credential is provisioned."""

        if not isinstance(env, Mapping) or any(type(key) is not str or type(value) is not str for key, value in env.items()):
            raise AdapterHostError("adapter host environment is invalid")
        frozen = MappingProxyType({key: env[key] for key in ADAPTER_ENV_KEYS if key in env})
        adapters: dict[str, Callable[[Mapping[str, Any]], AdapterResult]] = {}
        if frozen.get("EXA_API_KEY"):
            adapters["ingest.search"] = lambda payload: _exa_search(payload, frozen)
        if frozen.get("FIRECRAWL_API_KEY"):
            adapters["ingest.url"] = lambda payload: _firecrawl_extract(payload, frozen)
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
        if type(result) is not AdapterResult or result.operation != operation:
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
    "SEARCH_CONTENT_SCHEMA",
]
