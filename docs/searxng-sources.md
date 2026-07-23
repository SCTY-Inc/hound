# SearXNG source map

<!-- Diátaxis: reference -->

This is the operator routing map for Hound's reviewed SearXNG overlay. It
records observed behavior from a dated pressure test; it is not an availability
guarantee. Search responses remain untrusted leads until selected URLs are
captured and inspected.

Prefer explicit engines in recurring owner workflows. Category searches are
useful for exploration, but their upstream engine set can change with SearXNG
configuration and availability. Hound does not silently choose a fallback:
owners must declare each alternative search, retain its record, and decide how
to combine the leads.

## Preferred routes

| Need | Preferred explicit engine | Alternative explicit route |
| --- | --- | --- |
| Broad web discovery | `exa web` | `google cse` when its upstream quota is healthy |
| Scholarly publications | `exa publications` | `semantic scholar`, `pubmed`, or `openairepublications` |
| US federal rules and notices | `federal register` | `google cse` |
| Current news | `bing news` | `duckduckgo news` |
| Code and repositories | `github` | `google cse` |
| Web-development references | `mdn` | `google cse` |
| Container packages | `docker hub` | `google cse` |
| Video discovery | `youtube` | `google cse` |

`exa web` and `exa publications` are reviewed routes through Hound's
credentialed Exa engine. The web route leaves Exa's category unset; the
publication route requests the publication category. The upstream engine name
`exa` is not enabled. Exa's key stays inside the separately operated SearXNG
service.

## Pressure test: 2026-07-23 UTC

The test exercised the loopback deployment backed by
[`ops/searxng/settings.yml`](../ops/searxng/settings.yml). It used bounded,
single-page Hound searches across care-workforce, caregiver-support, policy,
research, and technical queries. The post-Exa-enable runtime probe reported
SearXNG configuration identity
`6032f1abce2480c13a8ade0f10db52a140562326a030d7c70dc95d028bd491e4`.

Status meanings:

- **Responsive:** the engine returned leads without an engine failure.
- **Query-dependent:** the engine completed without failure but returned no
  leads for at least one probe. That is not an outage.
- **Blocked:** SearXNG reported an upstream error, CAPTCHA, denial, or rate
  limit. Do not use the route as the sole source.

### Responsive sources

| Engine | Observed result | Routing note |
| --- | --- | --- |
| `exa web` | Ten relevant caregiver-program leads; official state Medicaid page ranked first | Preferred broad-web route |
| `exa publications` | Five relevant publications with DOI URLs | Preferred research route |
| `federal register` | Results in every probe; up to 21 leads | Preferred US government route |
| `bing news` | Three news leads | Preferred news route |
| `duckduckgo news` | Three leads in one probe; zero without failure in another | Responsive but query-dependent |
| `semantic scholar` | Three publication leads | Useful scholarly alternative |
| `pubmed` | Three leads | Responsive; relevance can be mixed |
| `openairepublications` | Zero, then three leads on a later query | Responsive but query-dependent |
| `openairedatasets` | One dataset lead | Useful when datasets are requested |
| `github` | Three repository leads | Preferred repository route |
| `mdn` | Three documentation leads | Preferred web-reference route |
| `docker hub` | Three package leads | Preferred container route |
| `youtube` | Three video leads | Preferred video route |
| `wikinews` | Three leads | Supplemental news route |
| `lemmy posts` | Zero, then three leads on a later query | Responsive but query-dependent |

`wikipedia`, `wikidata`, `stackoverflow`, `pypi`, `openstreetmap`, `photon`,
and `wordnik` completed without an upstream error but returned no leads for the
topic-specific probes. Retest them with a source-appropriate query before
classifying them.

### Category routes

| Category | Observed result | Routing note |
| --- | --- | --- |
| `government` | Five leads without an engine failure | Useful exploratory route |
| `general`, `web` | Five leads with several blocked general engines | Prefer explicit `exa web` |
| `news`, `government` + `news` | Five leads with several blocked news engines | Prefer explicit `bing news` |
| `science`, `scientific publications` | Five leads despite arXiv and Google Scholar failures | Prefer explicit `exa publications` |
| `it` | Five leads without an engine failure on the final probe | Prefer a source-specific engine when possible |
| `repos` | Five leads; Codeberg timed out | Prefer explicit `github` |
| `software wikis` | Two leads without an engine failure | Useful exploratory route |
| `apps`, `blogs`, `books`, `dictionaries`, `images`, `packages`, `social media`, `videos`, `wikimedia` | Returned leads | Some calls were degraded by the secondary engines listed below |
| `map`, `q&a`, `shopping`, `translate`, `weather` | No useful leads in the topic probes | Retest with source-appropriate queries |

### Blocked or degraded sources

| Engine | Observed failure | Use instead |
| --- | --- | --- |
| `google cse` | Initially responsive, then suspended after upstream rate limits during the benefits radar | `exa web` |
| `duckduckgo` | CAPTCHA | `exa web` |
| `brave` | Too many requests | `exa web` |
| `startpage` | CAPTCHA | `exa web` |
| `brave.news` | Too many requests | `bing news` or `duckduckgo news` |
| `google news` | CAPTCHA | `bing news` or `duckduckgo news` |
| `startpage news` | CAPTCHA | `bing news` or `duckduckgo news` |
| `reuters` | Upstream HTTP error | `bing news` or `duckduckgo news` |
| `google scholar` | Access denied | `exa publications` or `semantic scholar` |
| `arxiv` | Timeout, then upstream rate limiting | `exa publications`, `semantic scholar`, or `openairepublications` |
| `openverse` | Access denied | Retest before image-source use |
| `tootfinder` | Access denied | `lemmy posts` when appropriate |

The reviewed operational overlay now sets the arXiv timeout to 15 seconds; the
change takes effect when the service reloads that configuration. It addresses
the original three-second timeout but cannot bypass upstream rate limiting.

Category fan-out also exposed partial failures from `annas archive`,
`brave.images`, `brave.videos`, `codeberg`, `deviantart`, `geizhals`, `lib.rs`,
`metacpan`, `startpage images`, `vimeo`, `wiktionary`, and `wttr.in`. Category
calls can still return useful leads while listing these engines under
`unresponsive_engines`; keep that degraded state visible.

## Endpoint surface

| Endpoint | Observed behavior | Hound use |
| --- | --- | --- |
| `GET /healthz` | Returned `OK` | Service health check |
| `GET /config` | Returned engine and category configuration | Required before every adapter search |
| `GET /search?format=json` | Returned JSON results and engine diagnostics | Required search transport |
| HTML root and search | Rendered normally | Human inspection only |
| `/about`, `/preferences`, `/stats`, `/stats/errors` | Rendered normally | Operator inspection only |
| `/opensearch.xml`, `/robots.txt` | Returned metadata | Not used by Hound |
| `/metrics` | Reported that open metrics are disabled | Not available in this overlay |
| `/autocomplete` probe | Returned HTML rather than completion JSON | Not used by Hound |

Search one source at a time with:

```bash
SEARXNG_ENDPOINT=http://127.0.0.1:8080 hound search \
  --adapter adapters/searxng/hound-driver.json \
  --json '{
    "query":"caregiver intervention outcomes",
    "limit":5,
    "options":{"engines":["semantic scholar"],"max_pages":1}
  }'
```

Record the run outside an ephemeral directory when the result will support an
operational routing decision. A later successful probe should add a new dated
observation rather than erase an earlier failure.
