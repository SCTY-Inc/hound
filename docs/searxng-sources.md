# SearXNG source map

<!-- Diátaxis: reference -->

This is the operator routing map for Hound's reviewed SearXNG overlay. It
records observed behavior from dated pressure tests; it is not an availability
guarantee. Search responses remain untrusted leads until selected URLs are
captured and inspected.

Prefer explicit engines in recurring owner workflows. Category searches are
useful for exploration, but their upstream engine set can change with SearXNG
configuration and availability. Hound does not silently choose a fallback:
owners must declare each alternative search, retain its record, and decide how
to combine the leads.

The complete engine inventory — all 282 engines with categories, enabled state,
and credential requirement — is [`searxng-inventory.md`](searxng-inventory.md).

## Two routing modes reach different engine sets

Hound accepts `options.engines` or `options.categories`, never both. They do not
reach the same providers, and the difference is larger than the names suggest.

**Explicit engine routing** is restricted to the engines `/config` reports as
`enabled: true` — 86 of 282. The adapter refuses any other name with
`SearXNG engine is not enabled`.

**Category routing** depends on whether the category is one of SearXNG's ten
tab categories (`general`, `images`, `videos`, `news`, `map`, `music`, `it`,
`science`, `files`, `social media`). A tab category queries only the same 86
default-enabled engines. **Every other category queries every engine carrying
that category, including engines `/config` reports as disabled.**

Measured on 2026-07-26, one probe per category:

| Category kind | Engines reached beyond the enabled 86 |
| --- | --- |
| All ten tab categories | none |
| `web` | `bing`, `mojeek`, `mojeek images`, `mojeek news`, `naver`, `presearch` (+ images/news/videos), `qwant`, `qwant images`, `qwant videos`, `seznam`, `yahoo` |
| `packages` | `alpine linux packages`, `cachy os packages`, `crates.io`, `hex`, `lib.rs`, `metacpan`, `npm`, `packagist`, `pkg.go.dev`, `pub.dev`, `voidlinux` |
| `scientific publications` | `crossref`, `openalex` |
| `repos` | `codeberg`, `gitlab`, `huggingface`, `huggingface datasets`, `sourcehut` |
| `wikimedia` | `wikibooks`, `wikiquote`, `wikisource`, `wikispecies`, `wikiversity`, `wikivoyage` |
| `q&a` | `caddy.community`, `discuss.python` |
| `software wikis` | `free software directory`, `minecraft wiki`, `nixos wiki` |
| `dictionaries` | `duden`, `jisho` |
| `books` | `annas archive`, `openlibrary` |
| `movies` | `imdb`, `rottentomatoes`, `senscritique`, `tmdb` |
| `apps` | `apk mirror`, `apple app store`, `fdroid`, `google play apps` |
| `icons` | `flaticon`, `material icons`, `selfhst icons`, `uxwing` |
| `blogs` | `searchmysite`, `wiby` |
| `cargo` | `crates.io` |
| `shopping` | `geizhals` |
| `currency`, `define`, `government`, `lyrics`, `other`, `radio`, `translate`, `weather` | none |

Two consequences an operator must hold:

- The "86 enabled engines" figure understates what this layer can reach. The
  best broad-web and scholarly routes measured are non-tab **categories**, not
  engines.
- A non-tab category route is wide but not declarable engine by engine. It
  cannot be pinned the way an explicit engine can, so its engine set can shift
  under you between runs. Record the returned `unresponsive_engines` every time.

## Preferred routes

| Need | Preferred route | Real alternative |
| --- | --- | --- |
| Broad web discovery | `categories: ["web"]` — 147–165 leads across 66–87 domains | `exa web` (16 leads, 15 domains) or `google cse` (20 leads, 19 domains) |
| Broad web, pinned and reproducible | `exa web` | `google cse` |
| Current news | `duckduckgo news` | `bing news`, then `wikinews` |
| Scholarly publications | `categories: ["scientific publications"]` — 76 leads across 21–22 domains from arXiv, Crossref, Exa, OpenAlex, PubMed | `exa publications`, `pubmed`, `arxiv`, `openairepublications` |
| US federal rules and notices | `federal register` | none — see "Where this layer ends" |
| Research datasets | `openairedatasets` | `categories: ["scientific publications"]` |
| Code and repositories | `github` | `categories: ["repos"]` for Codeberg, GitLab, Hugging Face, SourceHut |
| Language and platform packages | `categories: ["packages"]` | `docker hub`; `pypi` returns nothing, see below |
| Web-development references | `mdn` | `categories: ["it"]` |
| Programming Q&A | `stackoverflow` | `askubuntu`, `superuser`, `categories: ["q&a"]` |
| Container packages | `docker hub` | `categories: ["packages"]` |
| Video discovery | `youtube` | `duckduckgo videos`, `bing videos`, `sepiasearch` |
| Images | `duckduckgo images` | `bing images`, `google cse images`, `wikicommons.images` |
| Social and forum posts | `lemmy posts` | `mastodon hashtags`, `tootfinder` |
| Geocoding and places | `photon` | none — `openstreetmap` is blocked |
| Reference facts | none usable by Hound | see "Answer-only engines" |
| Dictionary and translation | none usable by Hound | see "Answer-only engines" |
| Weather | none | `wttr.in` is blocked |

`exa web` and `exa publications` are reviewed routes through Hound's
credentialed Exa engine. The web route leaves Exa's category unset; the
publication route requests the publication category. The upstream engine name
`exa` is not enabled. Exa's key stays inside the separately operated SearXNG
service.

`categories: ["web"]` mixes image and video results into a text discovery run
(`bing images`, `bing videos`, `google cse images`, `qwant videos` all answer).
Filter by lead URL or accept the noise; do not assume text-only leads.

## Pressure test: 2026-07-26 UTC

Run against the loopback deployment backed by
[`ops/searxng/settings.yml`](../ops/searxng/settings.yml) and
[`ops/systemd/hound-searxng.service`](../ops/systemd/hound-searxng.service),
which publishes `127.0.0.1:8888`. SearXNG version `2026.7.19+6da6eee26`.
Configuration identity
`6032f1abce2480c13a8ade0f10db52a140562326a030d7c70dc95d028bd491e4` — the same
identity as the 2026-07-23 test, so the two runs are directly comparable and
every difference below is upstream behavior, not a configuration change.

Method: [`ops/searxng/probe.py`](../ops/searxng/probe.py), three
domain-appropriate probes per engine across all 86 default-enabled engines,
plus one probe per category. 292 requests for the engine sweep and 34 for the
category sweep; roughly 440 requests in total including exploratory probes.

Status meanings, unchanged:

- **Responsive:** the engine returned leads without an engine failure.
- **Query-dependent:** the engine completed without failure but returned no
  leads for at least one probe. That is not an outage.
- **No-leads:** the engine completed without failure and returned no leads for
  any probe.
- **Blocked:** SearXNG reported an upstream error, CAPTCHA, denial, or rate
  limit. Do not use the route as the sole source.

A route that fails on some probes and answers on others is classified
**blocked**, not responsive. Intermittent availability is the dangerous shape
for daily automation, and the definition already says such a route cannot be
the sole source.

Result: **48 responsive, 1 query-dependent, 11 no-leads, 26 blocked.**

### Responsive sources

Leads and distinct domains are the maximum observed across three probes.

| Engine | Leads | Domains | Routing note |
| --- | --- | --- | --- |
| `google cse` | 20 | 19 | Best single-engine domain diversity measured |
| `exa web` | 16 | 15 | Preferred pinned broad-web route |
| `duckduckgo news` | 19 | 15 | Preferred news route; see resolution below |
| `exa publications` | 16 | 9 | Preferred pinned research route |
| `bing news` | 9 | 8 | Fragile; see resolution below |
| `federal register` | 20 | 1 | Preferred and only US government route |
| `pubmed` | 20 | 1 | Reliable biomedical route |
| `arxiv` | 10 | 1 | Recovered from the 2026-07-23 timeout failure |
| `openairepublications` | 10 | 4 | Now responsive on every probe |
| `openairedatasets` | 10 | 5 | Preferred dataset route |
| `github` | 30 | 1 | Preferred repository route |
| `mdn` | 10 | 1 | Preferred web-reference route |
| `docker hub` | 10 | 1 | Preferred container route |
| `stackoverflow`, `askubuntu`, `superuser` | 10 | 1 | Q&A routes, all responsive |
| `youtube` | 20 | 1 | Preferred video route |
| `duckduckgo videos` | 60 | 2 | Highest video volume |
| `bing videos` | 47 | 2 | Video alternative |
| `dailymotion`, `sepiasearch` | 10 | 1–6 | Video alternatives |
| `duckduckgo images` | 81 | 57 | Preferred image route |
| `bing images` | 35 | 28 | Image alternative |
| `google cse images` | 20 | 14 | Image alternative |
| `wikicommons.images` | 10 | 1 | Licensed image route |
| `flickr`, `pexels`, `unsplash`, `artic`, `pinterest` | 18–25 | 1–8 | Image sources |
| `devicons`, `lucide` | 50–101 | 1 | Icon routes |
| `lemmy posts`, `lemmy communities`, `lemmy users` | 10 | 9–10 | Preferred social routes |
| `mastodon hashtags`, `mastodon users` | 40 | 1–29 | Social alternatives |
| `tootfinder` | 100 | 33 | Recovered from 2026-07-23 access denial |
| `wikinews` | 5 | 1 | Supplemental news route |
| `wiktionary` | 5 | 1 | Only dictionary route returning leads |
| `photon` | 10 | 1 | Preferred geocoding route |
| `mankier`, `hoogle` | 20–25 | 1 | Manual-page and Haskell routes |
| `mixcloud`, `radio browser` | 10 | 1–9 | Music and radio routes |
| `pdbe` | 9 | 1 | Protein structure route |
| `bt4g` | 15 | 1 | See "Where this layer ends" before using |
| `chefkoch` | 17 | 1 | German recipe route |

### Query-dependent sources

| Engine | Observed result |
| --- | --- |
| `soundcloud` | Zero on one probe, ten on two others; not an outage |

### No-leads sources

These completed without any upstream failure and returned nothing for three
domain-appropriate probes. That is a different fault from a blocked route and
must not be reported as one.

| Engine | Note |
| --- | --- |
| `pypi` | Zero leads for `requests`, `numpy`, `httpx`. Upstream result parsing appears broken; not fixable from this overlay. Use `categories: ["packages"]`. |
| `arch linux wiki` | Zero leads for `systemd`, `pacman`, `kernel module`. Same shape as `pypi`. |
| `bandcamp` | Zero leads, no answers, no infoboxes. |
| `etymonline` | Zero leads. |
| `wikidata` | Zero leads. |
| `wikipedia`, `wordnik`, `currency` | Answer-only; see below. |
| `lingva`, `dictzone`, `mymemory translated` | Translation engines; see below. |

### Answer-only engines: working, and invisible to Hound

`wikipedia` returns an **infobox**, `wordnik` returns four **answers**, and
`currency` returns one **answer**. SearXNG produced real output in each case.
Hound's adapter converts only the `results` array into leads
([`src/hound_web_adapters/searxng.py`](../src/hound_web_adapters/searxng.py)),
so `answers` and `infoboxes` are discarded and the search looks empty.

This is a structural limit of the adapter, not an upstream failure. It is why
"reference facts" and "dictionary and translation" have no usable route in the
preferred-routes table. Closing it would mean teaching the adapter to carry
`answers` and `infoboxes` as a distinct, clearly non-lead output — an owner
decision, not a configuration change.

The three translation engines (`lingva`, `dictzone`, `mymemory translated`) are
unreachable for a second, independent reason: they need SearXNG's `:language`
query syntax, and the adapter deliberately rejects any token beginning with `:`
as control syntax. Translation is outside this layer.

### Blocked or degraded sources

| Engine | Observed failure | Cause | Use instead |
| --- | --- | --- | --- |
| `duckduckgo` | CAPTCHA | Upstream | `categories: ["web"]`, `exa web` |
| `startpage`, `startpage news`, `startpage images` | CAPTCHA | Upstream | `exa web`, `duckduckgo news` |
| `google news` | CAPTCHA | Upstream | `duckduckgo news`, `bing news` |
| `brave`, `brave.news`, `brave.images`, `brave.videos` | Too many requests | Upstream | `exa web`, `duckduckgo news` |
| `google scholar` | Access denied | Upstream | `categories: ["scientific publications"]` |
| `semantic scholar` | Reported as timeout | **Upstream AWS WAF bot challenge** — see below | `categories: ["scientific publications"]`, `pubmed` |
| `reuters` | HTTP 401 Unauthorized | Upstream authentication wall | `duckduckgo news`, `bing news` |
| `openstreetmap` | Access denied | Upstream | `photon` |
| `openverse`, `deviantart`, `vimeo`, `genius`, `kickass`, `piratebay` | Access denied | Upstream | Route-specific alternatives above |
| `solidtorrents` | Access denied, then parsing error | Upstream | — |
| `wikicommons.audio`, `wikicommons.files` | Too many requests | Wikimedia shared-IP rate limit | `wikicommons.images` still responds |
| `wikicommons.videos` | Intermittent: 10 leads on one probe, rate limited on others | Wikimedia shared-IP rate limit | `youtube`, `duckduckgo videos` |
| `lemmy comments` | Intermittent timeout; 10 leads on one probe | Upstream latency, not a local timeout defect | `lemmy posts` |
| `gentoo` | Intermittent timeout | Upstream latency; the 10s timeout is already generous | `categories: ["software wikis"]` |
| `wttr.in` | Parsing error | Upstream format change | none |

`semantic scholar` deserves its own note because its label is misleading.
SearXNG reports **timeout**, which suggests the arXiv-style local fix. It is
not. The endpoint SearXNG calls,
`https://www.semanticscholar.org/api/1/search`, answers in about 50ms with
`HTTP 202` and the header `x-amzn-waf-action: challenge` — an AWS WAF bot
challenge with an empty body. Raising the timeout cannot help, and defeating
the challenge is out of bounds. This is a regression from 2026-07-23, when the
engine returned three leads. Crossref and OpenAlex, reachable through
`categories: ["scientific publications"]`, cover the same need.

## What can be fixed locally, and what cannot

**Fixed in this pass.** [`examples/searxng/settings.yml`](../examples/searxng/settings.yml)
did not carry the arXiv timeout override that the 2026-07-23 test established
and that [`ops/searxng/settings.yml`](../ops/searxng/settings.yml) already had.
An operator copying the example would have reproduced the known-broken
three-second timeout. The example now matches the reviewed operational overlay,
and `tests/test_searxng_overlay.py` asserts the two agree. A running service
picks this up only when it reloads that configuration.

**Confirmed fixed and now verified.** The arXiv timeout change from 3s to 15s
has taken effect in the running service — `/config` reports `timeout: 15` and
arXiv returned ten leads on every probe. The 2026-07-23 entry noting the change
was pending a reload can be considered closed.

**Not a local defect, despite the label.** `semantic scholar`, `lemmy comments`,
and `gentoo` all surface as timeouts. Direct measurement of each upstream shows
`lemmy.ml` answering in 0.06–0.57s against a 3s budget and `wiki.gentoo.org` in
3.9–4.8s against a 10s budget. Both budgets are already generous; the failures
are upstream latency spikes. `semantic scholar` is a bot challenge, above.
Raising these timeouts would add delay without adding leads.

**Not fixable from this repository at all.** Every CAPTCHA (`duckduckgo`,
`startpage`, `google news`), every rate limit (`brave` family, Wikimedia
commons), every access denial (`google scholar`, `openstreetmap`, `openverse`,
`vimeo`, `genius`), the `reuters` authentication wall, and the `pypi` and
`arch linux wiki` empty-result faults are upstream. Working around a CAPTCHA or
a rate limit is out of scope by policy, not only by capability.

**Deliberately not changed.** No engine was enabled or disabled to improve the
responsive count. Several permanently blocked engines (`reuters`, `startpage`,
`brave` family) could be disabled locally to quiet category fan-out, but that
would hide a degraded route rather than surface it, which contradicts this
layer's stated posture. Recommend it to the owner; do not do it silently.

## A requested route can fail without saying so

Hound distinguishes an engine that returns nothing from an engine that fails —
but only when the caller routes explicitly, and only in one case.

`src/hound_web_adapters/searxng.py` raises
`all explicitly requested SearXNG engines were unresponsive` when every named
engine appears in `unresponsive_engines` **and** no leads were returned. Below
that threshold the failure is recorded in
`output.routing.unresponsive_engines` and the search succeeds. Three real gaps
follow:

1. **Partial engine failure is silent.** gc-web Pulse requests
   `['bing news', 'duckduckgo news']`. If `bing news` fails and `duckduckgo
   news` returns zero leads without failing, not every requested engine was
   unresponsive, so no error is raised and Pulse sees an empty, healthy-looking
   result. `bing news` fails exactly this way: the service log shows
   `lxml.etree.ParserError: Document is empty`, and the third probe in this run
   degraded to a single lead.
2. **Category routing has no guard at all.** The check requires
   `selected_engines`. A category search where every engine fails returns zero
   leads and no error.
3. **Unrouted search has no guard either.** gc-intel and gc-wiki call
   `hound search` with only `query` and `limit`, so SearXNG runs the default
   `general` set. Measured today, that set is `exa web` and `google cse`
   answering while `brave`, `duckduckgo` and `startpage` are all blocked. If
   `google cse` were suspended, both lanes would quietly fall back to `exa web`
   alone with no signal.

The routing record always carries the truth. Consumers that do not read
`output.routing.unresponsive_engines` cannot tell degradation from emptiness.

## Resolutions of open questions

| Question | Resolution on 2026-07-26 |
| --- | --- |
| `google cse` — really blocked? | **Responsive, and healthy.** Twenty leads on every one of three probes, 19 distinct domains, the best single-engine diversity measured. The service log records zero `google cse` errors in 24 hours across roughly 440 requests. The 2026-07-23 suspension was a transient upstream rate limit, not standing quota exhaustion. It carries no API key in this image, so there is no quota to inspect and no per-day ceiling that can be asserted; treat recovery as observed, not guaranteed, and keep `exa web` declared alongside it. |
| `duckduckgo news` — query-dependent or dead? | **Responsive.** Seventeen to nineteen leads on all three probes, 15 distinct domains. Not dead. The single zero-lead probe on 2026-07-23 was query-dependence, and one probe returning zero remains insufficient to classify an engine. |
| `exa web` — safe as a daily dependency? | **Yes, with a declared alternative.** Sixteen leads on all three probes, 15 distinct domains, no failure in any run today. It carries `EXA_API_KEY`, so its failure mode is credential or quota rather than CAPTCHA, and that mode is not observable from this repository. Do not make it a sole source. |
| Can a zero-lead engine be told apart from a failing one? | **At the SearXNG layer, always** — `unresponsive_engines` names every failure. **At the Hound layer, only for fully-failed explicit routes.** See the section above. |

## Changes since the 2026-07-23 baseline

Same configuration identity, so every difference is upstream behavior or new
measurement coverage.

**Recovered:** `arxiv` (timeout fix now in effect), `google cse` (from
rate-limit suspension), `tootfinder` (from access denied),
`openairepublications` (now responsive on every probe), `duckduckgo news` (now
responsive on every probe).

**Regressed:** `semantic scholar` (responsive → blocked by an AWS WAF bot
challenge), `openstreetmap` (→ access denied; `photon` covers the need).

**Newly measured, not previously classified:** 71 of the 86 enabled engines had
no dated record before this run. `pypi`, `wikipedia`, `wikidata`,
`stackoverflow`, `openstreetmap`, `photon` and `wordnik` were explicitly listed
as needing a source-appropriate retest on 2026-07-23; all seven are now
classified.

**Newly documented structure:** the tab-versus-sub-category dispatch rule, the
`web` and `scientific publications` category routes, the answer-only engine
class, and the three silent-degradation gaps.

**Corrected:** the endpoint example below used port 8080; the operational unit
publishes 8888. Port 8080 remains correct for the standalone container in
[`examples/searxng/README.md`](../examples/searxng/README.md).

## Where this layer ends

Knowing the boundary is the point of the map.

- **Paywalled and subscription press.** Reuters answers `401 Unauthorized`.
  Nothing in this layer authenticates to a publisher, and nothing should.
- **Anything requiring a login.** No engine here carries a user session. Sources
  behind an account — most social platforms' full APIs, professional networks,
  vendor portals, licensed databases — are out of reach by design.
- **Anything behind a CAPTCHA or bot challenge.** `duckduckgo`, `startpage`,
  `google news` and `semantic scholar` are unreachable because a human check
  stands in front of them. That is the provider's decision and this layer
  respects it. Do not route around it.
- **Rate-limited providers under shared egress.** The `brave` family and the
  Wikimedia commons endpoints rate-limit this host's address. More requests make
  this worse, not better.
- **Sources whose terms forbid automated collection.** The torrent engines
  (`bt4g`, `piratebay`, `kickass`, `solidtorrents`) and shadow-library engines
  (`annas archive`, reachable through `categories: ["books"]`) are present in
  the upstream image and are listed here for completeness of the inventory.
  They are not appropriate evidence sources for any Hound lane.
- **Answers rather than links.** Infobox and answer output is discarded by the
  adapter, so this layer cannot currently deliver a fact — only a lead to a
  document that may contain one.
- **State, local and international government.** `federal register` is the only
  government engine, and it covers US federal rules and notices only. There is
  no route to state legislatures, municipal records, or non-US government
  sources. This is a real gap, not an omission.
- **Guarantees of any kind.** Every classification here is a dated observation.
  A responsive engine can be blocked an hour later; `google cse` moved in both
  directions within four days. Declare alternatives; do not assume.

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
SEARXNG_ENDPOINT=http://127.0.0.1:8888 hound search \
  --adapter adapters/searxng/hound-driver.json \
  --json '{
    "query":"caregiver intervention outcomes",
    "limit":5,
    "options":{"engines":["pubmed"],"max_pages":1}
  }'
```

Record the run outside an ephemeral directory when the result will support an
operational routing decision. A later successful probe should add a new dated
observation rather than erase an earlier failure.

## Re-running this map

[`ops/searxng/probe.py`](../ops/searxng/probe.py) regenerates every
classification above. It is standard library only, read-only against every
corpus, and bounded by `--max-requests`. It issues HTTP GET requests to the
SearXNG endpoint and writes nothing but the report named by `--out`.

```bash
# full sweep: 86 engines x 3 domain-appropriate probes + one probe per category
SEARXNG_ENDPOINT=http://127.0.0.1:8888 python3 ops/searxng/probe.py \
  --probes 3 --delay 1.5 --max-requests 400 --out /tmp/searxng-probe.json

# recheck one route after an incident
python3 ops/searxng/probe.py --engines 'google cse,exa web' --probes 5 \
  --skip-categories

# category reach only, to re-derive the dispatch table above
python3 ops/searxng/probe.py --skip-engines --max-requests 60

# regenerate docs/searxng-inventory.md
python3 ops/searxng/probe.py --inventory > docs/searxng-inventory.md
```

The full sweep takes roughly twenty minutes at the default 1.5s delay and makes
292 engine requests plus 34 category requests. Keep the delay: several engines
here rate-limit this host's address, and a faster sweep degrades the very routes
it is measuring.

Every report records `config_sha256`. Compare it against the identity in the
dated section above before treating two runs as comparable — a different
identity means the configuration changed and the engine set may differ.

## Pressure test: 2026-07-23 UTC (superseded, retained)

The earlier test exercised the same loopback deployment and reported
configuration identity
`6032f1abce2480c13a8ade0f10db52a140562326a030d7c70dc95d028bd491e4`. It used
bounded, single-page Hound searches across care-workforce, caregiver-support,
policy, research, and technical queries, covering roughly fifteen engines.

Responsive then: `exa web`, `exa publications`, `federal register`, `bing news`,
`duckduckgo news` (query-dependent), `semantic scholar`, `pubmed`,
`openairepublications` (query-dependent), `openairedatasets`, `github`, `mdn`,
`docker hub`, `youtube`, `wikinews`, `lemmy posts` (query-dependent).

`wikipedia`, `wikidata`, `stackoverflow`, `pypi`, `openstreetmap`, `photon`, and
`wordnik` completed without an upstream error but returned no leads for the
topic-specific probes, and were flagged for retest with a source-appropriate
query. That retest is the 2026-07-26 run above.

Blocked then: `google cse` (rate-limit suspension mid-test), `duckduckgo`
(CAPTCHA), `brave` (too many requests), `startpage` (CAPTCHA), `brave.news`,
`google news` (CAPTCHA), `startpage news` (CAPTCHA), `reuters` (HTTP error),
`google scholar` (access denied), `arxiv` (timeout, then rate limiting),
`openverse` (access denied), `tootfinder` (access denied).

Category fan-out then also exposed partial failures from `annas archive`,
`brave.images`, `brave.videos`, `codeberg`, `deviantart`, `geizhals`, `lib.rs`,
`metacpan`, `startpage images`, `vimeo`, `wiktionary`, and `wttr.in`. Several of
those names are engines `/config` reports as disabled; the
tab-versus-sub-category rule documented above explains why a category call
reached them.
