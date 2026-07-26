# SearXNG engine inventory

<!-- Diátaxis: reference -->

Every engine in the running SearXNG configuration. Routing guidance lives in
[`searxng-sources.md`](searxng-sources.md); this page is the raw ledger.

Regenerate with:

```bash
SEARXNG_ENDPOINT=http://127.0.0.1:8888 python3 ops/searxng/probe.py --inventory \
  > docs/searxng-inventory.md
```

## How to read the `Enabled` column

`yes` means `/config` reports `enabled: true`, and Hound may name the engine in
`options.engines`. `no` means the engine is disabled by the **upstream SearXNG
image default** — not by a decision recorded in this repository. Of the 196
disabled engines, zero were disabled deliberately here: the overlay
(`ops/searxng/settings.yml`) adds `exa web`, `exa publications` and
`federal register`, raises the arXiv timeout, and changes no other engine's
enabled state. The disabled majority was never considered, not rejected.

A disabled engine is still reachable through a non-tab category search. See
"Two routing modes reach different engine sets" in the source map.

## Credentials

The credential surface is almost empty, so enabling more engines is not gated
behind buying keys.

- **Required:** `exa web` and `exa publications` need `EXA_API_KEY`, supplied to
  the container by `ops/systemd/hound-searxng.service` and never seen by Hound.
  `iqiyi` needs an `api_key` and is disabled.
- **Optional:** `semantic scholar` accepts an `api_client_id` and
  `mymemory translated` accepts an `api_key`; both run keyless at lower quota.
- **Every other engine of the 282 runs keyless.**

<!-- SearXNG config identity 6032f1abce2480c13a8ade0f10db52a140562326a030d7c70dc95d028bd491e4 -->
<!-- 282 engines, 86 enabled -->

| Engine | Shortcut | Categories | Enabled | Credential |
| --- | --- | --- | --- | --- |
| `1337x` | `1337x` | files | no | none |
| `1x` | `1x` | images | no | none |
| `360search` | `360so` | general | no | none |
| `360search videos` | `360sov` | videos | no | none |
| `500px` | `500` | images | no | none |
| `9gag` | `9g` | social media | no | none |
| `abcnyheter` | `abc` | general | no | none |
| `acfun` | `acf` | videos | no | none |
| `adobe stock` | `asi` | images | no | none |
| `adobe stock audio` | `asa` | music | no | none |
| `adobe stock video` | `asv` | videos | no | none |
| `alpine linux packages` | `alp` | packages, it | no | none |
| `anaconda` | `conda` | it | no | none |
| `annas archive` | `aa` | files, books | no | none |
| `ansa` | `ans` | news | no | none |
| `apk mirror` | `apkm` | files, apps | no | none |
| `apple app store` | `aps` | files, apps | no | none |
| `apple maps` | `apm` | map | no | none |
| `arch linux wiki` | `al` | it, software wikis | yes | none |
| `artic` | `arc` | images | yes | none |
| `artstation` | `as` | images | no | none |
| `arxiv` | `arx` | science, scientific publications | yes | none |
| `askubuntu` | `ubuntu` | it, q&a | yes | none |
| `ayo` | `ayo` | general | no | none |
| `baidu` | `bd` | general | no | none |
| `baidu images` | `bdi` | images | no | none |
| `baidu kaifa` | `bdk` | it | no | none |
| `bandcamp` | `bc` | music | yes | none |
| `bilibili` | `bil` | videos | no | none |
| `bing` | `bi` | general, web | no | none |
| `bing images` | `bii` | images, web | yes | none |
| `bing news` | `bin` | news | yes | none |
| `bing videos` | `biv` | videos, web | yes | none |
| `bitbucket` | `bb` | it, repos | no | none |
| `bitchute` | `bit` | videos | no | none |
| `boardreader` | `boa` | general, social media | no | none |
| `bpb` | `bpb` | general | no | none |
| `brave` | `br` | general, web | yes | none |
| `brave.images` | `brimg` | images, web | yes | none |
| `brave.news` | `brnews` | news | yes | none |
| `brave.videos` | `brvid` | videos, web | yes | none |
| `bt4g` | `bt4g` | files | yes | none |
| `btdigg` | `bt` | files | no | none |
| `cachy os packages` | `cos` | packages, it | no | none |
| `caddy.community` | `caddy` | it, q&a | no | none |
| `cara` | `ca` | images | no | none |
| `chefkoch` | `chef` | other | yes | none |
| `codeberg` | `cb` | it, repos | no | none |
| `crates.io` | `crates` | it, packages, cargo | no | none |
| `crossref` | `cr` | science, scientific publications | no | none |
| `crowdview` | `cv` | general | no | none |
| `currency` | `cc` | currency, general | yes | none |
| `dailymotion` | `dm` | videos | yes | none |
| `ddg definitions` | `ddd` | general | no | none |
| `deezer` | `dz` | music | no | none |
| `destatis` | `destat` | other | no | none |
| `deviantart` | `da` | images | yes | none |
| `devicons` | `di` | images, icons | yes | none |
| `dictzone` | `dc` | general, translate | yes | none |
| `discuss.python` | `dpy` | it, q&a | no | none |
| `docker hub` | `dh` | it, packages | yes | none |
| `dogpile` | `dog` | general | no | none |
| `dogpile images` | `dogi` | images | no | none |
| `dogpile news` | `dogn` | news | no | none |
| `dogpile videos` | `dogv` | videos | no | none |
| `duckduckgo` | `ddg` | general, web | yes | none |
| `duckduckgo images` | `ddi` | images | yes | none |
| `duckduckgo news` | `ddn` | news | yes | none |
| `duckduckgo videos` | `ddv` | videos | yes | none |
| `duckduckgo weather` | `ddw` | weather, other | no | none |
| `duckduckgo web` | `ddgw` | general | no | none |
| `duden` | `du` | dictionaries, other | no | none |
| `emojipedia` | `em` | other | no | none |
| `encyclosearch` | `es` | general | no | none |
| `erowid` | `ew` | other | no | none |
| `etymonline` | `et` | dictionaries, other | yes | none |
| `exa publications` | `exap` | science, scientific publications | yes | `EXA_API_KEY` (required) |
| `exa web` | `exaw` | general, web | yes | `EXA_API_KEY` (required) |
| `fastbot` | `fa` | general | no | none |
| `fdroid` | `fd` | files, apps | no | none |
| `federal register` | `fr` | government, news | yes | none |
| `findfiles` | `fif` | files | no | none |
| `findfiles images` | `fifi` | images | no | none |
| `findfiles music` | `fifm` | music | no | none |
| `findfiles videos` | `fifv` | videos | no | none |
| `findthatmeme` | `ftm` | images | no | none |
| `fireball` | `fire` | general | no | none |
| `fireball news` | `firen` | news | no | none |
| `fireball videos` | `firev` | videos | no | none |
| `flaticon` | `fli` | images, icons | no | none |
| `flickr` | `fl` | images | yes | none |
| `free software directory` | `fsd` | it, software wikis | no | none |
| `frinkiac` | `frk` | images | no | none |
| `fynd` | `fynd` | general | no | none |
| `fyyd` | `fy` | other | no | none |
| `gabanza` | `gab` | general | no | none |
| `geizhals` | `geiz` | shopping, other | no | none |
| `genius` | `gen` | music, lyrics | yes | none |
| `gentoo` | `ge` | it, software wikis | yes | none |
| `giphy` | `gif` | images | no | none |
| `gitea.com` | `gitea` | it, repos | no | none |
| `github` | `gh` | it, repos | yes | none |
| `gitlab` | `gl` | it, repos | no | none |
| `gmx` | `gmx` | general | no | none |
| `goodreads` | `good` | other | no | none |
| `google cse` | `goc` | general, web | yes | none |
| `google cse images` | `goci` | images, web | yes | none |
| `google news` | `gon` | news | yes | none |
| `google play apps` | `gpa` | files, apps | no | none |
| `google play movies` | `gpm` | videos | no | none |
| `google scholar` | `gos` | science, scientific publications | yes | none |
| `habrahabr` | `habr` | it | no | none |
| `hackernews` | `hn` | it | no | none |
| `hex` | `hex` | it, packages | no | none |
| `hoogle` | `ho` | it, packages | yes | none |
| `huggingface` | `hf` | it, repos | no | none |
| `huggingface datasets` | `hfd` | it, repos | no | none |
| `huggingface spaces` | `hfs` | it, repos | no | none |
| `il post` | `pst` | news | no | none |
| `imdb` | `imdb` | movies, other | no | none |
| `imgur` | `img` | images | no | none |
| `ina` | `in` | videos | no | none |
| `infospace` | `ifs` | general | no | none |
| `ipernity` | `ip` | images | no | none |
| `iqiyi` | `iq` | videos | no | `api_key` (required) |
| `jisho` | `js` | dictionaries, other | no | none |
| `kickass` | `kc` | files | yes | none |
| `lemmy comments` | `lecom` | social media | yes | none |
| `lemmy communities` | `leco` | social media | yes | none |
| `lemmy posts` | `lepo` | social media | yes | none |
| `lemmy users` | `leus` | social media | yes | none |
| `lib.rs` | `lrs` | it, packages | no | none |
| `library genesis` | `lg` | files | no | none |
| `library of congress` | `loc` | images | no | none |
| `lingva` | `lv` | general, translate | yes | none |
| `lobste.rs` | `lo` | it | no | none |
| `lucide` | `luc` | images, icons | yes | none |
| `magnific` | `mag` | images | no | none |
| `mankier` | `man` | it | yes | none |
| `mastodon hashtags` | `mah` | social media | yes | none |
| `mastodon users` | `mau` | social media | yes | none |
| `material icons` | `mi` | images, icons | no | none |
| `mdn` | `mdn` | it | yes | none |
| `media.ccc.de` | `c3tv` | videos | no | none |
| `mediathekviewweb` | `mvw` | videos | no | none |
| `metacpan` | `cpan` | it, packages | no | none |
| `microsoft learn` | `msl` | it | no | none |
| `minecraft wiki` | `mcw` | software wikis, other | no | none |
| `mixcloud` | `mc` | music | yes | none |
| `mojeek` | `mjk` | general, web | no | none |
| `mojeek images` | `mjkimg` | images, web | no | none |
| `mojeek news` | `mjknews` | news, web | no | none |
| `moviepilot` | `mp` | movies, other | no | none |
| `mozhi` | `mz` | general, translate | no | none |
| `mwmbl` | `mwm` | general | no | none |
| `mymemory translated` | `tl` | general, translate | yes | `api_key` (optional) |
| `national vulnerability database` | `nvd` | it | no | none |
| `naver` | `nvr` | general, web | no | none |
| `naver images` | `nvri` | images | no | none |
| `naver news` | `nvrn` | news | no | none |
| `naver videos` | `nvrv` | videos | no | none |
| `niconico` | `nico` | videos | no | none |
| `nixos wiki` | `nixw` | it, software wikis | no | none |
| `npm` | `npm` | it, packages | no | none |
| `nyaa` | `nt` | files | no | none |
| `odysee` | `od` | videos | no | none |
| `ollama` | `ollama` | it, repos | no | none |
| `openairedatasets` | `oad` | science | yes | none |
| `openairepublications` | `oap` | science | yes | none |
| `openalex` | `oa` | science, scientific publications | no | none |
| `openlibrary` | `ol` | general, books | no | none |
| `openmeteo` | `om` | weather, other | no | none |
| `openrepos` | `or` | files | no | none |
| `openstreetmap` | `osm` | map | yes | none |
| `openverse` | `opv` | images | yes | none |
| `packagist` | `pack` | it, packages | no | none |
| `pdbe` | `pdb` | science | yes | none |
| `peertube` | `ptb` | videos | no | none |
| `pexels` | `pe` | images | yes | none |
| `photon` | `ph` | map | yes | none |
| `pi-hole.community` | `pi` | it, q&a | no | none |
| `picjumbo` | `pj` | images | no | none |
| `pinterest` | `pin` | images | yes | none |
| `piratebay` | `tpb` | files | yes | none |
| `pixabay images` | `pixi` | images | no | none |
| `pixabay videos` | `pixv` | videos | no | none |
| `pkg.go.dev` | `pgo` | packages, it | no | none |
| `podchaser` | `poc` | other | no | none |
| `presearch` | `ps` | general, web | no | none |
| `presearch images` | `psimg` | images, web | no | none |
| `presearch news` | `psnews` | news, web | no | none |
| `presearch videos` | `psvid` | general, web | no | none |
| `privacywall` | `pw` | general | no | none |
| `privacywall images` | `pwi` | images | no | none |
| `privacywall videos` | `pwv` | videos | no | none |
| `pub.dev` | `pd` | packages, it | no | none |
| `public domain image archive` | `pdia` | images | no | none |
| `pubmed` | `pub` | science, scientific publications | yes | none |
| `pypi` | `pypi` | it, packages | yes | none |
| `quark` | `qk` | general | no | none |
| `quark images` | `qki` | images | no | none |
| `qwant` | `qw` | general, web | no | none |
| `qwant images` | `qwi` | images, web | no | none |
| `qwant news` | `qwn` | news | no | none |
| `qwant videos` | `qwv` | videos, web | no | none |
| `radio browser` | `rb` | music, radio | yes | none |
| `reddit` | `re` | social media | no | none |
| `reloado` | `rel` | general | no | none |
| `resulthunter` | `reh` | general | no | none |
| `resulthunter images` | `rehi` | images | no | none |
| `reuters` | `reu` | news | yes | none |
| `rottentomatoes` | `rt` | movies, other | no | none |
| `rubygems` | `rbg` | it, packages | no | none |
| `rumble` | `ru` | videos | no | none |
| `searchch` | `sch` | general | no | none |
| `searchmysite` | `sms` | general, blogs | no | none |
| `searchtoday` | `std` | general | no | none |
| `selfhst icons` | `si` | images, icons | no | none |
| `semantic scholar` | `se` | science, scientific publications | yes | `api_client_id` (optional) |
| `senscritique` | `scr` | movies, other | no | none |
| `sepiasearch` | `sep` | videos | yes | none |
| `seznam` | `szn` | general, web | no | none |
| `shopify stock` | `shs` | images | no | none |
| `sogou` | `sogou` | general | no | none |
| `sogou images` | `sogoui` | images | no | none |
| `sogou videos` | `sogouv` | videos | no | none |
| `sogou wechat` | `sogouw` | news | no | none |
| `solidtorrents` | `solid` | files | yes | none |
| `soundcloud` | `sc` | music | yes | none |
| `sourcehut` | `srht` | it, repos | no | none |
| `stackoverflow` | `st` | it, q&a | yes | none |
| `startpage` | `sp` | general, web | yes | none |
| `startpage images` | `spi` | images, web | yes | none |
| `startpage news` | `spn` | news, web | yes | none |
| `steam` | `stm` | other | no | none |
| `stocksnap` | `sto` | images | no | none |
| `superuser` | `su` | it, q&a | yes | none |
| `tagesschau` | `ts` | general, news | no | none |
| `tineye` | `tin` | general | no | none |
| `tmdb` | `tm` | movies, other | no | none |
| `tokyotoshokan` | `tt` | files | no | none |
| `tootfinder` | `toot` | social media | yes | none |
| `tusksearch` | `tu` | general | no | none |
| `tusksearch images` | `tui` | images | no | none |
| `tusksearch news` | `tun` | news | no | none |
| `tusksearch videos` | `tuv` | videos | no | none |
| `unsplash` | `us` | images | yes | none |
| `uxwing` | `ux` | images, icons | no | none |
| `vimeo` | `vm` | videos | yes | none |
| `voidlinux` | `void` | packages, it | no | none |
| `vuhuv` | `vu` | general | no | none |
| `vuhuv images` | `vui` | images | no | none |
| `vuhuv videos` | `vuv` | videos | no | none |
| `wiby` | `wib` | general, blogs | no | none |
| `wikibooks` | `wb` | general, wikimedia | no | none |
| `wikicommons.audio` | `wca` | music | yes | none |
| `wikicommons.files` | `wcf` | files | yes | none |
| `wikicommons.images` | `wci` | images | yes | none |
| `wikicommons.videos` | `wcv` | videos | yes | none |
| `wikidata` | `wd` | general | yes | none |
| `wikimini` | `wkmn` | general | no | none |
| `wikinews` | `wn` | news, wikimedia | yes | none |
| `wikipedia` | `wp` | general | yes | none |
| `wikiquote` | `wq` | general, wikimedia | no | none |
| `wikisource` | `ws` | general, wikimedia | no | none |
| `wikispecies` | `wsp` | general, science, wikimedia | no | none |
| `wikiversity` | `wv` | general, wikimedia | no | none |
| `wikivoyage` | `wy` | general, wikimedia | no | none |
| `wiktionary` | `wt` | dictionaries, wikimedia, other | yes | none |
| `wolframalpha` | `wa` | general | no | none |
| `wordnik` | `wnik` | dictionaries, define, other | yes | none |
| `woxikon.de synonyme` | `woxi` | dictionaries, other | no | none |
| `wttr.in` | `wttr` | weather, other | yes | none |
| `yacy` | `ya` | general | no | none |
| `yacy images` | `yai` | images | no | none |
| `yahoo` | `yh` | general, web | no | none |
| `yandex` | `yd` | general | no | none |
| `yandex images` | `ydi` | images | no | none |
| `yandex music` | `ydm` | music | no | none |
| `yep` | `yep` | general | no | none |
| `youtube` | `yt` | videos, music | yes | none |
| `zapmeta` | `zpm` | general | no | none |
