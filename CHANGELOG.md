# Changelog

All notable changes to `@ismalicious/mcp-server` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-09-30

### Added

- `check_password_exposure`: whether a password, or its SHA-1 or NTLM hash,
  is in Have I Been Pwned's Pwned Passwords corpus, and how many times. A
  plaintext password is hashed on the caller's machine; only the first five
  hex digits of the hash are sent (`GET /pwned-passwords/range/{prefix}`),
  and the match is made locally. One request of the monthly quota.
- `check_indicator` on a 40-hex (SHA-1) or 32-hex (NTLM) value now carries
  `pwnedPassword: { hashType, count }` when the value is the hash of a
  breached password, and its headline says so. The file verdict is unchanged.

## [0.3.1] - 2026-09-29

The source is public: <https://github.com/hexablob/ismalicious-mcp-server>
mirrors this package. Until now `repository` named the private monorepo, which
answers 404 outside it.

### Added

- `LICENSE` (MIT) ships in the tarball. `repository` and `bugs` in
  `package.json`, and `repository` in the MCP registry entry, point at the
  public repository.
- `glama.json` (maintainer) and a `Dockerfile` that builds the package and
  runs the stdio server, which Glama needs to list it. The image sets a
  placeholder key pair, so `tools/list` returns the seven keyed tools instead
  of `bootstrap_key` alone. Listing makes no network call; a real pair passed
  with `-e` replaces the placeholder, and empty values restore bootstrap mode.

### Changed

- `search_indicators`: the default API now answers with the domains the corpus
  lists that look like the keyword — typosquats, homoglyphs, the name on other
  TLDs or hosting platforms, phishing-word combinations — most dangerous
  first, up to 500. The 25-per-label index search it replaces had failed on
  every call since the index was lost (2026-09-23). Tool and `keywords`
  descriptions say so; the projection is unchanged.

### Fixed

- `check_indicator`: a hash NSRL knows (`flags.knownGood`) that a threat source
  also lists is no longer `malicious` / `block`. `/check` keeps
  `malicious: true` for the listing and adds `knownGood` for NSRL; the ladder
  read the first and ignored the second, so an agent was told to block known
  software on a feed's word alone. It is now `suspicious` / `review`, with a
  headline that names the conflict; `blocklist` still lists the citing
  sources. `check_indicators` is unchanged: its rows come from `/bulk/check`,
  which carries no NSRL flag, and relay the API's `recommendedAction`.

## [0.3.0] - 2026-09-21

- Search results now identify `total_hits` as the upstream sample size and
  preserve truncation uncertainty (`null`) when the backend cannot prove
  completeness. The default API retains the existing 25-hit per-term bound.

The two v0.3 tools that have a backend route. `history` and `asn` are not
here: nothing serves them.

### Added

- `search_indicators`: `POST /search?keywords=` returns a bounded sample for
  a keyword, projected to `{ keywords, total_hits, total_hits_scope,
returned, truncated, indicators: [{ value, type? }] }` with the dataset key
  prefix (`domain:`, `ip:`, …) split off. `limit` 1–500 (default 50) limits
  the sample returned by the backend. One request.
- `check_indicators`: `POST /bulk/check` for up to 100 indicators, one
  compact row each (`entity`, `type`, `malicious`, `recommendedAction`,
  `riskScore`, `riskLevel`, `sources`, `categories`, `lookupStatus`,
  `infrastructure`, `error`) under `{ submitted, processed, malicious,
notes?, results }`. **Each indicator charges one request**; the plan caps
  the batch (Free 10, Basic 50, Pro 100, Enterprise 500) and a batch over
  the cap is refused whole, relayed as `bad_request`.
- Tools may declare `maxResultBytes`; the two list tools raise the 4 KB
  result cap (16 KB and 24 KB) so a full batch is not clipped to five rows.
- `ISMALICIOUS_TIMEOUT_MS` defaults: `search_indicators` 20 s,
  `check_indicators` 60 s.

### Fixed

- `check_indicator` called a hash no source has seen `clean` and recommended
  `allow`: the API answers such a miss with a full document whose counters
  are zero, which the verdict ladder read as a clean file. A document with
  `lookupStatus: "unknown"` is now `unknown` / `unverified`, its headline says
  that unknown is not clean, and `risk` keeps only the summary (the numeric
  score measures nothing). 0.2.0 has the bug: an agent there was told to
  allow any file missing from every feed.

## [0.2.1] - Unreleased

Listings now carry a class. A cloud provider's published ranges, a Tor exit
list or an ad-blocking list say what an entity is, or what a customer may
choose to block; they are not a malicious verdict, and `check_indicator`
stops treating them as one.

### Added

- `check_indicator` returns `infrastructure` — `{ attributes, sources }` —
  whenever the document carries a listing whose `threatClass` is
  `infrastructure`, `policy` or `allowlist`. `attributes` is the sorted set of
  what the entity is known as (`tor-exit`, `vpn`, `proxy`, `doh-resolver`,
  `dns-resolver`, `sinkhole`, `cloud`, `cdn`, `crawler`, `scanner`,
  `monitoring`, `disposable-email`, `dynamic-dns`, `url-shortener`, `bogon`,
  `saas`, `allowlist`), taken from the API's own `infrastructure` block or,
  for documents that predate it, derived from the listing categories.
  `sources` cites up to ten such listings with their `threatClass`. The
  `headline` names the attributes.

### Changed

- The fallback verdict for documents without reputation counts (every stored
  document) ignores non-threat listings: an IP listed only by a Microsoft 365
  or Azure range, a Tor exit list or an allowlist is `clean` / `allow`, where
  it used to be `suspicious` / `review` (or `malicious` when the risk level
  was high). An indicator cited by a honeypot feed and sitting in a cloud
  range keeps its honeypot verdict. This matches `verdict_from_doc` in the
  gate, so `check_url` and `check_indicator` still agree.
- `blocklist.hits`, `blocklist.listed` and `blocklist.sources` count threat
  listings only; the others moved to `infrastructure`.
- Tool description and server instructions mention `infrastructure`.

## [0.2.0] - 2026-09-04

The server now covers what a client agent has been observed looking for by
hand: indicator enrichment, the CVE catalog on one path, and a verdict it can
relay. `scan_before_use` and `check_url` keep their names, schemas and success
bodies.

### Added

- `check_indicator`: reputation verdict for an IP, domain, URL or hash, projected
  from the `/check` document to under 4 KB — `verdict`, a deterministic
  `headline`, `recommendedAction` (block/review/allow/unverified), risk,
  reputation counts, up to ten citing sources, timeline, network and
  registration context, known CVEs, flags, `reportUrl`.
- `get_cve`: one CVE by id with CVSS, EPSS, CISA KEV status and due date,
  exploitation evidence and references. A 404 explains that `GET /cve?id=` is
  the only route.
- `recent_cves`: latest CVEs, optional severity filter, at most 20.
- `bootstrap_key`: without a configured key the server starts in a reduced
  mode and can mint a free key from an email address (`POST /api/keys/instant`,
  one per IP per day on this channel), then uses it for the session.
- Resource `ismalicious://quota`: scan quota and the request-quota headers of
  the last billed call.
- `initialize` returns `instructions`, echoes a supported client
  `protocolVersion` (`2025-06-18`, `2025-03-26`) and advertises
  `tools.listChanged`.
- Per-tool timeouts (gate 15 s, `check_indicator` 25 s, CVE 10 s) with the
  `ISMALICIOUS_TIMEOUT_MS` override; `notifications/cancelled` aborts the
  in-flight HTTP call and the request gets no response, as the spec requires.
- `X-Ismalicious-Tool` request header naming the calling tool.

### Changed

- Failures return a typed envelope with `isError: true`:
  `{ error: rate_limited | unauthorized | forbidden | not_found | bad_request |
upstream_error | timeout | network_error | invalid_params, status, message,
quota?, hint? }`. A 429 carries `quota.kind` (burst, monthly, daily, scans,
  issuance), `retry_after` and `resets_at`. A 2xx without a JSON body is an
  `upstream_error`, no longer a successful `"null"`.
- Tool results are compact JSON (no pretty-printing) and capped at 4 KB.
- A missing key pair no longer exits the process.
- The version lives in `src/version.ts`; `scripts/check-version.mjs` fails the
  build when `package.json`, `server.json` and the User-Agent disagree.

## [0.1.0] - 2026-09-04

Initial release: `scan_before_use` (`POST /gate/scan`) and `check_url`
(`GET /gate/url`), zero dependencies, stdio transport. Published to npm and to
the official MCP registry as `com.ismalicious/mcp-server`.
