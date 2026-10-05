# Changelog

## 0.6.1 (unreleased)

- Mirror the complete 0.6.0 source, including `scan_email`, in the public repository.
- Prepare an explicitly dispatched public-source npm provenance release workflow. No release or trusted publisher is created by this change.
- Use patched Vitest and esbuild versions for standalone build/test CI. The distributed server keeps zero runtime dependencies and the existing tool behavior.


All notable changes to `@ismalicious/mcp-server` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-10-01

One new tool: `scan_email` reads a whole email message, not one address, for
phishing and malware. It calls `POST /mail/scan`, so this release is published
after the API that serves it (PUBLISHING.md); against an API without the route
the tool answers `not_found`, and nothing else changes.

### Added

- `scan_email`: send the raw message (`eml`, up to 10 MiB, preferred: its
  attachments are read for structure, never run) or the fields you already
  parsed (`message`: `headers`, `from`, `replyTo`, `returnPath`, `subject`,
  `text`, `html`, `attachments` with names, types and any of `sha256` /
  `sha1` / `md5`), plus what you know about your own receiving system:
  `authservId`,
  `trustAuthenticationResults`, `trustedHops`, `connectingIp`. Exactly one of
  `eml` and `message`; anything else is refused before a request.
- The answer is the API's own verdict, projected under 4 KB: `verdict`
  (`malicious` / `suspicious` / `clean` / `inconclusive`),
  `recommendedAction` (`quarantine` / `review` / `warn` / `deliver`),
  `riskScore`, a `headline` to relay, the six strongest `reasons`, the
  `sender`, `authentication`, `connectingIp`, the links and attachments that
  carry a signal (`links.flagged`, `attachments.flagged`), addresses and
  numbers in the body the dataset flags (`contacts`), prompt-injection findings
  aimed at an AI reading the mail (`injection`, hidden text included) and
  `coverage.skipped`, what the scan could not check and why. Hosts are written
  defanged (`evil[.]example`).
- Beyond hashes and names, the answer carries what the scan read in the message
  itself: brand look-alikes in the sender, `Reply-To`, links and display name
  (`sender.brand_lookalike`, `link.brand_lookalike`,
  `headers.display_name_brand`: the brand and its real site are named);
  whether the sender's domain can be forged (`sender.spoofable`, from its DMARC
  policy); domains registered in the last 45 days that looked like an
  impersonation; and, from a raw message, the structure of attachments
  (`attachments.flagged[].detectedType` and flags such as `disguised_program`,
  `macro_project`, `remote_template`, `archive_risky`, `pdf_launch`,
  `html_smuggling`), the addresses found inside them and inside an attached
  message, read as a message of its own (`links.flagged[].origin` and `from`).
- What the verdict means: `malicious` needs a listing in the dataset (the shape
  of a message alone asks for a `review` at most); `clean` is a positive claim
  and needs your own system's DMARC pass (`authservId` or
  `trustAuthenticationResults`) from a sender domain the dataset knows as
  established, so a message with nothing against it and no such evidence is
  `inconclusive`, which is not safe; `deliver` is no
  objection from this scan, never a reason to release a message another engine
  quarantined. A body the server cannot read is reported as unscanned and sent
  to `review`, never delivered.
- One scan of the scan meter per message, whatever its size, never a request of
  the monthly quota. Never cached (every message is a meter event), 20 s
  timeout (`ISMALICIOUS_TIMEOUT_SCAN_EMAIL_MS`), counted by Rust as
  `mcp_tool_scan_email`.

## [0.5.0] - 2026-09-30

Email addresses and phone numbers get a real verdict, and each call waits
less. Until this release an email address or a phone number sent to
`check_indicator` was looked up as the domain `user@host` or `+336…`, came
back `clean` / `allow`, and was charged a request: a false allow for the
indicators an agent triaging mail or calls sends most. The two tools that
take indicators now type them locally before any request, `check_indicator`
asks for the `fast` level (cached data, no live DNS, WHOIS or OTX call) by default, and the client keeps its
connection, caches results briefly and shares identical calls in flight.

The `fast` level, and the email and phone verdicts, need the matching API
deploy, and this release is published after it (PUBLISHING.md). A server that
predates it reads `fast` as `standard` for an IP, a domain or a URL, but for
a hash it stores `enrichmentLevel: "fast"` in the document it caches for 30
days. An email address or phone number it answers as a domain comes back
`unknown` / `unverified` with a note, never `clean` / `allow` (see Fixed).

### Added

- `check_indicator` checks email addresses and phone numbers: same route
  (`GET /check`), same cost (one request). The API answers them from its
  dataset only — listings of the address or number, the sender domain's
  reputation, disposable and MX facts from cached DNS — and never calls one
  clean: not being in our sources is `unknown` / `unverified`. A listing makes
  it malicious at source confidence 70 or more, or with two independent
  publishers at 60 or more; one list below that is `suspicious`. The result
  adds `lookupStatus` (`found` / `unknown`), up to five `reasons`, and an
  `email` block (`domain`, `disposable`, `freeProvider`, `mx` true, false
  for a null MX, or null when no cached DNS answer lists an MX,
  `domainReputation`) or a `phone` block
  (`e164`, `countryCallingCode`, `resolvedWith`). A new optional `country`
  (ISO 3166-1 alpha-2) resolves a number written in national format
  (`06 12 34 56 78` with `FR` is `+33612345678`), sent as `country=`.
- `check_indicators` takes email addresses and phone numbers in the same
  batch as the other kinds, and the same optional `country`. Their rows carry
  `type: "email" | "phone"`, `lookupStatus`, and `recommendedAction`
  `unverified` when nothing is known either way.
- Local typing before any request (`src/indicators.ts`), shared by both
  tools. Input is NFKC-normalised, so full-width digits, `＠`, `－` and `．`
  from CJK text read as ASCII, and `。` separates labels. Defanged input is
  refanged — `hxxp(s)` in any case, `[.]` `(.)` `{.}` `[dot]`, `[:]`, `[@]`
  `[at]`, `[/]`, surrounding brackets or quotes, trailing sentence
  punctuation — and the refanged value is what is sent. A result, or a bulk
  row, carries `input` when it differs. Also read as what they hold: a
  display-name address (`Name <a@b.com>`), a contact link with or without
  `//` (`mailto:` with `?subject=…` when it holds an address; `tel:` with
  `;ext=…`, `sms:` with `?body=…`, `callto:` and `sip:` when what they dial
  is a number, typeset as below or not), a
  spreadsheet export's `=+1…`, `="+1…"` or `'+1…`, a number as typeset
  (no-break or thin spaces, typographic dashes, `(+33)`, `+44 (0)20`,
  `030/1234567`, a trailing extension or line label such as `cell` or
  `(mob)`) and a labelled hash (`sha256:…`,
  `SHA256: …`, `MD5=…`; a label that does not match the length is refused).
- A URL with a scheme is sent as the API reads it: scheme and host
  lowercased (`HTTPS://PHISH.EXAMPLE/login`), an IPv6 host compressed and
  lowercased (`[2001:DB8:0::1]` is `[2001:db8::1]`), `https:/host` read as
  `https://host`, the userinfo dropped (`http://paypal.com@evil.example/` is
  `http://evil.example/`), and the root dot after the host too
  (`http://evil.com./login` is `http://evil.com/login`, as `evil.com.` alone
  is `evil.com`; so is `evil.com./login` without a scheme). An IDN host keeps
  the form it was typed in.
- `check_indicator` `enrichment: "fast"`, now the default: cached
  intelligence only, no live upstream call before the answer. Facets the
  cache did not hold come back in `meta.pending` (`dns`, `whois`, `circl`…),
  the API fetches them in the background, and only then does the headline
  ask for one re-check after a few seconds, saying that the answer stands if
  they are still pending then (each re-check is a billed request); such a
  result is never replayed from the client cache, so that re-check reaches
  the API. A hash nobody has
  cached may still wait up to ~2.5 s on CIRCL. `standard` (may call DNS, OTX
  or CIRCL before answering) and `basic` (no risk score) are unchanged.
- `check_indicator` projection: up to three evidence `reasons` from the API
  (`evidence.reasons`, else the score factors that raised the score), minus
  the risk summary. For a hash: `file` (family, file type, MIME type, name,
  size, signature, tags, the file's other digests), `categories` and
  `lookupStatus`; the malicious headline names the family. A citing source
  reached through another digest of the same file says `via: "alias"`, one
  reached through a listed range `via: "cidr"`. OTX pulse content is not
  surfaced.
- `tools/list` gives every tool a `title` and MCP `annotations`: the lookup
  tools are read-only, idempotent and open-world; `bootstrap_key` is not
  read-only, not idempotent and not destructive. Names, schemas and order
  are unchanged apart from the inputs listed here.
- Connection reuse: requests go through `node:http` / `node:https` with one
  keep-alive pool per scheme (16 sockets, idle sockets kept 30 s) instead of
  the global `fetch`, whose sockets closed after 4 s idle — less than the
  pause between two tool calls of an agent, so nearly every call paid a new
  TCP and TLS handshake. Responses are requested with gzip or brotli.
  A GET that fails on a reused socket before any response (`ECONNRESET`,
  `EPIPE`, socket hang up) is retried once; a POST never is. Only same-host
  redirects are followed, at most three, since the request carries the key;
  the `fetch` wire used behind an env proxy on an older Node follows the
  same rule (`redirect: "manual"`).
- One unauthenticated `GET /health` after `initialize`, only when a key is
  configured, so the first tool call finds the connection open. Never
  awaited, never billed; `ISMALICIOUS_PREWARM=0` turns it off, and the
  Docker image sets it. Listing tools still makes no request.
- Result cache and shared calls: a successful result is replayed to an
  identical call (same key, tool and normalised arguments — a defanged and a
  plain form of one indicator are the same call, and each gets its own
  `input`) for 60 s (`check_indicator`,
  `check_indicators`, `check_url`), 1 h (`get_cve`) or 5 min (`recent_cves`,
  `search_indicators`); `scan_before_use` and `bootstrap_key` never are. 500
  entries at most; errors and results with pending facets never stored. A
  replay costs no request and says so:
  `meta.cached`, `meta.ageSec` and `meta.latencyMs: 0`, or a top-level
  `_cache` on results without `meta`. Identical calls in flight share one
  request, aborted only when every caller has cancelled.
- `meta.latencyMs`: the client-measured time of the call's round trips.
- `check_indicators` rows keep the API's `pending` (`["circl"]` for a hash
  whose lookup outlasted the API's deadline), and the result counts them in
  `pendingRows` with a note to re-check them once: that `unknown` is not
  settled.
- Environment: `ISMALICIOUS_WEB_BASE` (base for `bootstrap_key`, the one
  route only `https://ismalicious.com/api` serves; defaults to
  `ISMALICIOUS_API_BASE`, or to `https://ismalicious.com/api` when that is
  `https://api.ismalicious.com`), `ISMALICIOUS_CACHE_TTL_S` (`0` turns the
  cache off, `N` caps every lifetime at N seconds), `ISMALICIOUS_PREWARM`,
  and `ISMALICIOUS_TIMEOUT_<TOOL>_MS` (one tool's timeout, e.g.
  `ISMALICIOUS_TIMEOUT_CHECK_INDICATOR_MS`, winning over
  `ISMALICIOUS_TIMEOUT_MS`, so failing fast on one call no longer cuts the
  60 s batch).
- `src/__tests__/tools-parity.test.ts`: the tool names, in order, against
  `MCP_TOOLS` in `apps/rust-api/src/infra/client.rs` and
  `apps/web/lib/growth-metrics-constants.ts`, run by this package's suite
  (the Rust copy of the check only runs when Rust changes). It skips a file
  that is absent, as in the public mirror.

### Changed

- The domain kind is an allowlist: two or more labels of letters, digits,
  hyphens and underscores (IDN labels with a punycode form too), an
  optional `:port`, 253 characters at most. A label may start or end with a
  hyphen (`secure-login-.blogspot.com`, `foo-.tumblr.com`), as browsers and
  the API's ingestion allow; the last one may not, nor be all digits.
  Anything else — `localhost`,
  `*.evil.com`, a number written with its keypad letters
  (`+1-800-FLOWERS`), a URL whose host is not a dotted domain or an IP
  (`https://intranet/`, `file:///x`) — is refused as below, where it used to
  be sent as a domain and answered `clean` / `allow`.
- SHA-512, SHA-384, TLSH, ssdeep and hexadecimal strings that are neither
  MD5, SHA-1 nor SHA-256 are refused before any request: `invalid_params`
  from `check_indicator`, a per-row `error` from `check_indicators` for a row
  that is never sent and never charged (the result counts them in
  `refused`). They used to go down the domain path, come back `clean` /
  `allow`, and cost a request. An imphash is 32 hex characters and is still
  looked up as an MD5.
- `check_indicators` returns its rows in input order, refused rows in place;
  a row with no match in the answer is appended after them.
- List results no longer shrink to five rows. `check_indicators` (48 KB) and
  `search_indicators` (32 KB) drop whole rows from the end when over their
  cap and say so with `returned`, `omitted`, `truncated: true` and a `note`;
  `malicious` still counts every row, and `check_indicators` adds
  `maliciousReturned` and `maliciousOmitted`. A 100-row batch of SHA-256
  hashes or of 150-character URLs now comes back whole.
- Tool descriptions say which tool to pick and what it costs:
  `check_indicator` is the tool for any single indicator of the six kinds;
  `check_indicators` lists every `recommendedAction` value (`block`,
  `escalate`, `review`, `monitor`, `allow`, `unverified`) and the billing
  rule; `search_indicators` gives its cost per host. Server instructions
  follow.
- `X-Ismalicious-Tool` counters start at this release (see Fixed): from it,
  Rust counts each tool under `mcp_tool_<name>`; before, all but the two gate
  tools landed in `mcp_tool_unknown`. The named series starting at the
  release date is that break, not a jump in adoption.

### Fixed

- An email address or phone number was answered `clean` / `allow`. Now it
  gets the API's verdict, and when the API does not type it as one — a
  server from before this release — `check_indicator` returns `unknown` /
  `unverified` with a `note` saying the API did not evaluate it, and
  `check_indicators` gives the row `malicious: false`, `recommendedAction:
unverified`, `lookupStatus: unknown` and an `error`.
- `X-Ismalicious-Tool` was never sent, although 0.2.0 listed it: only a
  helper no call path used set it. Every tool call now carries it.
- `::ffff:1.2.3.4` (an IPv4-mapped IPv6 address) was typed a domain; it is
  an IP, as are a bracketed IPv6 address and a CIDR.
- `check_indicators` said "duplicates and rejects are free". Only exact
  duplicates (after trimming and lowercasing) are; a row the API cannot type
  is charged like any other. The description now says so, and the refusals
  above are what is actually free.
- `check_indicators` sent entries under 3 characters. The API drops them, so
  they vanished from `results` without a row, and a batch of nothing else
  was charged one request. They are now refused rows, never sent.
- Input the API cannot read went down the domain path and came back `clean`
  / `allow`: `Name <a@evil.com>`, `mailto:a@evil.com?subject=…`,
  `"john doe"@x.com`, `+33 6 12…` with no-break spaces, `+1 415‑555‑2671`
  with non-breaking hyphens, `sha256:<hex>`. The forms above are now read as
  what they hold, and what is still unreadable is refused at no cost.
- `check_indicator` typed its input before checking its length, and the
  refanging rescanned the string on every pass: `a` followed by 20,000 `)`
  blocked the stdio server for 9 s. The length is checked first (typing
  itself refuses more than 2,048 characters, NFKC expansion included), and
  refanging is linear: the display-name pattern, which backtracked
  quadratically on `<@@@…` (a hostile 100-item batch held the loop 2 s),
  is a single scan: a hostile 100-item batch is typed in milliseconds.
- Contact values in common non-ASCII or URI forms were typed as a domain or
  a URL, sent, charged and answered `clean` / `allow`: full-width digits
  (`０９０−１２３４−５６７８`), `user＠evil.com`, `sms:+1…`, `callto:+1…`,
  `tel://+1…`, `mailto://user@evil.com`, `+1-800-FLOWERS` and `=+1…` from a
  spreadsheet. The first seven are read as the number or the address; the
  vanity number is refused at no cost.
- A URL kept its upper-case scheme: `HXXPS://EVIL[.]COM/login` refanged to
  `httpS://EVIL.COM/login`, and `HTTPS://PHISH.EXAMPLE/login` and
  `https:/evil.com/login` were sent verbatim. The API looked up the host
  `https`, missed, and a listed URL came back `clean` / `allow`. Such URLs
  are now sent normalised (see Added). A URL with an IPv6 host
  (`http://[2001:db8::1]/x`) is sent as it was: the API looked its host up as
  `[2001`, and what fixes that is the API's own hostname extraction in the
  2026-09-30 deploy, not this client — against an older API it still comes
  back `clean` / `allow`, one more reason the API is deployed first
  (PUBLISHING.md).
- The `fetch` fallback wire (env-proxy mode on a Node whose agents cannot
  proxy) followed a cross-origin redirect with `X-API-KEY`: undici strips
  only `Authorization` and `Cookie`. It now refuses it, as the default wire
  does.
- A replayed or shared result echoed the `input` of the call that fetched
  it: `evil.com` after `evil[.]com` came back with `input: "evil[.]com"`.
- Behind an egress proxy with Node's env-proxy mode on
  (`NODE_USE_ENV_PROXY=1`, `HTTPS_PROXY`), every call failed on DNS: the
  keep-alive agents ignored the proxy the global `fetch` had honoured. They
  now take Node's proxy variables (Node 22.21+ / 24.5+), and an older Node in
  that mode goes through `fetch`.
- `search_indicators` said it costs one request of the monthly quota. That
  holds on the API host (`https://api.ismalicious.com`); through the default
  `https://ismalicious.com/api` the route is not charged on the monthly
  quota, only counted against the burst rate limit.
- `check_indicators` memoised its parse on the identity of the arguments
  object. An embedder of `createServer` that reused one object, or mutated
  it between calls, got the previous batch's parse, sent it, and with the
  cache on got the previous batch's answer: an `allow` for indicators never
  looked up. The batch is typed from the values the arguments hold at each
  call.
- `tools/call` with `arguments` that are not an object (`"abc"`, `5`,
  `true`, an array) reached the tools: `check_indicators` threw (JSON-RPC
  `-32603`) and the others answered with a misleading message
  (`content is required`). Every tool now answers `invalid_params` before
  running; absent or `null` arguments still mean none, and so does an empty
  array, which some encoders write for an empty map (PHP's
  `json_encode([])`).
- A bare host holding a code point IDNA ignores — U+00AD, the soft hyphen a
  hyphenating page inserts (`ev<U+00AD>il.com`), a variation selector, the
  combining grapheme joiner — passed the hostname check on its IDNA form
  (`evil.com`) and was sent as typed; the API missed it and answered
  `clean` / `allow`, while the URL form of the same host was normalised by
  the parser. Those code points are now dropped from every input, as the
  zero-width ones were, and each non-ASCII label of a bare host is sent in
  its IDNA form (`evẞl.com` is `evssl.com`), as a URL's host is.
- `callto:john.doe` and `callto://john.doe` (Skype names) were sent as the
  domain `john.doe`, or as a URL on it, and answered `clean` / `allow`; so
  were a `tel:`, `sms:` or `sip://` link to a host or a user name, and a
  `mailto:` without an address. A `tel:`, `sms:`, `callto:` or `sip:` link
  is now read only when what it dials is a number, as typeset or not
  (`tel:030/1234567`, `tel:+1–415–555–2671`, `Tel: +1 415 555 2671 x123`,
  `Tel: 415-555-2671 (mob)`), a `mailto:` only when it holds an `@`,
  defanged or not; any other is refused at no cost (an unsent, unbilled row
  in a batch).
- The vanity-number rule took any digits-then-letters string for a number
  written with keypad letters: `+1 415 555 2671 cell`, `415-555-2671 (mob)`,
  `0800 FREE CALL`, `5G-ROUTER-01`, `2FA-TOKEN-123` and `3D-SECURE-2024`
  were refused with advice to dial their letters, which bought a billed
  lookup of a number that does not exist. It now takes the keypad shape only
  (digit groups, then letters alone in hyphenated words: `+1-800-FLOWERS`,
  `1-800-GOT-JUNK`). A trailing line label (`cell`, `mobile`, `office`,
  `fax`, `(mob)`…) comes off an otherwise valid number, which is checked,
  and anything else gets the generic refusal.

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
