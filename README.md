# @ismalicious/mcp-server

A zero-dependency [Model Context Protocol](https://modelcontextprotocol.io)
server that gives an AI agent isMalicious threat intelligence: reputation
verdicts for IP addresses, domains, URLs, file hashes, email addresses and
phone numbers, the CVE catalog, the isinjected gate that scans untrusted
content for prompt injection before the agent acts on it, and a scanner that
reads one whole email message for phishing and malware.

## Install

```json
{
  "mcpServers": {
    "ismalicious": {
      "command": "npx",
      "args": ["-y", "@ismalicious/mcp-server"],
      "env": {
        "ISMALICIOUS_API_KEY": "your-api-key",
        "ISMALICIOUS_API_SECRET": "your-api-secret"
      }
    }
  }
}
```

Keys: <https://ismalicious.com/app/account>. Free keys exist. Without the two
variables the server still starts, offering only `bootstrap_key`, which mints a
free key from an email address and uses it for the session (see below).

Registry name: `com.ismalicious/mcp-server`
(<https://registry.modelcontextprotocol.io/v0/servers?search=ismalicious>).

## Tools

| Tool                      | What it answers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Cost                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `scan_before_use`         | Prompt-injection scan plus link reputation over a block of untrusted text. `block \| warn \| allow`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | 1 scan                                                                   |
| `check_url`               | Reputation of one URL, domain or IP before fetching it. `block \| warn \| allow`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | 1 scan                                                                   |
| `check_indicator`         | The one tool for any single indicator: IP, domain, URL, file hash (MD5, SHA-1, SHA-256), email address or phone number, defanged or not. `verdict` (malicious/suspicious/clean/unknown — never clean for an email address or phone number), a `headline` you can relay verbatim, `recommendedAction` (block/review/allow/unverified), risk 0-100, citing threat blocklists, up to three evidence `reasons`, `infrastructure` (cloud, CDN, Tor exit…), first/last seen, network, registration or file context. `fast` by default (no live DNS, WHOIS or OTX call; a cold hash may wait ~2.5 s on CIRCL). Under 4 KB. | 1 request                                                                |
| `get_cve`                 | One CVE by id: description, CVSS, EPSS, CISA KEV status and due date, exploitation evidence, references. The only CVE path.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 1 request                                                                |
| `recent_cves`             | Latest CVEs, optional `severity`, at most 20.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 1 request                                                                |
| `search_indicators`       | Domains the corpus lists that look like a brand or domain — typosquats, homoglyphs, other TLDs or hosts, phishing-word combinations — most dangerous first. `total_hits` counts the upstream sample; `truncated` is true when omission is known, null when unknown. Follow up with `check_indicators` for verdicts.                                                                                                                                                                                                                                                                                                 | 1 request on `api.ismalicious.com`; burst limit only on the default base |
| `check_indicators`        | Up to 100 indicators of any of the six kinds in one call: per row `malicious`, `recommendedAction` (block/escalate/review/monitor/allow/unverified), risk, blocklist count, categories, `lookupStatus`, `infrastructure`. **Each unique indicator sent charges one request**, including rows the API cannot type; SHA-512, TLSH and ssdeep rows are refused locally and cost nothing. Plans cap the batch (Free 10, Basic 50, Pro 100).                                                                                                                                                                             | 1 request per indicator                                                  |
| `check_password_exposure` | Whether a password, or its SHA-1 or NTLM hash, is in known breach dumps (Have I Been Pwned's Pwned Passwords) and how many times. A password is hashed locally; only the first 5 hex digits of the hash are sent.                                                                                                                                                                                                                                                                                                                                                                                                   | 1 request                                                                |
| `scan_email`              | Scan one email message for phishing and malware: raw `eml` or parsed `message`. `verdict` (malicious/suspicious/clean/inconclusive), `recommendedAction` (quarantine/review/warn/deliver), risk 0-100, a `headline` to relay, the strongest `reasons`, `coverage.skipped`. `malicious` needs a listing in the dataset; `clean` needs your own system's DMARC pass and a sender domain the dataset knows as established; `deliver` never releases a message another engine held. From a raw message, attachments are also read for structure; it never runs an attachment or fetches a link.                         | 1 scan per message                                                       |
| `bootstrap_key`           | Only without a configured key: mint a free key from an email, one per IP per day.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | —                                                                        |

The default search API reads a bare keyword as its `.com` (`paypal` →
`paypal.com`) and returns at most 500 listed lookalikes. `limit` only reduces
that sample. Only listed domains are returned and a name buried in a longer
hostname is not matched, so an empty answer does not prove that no lookalike
exists.
The MCP result labels `total_hits_scope` as `upstream_sample`. Legacy or custom
API responses without completeness metadata produce `truncated: null`.

Scans and requests are two meters: <https://ismalicious.com/api-docs>.

### Indicator types

`check_indicator` and `check_indicators` type each indicator before any
request, the way the API does:

| Kind          | Recognised as                                                                                                                                                                                                                                            |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IP            | IPv4, IPv6 (including `::ffff:1.2.3.4` and `[2001:db8::1]`), or a CIDR.                                                                                                                                                                                  |
| URL           | A scheme (`https://…`, or the typo `https:/…`) and a host that is a dotted domain or an IP, or a `/` after such a host. Sent with the scheme and host lowercased, the userinfo and a root dot after the host (`evil.com./`) dropped. Judged on its host. |
| File hash     | MD5 (32 hex), SHA-1 (40) or SHA-256 (64), bare or labelled (`sha256:…`, `SHA256: …`, `MD5=…`). An imphash is 32 hex characters and is looked up as an MD5.                                                                                               |
| Email address | One `@`, no `/` or `://` (so `http://user@host/` stays a URL), a domain of two or more labels. Lowercased. `Name <user@host>` and `mailto:user@host?subject=…` are read as the address.                                                                  |
| Phone number  | Digits, spaces and `+ - . ( )` only, `+` first if at all, 7 to 15 digits. `+…` and `00…` are international; pass `country` (ISO 3166-1 alpha-2) for a national number such as `06 12 34 56 78`; without it, 10 digits read as North American.            |
| Domain        | Two or more labels of letters, digits, hyphens and underscores (non-ASCII letters too, when the label has a punycode form), an optional `:port`, 253 characters at most. An allowlist: nothing else is sent as a domain.                                 |

Every value is NFKC-normalised first, so full-width forms from CJK text
(`０９０−１２３４−５６７８`, `user＠evil.com`, `ｅｖｉｌ．ｃｏｍ`) read as their ASCII
selves, and an ideographic full stop (`。`) separates labels. Numbers are read
as typeset before the phone rule applies, and that form is what is sent:
no-break and thin spaces become spaces, typographic dashes and the minus sign
become `-`, `(+33) 6 …` becomes `+33 6 …`, `+44 (0)20 …` loses the national
`(0)`, `030/1234567` its slash, `tel:` links their `;ext=…` parameters, and a
trailing extension (`x123`, `ext. 123`) is dropped. A contact link is read as
the address or number it holds, with or without `//`: `mailto:`, `tel:`,
`sms:` (and its `?body=…`), `callto:`, and `sip:` when its user part is a
number. So is a spreadsheet export's `=+1…`, `="+1…"` or `'+1…`.

Input that is none of these is refused before any request (`invalid_params`;
in a batch, a row with an `error`, not sent and not charged), never sent as a
domain: an `@` the email rule rejects (`"john doe"@example.com`,
`user@localhost`, `user@evil.com/`), digits and separators the phone rule
rejects (`12345`), a number written with its keypad letters
(`+1-800-FLOWERS`), a URL whose host is not a dotted domain or an IP
(`https://intranet/`), and anything else that is not a hostname (`localhost`,
`*.evil.com`, spaces, quotes or brackets). Sent as a domain, each came back
"not listed", which read as `clean` / `allow`.

Defanged input is refanged first, and the refanged value is what is sent:
`hxxp(s)` in any case, `[.]` `(.)` `{.}` `[dot]`, `[:]`, `[@]` `[at]`, `[/]`,
surrounding brackets or quotes, a contact scheme, a display name around an
address, trailing sentence punctuation. The result carries `input` when it differs from `indicator` by
more than letter case.

SHA-512, SHA-384, TLSH, ssdeep and other hexadecimal strings of 32 characters
or more are refused before any request (`invalid_params`; in a batch, a row
with an `error`, not sent and not charged): the API indexes MD5, SHA-1 and
SHA-256 only.

An email address or a phone number is never `clean`. The API's email and
phone sources are a few feeds, so not being in them is `unknown` /
`unverified`, not evidence of safety. Its verdict comes from the address or
number's own listings and, for an email address, the sender domain. A listing
makes it malicious when its source's confidence is 70 or more, or when two
independent publishers at 60 or more agree; one list below that (the
consumer-complaint number feeds and the one address blacklist sit at 55) makes
it suspicious, because such lists name a displayed caller ID or From address,
often forged. For an email address, a
malicious domain that is not a shared mail provider makes the address
malicious; a domain with threat listings, a disposable domain or a domain
whose null MX says it accepts no mail makes it suspicious. Everything is read
from the API's dataset and cached DNS: `mx` is `false` only for a null MX,
and `null` when no DNS answer is cached or the cached one lists no MX. An API server
that predates email and phone support answers them as domains; the result is
then `unknown` / `unverified` with a `note`, never `clean` / `allow`.

### `check_indicator` example

```json
{
  "indicator": "45.148.10.242",
  "type": "ip",
  "verdict": "malicious",
  "headline": "45.148.10.242 is flagged malicious by 7 sources (scanner); risk 78/100; seen from 2026-06-02 to 2026-09-01.",
  "recommendedAction": "block",
  "malicious": true,
  "risk": { "score": 78, "level": "high" },
  "reputation": {
    "malicious": 7,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 0
  },
  "blocklist": {
    "hits": 7,
    "listed": true,
    "sources": [{ "name": "…", "category": "ip" }]
  },
  "network": { "countryCode": "NL", "asn": "AS…", "org": "…" },
  "flags": {
    "delisted": false,
    "knownGood": false,
    "microsoftTenant": false,
    "ransomware": false,
    "relatedInfrastructure": true
  },
  "reportUrl": "https://ismalicious.com/report?query=45.148.10.242"
}
```

`blocklist` counts threat listings only. Listings whose `threatClass` is
`infrastructure`, `policy` or `allowlist` — a cloud provider's published
ranges, a Tor exit list, an ad-blocking list — say what the entity is or what
a customer may choose to block, not that it attacked anyone, so they never
reach the verdict. They are reported under `infrastructure`, which is absent
when there are none:

```json
{
  "indicator": "13.107.6.152",
  "type": "ip",
  "verdict": "clean",
  "headline": "13.107.6.152 is not listed by any threat source; known infrastructure: cloud, saas; risk 12/100.",
  "recommendedAction": "allow",
  "malicious": false,
  "risk": { "score": 12, "level": "low" },
  "blocklist": { "hits": 0, "listed": false, "sources": [] },
  "infrastructure": {
    "attributes": ["cloud", "saas"],
    "sources": [
      {
        "name": "Azure IP Ranges",
        "category": "infrastructure",
        "threatClass": "infrastructure"
      },
      {
        "name": "Microsoft 365 endpoints",
        "category": "infrastructure",
        "threatClass": "infrastructure"
      }
    ]
  },
  "network": {
    "countryCode": "US",
    "asn": "AS8075",
    "org": "Microsoft Azure Cloud (eastus2)"
  },
  "reportUrl": "https://ismalicious.com/report?query=13.107.6.152"
}
```

`attributes` is one or more of `tor-exit`, `vpn`, `proxy`, `doh-resolver`,
`dns-resolver`, `sinkhole`, `cloud`, `cdn`, `crawler`, `scanner`,
`monitoring`, `disposable-email`, `dynamic-dns`, `url-shortener`, `bogon`,
`saas`, `allowlist`; new ones may appear. An indicator cited by a honeypot
feed _and_ sitting in a cloud range keeps its honeypot verdict.

### Email address and phone number examples

```json
{
  "indicator": "billing@invoices-portal.example",
  "type": "email",
  "verdict": "suspicious",
  "headline": "billing@invoices-portal.example is listed by 1 threat source (spam, scam); the domain invoices-portal.example is not in our dataset; risk 50/100.",
  "recommendedAction": "review",
  "malicious": false,
  "lookupStatus": "found",
  "risk": {
    "score": 50,
    "level": "medium",
    "summary": "billing@invoices-portal.example is on a low-confidence list: review before trusting it"
  },
  "reasons": [
    "Address listed by 1 threat feed: Sefinek - Blacklisted Emails (spam, scam, abuse)",
    "Highest source confidence 55/100: below 70, one list is not enough for a malicious verdict"
  ],
  "categories": ["spam", "scam", "abuse"],
  "blocklist": {
    "hits": 1,
    "listed": true,
    "sources": [{ "name": "Sefinek - Blacklisted Emails", "category": "spam" }]
  },
  "timeline": { "firstSeen": "2026-09-01", "lastSeen": "2026-09-29" },
  "email": {
    "domain": "invoices-portal.example",
    "disposable": false,
    "freeProvider": false,
    "mx": true,
    "domainReputation": {
      "lookupStatus": "unknown",
      "malicious": false,
      "blocklistHits": 0,
      "sources": []
    }
  },
  "flags": { "delisted": false },
  "meta": { "enrichment": "fast", "processingMs": 2, "latencyMs": 41 }
}
```

`check_indicator` with `{ "indicator": "06 12 34 56 78", "country": "FR" }`:

```json
{
  "indicator": "+33612345678",
  "input": "06 12 34 56 78",
  "type": "phone",
  "verdict": "unknown",
  "headline": "+33612345678 is not in any source we hold; absence is not evidence of safety.",
  "recommendedAction": "unverified",
  "malicious": false,
  "lookupStatus": "unknown",
  "risk": {
    "summary": "No evidence about +33612345678: unverified, not a clean verdict"
  },
  "reasons": [
    "No phone feed lists this number",
    "Absence from our dataset is not evidence that the number is safe"
  ],
  "blocklist": { "hits": 0, "listed": false, "sources": [] },
  "phone": {
    "e164": "+33612345678",
    "countryCallingCode": "33",
    "resolvedWith": "country"
  },
  "flags": { "delisted": false },
  "meta": { "enrichment": "fast", "processingMs": 1, "latencyMs": 38 }
}
```

`resolvedWith` is `e164` (written with `+` or `00`), `country` (resolved with
`country`), `nanp-guess` (10 digits read as North American) or `digits` (no
country could be told; `e164` is then `null`).

A hash the dataset knows also carries `file` (family, file type, MIME type,
name, size, signature, tags, the file's other digests) and `lookupStatus`; a
citing source reached through another digest of the same file says
`via: "alias"`, one reached through a listed range `via: "cidr"`.

A hash NSRL knows (`flags.knownGood`) that a threat blocklist also lists comes
back `suspicious` with `recommendedAction: "review"`, never `malicious` /
`block`: NSRL identifies known software, it does not clear it, and the two
sources disagree, which is a call for an analyst. The headline names the
conflict (`<sha256> is known software (NSRL), yet 2 sources list it; review
before blocking.`) and `blocklist` still lists the citing sources.
`check_indicators` relays each row's `recommendedAction` from the API as it
comes; its rows carry no NSRL flag.

`check_indicators` returns its rows in input order. When the result would pass
48 KB, whole rows are dropped from the end and the result says so with
`returned`, `omitted`, `truncated: true` and a `note`; `malicious` still counts
every row, split into `maliciousReturned` and `maliciousOmitted`.
`search_indicators` does the same with `indicators` past 32 KB.

### `scan_email` example

`scan_email` with a parsed message whose shape alone is suspicious (nothing in
the dataset lists any of it, so it is a review, never a quarantine):

```json
{
  "message": {
    "headers": [
      {
        "name": "From",
        "value": "\"support@paypal.com\" <noreply@paypal-secure.test>"
      },
      { "name": "Reply-To", "value": "helpdesk@gmail.com" }
    ],
    "subject": "Your account is limited",
    "html": "<p>Confirm now: <a href=\"https://login.lookalike.test/verify\">www.paypal.com</a></p>"
  }
}
```

```json
{
  "verdict": "suspicious",
  "recommendedAction": "review",
  "riskScore": 85,
  "headline": "Review: The sender's domain imitates a well-known brand.",
  "reasons": [
    {
      "code": "sender.brand_lookalike",
      "severity": "high",
      "summary": "The sender's domain imitates a well-known brand.",
      "evidence": "paypal-secure[.]test pairs PayPal (paypal[.]com) with a word phishing uses"
    },
    {
      "code": "headers.display_name_address",
      "severity": "high",
      "summary": "The display name shows one address while the message comes from another.",
      "evidence": "support@paypal.com <noreply@paypal-secure.test>"
    },
    {
      "code": "link.anchor_mismatch",
      "severity": "high",
      "summary": "A link shows one site and opens another.",
      "evidence": "shows paypal.com opens login[.]lookalike[.]test"
    },
    {
      "code": "headers.display_name_brand",
      "severity": "medium",
      "summary": "The display name claims a well-known brand while the message comes from another domain.",
      "evidence": "PayPal claimed, From noreply@paypal-secure[.]test"
    },
    {
      "code": "headers.reply_to_freemail",
      "severity": "medium",
      "summary": "Replies go to a free mail address while the message claims a company domain.",
      "evidence": "From noreply@paypal-secure.test / Reply-To helpdesk@gmail.com"
    },
    {
      "code": "sender.no_mail_authentication",
      "severity": "low",
      "summary": "The sender's domain publishes neither SPF nor DMARC: anyone can send as it.",
      "evidence": "paypal-secure.test"
    }
  ],
  "sender": {
    "address": "noreply@paypal-secure.test",
    "domain": "paypal-secure.test",
    "displayName": "support@paypal.com",
    "verdict": "unknown",
    "replyTo": ["helpdesk@gmail.com"],
    "posture": "F",
    "spoofable": true
  },
  "authentication": {
    "status": "unverified",
    "hint": "No Authentication-Results header from a system you vouched for was read, so a message with nothing against it is inconclusive, never clean. Pass authservId (the id your receiving system writes in that header) or trustAuthenticationResults to let a DMARC pass count."
  },
  "links": {
    "total": 1,
    "flagged": [
      {
        "host": "login[.]lookalike[.]test",
        "verdict": "unknown",
        "flags": ["anchor_mismatch"],
        "shownDomain": "paypal.com"
      }
    ]
  },
  "attachments": {
    "total": 0,
    "unknown": 0,
    "flagged": []
  },
  "injection": {
    "score": 0
  },
  "coverage": {
    "skipped": [
      {
        "check": "authentication",
        "reason": "no Authentication-Results header from a system you vouched for (context.authservId or trustAuthenticationResults); SPF, DKIM and DMARC are not verified by this scan yet"
      },
      {
        "check": "connecting_ip",
        "reason": "no public address in the Received chain at or below the trusted boundary"
      }
    ]
  },
  "meta": {
    "apiLatencyMs": 2
  }
}
```

The verdict, the action, the score and the headline are the API's; the server
only keeps the strongest six `reasons`, the links and attachments that carry a
signal, and what was not checked, and writes hosts defanged (`evil[.]example`)
so the text can be pasted into a ticket or a chat. `authentication.status` is
`unverified` unless you name your receiving system (`authservId`, the id it
writes in `Authentication-Results`) or vouch for every such header
(`trustAuthenticationResults`): anyone can write one into a message, so
nothing else is believed, and without it a message with nothing against it is
`inconclusive`, never `clean`. Even with it, `clean` is kept for a sender domain
the dataset knows as established (among the 100 000 most visited, not a free
mailbox): attackers publish DMARC for the domains they register.
`trustedHops` and `connectingIp` say which
server delivered the message to yours. Sent as `eml`, attachments are also read
for structure and never run (`attachments.flagged[].detectedType` and `flags`:
a program under a document name, macros and remote templates in Office files,
risky entries or a password in an archive, PDF actions, HTML that rebuilds a
file), the addresses found inside them are looked up as links
(`links.flagged[].origin: "attachment"`), and a message attached to it is read
as a message of its own (`origin: "attached_message"`). Sent as `message`, an
attachment is its digests and its name, and `coverage.skipped` says so. A
message over 10 MiB is refused (send `message` with the attachments' digests
instead). Each message costs one scan of the scan meter, not a request.

## Errors

Every failure is a result with `isError: true` and this body:

```json
{
  "error": "rate_limited",
  "status": 429,
  "message": "Rate limit exceeded",
  "quota": {
    "kind": "burst",
    "limit": 60,
    "remaining": 0,
    "plan": "FREE",
    "retry_after": 30,
    "resets_at": "…"
  },
  "hint": "Wait 30s before retrying."
}
```

`error` is one of `rate_limited`, `unauthorized`, `forbidden`, `not_found`,
`bad_request`, `upstream_error`, `timeout`, `network_error`, `invalid_params`.
`quota.kind` is `burst`, `monthly`, `daily`, `scans` or `issuance`. A 401 says
whether no key is configured or the configured one was refused.

## Timeouts and cancellation

Gate tools 15 s, `check_indicator` 25 s, CVE tools 10 s, `search_indicators`
20 s, `check_indicators` 60 s, `check_password_exposure` 10 s, `scan_email`
20 s, `bootstrap_key` 15 s. `ISMALICIOUS_TIMEOUT_MS`
replaces all of them; `ISMALICIOUS_TIMEOUT_<TOOL>_MS` (for example
`ISMALICIOUS_TIMEOUT_CHECK_INDICATOR_MS=3000`) sets one tool's and wins. A
`notifications/cancelled` from the client aborts the HTTP call; the cancelled
request gets no response.

## Latency

What the server itself does to answer sooner:

- **`fast` enrichment** is `check_indicator`'s default: the API answers from
  cached intelligence without calling a live upstream first. Facets it did
  not have cached are listed in `meta.pending` and fetched in the
  background; only then does the headline ask for one re-check after a few
  seconds, and it says that a facet still pending after it is not coming
  (the answer stands; each re-check is a billed request). A hash no source
  has cached may still wait a few seconds on CIRCL before the answer. `standard` may call DNS, OTX or CIRCL before
  answering. `fast` needs an API deploy from 2026-09-30 or later: an older
  server reads it as `standard` for an IP, a domain or a URL, but stores
  `enrichmentLevel: "fast"` in the hash document it caches, which is why this
  release follows that deploy. Email addresses and phone numbers are
  answered from cached data at every level.
- **Connection reuse**: one keep-alive pool per scheme (16 sockets, idle
  sockets kept 30 s), gzip or brotli responses, so a call a few seconds after
  the previous one does not pay a new TCP and TLS handshake. After
  `initialize`, when a key is set, one unauthenticated `GET /health` opens
  the connection before the first tool call (`ISMALICIOUS_PREWARM=0` to
  skip).
- **Result cache**: a successful result is replayed to an identical call —
  same key, tool and normalised arguments — for 60 s (`check_indicator`,
  `check_indicators`, `check_url`), 1 h (`get_cve`) or 5 min (`recent_cves`,
  `search_indicators`). A result that lists pending facets is never
  replayed: the re-check it invites goes to the API. A
  replay costs no request and says so (`meta.cached`, `meta.ageSec`, or a
  top-level `_cache`). `scan_before_use`, `scan_email`, `bootstrap_key` and
  errors are never cached. `ISMALICIOUS_CACHE_TTL_S` caps or (with `0`) disables it.
- **Shared calls**: identical calls in flight share one request, a result
  with pending facets included. A defanged and a plain form of one indicator
  are one call; each caller still gets its own `input`.

`meta.latencyMs` on a `check_indicator` result is the client-measured round
trip; `meta.processingMs` is the API's own time.

### Calling the API host directly

By default the server calls `https://ismalicious.com/api`, which forwards to
the API. Setting `ISMALICIOUS_API_BASE=https://api.ismalicious.com` calls the
API host directly and skips that hop. `bootstrap_key` still goes to
`https://ismalicious.com/api` (its route exists only there; see
`ISMALICIOUS_WEB_BASE`). One billing difference: on the API host
`search_indicators` is charged one request of the monthly quota, where the
default base only counts it against the burst rate limit.

## Resource

`ismalicious://quota` (`application/json`): the scan meter from
`GET /gate/quota` and the request-quota headers seen on the last billed call
of this session.

## Environment

| Variable                                        | Meaning                                                                                                                                                                                                     |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ISMALICIOUS_API_KEY`, `ISMALICIOUS_API_SECRET` | Key pair; optional (bootstrap mode without them).                                                                                                                                                           |
| `ISMALICIOUS_API_BASE`                          | Defaults to `https://ismalicious.com/api`; `https://api.ismalicious.com` calls the API host directly (see above).                                                                                           |
| `ISMALICIOUS_WEB_BASE`                          | Base for `bootstrap_key`. Defaults to `ISMALICIOUS_API_BASE`, or to `https://ismalicious.com/api` when that is `https://api.ismalicious.com`.                                                               |
| `ISMALICIOUS_TIMEOUT_MS`                        | Overrides every tool timeout.                                                                                                                                                                               |
| `ISMALICIOUS_TIMEOUT_<TOOL>_MS`                 | One tool's timeout, e.g. `ISMALICIOUS_TIMEOUT_CHECK_INDICATOR_MS`; wins over `ISMALICIOUS_TIMEOUT_MS`.                                                                                                      |
| `ISMALICIOUS_CACHE_TTL_S`                       | `0` turns the result cache off; `N` caps every cache lifetime at N seconds (never raises one).                                                                                                              |
| `ISMALICIOUS_PREWARM`                           | `0` (or `false`, `off`, `no`) skips the connection warm-up after `initialize`.                                                                                                                              |
| `NODE_USE_ENV_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Node's env-proxy mode (`NODE_USE_ENV_PROXY=1` or `--use-env-proxy`): calls go through the proxy, keeping the connection pool on Node 22.21+ / 24.5+. Off, the proxy variables are ignored, as with `fetch`. |

## Development

```bash
pnpm --filter @ismalicious/mcp-server typecheck test build
node packages/mcp-server/scripts/check-version.mjs   # versions and server.json shape
node packages/mcp-server/scripts/smoke.mjs           # stdio end-to-end against a stub API
```

The version is declared once in `src/version.ts`. See `PUBLISHING.md` for npm
and the MCP registry; `CHANGELOG.md` for what changed.

The `Dockerfile` is the build Glama runs to list the server. It sets a
placeholder key pair so `tools/list` shows every tool; pass a real pair with
`docker run -i -e ISMALICIOUS_API_KEY=… -e ISMALICIOUS_API_SECRET=…`, or empty
values for bootstrap mode.
