# @ismalicious/mcp-server

A zero-dependency [Model Context Protocol](https://modelcontextprotocol.io)
server that gives an AI agent isMalicious threat intelligence: reputation
verdicts for indicators, the CVE catalog, and the isinjected gate that scans
untrusted content for prompt injection before the agent acts on it.

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

| Tool                | What it answers                                                                                                                                                                                                                                                                                                                                                       | Cost                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `scan_before_use`   | Prompt-injection scan plus link reputation over a block of untrusted text. `block \| warn \| allow`.                                                                                                                                                                                                                                                                  | 1 scan                  |
| `check_url`         | Reputation of one URL, domain or IP before fetching it. `block \| warn \| allow`.                                                                                                                                                                                                                                                                                     | 1 scan                  |
| `check_indicator`   | Full reputation picture of an IP, domain, URL or hash: `verdict` (malicious/suspicious/clean/unknown), a `headline` you can relay verbatim, `recommendedAction` (block/review/allow/unverified), risk 0-100, citing threat blocklists, `infrastructure` (what it is known as: cloud, CDN, Tor exit…), first/last seen, network, registration, known CVEs. Under 4 KB. | 1 request               |
| `get_cve`           | One CVE by id: description, CVSS, EPSS, CISA KEV status and due date, exploitation evidence, references. The only CVE path.                                                                                                                                                                                                                                           | 1 request               |
| `recent_cves`       | Latest CVEs, optional `severity`, at most 20.                                                                                                                                                                                                                                                                                                                         | 1 request               |
| `search_indicators` | Domains the corpus lists that look like a brand or domain — typosquats, homoglyphs, other TLDs or hosts, phishing-word combinations — most dangerous first. `total_hits` counts the upstream sample; `truncated` is true when omission is known, null when unknown. Follow up with `check_indicators` for verdicts.                                                   | 1 request               |
| `check_indicators`  | Reputation of up to 100 indicators in one call: per row `malicious`, `recommendedAction`, risk, blocklist count, categories, `infrastructure`. **Each indicator charges one request** (duplicates and rejects are free); plans cap the batch (Free 10, Basic 50, Pro 100).                                                                                            | 1 request per indicator |
| `bootstrap_key`     | Only without a configured key: mint a free key from an email, one per IP per day.                                                                                                                                                                                                                                                                                     | —                       |

The default search API reads a bare keyword as its `.com` (`paypal` →
`paypal.com`) and returns at most 500 listed lookalikes. `limit` only reduces
that sample. Only listed domains are returned and a name buried in a longer
hostname is not matched, so an empty answer does not prove that no lookalike
exists.
The MCP result labels `total_hits_scope` as `upstream_sample`. Legacy or custom
API responses without completeness metadata produce `truncated: null`.

Scans and requests are two meters: <https://ismalicious.com/api-docs>.

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

A hash NSRL knows (`flags.knownGood`) that a threat blocklist also lists comes
back `suspicious` with `recommendedAction: "review"`, never `malicious` /
`block`: NSRL identifies known software, it does not clear it, and the two
sources disagree, which is a call for an analyst. The headline names the
conflict (`<sha256> is known software (NSRL), yet 2 sources list it; review
before blocking.`) and `blocklist` still lists the citing sources.
`check_indicators` relays each row's `recommendedAction` from the API as it
comes; its rows carry no NSRL flag.

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
20 s, `check_indicators` 60 s, `bootstrap_key` 15 s. `ISMALICIOUS_TIMEOUT_MS`
replaces all of them. A `notifications/cancelled`
from the client aborts the HTTP call; the cancelled request gets no response.

## Resource

`ismalicious://quota` (`application/json`): the scan meter from
`GET /gate/quota` and the request-quota headers seen on the last billed call
of this session.

## Environment

| Variable                                        | Meaning                                           |
| ----------------------------------------------- | ------------------------------------------------- |
| `ISMALICIOUS_API_KEY`, `ISMALICIOUS_API_SECRET` | Key pair; optional (bootstrap mode without them). |
| `ISMALICIOUS_API_BASE`                          | Defaults to `https://ismalicious.com/api`.        |
| `ISMALICIOUS_TIMEOUT_MS`                        | Overrides every tool timeout.                     |

## Development

```bash
npm install
npm run typecheck && npm test && npm run build
node scripts/check-version.mjs   # versions and server.json shape
node scripts/smoke.mjs           # stdio end-to-end against a stub API
```

The version is declared once in `src/version.ts`; `CHANGELOG.md` lists what changed.
This repository mirrors `packages/mcp-server` from the isMalicious monorepo, where
releases to npm and the MCP registry are cut. Issues and pull requests are welcome here.
