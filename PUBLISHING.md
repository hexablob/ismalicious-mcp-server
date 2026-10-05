# Publishing the gate MCP server

Three registries, in dependency order. Everything below is prepared in-repo;
each publish step is an external action — run deliberately.

## 0. Release order: the API first

Publish a version only once the API it relies on is live. From 0.5.0,
`check_indicator` sends `enrichment=fast` on every call (0.4.0, already
published, sends `basic` or `standard` only); a Rust API from before
2026-09-30 reads it as `standard` for an IP, a domain or a URL, but for a hash
it writes `enrichmentLevel: "fast"` into the document it caches in Redis for
30 days (`hash:{h}`), and every later reader of that document — SDK
consumers included, whose type allows `basic | standard | full` — gets it
back. Before tagging `mcp-v0.5.0`, check that the API echoes the level:
`GET /check?query=8.8.8.8&enrichment=fast` answers `"enrichmentLevel": "fast"`
(an older server answers `standard`).

From 0.6.0, `scan_email` calls `POST /mail/scan`; publish `mcp-v0.6.0` once the
API that serves it is live. Before tagging, check the route exists:
`POST /mail/scan` with an empty JSON body answers `400` (`send exactly one of
emlBase64, eml and message`), not `404`. The tool also needs the web deploy
that lists it in `MCP_TOOLS` (`apps/web/lib/growth-metrics-constants.ts`):
the growth panel reads the `mcp_tool_scan_email` counter only then, and Rust
counts an unknown tool name under `unknown` (`apps/rust-api/src/infra/client.rs`).

## 1. npm (prerequisite for everything else)

Done 2026-09-04 — `@ismalicious/mcp-server@0.1.0`. Publish future versions
through `.github/workflows/mcp-publish.yml` (tag `mcp-v*`, or
`gh workflow run mcp-publish.yml -f version=X.Y.Z`) rather than by hand: CI
builds from the repo, so it cannot ship a stale `dist/`. It nearly did — the
committed `dist/` was a day behind `src/` and would have shipped a binary
without the User-Agent stamping that measures adoption. Hence the
`prepublishOnly` guard on the package.

Two token traps cost three failed runs before the first publish landed. A
classic npm token demands an OTP the CI cannot type (`npm error code EOTP`) —
use an **Automation** token. And a granular token restricted to _selected
packages_ cannot create a package that does not exist yet, which surfaces as a
`404` on the `PUT`, not as a permission error — grant the whole **scope**, or
choose "All packages".

```bash
cd packages/mcp-server
pnpm build && pnpm test
npm publish --access public   # needs npm login with rights on @ismalicious
```

`package.json` carries `mcpName: "com.ismalicious/mcp-server"` — the official
MCP registry reads that field from the published tarball to prove we own the
npm package. Do not remove it.

## 2. Official MCP registry (registry.modelcontextprotocol.io)

Done 2026-09-04 — `com.ismalicious/mcp-server` 0.1.0 is live and `active`.
What follows is the recipe as it actually worked, which is not what the first
draft of this file said.

```bash
# The tool is a single Go binary; there is no brew on this host.
curl -sL -o mcp-publisher.tar.gz \
  https://github.com/modelcontextprotocol/registry/releases/download/v1.8.1/mcp-publisher_linux_amd64.tar.gz
tar xzf mcp-publisher.tar.gz && install -m755 mcp-publisher /usr/local/bin/

cd packages/mcp-server
mcp-publisher login dns --domain ismalicious.com \
  --private-key "$(cat /root/.mcp-publisher/ismalicious-ed25519.hex)"
mcp-publisher publish
```

**The DNS proof.** `login dns` needs an ed25519 private key in hex, and the
matching public key published as a TXT record on the **apex** — not on a
`_mcp-registry` subdomain. Running `login` before the record exists prints the
exact string to add, which is the fastest way to get it right:

```
v=MCPv1; k=ed25519; p=<public key, base64>
```

The keypair for ismalicious.com lives in `/root/.mcp-publisher/` (mode 600) on
the deploy host. It is needed again for every future `login`; losing it means
generating a new pair and replacing the TXT record. The apex already carries an
SPF and a Brevo record — **add** a third TXT, never replace.

**The schema moved.** This file first described the 2025-07-09 schema and
snake_case fields. The registry now validates against **2025-12-11** with
**camelCase**, and rejected the old manifest with:

```
422 validation failed
  body.description         expected length <= 100
  body.packages[0].registryType  expected length >= 1
```

`registry_type` → `registryType`, `registry_base_url` → `registryBaseUrl`,
`environment_variables` → `environmentVariables`, `is_required` → `isRequired`,
`is_secret` → `isSecret`. `description` is capped at 100 characters, `title` at
100, `name` at 200. Required at the root: `name`, `description`, `version`; in
a package: `registryType`, `identifier`, `transport`.

**`repository` names the public mirror.** Since 0.3.1, `server.json` and
`package.json` point at <https://github.com/hexablob/ismalicious-mcp-server>,
which mirrors this directory (see "Public mirror" below). They must never name
this monorepo: it is private, and a link there is a 404 for everyone reading
the registry.

Keep `server.json`'s `version` in lockstep with `package.json` on every release
— the registry rejects a version that does not exist on npm. Since 0.2.0 this
is enforced rather than remembered: the version is declared once in
`src/version.ts`, and `node scripts/check-version.mjs` (run by `prepublishOnly`,
by the `mcp-server` CI job and, with `--expect <tag version>`, by
`mcp-publish.yml`) fails when `package.json`, `server.json` — root and
`packages[0]` — or the User-Agent disagree, or when `server.json` breaks one of
the 2025-12-11 rules above (lengths, camelCase, `identifier`, `transport`).
`mcp-publish.yml` also validates `server.json` against the schema the registry
publishes (`scripts/validate-server-json.mjs`, ajv installed to a scratch
prefix; the schema is draft-07 and needs `ajv-formats`). To check what is live:
`curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=ismalicious'`.

Release order for a version that needs new API fields (0.2.0 did: EPSS/KEV on
`GET /cve?id=`): deploy `apps/rust-api` first via `main-pipeline.yml`, then push
the `mcp-v<version>` tag, then `mcp-publisher publish` from this directory.

## 3. Smithery (smithery.ai)

Not done. Manifest: `smithery.yaml` (this directory). Smithery ingests from a
GitHub repository; connect the public mirror, never the monorepo.

## 4. Glama (glama.ai)

Glama lists a server only once it can build it and answer `tools/list`. It
reads two files at the root of the public mirror: `glama.json` (the GitHub
users allowed to claim and edit the listing) and `Dockerfile` (the build it
runs). The image sets a placeholder key pair so introspection sees the seven
keyed tools rather than `bootstrap_key` alone; listing tools makes no network
call. After the mirror carries both files, claim the listing on glama.ai as
`hexablob`.

## Public mirror

<https://github.com/hexablob/ismalicious-mcp-server> is this directory, cut
at each release; this monorepo stays the source. It differs on purpose: no
`PUBLISHING.md`, a standalone `tsconfig.json` without the workspace `extends`,
no `@ismalicious/typescript-config` devDependency, a `package-lock.json`, npm
commands in `prepublishOnly`, and a README "Development" section written for
npm. Push the mirror after the monorepo release PR merges.

npm provenance is still off: it needs the publish to run from a GitHub
Actions workflow in the public repository whose URL matches `repository`, and
`mcp-publish.yml` runs in this private one.

## After publishing

- ~~Update `docs/gate-api.md` with the registry links.~~ Done 2026-09-04.
- The `/prompt-injection-scanner` marketing page and `/automated-access`
  should link the registry entries once live.
- Watch `quota_scans:*` (Redis) and `/gate` rows in `ApiUsageDaily` for
  adoption — the flywheel described in docs/gate-api.md starts here.
