# Publishing from public source

The public source is `hexablob/ismalicious-mcp-server`. This candidate starts
from the source used for npm 0.6.0 (`c9d76908e864f038495e511c68d317c4f2ce7ca4`),
including `scan_email`. The private workspace configuration is replaced by a
standalone tsconfig. Version 0.6.1 changes release metadata and the build/test
toolchain; it does not remove or change the nine keyed tools.

No existing npm version has a provenance attestation as of October 5, 2026.
Source-map comparison ties all 54 embedded sources in npm 0.6.0 to that source
revision. This comparison is evidence of source correspondence, not a
historical build attestation or a bit-identical bundle reproduction. npm
registry signatures are different from build provenance.

## Local checks

Use Node 24 for development and CI (the distributed server still requires
Node 18 or newer):

```sh
npm ci --ignore-scripts
npm run check-version
npm run typecheck
npm test
npm run build
npm run smoke
npm audit --audit-level=low
npm pack --dry-run --json
```

Tests and smoke use fixtures. Two private-monorepo cross-language parity tests
are skipped in this standalone repository. No live API key is required.

## Release prerequisites and manual execution

The prepared workflow has not published a package. Before release, an owner
must approve the source changes, merge this PR and create the reviewed tag
`v0.6.1` on the exact signed source commit. Configure the npm package's trusted
publisher for GitHub user `hexablob`, repository `ismalicious-mcp-server`,
workflow filename `npm-publish.yml`, with direct `npm publish` permission.
This permission setup is a separate action; no publisher or npm token has
been created by this change. The public GitHub-hosted runner builds the
reviewed tag and uses OIDC and `--provenance`. There is no credential fallback,
automatic tag-push publication, or automatic permission change.

Only after those approvals, dispatch `npm-publish.yml` from `main`, selecting
`release_tag=v0.6.1` and `confirmation=PUBLISH`. It publishes under the
`review-candidate` npm dist-tag, preserving the existing `latest` version.
The workflow fails if the version already exists, its tag differs from its
version, tests fail or provenance metadata is absent. A failed post-publish
check does not roll back the immutable npm release; inspect before retrying.

## Independent verification and OpenHands eligibility

The workflow prints the real `dist.attestations.url`. Then use an empty
directory, install the exact candidate with scripts disabled, and verify:

```sh
npm init -y
npm install --save-exact --ignore-scripts @ismalicious/mcp-server@0.6.1
npm audit signatures
npm view @ismalicious/mcp-server@0.6.1 dist.attestations gitHead --json
npm view @ismalicious/mcp-server time --json
```

Inspect the attestation's source repository, commit and workflow. The source
commit must match the release tag and the prepared signed commit. Only after
the exact new version has actually been published for seven complete days,
update the OpenHands catalogue pin and recapture its raw SDK fixture output.
Compute eligibility from the registry's real publication timestamp plus
seven days; a source tag or a dry run does not start that clock. Keep the
OpenHands PR draft until its human-authored note and maintainer fit decision
are resolved.

References: [npm provenance](https://docs.npmjs.com/generating-provenance-statements/)
and [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).
