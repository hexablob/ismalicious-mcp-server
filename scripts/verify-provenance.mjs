#!/usr/bin/env node
import { readFileSync } from 'node:fs';
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const url = `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/${pkg.version}`;
let metadata;
for (let attempt = 0; attempt < 12; attempt++) {
  const response = await fetch(url);
  if (response.ok) {
    metadata = await response.json();
    if (metadata.dist?.attestations?.url) break;
  } else if (response.status !== 404) {
    throw new Error(`Registry lookup failed: ${response.status}`);
  }
  if (attempt < 11) await new Promise(resolve => setTimeout(resolve, 5000));
}
if (!metadata?.dist?.attestations?.url) throw new Error('Published provenance metadata is missing');
console.log(JSON.stringify({
  package: `${pkg.name}@${pkg.version}`,
  gitHead: metadata.gitHead,
  attestationUrl: metadata.dist.attestations.url,
  note: 'Metadata presence checked only. Independently verify using npm audit signatures.'
}, null, 2));
