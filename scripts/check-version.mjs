#!/usr/bin/env node
/**
 * CLI over version-check.mjs. Exit 1 with one line per problem.
 *
 *   node scripts/check-version.mjs             # consistency only
 *   node scripts/check-version.mjs --expect 0.2.0
 */
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { collectVersionProblems, readVersions } from "./version-check.mjs";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..");
const expectIdx = process.argv.indexOf("--expect");
const expect = expectIdx >= 0 ? process.argv[expectIdx + 1] : undefined;

const problems = collectVersionProblems(dir, { expect });
if (problems.length > 0) {
  for (const p of problems) console.error(`check-version: ${p}`);
  process.exit(1);
}
console.log(`check-version: ok (${readVersions(dir).pkg.version})`);
