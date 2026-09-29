/**
 * The version lives in four places that npm and the MCP registry each read
 * independently: package.json, server.json (root and packages[0]) and
 * src/version.ts (the User-Agent). This module says whether they agree, and
 * whether server.json still satisfies the 2025-12-11 registry schema rules
 * learned on 2026-09-04 (see PUBLISHING.md). Pure: no process.exit, no output.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

export function readVersions(dir) {
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const server = JSON.parse(readFileSync(join(dir, "server.json"), "utf8"));
  const versionTs = readFileSync(join(dir, "src", "version.ts"), "utf8");
  const match = /SERVER_VERSION\s*=\s*['"]([^'"]+)['"]/.exec(versionTs);
  return { pkg, server, versionTs: match ? match[1] : null };
}

export function collectVersionProblems(dir, { expect } = {}) {
  const problems = [];
  const { pkg, server, versionTs } = readVersions(dir);
  const first = Array.isArray(server.packages) ? server.packages[0] : undefined;

  if (!versionTs) problems.push("src/version.ts: SERVER_VERSION not found");
  const versions = {
    "package.json version": pkg.version,
    "server.json version": server.version,
    "server.json packages[0].version": first?.version,
    "src/version.ts SERVER_VERSION": versionTs,
  };
  const distinct = new Set(Object.values(versions));
  if (distinct.size !== 1) {
    problems.push(
      `versions disagree: ${Object.entries(versions)
        .map(([k, v]) => `${k}=${v ?? "(missing)"}`)
        .join(", ")}`,
    );
  }
  if (expect && pkg.version !== expect) {
    problems.push(`package.json version ${pkg.version} != expected ${expect}`);
  }

  if (pkg.mcpName !== server.name) {
    problems.push(
      `package.json mcpName (${pkg.mcpName}) != server.json name (${server.name})`,
    );
  }
  if (
    typeof server.name !== "string" ||
    server.name.length === 0 ||
    server.name.length > 200
  ) {
    problems.push("server.json name must be 1-200 characters");
  }
  if (
    typeof server.description !== "string" ||
    server.description.length === 0 ||
    server.description.length > 100
  ) {
    problems.push(
      `server.json description must be 1-100 characters (is ${server.description?.length ?? 0})`,
    );
  }
  if (
    server.title !== undefined &&
    (typeof server.title !== "string" || server.title.length > 100)
  ) {
    problems.push("server.json title must be at most 100 characters");
  }
  if (!first) {
    problems.push("server.json packages[0] missing");
  } else {
    if (first.registryType !== "npm")
      problems.push('server.json packages[0].registryType must be "npm"');
    if (first.identifier !== pkg.name) {
      problems.push(
        `server.json packages[0].identifier (${first.identifier}) != package.json name (${pkg.name})`,
      );
    }
    if (first.transport?.type !== "stdio")
      problems.push('server.json packages[0].transport.type must be "stdio"');
    for (const [i, env] of (first.environmentVariables ?? []).entries()) {
      if (typeof env.name !== "string" || typeof env.description !== "string") {
        problems.push(
          `server.json packages[0].environmentVariables[${i}] needs name and description`,
        );
      }
    }
  }
  const schema = server.$schema ?? "";
  if (!schema.includes("/2025-12-11/")) {
    problems.push(
      `server.json $schema should be the 2025-12-11 schema (is ${schema || "(none)"})`,
    );
  }
  for (const key of [
    "registry_type",
    "registry_base_url",
    "environment_variables",
    "is_required",
    "is_secret",
  ]) {
    if (JSON.stringify(server).includes(`"${key}"`)) {
      problems.push(
        `server.json uses snake_case key ${key}; the 2025-12-11 schema is camelCase`,
      );
    }
  }
  return problems;
}
