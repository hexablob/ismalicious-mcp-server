/**
 * Tool-name parity, from this side.
 *
 * The names live in three places: the tool files here, `MCP_TOOLS` in
 * `apps/rust-api/src/infra/client.rs` (the closed set Rust counts per tool)
 * and `MCP_TOOLS` in `apps/web/lib/growth-metrics-constants.ts` (the admin
 * growth panel and the install copy). Rust checks all three, but only in
 * the Rust CI job, which a change to this package alone does not run. This
 * test runs with the package's own suite.
 *
 * The package is mirrored to a public repository without the monorepo, so a
 * missing file skips its check instead of failing.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TOOLS } from "../tools/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..", "..");
const RUST_CLIENT = join(repoRoot, "apps/rust-api/src/infra/client.rs");
const WEB_CONSTANTS = join(
  repoRoot,
  "apps/web/lib/growth-metrics-constants.ts",
);
const TOOLS_DIR = join(here, "..", "tools");

const names = TOOLS.map((t) => t.name);

/** The quoted strings of the array literal that follows `marker`. */
function arrayAfter(source: string, marker: RegExp): string[] {
  const start = source.search(marker);
  if (start < 0) throw new Error(`${marker} not found`);
  const open = source.indexOf("[", source.indexOf("=", start));
  const close = source.indexOf("]", open);
  return [...source.slice(open, close).matchAll(/["']([a-z_]+)["']/g)].map(
    (m) => m[1],
  );
}

describe("MCP tool names", () => {
  it.skipIf(!existsSync(RUST_CLIENT))(
    "match MCP_TOOLS in apps/rust-api/src/infra/client.rs, in order",
    () => {
      const rust = arrayAfter(
        readFileSync(RUST_CLIENT, "utf8"),
        /pub const MCP_TOOLS\s*:/,
      );
      expect(rust).toEqual(names);
    },
  );

  it.skipIf(!existsSync(WEB_CONSTANTS))(
    "match MCP_TOOLS in apps/web/lib/growth-metrics-constants.ts, in order",
    () => {
      const web = arrayAfter(
        readFileSync(WEB_CONSTANTS, "utf8"),
        /export const MCP_TOOLS\s*=/,
      );
      expect(web).toEqual(names);
    },
  );

  it("are each declared first in their own tool file, as the Rust test reads them", () => {
    // `client.rs` takes the first `name: "…"` of every file in src/tools
    // except these three; a helper module there would break it.
    const declared = readdirSync(TOOLS_DIR)
      .filter(
        (f) =>
          f.endsWith(".ts") &&
          !["index.ts", "types.ts", "request.ts"].includes(f),
      )
      .map((f) => {
        const src = readFileSync(join(TOOLS_DIR, f), "utf8");
        const m = /name: "([^"]+)"/.exec(src);
        const first = src.indexOf("name: ");
        expect(m, f).not.toBeNull();
        expect(m?.index, `${f}: first \`name: \` is not the tool name`).toBe(
          first,
        );
        return m?.[1];
      });
    expect([...declared].sort()).toEqual([...names].sort());
  });
});
