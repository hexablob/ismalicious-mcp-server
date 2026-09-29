import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain ESM script shared with the CLI; no types on purpose
import { collectVersionProblems } from "../../scripts/version-check.mjs";
import { SERVER_VERSION } from "../version.js";

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

describe("version consistency", () => {
  it("package.json, server.json (twice) and version.ts agree", () => {
    expect(collectVersionProblems(pkgDir)).toEqual([]);
  });
  it("flags a mismatch with --expect", () => {
    expect(collectVersionProblems(pkgDir, { expect: "0.0.0-nope" })).toEqual([
      expect.stringContaining(
        `package.json version ${SERVER_VERSION} != expected 0.0.0-nope`,
      ),
    ]);
  });
});
