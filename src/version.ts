/**
 * The one place the version lives.
 *
 * `package.json`, `server.json` (twice) and the User-Agent this server sends
 * must all agree with this constant; `scripts/check-version.mjs` and
 * `src/__tests__/version.test.ts` fail when they do not. Bump here first.
 */
export const SERVER_VERSION = "0.4.0";
export const SERVER_NAME = "@ismalicious/mcp-server";
