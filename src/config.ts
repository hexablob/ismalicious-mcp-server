/**
 * Environment → server configuration, kept apart from `index.ts` (which
 * starts the server on import) so each rule can be tested.
 *
 *   ISMALICIOUS_API_BASE              — keyed tools; default https://ismalicious.com/api
 *   ISMALICIOUS_WEB_BASE              — tools only the Next.js app serves (bootstrap_key)
 *   ISMALICIOUS_TIMEOUT_MS            — replaces every tool's timeout
 *   ISMALICIOUS_TIMEOUT_<TOOL>_MS     — one tool's timeout, e.g. ISMALICIOUS_TIMEOUT_CHECK_INDICATOR_MS; wins
 *   ISMALICIOUS_CACHE_TTL_S           — 0 turns the result cache off; N caps every TTL at N seconds
 *   ISMALICIOUS_PREWARM               — 0 skips the connection warm-up after initialize
 */

import type { CacheConfig } from "./server.js";

export type Env = Readonly<Record<string, string | undefined>>;
export type Log = (message: string) => void;

export const DEFAULT_API_BASE = "https://ismalicious.com/api";
export const DEFAULT_WEB_BASE = "https://ismalicious.com/api";
/** The Rust host: serves every keyed route, but not `/keys/instant`. */
export const RUST_API_HOST = "api.ismalicious.com";

function nonEmpty(value: string | undefined): string | undefined {
  const v = value?.trim();
  return v ? v : undefined;
}

function isRustHost(base: string): boolean {
  try {
    return new URL(base).hostname.toLowerCase() === RUST_API_HOST;
  } catch {
    return false;
  }
}

/**
 * Two bases, because no single host serves every tool: `/keys/instant` is a
 * Next.js route, so bootstrap_key 404s on the Rust host. A deployment that
 * set only ISMALICIOUS_API_BASE to something else (a self-hosted copy, a
 * test stub) keeps sending web tools there, as before.
 */
export function resolveBases(env: Env): { apiBase: string; webBase: string } {
  const apiBase = nonEmpty(env.ISMALICIOUS_API_BASE) ?? DEFAULT_API_BASE;
  const webBase =
    nonEmpty(env.ISMALICIOUS_WEB_BASE) ??
    (isRustHost(apiBase) ? DEFAULT_WEB_BASE : apiBase);
  return { apiBase, webBase };
}

function positiveMs(name: string, raw: string, log: Log): number | undefined {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    log(`ignoring ${name}=${raw} (not a positive number)`);
    return undefined;
  }
  return n;
}

export function resolveTimeoutOverride(env: Env, log: Log): number | undefined {
  const raw = nonEmpty(env.ISMALICIOUS_TIMEOUT_MS);
  return raw ? positiveMs("ISMALICIOUS_TIMEOUT_MS", raw, log) : undefined;
}

export function toolTimeoutVariable(tool: string): string {
  return `ISMALICIOUS_TIMEOUT_${tool.toUpperCase()}_MS`;
}

/**
 * One tool's deadline without touching the others: failing check_indicator
 * fast at 3 s must not cut the 60 s check_indicators batch.
 */
export function resolveToolTimeouts(
  env: Env,
  tools: readonly string[],
  log: Log,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const tool of tools) {
    const name = toolTimeoutVariable(tool);
    const raw = nonEmpty(env[name]);
    if (!raw) continue;
    const ms = positiveMs(name, raw, log);
    if (ms !== undefined) out[tool] = ms;
  }
  return out;
}

export function resolveCache(env: Env, log: Log): false | CacheConfig {
  const raw = nonEmpty(env.ISMALICIOUS_CACHE_TTL_S);
  if (!raw) return {};
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    log(`ignoring ISMALICIOUS_CACHE_TTL_S=${raw} (not a number of seconds)`);
    return {};
  }
  return n === 0 ? false : { maxTtlSec: n };
}

export function resolvePrewarm(env: Env): boolean {
  const raw = nonEmpty(env.ISMALICIOUS_PREWARM);
  return !(raw && /^(0|false|off|no)$/i.test(raw));
}
