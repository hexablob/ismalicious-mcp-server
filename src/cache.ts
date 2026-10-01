/**
 * In-process result cache for the dispatch layer.
 *
 * An agent re-checks the same indicator within a session — check_url then
 * check_indicator, a plan that loops, two parallel calls for the same alert —
 * and each repeat cost a round trip and a request of quota. A hit answers in
 * under a millisecond and costs nothing. Bounded (LRU) and short-lived: a
 * verdict can be at most one TTL stale, which is the price of the hit.
 *
 * Only successful results are stored. Errors are not, nor results the API
 * marked as still being completed (`pending`): the re-check they invite must
 * reach the API. Identical calls in flight still share one request, so a
 * burst of them collapses either way.
 */

import { createHash } from "node:crypto";

export const CACHE_MAX_ENTRIES = 500;

export interface CachedResult {
  value: unknown;
  /** Clock reading (ms) when the result was stored. */
  storedAt: number;
}

export interface ResultCache {
  get(key: string, nowMs: number): CachedResult | undefined;
  set(key: string, value: unknown, ttlSec: number, nowMs: number): void;
  readonly size: number;
}

interface Entry extends CachedResult {
  expiresAt: number;
}

/**
 * A `Map` is the LRU: insertion order is recency order once a read re-inserts
 * the entry, so the first key is always the least recently used.
 */
export function createResultCache(
  maxEntries: number = CACHE_MAX_ENTRIES,
): ResultCache {
  const entries = new Map<string, Entry>();
  return {
    get(key, nowMs) {
      const entry = entries.get(key);
      if (!entry) return undefined;
      entries.delete(key);
      if (entry.expiresAt <= nowMs) return undefined;
      entries.set(key, entry);
      return { value: entry.value, storedAt: entry.storedAt };
    },
    set(key, value, ttlSec, nowMs) {
      if (!(ttlSec > 0)) return;
      entries.delete(key);
      entries.set(key, {
        value,
        storedAt: nowMs,
        expiresAt: nowMs + ttlSec * 1000,
      });
      while (entries.size > maxEntries) {
        const oldest = entries.keys().next().value;
        if (oldest === undefined) break;
        entries.delete(oldest);
      }
    },
    get size() {
      return entries.size;
    },
  };
}

/** JSON with object keys sorted at every depth and `undefined` dropped. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value)) ?? "null";
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

/**
 * Who is asking, without the secret: two keys never share an entry, and the
 * `X-API-KEY` value (base64 of key:secret) never sits in memory as a map key.
 */
export function keyIdentity(apiKeyHeader: string | null): string {
  if (apiKeyHeader === null) return "anonymous";
  return createHash("sha256").update(apiKeyHeader).digest("hex").slice(0, 32);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyArray(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

/**
 * True when a raw API body or a projection says facets are still missing
 * (`pending: ["dns", "whois", …]` from `GET /check?enrichment=fast`, or a
 * bulk row carrying one): the next call is expected to be more complete, so
 * the answer is never replayed from the cache.
 */
export function reportsPending(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (nonEmptyArray(value.pending)) return true;
  if (isRecord(value.meta) && nonEmptyArray(value.meta.pending)) return true;
  return (
    Array.isArray(value.results) &&
    value.results.some((row) => isRecord(row) && nonEmptyArray(row.pending))
  );
}
