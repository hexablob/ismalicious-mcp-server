/** Defensive readers over untyped API JSON. Never throw, never coerce. */

export type Rec = Record<string, unknown>;

export function isRec(v: unknown): v is Rec {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function rec(v: unknown): Rec | undefined {
  return isRec(v) ? v : undefined;
}

export function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function num(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

export function bool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

export function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

export function strs(v: unknown, max: number): string[] {
  return arr(v)
    .map((x) =>
      typeof x === "string" ? x : typeof x === "number" ? String(x) : undefined,
    )
    .filter((x): x is string => x !== undefined)
    .slice(0, max);
}

export function clip(s: string | undefined, max: number): string | undefined {
  if (s === undefined) return undefined;
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** `2026-08-11T10:00:00Z` → `2026-08-11`; anything unparseable is kept as-is. */
export function day(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(s);
  return m ? m[1] : s;
}

/** Drop `undefined` values so the JSON handed to the model has no noise. */
export function compact<T extends Rec>(o: T): Partial<T> {
  const out: Rec = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined) continue;
    if (isRec(v)) {
      const inner = compact(v);
      if (Object.keys(inner).length === 0) continue;
      out[k] = inner;
      continue;
    }
    out[k] = v;
  }
  return out as Partial<T>;
}
