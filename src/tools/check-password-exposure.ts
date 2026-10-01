import { createHash } from "node:crypto";

import { invalidParams } from "../errors.js";
import { fetchJson } from "./request.js";
import { fail, ok, READ_ONLY_TOOL, type ToolDefinition } from "./types.js";

/** Hex digits sent (the range prefix) and matched locally after it. */
const PREFIX_LENGTH = 5;
const SUFFIX_LENGTH = 12;

type Mode = "sha1" | "ntlm";

interface RangeBody {
  entries?: Array<{ suffix?: unknown; count?: unknown }>;
  source?: unknown;
  corpusUpdatedAt?: unknown;
}

/**
 * The hash to look up and its mode, from exactly one of the three inputs.
 * A plaintext password is hashed here, with SHA-1: NTLM needs MD4, which
 * Node's OpenSSL 3 no longer ships by default.
 */
function hashFromArgs(
  args: Record<string, unknown>,
): { hash: string; mode: Mode } | string {
  const given = (["password", "sha1", "ntlm"] as const).filter(
    (k) => typeof args[k] === "string" && (args[k] as string).length > 0,
  );
  if (given.length !== 1) {
    return "give exactly one of password, sha1 or ntlm.";
  }
  const key = given[0];
  const value = args[key] as string;
  if (key === "password") {
    if (value.length > 1024) return "password is longer than 1024 characters.";
    return {
      hash: createHash("sha1").update(value, "utf8").digest("hex"),
      mode: "sha1",
    };
  }
  const hash = value.trim();
  const length = key === "sha1" ? 40 : 32;
  if (hash.length !== length || !/^[0-9a-f]+$/i.test(hash)) {
    return `${key} must be ${length} hex characters.`;
  }
  return { hash, mode: key };
}

export const checkPasswordExposure: ToolDefinition = {
  name: "check_password_exposure",
  title: "Check password breach exposure",
  description:
    "Whether a password appears in known data breaches (Have I Been Pwned's Pwned Passwords corpus) and how many times. Give `password` (hashed with SHA-1 on this machine, never sent), or a `sha1` or `ntlm` hash, e.g. from a credential dump or an Active Directory audit. k-anonymity: only the first 5 hex digits of the hash leave this machine. Use it before accepting, generating or storing a password. Costs one request of the monthly quota.",
  inputSchema: {
    type: "object",
    properties: {
      password: {
        type: "string",
        description:
          "The password to check. Hashed locally; neither it nor its full hash is sent.",
        minLength: 1,
        maxLength: 1024,
      },
      sha1: {
        type: "string",
        description: "SHA-1 of the password, 40 hex characters.",
        minLength: 40,
        maxLength: 40,
      },
      ntlm: {
        type: "string",
        description:
          "NTLM hash of the password (MD4 of its UTF-16LE form), 32 hex characters.",
        minLength: 32,
        maxLength: 32,
      },
    },
    additionalProperties: false,
  },
  annotations: READ_ONLY_TOOL,
  requiresKey: true,
  timeoutMs: 10_000,
  // No `cacheTtlSec`: the cache key would hold the password itself.
  async call(args, ctx) {
    const input = hashFromArgs(args);
    if (typeof input === "string") return fail(invalidParams(input));
    const hash = input.hash.toUpperCase();
    const prefix = hash.slice(0, PREFIX_LENGTH);
    const suffix = hash.slice(PREFIX_LENGTH, PREFIX_LENGTH + SUFFIX_LENGTH);
    const fetched = await fetchJson(ctx, () =>
      ctx.http.get(`/pwned-passwords/range/${prefix}?mode=${input.mode}`, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    if (!fetched.ok) return fail(fetched.error);
    const body = (fetched.json ?? {}) as RangeBody;
    const match = (body.entries ?? []).find(
      (e) => typeof e.suffix === "string" && e.suffix.toUpperCase() === suffix,
    );
    const count = typeof match?.count === "number" ? match.count : 0;
    return ok({
      exposed: count > 0,
      count,
      hashType: input.mode,
      recommendation:
        count > 0
          ? "Do not use this password: it is in breach dumps attackers replay."
          : "Not in the breach corpus. That is not a strength rating.",
      privacy: `Only the first ${PREFIX_LENGTH} hex digits of the hash were sent.`,
      source:
        typeof body.source === "string"
          ? body.source
          : "Have I Been Pwned — Pwned Passwords",
      corpusUpdatedAt:
        typeof body.corpusUpdatedAt === "string" ? body.corpusUpdatedAt : null,
    });
  },
};
