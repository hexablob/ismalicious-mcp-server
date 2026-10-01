/**
 * `bootstrap_key`: the no-key start.
 *
 * `POST /api/keys/instant` mints a FREE key for an email address and mails a
 * claim link. The pair is used for the rest of this session and returned so
 * the operator can persist it in the MCP client config. It is issued once per
 * IP per day on this channel (the web keeps its own bucket), on purpose, and
 * without CAPTCHA to start with.
 */

import { invalidParams } from "../errors.js";
import { rec, str } from "../projections/fields.js";
import { fetchJson } from "./request.js";
import { fail, ok, type ToolDefinition } from "./types.js";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const bootstrapKey: ToolDefinition = {
  name: "bootstrap_key",
  title: "Mint a free API key",
  description:
    "No API key is configured. Mint a free isMalicious API key from an email address, use it for the rest of this session, and return it so it can be saved in the MCP client config (ISMALICIOUS_API_KEY / ISMALICIOUS_API_SECRET). One key per IP address per day; the address receives a link to claim the account. Ask the user for their email before calling.",
  inputSchema: {
    type: "object",
    properties: {
      email: {
        type: "string",
        format: "email",
        description: "The email address that will own the key.",
        maxLength: 254,
      },
    },
    required: ["email"],
    additionalProperties: false,
  },
  // Creates an account and a key, and emails the address: a write, not
  // destructive, and a second call is refused rather than repeated.
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
  // `/keys/instant` exists only in the Next.js app, never on the Rust host.
  surface: "web",
  requiresKey: false,
  bootstrapOnly: true,
  timeoutMs: 15_000,
  // No cacheTtlSec: minting is a side effect and must never be replayed.
  async call(args, ctx) {
    const email =
      typeof args.email === "string" ? args.email.trim().toLowerCase() : "";
    if (!email || email.length > 254 || !EMAIL.test(email)) {
      return fail(invalidParams("email must be a valid address."));
    }
    const fetched = await fetchJson(ctx, () =>
      ctx.http.post(
        "/keys/instant",
        { email },
        { signal: ctx.signal, timeoutMs: ctx.timeoutMs },
      ),
    );
    if (!fetched.ok) {
      const err = fetched.error;
      if (err.status === 429) {
        err.quota = {
          ...(err.quota ?? { kind: "issuance" }),
          kind: "issuance",
          limit: 1,
        };
        err.hint =
          "One key per IP address per day on this channel. Use the key already issued, or create one at https://ismalicious.com/app/account.";
      } else if (err.status === 409) {
        err.hint =
          "This email already has an account or a key. Read the key from https://ismalicious.com/app/account (log in or reset the password) and set ISMALICIOUS_API_KEY / ISMALICIOUS_API_SECRET.";
      } else if (err.status === 404) {
        err.hint =
          "Key issuance lives on the web API only. Set ISMALICIOUS_WEB_BASE to https://ismalicious.com/api (the default), not to the Rust host.";
      }
      return fail(err);
    }
    const body = rec(fetched.json) ?? {};
    const apiKey = str(body.apiKey);
    const apiSecret = str(body.apiSecret);
    if (!apiKey || !apiSecret) {
      return fail({
        error: "upstream_error",
        status: fetched.response.status,
        message: "The issuance endpoint answered without a key pair.",
      });
    }
    ctx.setApiKey({ apiKey, apiSecret });
    return ok({
      ok: true,
      message:
        "Key issued and active for this session. All tools are now available. Save the two variables below in the MCP client config so the key survives a restart; the claim link was emailed to the address.",
      apiKey,
      apiSecret,
      persist: {
        env: {
          ISMALICIOUS_API_KEY: apiKey,
          ISMALICIOUS_API_SECRET: apiSecret,
        },
      },
      quota: body.quota ?? null,
      account: str(body.account) ?? null,
      docs: str(body.docs) ?? "https://ismalicious.com/api-docs",
    });
  },
};
