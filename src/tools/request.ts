/**
 * One request, one outcome: either a JSON body worth projecting, or the
 * error envelope. Every tool funnels through here so the mapping from HTTP
 * to `isError` lives in exactly one place (`errors.ts`).
 */

import {
  envelopeFromException,
  envelopeFromResponse,
  type ErrorContext,
  type ToolErrorEnvelope,
} from "../errors.js";
import type { HttpResponse } from "../http.js";
import type { ToolContext } from "./types.js";

export type Fetched =
  | { ok: true; json: unknown; response: HttpResponse }
  | { ok: false; error: ToolErrorEnvelope };

export async function fetchJson(
  ctx: ToolContext,
  run: () => Promise<HttpResponse>,
  errorCtx: Partial<ErrorContext> = {},
): Promise<Fetched> {
  let response: HttpResponse;
  try {
    response = await run();
  } catch (e) {
    return { ok: false, error: envelopeFromException(e) };
  }
  const envelope = envelopeFromResponse(
    response,
    { keyConfigured: ctx.keyConfigured, ...errorCtx },
    ctx.now(),
  );
  if (envelope) return { ok: false, error: envelope };
  return { ok: true, json: response.json, response };
}
