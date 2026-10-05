/**
 * `scan_email`: one inbound message against the dataset, via `POST /mail/scan`
 * (docs/mail-scan.md). Added in 0.6.0.
 *
 * The request is the API's own: either the raw message (`eml`) or what the
 * caller already parsed (`message`), plus what the caller knows about their own
 * receiving system. The answer is projected (`projections/scan-email.ts`) to
 * stay under the result limit an agent can read.
 *
 * No `cacheTtlSec`: every scan is a meter event (`quota_scans:*`), like
 * `scan_before_use`, and a message is not assumed to be harmless the second
 * time it is seen.
 */

import { isRecord } from "../cache.js";
import { invalidParams } from "../errors.js";
import { projectScanEmail } from "../projections/scan-email.js";
import { fetchJson } from "./request.js";
import { fail, ok, READ_ONLY_TOOL, type ToolDefinition } from "./types.js";

/** The API refuses a larger message; refuse it here before sending it. */
export const MAX_EML_CHARS = 10 * 1024 * 1024;
const MAX_TRUSTED_HOPS = 10;

/** The fields of `message` the API reads. Anything else is dropped. */
const MESSAGE_FIELDS = [
  "headers",
  "from",
  "replyTo",
  "returnPath",
  "subject",
  "text",
  "html",
  "attachments",
] as const;

const STRING_FIELDS = [
  "from",
  "replyTo",
  "returnPath",
  "subject",
  "text",
  "html",
] as const;

function readMessage(
  value: unknown,
):
  | { ok: true; message: Record<string, unknown> }
  | { ok: false; error: string } {
  if (!isRecord(value))
    return { ok: false, error: "message must be an object." };
  const message: Record<string, unknown> = {};
  for (const field of MESSAGE_FIELDS) {
    if (value[field] !== undefined) message[field] = value[field];
  }
  for (const field of STRING_FIELDS) {
    if (message[field] !== undefined && typeof message[field] !== "string") {
      return { ok: false, error: `message.${field} must be a string.` };
    }
  }
  if (message.headers !== undefined) {
    const headers = message.headers;
    const valid =
      Array.isArray(headers) &&
      headers.every(
        (h) =>
          isRecord(h) &&
          typeof h.name === "string" &&
          typeof h.value === "string",
      );
    if (!valid) {
      return {
        ok: false,
        error: "message.headers must be a list of { name, value } strings.",
      };
    }
  }
  if (message.attachments !== undefined) {
    const attachments = message.attachments;
    if (!Array.isArray(attachments) || !attachments.every(isRecord)) {
      return {
        ok: false,
        error: "message.attachments must be a list of objects.",
      };
    }
  }
  if (Object.keys(message).length === 0) {
    return { ok: false, error: "message is empty." };
  }
  return { ok: true, message };
}

export const scanEmail: ToolDefinition = {
  name: "scan_email",
  title: "Scan an email for phishing and malware",
  description:
    "Scan ONE email message for phishing and malware before delivering, opening or acting on it. Send the raw message (eml, preferred) or the fields you already parsed (message: headers, text, html, attachment names, types and digests). Returns a verdict (malicious | suspicious | clean | inconclusive), a recommendedAction (quarantine | review | warn | deliver), a 0-100 riskScore, a headline you can relay as is, the strongest reasons, and what it could not check (coverage.skipped). It reads the sender and Reply-To, the connecting server, every link host and every attachment hash against threat intelligence, plus the tells of a phishing message: link text that names another site, a domain or a display name that imitates a well-known brand, a program named like a document, a display name that shows another address, credentials in a URL, an IDN homograph. From a raw message it also reads attachments for structure, never running them: the file type from its bytes, macros and remote templates in Office files, risky entries in archives, PDF actions, HTML that rebuilds a file in the browser; a message attached to it is read as a message of its own. It also flags text aimed at an AI reading the mail (prompt injection, including text hidden from a person). It never runs an attachment, fetches a link or calls a third party while you wait. malicious needs a listing in our data: the shape of a message alone asks for a review at most. clean is a positive claim and needs your own receiving system's DMARC pass: pass authservId (the id it writes in its Authentication-Results header) or trustAuthenticationResults, otherwise a message with nothing against it is inconclusive, which is not safe. deliver means no objection from this scan; never use it to release a message another engine quarantined. Costs one scan of the scan meter per message, whatever its size (not a request of the monthly quota).",
  inputSchema: {
    type: "object",
    properties: {
      eml: {
        type: "string",
        description:
          "The whole message as RFC 5322 text (a .eml file), headers first. Up to 10 MiB. Preferred when you have it: attachments are then read for structure. Use message for one that is too large, or that you only have parsed. Send exactly one of eml and message.",
        minLength: 1,
      },
      message: {
        type: "object",
        description:
          "A message you already parsed (Microsoft Graph, Gmail API…). Attachments carry digests, not bytes, so their structure is not read. Send exactly one of eml and message.",
        properties: {
          headers: {
            type: "array",
            description:
              "Every header, in message order, exactly as received (Graph: internetMessageHeaders). Needed for the Received chain (the server that delivered it) and Authentication-Results.",
            items: {
              type: "object",
              properties: {
                name: { type: "string" },
                value: { type: "string" },
              },
              required: ["name", "value"],
            },
          },
          from: {
            type: "string",
            description:
              "The sender, `Name <address>` or an address. Only needed when headers has no From.",
          },
          replyTo: { type: "string", description: "The Reply-To address." },
          returnPath: {
            type: "string",
            description: "The Return-Path address.",
          },
          subject: { type: "string" },
          text: { type: "string", description: "The plain-text body." },
          html: { type: "string", description: "The HTML body." },
          attachments: {
            type: "array",
            description:
              "Attachments as metadata and digests; contents are not needed. Any of sha256, sha1 and md5 is enough; the more digests, the more of the dataset can answer.",
            items: {
              type: "object",
              properties: {
                filename: { type: "string" },
                contentType: { type: "string" },
                size: { type: "integer", minimum: 0 },
                sha256: { type: "string" },
                sha1: { type: "string" },
                md5: { type: "string" },
                inline: {
                  type: "boolean",
                  description:
                    "True for a part shown inside the body. One with a picture's type and name is listed, not looked up; any other inline part is read like an attachment.",
                },
              },
            },
          },
        },
        additionalProperties: false,
      },
      authservId: {
        type: "string",
        description:
          "The authserv-id your receiving system writes in its Authentication-Results header (for example mx.google.com). Only a header carrying it is read as SPF/DKIM/DMARC evidence, because anyone can write one into a message.",
      },
      trustAuthenticationResults: {
        type: "boolean",
        description:
          "True when every Authentication-Results header in the message was added by your own infrastructure (Exchange Online writes it with no authserv-id). Needed, with or instead of authservId, for a message to be clean.",
      },
      trustedHops: {
        type: "integer",
        minimum: 1,
        maximum: MAX_TRUSTED_HOPS,
        description:
          "How many Received headers, counted from the top, your own servers wrote. The connecting server is the one the last of them recorded. Default 1.",
      },
      connectingIp: {
        type: "string",
        description:
          "The IP address that connected to your infrastructure, when you already have it. Overrides the Received chain.",
      },
    },
    additionalProperties: false,
  },
  annotations: READ_ONLY_TOOL,
  requiresKey: true,
  timeoutMs: 20_000,
  async call(args, ctx) {
    const hasEml = args.eml !== undefined && args.eml !== null;
    const hasMessage = args.message !== undefined && args.message !== null;
    if (hasEml === hasMessage) {
      return fail(invalidParams("send exactly one of eml and message."));
    }

    const body: Record<string, unknown> = {};
    if (hasEml) {
      if (typeof args.eml !== "string" || args.eml.trim().length === 0) {
        return fail(invalidParams("eml must be a non-empty string."));
      }
      if (args.eml.length > MAX_EML_CHARS) {
        return fail(
          invalidParams(
            "eml is larger than 10 MiB; send message with attachment digests instead.",
          ),
        );
      }
      body.eml = args.eml;
    } else {
      const read = readMessage(args.message);
      if (!read.ok) return fail(invalidParams(read.error));
      body.message = read.message;
    }

    const context: Record<string, unknown> = {};
    if (args.authservId !== undefined) {
      if (typeof args.authservId !== "string") {
        return fail(invalidParams("authservId must be a string."));
      }
      if (args.authservId.trim()) context.authservId = args.authservId.trim();
    }
    if (args.trustAuthenticationResults !== undefined) {
      if (typeof args.trustAuthenticationResults !== "boolean") {
        return fail(
          invalidParams("trustAuthenticationResults must be true or false."),
        );
      }
      context.trustAuthenticationResults = args.trustAuthenticationResults;
    }
    if (args.trustedHops !== undefined) {
      const hops = args.trustedHops;
      if (
        typeof hops !== "number" ||
        !Number.isInteger(hops) ||
        hops < 1 ||
        hops > MAX_TRUSTED_HOPS
      ) {
        return fail(
          invalidParams(
            `trustedHops must be an integer from 1 to ${MAX_TRUSTED_HOPS}.`,
          ),
        );
      }
      context.trustedHops = hops;
    }
    if (args.connectingIp !== undefined) {
      if (typeof args.connectingIp !== "string") {
        return fail(invalidParams("connectingIp must be a string."));
      }
      if (args.connectingIp.trim()) {
        context.connectingIp = args.connectingIp.trim();
      }
    }
    if (Object.keys(context).length > 0) body.context = context;

    const fetched = await fetchJson(ctx, () =>
      ctx.http.post("/mail/scan", body, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    return fetched.ok
      ? ok(projectScanEmail(fetched.json))
      : fail(fetched.error);
  },
};
