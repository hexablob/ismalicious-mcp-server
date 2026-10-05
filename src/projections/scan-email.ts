/**
 * `scan_email`: the `POST /mail/scan` answer reduced to what an agent needs to
 * decide what to do with one message and to tell a person why, in under 4 KB.
 *
 * The verdict, the action, the score and the headline are the API's own. They
 * follow rules that live in one place (`docs/mail-scan.md`: only a listing in
 * the dataset can make a message malicious, `clean` needs a DMARC pass the
 * caller vouched for from an established sender, absence of evidence is `inconclusive`) and this
 * projection never recomputes them. What it adds is size discipline — the
 * strongest reasons, the links and attachments that carry a signal, what the
 * scan did not check — and defanged hosts, so the text can be pasted into a
 * ticket or a chat without making a link of it.
 */

import {
  arr,
  bool,
  clip,
  compact,
  isRec,
  num,
  rec,
  str,
  strs,
  type Rec,
} from "./fields.js";

export type EmailVerdict =
  "malicious" | "suspicious" | "clean" | "inconclusive";
export type EmailAction = "quarantine" | "review" | "warn" | "deliver";

const VERDICTS: readonly string[] = [
  "malicious",
  "suspicious",
  "clean",
  "inconclusive",
];
const ACTIONS: readonly string[] = ["quarantine", "review", "warn", "deliver"];

const MAX_REASONS = 6;
const MAX_LINKS = 6;
const MAX_ATTACHMENTS = 6;
const MAX_CONTACTS = 4;
const MAX_SKIPPED = 4;

export interface EmailReason {
  code: string;
  severity: string;
  summary: string;
  evidence?: string;
}

export interface ScanEmailProjection {
  verdict: EmailVerdict;
  recommendedAction: EmailAction;
  /** 0-100; 90 and above only for `malicious`. */
  riskScore: number;
  /** One sentence to relay as is. */
  headline: string;
  /** The strongest findings first. */
  reasons: EmailReason[];
  sender: {
    address?: string;
    domain?: string;
    displayName?: string;
    /** What the dataset says: malicious, suspicious or unknown. */
    verdict?: string;
    replyTo?: string[];
    freeProvider?: boolean;
    disposable?: boolean;
    /** Published mail posture of the sender's domain, A to F. */
    posture?: string;
    /** The domain publishes nothing that would make a receiver reject a message forged with it (no DMARC, or `p=none`). */
    spoofable?: boolean;
  };
  authentication: {
    /** `trusted` when it comes from a header the caller vouched for. */
    status: string;
    spf?: string;
    dkim?: string;
    dmarc?: string;
    /** How to let a DMARC pass count, when none could. */
    hint?: string;
  };
  connectingIp?: { address: string; verdict?: string };
  links: {
    total: number;
    /** Links the dataset lists or that carry a structural flag. */
    flagged: Array<{
      host: string;
      verdict: string;
      flags?: string[];
      shownDomain?: string;
      /** `attachment` or `attached_message` when the link is not in the message's own text. */
      origin?: string;
      /** The attachment or attached message it was found in. */
      from?: string;
    }>;
  };
  attachments: {
    total: number;
    /** Files neither the dataset nor NSRL knows: not a safety claim. */
    unknown: number;
    flagged: Array<{
      filename?: string;
      verdict: string;
      knownGood?: boolean;
      family?: string;
      /** What the bytes are, for a raw message: `pe`, `ooxml`, `pdf`, `zip`… */
      detectedType?: string;
      flags?: string[];
      /** The attached message it came out of. */
      from?: string;
    }>;
  };
  /** Addresses and numbers written in the body that the dataset flags. */
  contacts?: Array<{ value: string; kind: string; verdict: string }>;
  injection: {
    /** Prompt-injection heuristics over the body, 0.0-1.0. */
    score: number;
    families?: string[];
    /** The same over text a reader never sees. */
    hiddenScore?: number;
  };
  coverage: {
    /** What the scan could not or did not check, and why. */
    skipped: Array<{ check: string; reason: string }>;
    truncated?: boolean;
  };
  meta: { apiLatencyMs?: number };
}

/** A host written so it cannot be clicked or auto-linked when relayed. */
export function defangHost(host: string): string {
  return host.replace(/\./g, "[.]");
}

/** Evidence that is one sentence long is kept; a pasted blob is clipped. */
function reasonOf(item: unknown): EmailReason | undefined {
  const r = rec(item);
  const code = str(r?.code);
  const summary = str(r?.summary);
  if (!r || !code || !summary) return undefined;
  return compact({
    code,
    severity: str(r.severity) ?? "info",
    summary: clip(summary, 200) as string,
    evidence: clip(str(r.evidence), 160),
  }) as EmailReason;
}

const LINK_RANK: Record<string, number> = {
  malicious: 0,
  suspicious: 1,
};

function projectLinks(raw: unknown): ScanEmailProjection["links"] {
  const links = arr(raw).filter(isRec);
  const flagged = links
    .map((link) => {
      const flags = strs(link.flags, 8).filter((f) => f !== "punycode");
      const verdict = str(link.verdict) ?? "unknown";
      const host = str(link.host);
      if (!host) return undefined;
      const listed = verdict === "malicious" || verdict === "suspicious";
      if (!listed && flags.length === 0) return undefined;
      return {
        rank: LINK_RANK[verdict] ?? 2,
        value: compact({
          host: defangHost(clip(host, 100) as string),
          verdict,
          flags: flags.length ? flags : undefined,
          shownDomain: clip(str(link.shownDomain), 60),
          origin: str(link.origin),
          from: clip(str(link.originName), 60),
        }) as ScanEmailProjection["links"]["flagged"][number],
      };
    })
    .filter((x): x is NonNullable<typeof x> => x !== undefined)
    .sort((a, b) => a.rank - b.rank)
    .slice(0, MAX_LINKS)
    .map((x) => x.value);
  return { total: links.length, flagged };
}

function projectAttachments(raw: unknown): ScanEmailProjection["attachments"] {
  const files = arr(raw).filter(isRec);
  const real = files.filter((f) => bool(f.inline) !== true);
  // A picture, by its bytes, is not a file the scan lacks a verdict on: the API
  // vouches for it, so it is not counted as unknown.
  const unknown = real.filter(
    (f) =>
      (str(f.verdict) ?? "unknown") === "unknown" &&
      f.knownGood !== true &&
      str(f.detectedType) !== "image",
  ).length;
  const flagged = real
    .map((file) => {
      const flags = strs(file.flags, 8).filter((f) => f !== "archive");
      const verdict = str(file.verdict) ?? "unknown";
      const listed = verdict === "malicious" || verdict === "suspicious";
      if (!listed && flags.length === 0) return undefined;
      return {
        rank: LINK_RANK[verdict] ?? 2,
        value: compact({
          filename: clip(str(file.filename), 80),
          verdict,
          knownGood: file.knownGood === true ? true : undefined,
          family: clip(str(file.family), 40),
          detectedType: str(file.detectedType),
          flags: flags.length ? flags : undefined,
          from: clip(str(file.originName), 60),
        }) as ScanEmailProjection["attachments"]["flagged"][number],
      };
    })
    .filter((x): x is NonNullable<typeof x> => x !== undefined)
    .sort((a, b) => a.rank - b.rank)
    .slice(0, MAX_ATTACHMENTS)
    .map((x) => x.value);
  return { total: files.length, unknown, flagged };
}

function projectSender(raw: unknown): ScanEmailProjection["sender"] {
  const s = rec(raw);
  if (!s) return {};
  const replyTo = strs(s.replyTo, 2);
  const posture = str(rec(s.posture)?.grade);
  const spoofable = rec(s.posture)?.spoofable === true ? true : undefined;
  return compact({
    address: clip(str(s.address), 120),
    domain: clip(str(s.domain), 100),
    displayName: clip(str(s.displayName), 80),
    verdict: str(s.verdict),
    replyTo: replyTo.length ? replyTo : undefined,
    freeProvider: s.freeProvider === true ? true : undefined,
    disposable: s.disposable === true ? true : undefined,
    posture,
    spoofable,
  }) as ScanEmailProjection["sender"];
}

const UNVERIFIED_HINT =
  "No Authentication-Results header from a system you vouched for was read, so a message with nothing against it is inconclusive, never clean. Pass authservId (the id your receiving system writes in that header) or trustAuthenticationResults to let a DMARC pass count (it earns clean only for a sender domain the dataset knows as established).";

function projectAuthentication(
  raw: unknown,
): ScanEmailProjection["authentication"] {
  const a = rec(raw);
  const status = str(a?.status) ?? "unverified";
  return compact({
    status,
    spf: str(a?.spf),
    dkim: str(a?.dkim),
    dmarc: str(a?.dmarc),
    hint: status === "unverified" ? UNVERIFIED_HINT : undefined,
  }) as ScanEmailProjection["authentication"];
}

/**
 * The projection of a `/mail/scan` body. A body this server cannot read (no
 * recognised verdict) is reported as unscanned and sent to review rather than
 * delivered: a malformed answer must not read as an all-clear.
 */
export function projectScanEmail(raw: unknown): ScanEmailProjection {
  const body = rec(raw) ?? ({} as Rec);
  const verdictWord = str(body.verdict);
  const readable = verdictWord !== undefined && VERDICTS.includes(verdictWord);
  const verdict = (readable ? verdictWord : "inconclusive") as EmailVerdict;
  const actionWord = str(body.recommendedAction);
  // An action this server cannot read follows the verdict, on the cautious
  // side: a malicious message is quarantined, everything else is reviewed
  // rather than delivered.
  const recommendedAction = (
    readable && actionWord !== undefined && ACTIONS.includes(actionWord)
      ? actionWord
      : verdict === "malicious"
        ? "quarantine"
        : "review"
  ) as EmailAction;

  const reasons = arr(body.reasons)
    .map(reasonOf)
    .filter((r): r is EmailReason => r !== undefined)
    .slice(0, MAX_REASONS);

  const contacts = arr(body.contacts)
    .filter(isRec)
    .filter((c) => ["malicious", "suspicious"].includes(str(c.verdict) ?? ""))
    .slice(0, MAX_CONTACTS)
    .map(
      (c) =>
        ({
          value: clip(str(c.value), 80) ?? "",
          kind: str(c.kind) ?? "",
          verdict: str(c.verdict) ?? "",
        }) as { value: string; kind: string; verdict: string },
    );

  const ip = rec(body.connectingIp);
  const ipAddress = str(ip?.address);
  const injection = rec(body.injection);
  const families = strs(injection?.families, 4);
  const hidden = num(injection?.hiddenScore) ?? 0;
  const coverage = rec(body.coverage);
  const skipped = arr(coverage?.skipped)
    .filter(isRec)
    .map((s) => ({
      check: str(s.check) ?? "",
      reason: clip(str(s.reason), 200) ?? "",
    }))
    .filter((s) => s.check)
    .slice(0, MAX_SKIPPED);

  return {
    verdict,
    recommendedAction,
    riskScore: Math.round(num(body.riskScore) ?? 0),
    headline: readable
      ? (clip(str(body.headline), 300) ?? "")
      : "The scan answered in a shape this server cannot read: treat the message as unscanned.",
    reasons,
    sender: projectSender(body.sender),
    authentication: projectAuthentication(body.authentication),
    ...(ipAddress
      ? {
          connectingIp: compact({
            address: ipAddress,
            verdict: str(ip?.verdict),
          }) as { address: string; verdict?: string },
        }
      : {}),
    links: projectLinks(body.links),
    attachments: projectAttachments(body.attachments),
    ...(contacts.length ? { contacts } : {}),
    injection: compact({
      score: Math.round((num(injection?.score) ?? 0) * 100) / 100,
      families: families.length ? families : undefined,
      hiddenScore: hidden > 0 ? Math.round(hidden * 100) / 100 : undefined,
    }) as ScanEmailProjection["injection"],
    coverage: compact({
      skipped,
      truncated: coverage?.truncated === true ? true : undefined,
    }) as ScanEmailProjection["coverage"],
    meta: compact({
      apiLatencyMs: num(body.latencyMs),
    }) as ScanEmailProjection["meta"],
  };
}
