/**
 * Local indicator typing, before any network call — shared by
 * `check_indicator` and `check_indicators`.
 *
 * Three jobs:
 *
 * - **Refang.** Threat reports and tickets defang what they quote
 *   (`hxxp://evil[.]com`, `user[@]evil[.]com`). Sent as is, `evil[.]com` was
 *   looked up literally and `hxxp://…` was read as the domain `hxxp`.
 * - **Refuse what cannot be looked up, for free.** The API indexes MD5,
 *   SHA-1 and SHA-256 only. A SHA-512, a TLSH or an ssdeep went down the
 *   domain path, came back "not listed" — read as clean / allow — and was
 *   charged a request. So did an address or a number in a form neither
 *   recogniser reads (`"john doe"@x.com`, `12345`). They are now refused
 *   here, before any request; the forms people paste (`Name <a@b.com>`,
 *   `+33 6 12…` typeset with no-break spaces, `sha256:<hex>`) are read as
 *   what they hold first.
 * - **Know the type the API should answer with**, so a server that predates
 *   email and phone support — which answers an address with a domain miss —
 *   is caught instead of relayed as a clean verdict.
 *
 * The email and phone rules mirror `parse_email` and `phone_digits` in
 * `apps/rust-api/src/domain/contact_indicators/` (the API contract of
 * 2026-09-30), so both sides type the same string the same way. The domain
 * kind is an allowlist, not what is left: a value that is not dotted
 * hostname labels is refused, never sent as a domain. Pure: no I/O, no
 * dependency beyond `node:net` and `node:url`.
 */

import { isIP, isIPv4, isIPv6 } from "node:net";
import { domainToASCII, domainToUnicode } from "node:url";

export type IndicatorKind =
  "ip" | "domain" | "url" | "hash" | "email" | "phone";
export type HashType = "md5" | "sha1" | "sha256";
export type UnsupportedHashType =
  "sha384" | "sha512" | "tlsh" | "ssdeep" | "hex";

/** Human wording for descriptions and refusals. */
export const SUPPORTED_HASHES = "MD5, SHA-1 or SHA-256";

export interface ClassifiedIndicator {
  ok: true;
  kind: IndicatorKind;
  /** What is sent to the API: refanged, and lowercased for an email address. */
  value: string;
  /** The input as received, trimmed. */
  input: string;
  hashType?: HashType;
}

export interface RefusedIndicator {
  ok: false;
  /** The input as received, trimmed. */
  input: string;
  /** The refanged value (empty when nothing was left). */
  value: string;
  /** Set when the input is a digest or fuzzy hash the API does not index. */
  unsupportedHash?: UnsupportedHashType;
  /**
   * The kind the value resembles without being one the API can look up (an
   * address the email rule rejects, a number the phone rule rejects).
   */
  looksLike?: "hash" | "email" | "phone";
  message: string;
}

export type Classification = ClassifiedIndicator | RefusedIndicator;

const WRAPPERS: ReadonlyArray<readonly [string, string]> = [
  ["<", ">"],
  ['"', '"'],
  ["'", "'"],
  ["`", "`"],
  ["(", ")"],
  ["[", "]"],
  ["{", "}"],
  ["“", "”"],
  ["‘", "’"],
];

/**
 * Zero-width characters a copy from a web page or a PDF carries along, and
 * every code point IDNA (UTS 46) ignores: the soft hyphen a hyphenating page
 * inserts, the combining grapheme joiner, the Mongolian free variation
 * selectors, the invisible plus, the variation selectors (U+FE00-FE0F and
 * their supplement) and the shorthand format controls. A host holding one was
 * validated on its IDNA form (`ev\u00ADil.com` is `evil.com`) and sent as typed,
 * so the API missed it and answered clean / allow; its URL form was already
 * normalised by the parser. Dropped everywhere, as the zero-width ones were.
 */
const INVISIBLE =
  /[\u00AD\u034F\u180B-\u180F\u200B-\u200D\u2060\u2064\uFE00-\uFE0F\uFEFF\u{1BCA0}-\u{1BCA3}\u{E0100}-\u{E01EF}]/gu;

/**
 * The ideographic and halfwidth ideographic full stops, which CJK text puts
 * between labels (`evil。com`) and NFKC leaves alone; IDNA reads them as `.`.
 */
const IDEOGRAPHIC_STOP = /[\u3002\uFF61]/g;

/**
 * Trailing characters a sentence adds and no indicator ends with. Quotes are
 * not here: they come in pairs, and `stripWrappers` takes the pair.
 */
const TRAILING = new Set([".", ",", ";", "!", "?"]);

const CLOSERS: Record<string, string> = { ")": "(", "]": "[", "}": "{" };

/**
 * Wrapper layers and refang passes applied at most. Real input carries two
 * or three (`"<hxxp://evil[.]com>".`); the bound keeps a hostile string of
 * thousands of brackets linear, since every pass rescans the value. What is
 * left past it is refused as unrecognisable, never sent as a domain.
 */
const MAX_PASSES = 12;

function count(s: string, c: string): number {
  let n = 0;
  for (const ch of s) if (ch === c) n += 1;
  return n;
}

/**
 * True when the opening bracket at 0 is closed by the last character, not
 * earlier: `(a) (b)` starts and ends with brackets without being wrapped.
 */
function closesAtEnd(s: string, open: string, close: string): boolean {
  if (open === close) return true;
  let depth = 0;
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === open) depth += 1;
    else if (s[i] === close) {
      depth -= 1;
      if (depth === 0) return i === s.length - 1;
    }
  }
  return false;
}

/** `<evil.com>`, `"evil.com"`, `[2001:db8::1]` → the inside; one layer. */
function stripWrapper(s: string): string {
  const pair = WRAPPERS.find(
    ([open, close]) =>
      s.length >= 2 &&
      s.startsWith(open) &&
      s.endsWith(close) &&
      closesAtEnd(s, open, close),
  );
  return pair ? s.slice(1, -1).trim() : s;
}

/**
 * A sentence's trailing `.`/`,`, or an unbalanced closing bracket. Counts
 * once and updates as it cuts: recounting per character made `a)))…` of
 * 20,000 brackets block the event loop for seconds.
 */
function stripTrailing(s: string): string {
  const opened: Record<string, number> = { "(": 0, "[": 0, "{": 0 };
  const closed: Record<string, number> = { ")": 0, "]": 0, "}": 0 };
  for (const ch of s) {
    if (ch in opened) opened[ch] += 1;
    else if (ch in closed) closed[ch] += 1;
  }
  let end = s.length;
  while (end > 0) {
    const last = s[end - 1];
    const opener = CLOSERS[last];
    if (TRAILING.has(last)) end -= 1;
    else if (opener && closed[last] > opened[opener]) {
      closed[last] -= 1;
      end -= 1;
    } else break;
  }
  return s.slice(0, end);
}

/**
 * Replace every match of `token` with `by`, eating the whitespace around
 * it (`evil [.] com` → `evil.com`). Split-and-trim rather than a leading
 * `\s*` in the pattern, which backtracks quadratically on a long run of
 * spaces.
 */
function replaceToken(s: string, token: RegExp, by: string): string {
  const parts = s.split(token);
  if (parts.length === 1) return s;
  return parts
    .map((p, i) => {
      const left = i > 0 ? p.trimStart() : p;
      return i < parts.length - 1 ? left.trimEnd() : left;
    })
    .join(by);
}

/** Only what a phone number or a dotted address is written with. */
const NUMERIC_SHAPE = /^[0-9 +\-.()]+$/;

/**
 * The contact URI schemes a copied link carries, with or without `//`:
 * `mailto:`, `tel:`, `sms:`, `callto:` (Skype) and `sip:` / `sips:`. Left on,
 * `sms:+1…` and `callto:+1…` went down the domain path as the host `sms` /
 * `callto`, and `tel://+1…` / `mailto://a@b` as URLs with that host: each a
 * miss, answered clean / allow.
 */
const CONTACT_SCHEME = /^(mailto|tel|sms|callto|sips?):(?:\/\/)?/i;

/**
 * A defanged `@`: `[@]`, `(at)`, `{ at }`. Not global, so `test` keeps no
 * state; `split` takes every match regardless.
 */
const DEFANGED_AT = /[[({]\s*(?:@|at)\s*[\])}]/i;

function decodeUri(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function isNumericShape(s: string): boolean {
  return NUMERIC_SHAPE.test(s) && /\d/.test(s);
}

/**
 * The address or the number a contact URI holds. They carry more than that:
 * `mailto:a@x.com?subject=Invoice` (header fields),
 * `tel:+1-415-555-2671;ext=12` (RFC 3966 parameters), `sms:+1…?body=…`
 * (RFC 5724). A `tel:`, `sms:`, `callto:` or `sip:` URI is read only when
 * what it dials is a number, typeset or not (`isDialledNumber`;
 * `sip:+14155552671@carrier.example;user=phone`), a `mailto:` only when it
 * holds an `@`, defanged or not. Anything else is left whole, scheme
 * included, for
 * `classifyIndicator` to refuse (`contactRefusal`): `callto:john.doe` is a
 * Skype name and `sip:alice@example.com` a SIP address, and until 0.5.0 the
 * rest of such a link was sent as the domain `john.doe` (or, after `//`, as
 * a URL on that host) and answered clean / allow.
 */
function stripContactScheme(s: string): string {
  const m = CONTACT_SCHEME.exec(s);
  if (!m) return s;
  const scheme = m[1].toLowerCase();
  const rest = s.slice(m[0].length);
  if (scheme === "mailto") {
    const address = decodeUri(rest.split("?")[0]);
    return address.includes("@") || DEFANGED_AT.test(address) ? address : s;
  }
  // `;` RFC 3966 parameters, `?` RFC 5724 fields, `&` the iOS `sms:` body.
  const dialled = decodeUri(rest.split(/[;?&]/)[0]);
  const number = stripWrapper(
    stripTrailing(
      (scheme === "sip" || scheme === "sips"
        ? dialled.split("@")[0]
        : dialled
      ).trim(),
    ).trim(),
  );
  return isDialledNumber(number) ? number : s;
}

/**
 * What a contact link dials is a number: digits and the separators a number
 * is written with; a number as typeset (`030/1234567`, typographic dashes,
 * encoded no-break spaces, a trailing extension, line label or `/`), which
 * `phoneForm` brings to a form the phone rule reads; or the keypad shape
 * (`tel:1-800-FLOWERS`), refused later with its own advice. This runs on the
 * link's rest before `phoneForm` and the later refang passes see it, so a
 * shape test alone refused `tel:030/1234567` and `tel:+1–415–555–2671` as
 * links to no number. A name or a host never passes: `isPhoneNumber` admits
 * no letter, and `phoneForm` strips only an extension or a known line label.
 */
function isDialledNumber(rest: string): boolean {
  if (isNumericShape(rest)) return true;
  const form = phoneForm(rest);
  return isPhoneNumber(form) || isVanityNumber(form);
}

/**
 * A contact link `stripContactScheme` left whole: it holds no number (or,
 * for `mailto:`, no address), so nothing in it is an indicator. `undefined`
 * when the value is not one.
 */
function contactRefusal(
  input: string,
  value: string,
): RefusedIndicator | undefined {
  const m = CONTACT_SCHEME.exec(value);
  if (!m) return undefined;
  const scheme = m[1].toLowerCase();
  const target = value.slice(m[0].length) || "nothing";
  if (scheme === "mailto") {
    return refused(
      input,
      value,
      `${input} is a mailto: link to ${target}, which is not an email address. Send the bare address, e.g. user@example.com.`,
      "email",
    );
  }
  return refused(
    input,
    value,
    `${input} is a ${scheme}: link to ${target}, not to a phone number the API can look up: a Skype or SIP user name, or a host, is none of the kinds it checks. Send the number the link dials (7 to 15 digits, + only first), e.g. +14155552671.`,
    target.includes("@") ? "email" : "phone",
  );
}

/**
 * A spreadsheet export's formula or text marker: `=+14155552671`,
 * `="+14155552671"` (the formula keeps the leading `+`), `'+14155552671`
 * (Excel's text prefix). No indicator starts with `=`; a leading `'` is only
 * dropped when no other `'` follows it, so a quoted `'evil.com'` still pairs
 * up.
 */
function stripSpreadsheetPrefix(s: string): string {
  if (s.startsWith("=")) return s.slice(1).trimStart();
  if (s.startsWith("'") && s.indexOf("'", 1) === -1)
    return s.slice(1).trimStart();
  return s;
}

/**
 * The address inside a display-name form, as a From header or a mail client
 * quotes it: `Billing <billing@evil.com>`, `"Doe, John" <john@evil.com>`.
 * The last `<…>` holding an `@` and no whitespace; a value with a scheme is a
 * URL and is left alone. One scan, no regular expression: the pattern
 * `<([^<>\s]*@[^<>\s]*)>` backtracked quadratically on `<@@@…`, 7 ms per
 * 2,000-character item and seconds for a hostile batch.
 */
function displayNameAddress(s: string): string {
  if (hasScheme(s) || !s.includes("<")) return s;
  let found: string | undefined;
  let open = -1;
  let at = false;
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (c === "<") {
      open = i;
      at = false;
    } else if (c === ">") {
      if (open >= 0 && at) found = s.slice(open + 1, i);
      open = -1;
    } else if (c === "@") at = true;
    else if (WHITESPACE.test(c)) open = -1;
  }
  return found ?? s;
}

const WHITESPACE = /\s/;

/** One pass of everything `refang` undoes. */
function refangPass(s: string): string {
  let out = stripSpreadsheetPrefix(stripWrapper(s.trim()));
  out = replaceToken(out, /[[({]\s*(?:\.|dot)\s*[\])}]/gi, ".");
  out = replaceToken(out, DEFANGED_AT, "@");
  out = out
    .replace(/\[:\]/g, ":")
    .replace(/\[(:?\/\/?)\]/g, "$1")
    .replace(/\\\./g, ".")
    // The `s` lowercased too: `HXXPS://` made `httpS://`, which the API read
    // as the host `https`.
    .replace(
      /^hxxp(s?)(?=:)/i,
      (_m, secure: string) => `http${secure.toLowerCase()}`,
    );
  out = displayNameAddress(stripContactScheme(out));
  return stripTrailing(out.trim()).trim();
}

/**
 * Longest input typed, in characters, before and after NFKC (which can
 * lengthen a string). The tools refuse longer input before typing; the bound
 * here keeps every pattern below linear whoever calls it.
 */
export const MAX_INDICATOR_CHARS = 2048;

/**
 * Undo the usual defanging: `hxxp(s)` → `http(s)`, `[.]` `(.)` `{.}` `[dot]`
 * → `.`, `[:]` → `:`, `[@]` `[at]` → `@`, `[/]` → `/`, `\.` → `.`; drop
 * zero-width characters and the code points IDNA ignores, surrounding
 * brackets or quotes, a spreadsheet's `=` or `'` marker, a `mailto:` prefix
 * before an address (and its `?subject=…`), a `tel:` (and its `;ext=…`),
 * `sms:`, `callto:` or `sip:` prefix before a number, with or without
 * `//`, a display name around an address, and trailing punctuation no
 * indicator ends with. Repeated until nothing changes: `'evil.com'.` needs
 * the `.` gone before the quotes pair up.
 *
 * NFKC first: CJK text writes numbers and addresses in full-width forms
 * (`０９０−１２３４−５６７８`, `user＠evil.com`), which no recogniser reads;
 * sent as is, each was looked up as a domain and answered clean / allow.
 */
export function refang(raw: string): string {
  return refangNormalized(raw.normalize("NFKC"));
}

function refangNormalized(normalized: string): string {
  let s = normalized
    .replace(INVISIBLE, "")
    .replace(IDEOGRAPHIC_STOP, ".")
    .trim();
  for (let pass = 0; pass < MAX_PASSES; pass += 1) {
    const next = refangPass(s);
    if (next === s) break;
    s = next;
  }
  return s;
}

const HEX = /^[0-9a-f]+$/i;
const DIGEST_LENGTH: Record<number, HashType> = {
  32: "md5",
  40: "sha1",
  64: "sha256",
};
const TLSH = /^T1[0-9a-f]{70}$/i;
/** `blocksize:chunk:chunk`, optionally `,"filename"`; the block size is 3·2ⁿ. */
const SSDEEP = /^(\d{1,10}):([A-Za-z0-9/+]{2,}):([A-Za-z0-9/+]+)(?:,".*")?$/;

function isSsdeepBlockSize(n: number): boolean {
  if (!Number.isSafeInteger(n) || n < 3 || n % 3 !== 0) return false;
  const q = n / 3;
  return (q & (q - 1)) === 0;
}

const UNSUPPORTED_LABEL: Record<UnsupportedHashType, (n: number) => string> = {
  sha384: () => "A SHA-384 digest",
  sha512: () => "A SHA-512 digest",
  tlsh: () => "A TLSH fuzzy hash",
  ssdeep: () => "An ssdeep fuzzy hash",
  hex: (n) => `A ${n}-character hexadecimal string`,
};

function unsupportedHash(value: string): UnsupportedHashType | undefined {
  if (TLSH.test(value)) return "tlsh";
  if (HEX.test(value) && value.length >= 32) {
    if (value.length === 96) return "sha384";
    if (value.length === 128) return "sha512";
    if (value.length === 70 || value.length === 72) return "tlsh";
    return "hex";
  }
  return undefined;
}

function isSsdeep(value: string): boolean {
  const m = SSDEEP.exec(value);
  return m !== null && isSsdeepBlockSize(Number(m[1]));
}

/** An address, or an address with a prefix length (`10.0.0.0/8`). */
function isIpOrCidr(value: string): boolean {
  if (isIP(value) !== 0) return true;
  const m = /^(.+)\/(\d{1,3})$/.exec(value);
  if (!m) return false;
  const prefix = Number(m[2]);
  if (isIPv4(m[1])) return prefix <= 32;
  if (isIPv6(m[1])) return prefix <= 128;
  return false;
}

function hasScheme(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
}

/** `https:/evil.com`: the one-slash typo, which no hostname starts with. */
const ONE_SLASH_HTTP = /^https?:\/(?!\/)/i;

/** The schemes whose host the WHATWG parser lowercases and punycodes. */
const SPECIAL_SCHEMES = new Set(["http:", "https:", "ftp:", "ws:", "wss:"]);

const HOST_LABEL = /^[a-z0-9_-]{1,63}$/;

/**
 * A hostname the API can look up: two or more labels of letters, digits,
 * hyphens and underscores (`_dmarc.example.com`), 253 characters at most,
 * and a last label that is neither all digits nor starts or ends with a
 * hyphen, as no top-level domain does (`evil.123`, `evil.com-` cut at a line
 * break). A label with non-ASCII letters counts when it has a punycode form
 * (`münchen.de`). An allowlist: `user＠evil.com`, `+1-800-FLOWERS`,
 * `sms:+1…` and every other shape that is not a hostname used to be sent as
 * a domain, looked up, missed, and relayed as clean / allow.
 *
 * Any other label may start or end with a hyphen
 * (`secure-login-.blogspot.com`, `foo-.tumblr.com`): user names on Blogspot,
 * Tumblr or GitHub make such hosts, browsers open them (WHATWG, CheckHyphens
 * off), and ingestion stores them (`normalize_domain`, `idna` with hyphens
 * allowed). Refusing them turned a listed phishing host into no verdict at
 * all.
 */
export function isHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const ascii = /^[\x21-\x7e]+$/.test(host)
    ? asciiLower(host)
    : domainToASCII(host);
  if (!ascii || ascii.length > 253) return false;
  const labels = ascii.split(".");
  // IDNA maps other separators to `.`; what is sent keeps them, so the
  // labels must be the ones typed.
  if (labels.length !== host.split(".").length) return false;
  const tld = labels[labels.length - 1];
  if (
    labels.length < 2 ||
    /^\d+$/.test(tld) ||
    tld.startsWith("-") ||
    tld.endsWith("-")
  )
    return false;
  return labels.every((l) => HOST_LABEL.test(l));
}

/**
 * `evil.com.` → `evil.com`: the root dot a fully qualified name may end with.
 * Browsers open it and it slips past a blocklist that compares strings;
 * ingestion stores the name without it (`normalize_domain` trims it), so the
 * API finds the listing only under the name without it. One dot: `evil.com..`
 * keeps an empty label and is no hostname.
 */
function withoutRootDot(host: string): string {
  return host.endsWith(".") ? host.slice(0, -1) : host;
}

function isPort(s: string): boolean {
  return /^\d{1,5}$/.test(s) && Number(s) <= 65_535;
}

/**
 * `host`, `host:port`, `[v6]` or `[v6]:port`, the host an IP or a hostname,
 * as it is sent: without the root dot after the host (`evil.com.:8443` →
 * `evil.com:8443`). `undefined` when it is none of these.
 */
function authorityForm(authority: string): string | undefined {
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0 || !isIPv6(authority.slice(1, close))) return undefined;
    const rest = authority.slice(close + 1);
    return rest === "" || (rest[0] === ":" && isPort(rest.slice(1)))
      ? authority
      : undefined;
  }
  const colon = authority.lastIndexOf(":");
  const port =
    colon > 0 && isPort(authority.slice(colon + 1))
      ? authority.slice(colon)
      : "";
  const host = withoutRootDot(
    authority.slice(0, authority.length - port.length),
  );
  if (isIP(host) !== 0) return host + port;
  return isHostname(host) ? canonicalHost(host) + port : undefined;
}

const ASCII_ONLY = /^[\x00-\x7f]*$/;

/**
 * A validated hostname as it is sent: each label typed with non-ASCII
 * characters in its IDNA form, given back in Unicode (`evẞl` is `evssl`, a
 * decomposed `ü` the composed one, `MÜNCHEN` is `münchen`), as the URL path
 * does in `hostAsTyped`; a label typed in ASCII as typed. `isHostname`
 * validates the IDNA form, so sending anything else is sending a host that
 * was not the one checked.
 */
function canonicalHost(host: string): string {
  if (ASCII_ONLY.test(host)) return host;
  const ascii = domainToASCII(host).split(".");
  const typed = host.split(".");
  if (ascii.length !== typed.length) return host;
  return typed
    .map((label, i) =>
      ASCII_ONLY.test(label) ? label : domainToUnicode(ascii[i]) || ascii[i],
    )
    .join(".");
}

/**
 * A URL with a scheme, as the API reads it: `new URL(value).href`, which
 * lowercases the scheme and the host (`HTTPS://PHISH.EXAMPLE/login`,
 * mixed-case schemes being a known evasion), brackets an IPv6 host and reads
 * `https:/host` as `https://host`; an IDN host keeps the form it was typed in
 * (`hostAsTyped`). The
 * userinfo is dropped: in `http://paypal.com@evil.example/` the host is
 * `evil.example`, and the API, which takes the host from the text, looked up
 * `paypal.com@evil.example`. So is the root dot after the host
 * (`http://evil.com./login`), as `evil.com.` alone loses it. `undefined` when
 * the value has no scheme, `null` when it has one but no host the API can
 * look up (`https://evil`, `file:///x`, a string the parser refuses).
 */
function normalizeSchemeUrl(value: string): string | null | undefined {
  if (!hasScheme(value) && !ONE_SLASH_HTTP.test(value)) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const host = withoutRootDot(url.hostname);
  const bracketed = host.startsWith("[") && host.endsWith("]");
  if (
    !(bracketed
      ? isIPv6(host.slice(1, -1))
      : isIP(host) !== 0 || isHostname(host))
  ) {
    return null;
  }
  if (host !== url.hostname) url.hostname = host;
  url.username = "";
  url.password = "";
  // An opaque host (`meow://EVIL.COM/`) keeps its case in the parser.
  if (!SPECIAL_SCHEMES.has(url.protocol)) {
    url.hostname = asciiLower(host);
    return url.href;
  }
  const shown = hostAsTyped(host, value);
  if (shown === host) return url.href;
  const port = url.port ? `:${url.port}` : "";
  return `${url.protocol}//${shown}${port}${url.pathname}${url.search}${url.hash}`;
}

/**
 * The parsed host with each label typed in non-ASCII letters given back in
 * them (`münchen.de`, not `xn--mnchen-3ya.de`), lowercased, as the API
 * received it before: which form a listing is stored under is the API's
 * business, and this normalisation is about case, scheme and userinfo only.
 * A label typed in punycode stays punycode.
 */
function hostAsTyped(host: string, typed: string): string {
  if (!host.includes("xn--")) return host;
  const authority = typed
    .replace(/^[a-z][a-z0-9+.-]*:\/*/i, "")
    .split(/[/?#\\]/)[0];
  const typedLabels = withoutRootDot(
    authority.slice(authority.lastIndexOf("@") + 1).replace(/:\d*$/, ""),
  ).split(".");
  const labels = host.split(".");
  if (typedLabels.length !== labels.length) return host;
  return labels
    .map((label, i) =>
      /^[\x00-\x7f]*$/.test(typedLabels[i])
        ? label
        : domainToUnicode(label) || label,
    )
    .join(".");
}

/**
 * A URL without a scheme (`evil.com/login`): a `/` after a host that is an
 * IP or a hostname, with an optional port. Not when that part holds an `@` —
 * userinfo without a scheme is an address with a stray slash
 * (`user@evil.com/`), which the API would have answered about the host — nor
 * when it is not a host at all (`123/456`, `foo/bar`). Given back as typed,
 * less the root dot after the host (`evil.com./login` → `evil.com/login`):
 * the API takes the host from the text. `undefined` when it is not one.
 */
function schemelessUrl(value: string): string | undefined {
  const slash = value.indexOf("/");
  if (slash <= 0) return undefined;
  const authority = value.slice(0, slash);
  if (authority.includes("@")) return undefined;
  const sent = authorityForm(authority);
  return sent === undefined ? undefined : sent + value.slice(slash);
}

/**
 * The keypad shape: digit groups (one may be bracketed), a separator, then
 * letters only, in words joined by hyphens — `+1-800-FLOWERS`,
 * `1-800-GOT-JUNK`, `+1 (800) CALL-NOW`, `1-800-356-FLOW`. Separators are
 * required between digit groups, so the pattern cannot split one run of
 * digits two ways and stays linear.
 */
const KEYPAD_NUMBER =
  /^\+?(?:\(\d{1,5}\)|\d+)(?:[ -]*\(\d{1,5}\)|[ -]+\d+)*[ -]+[A-Za-z]+(?:-[A-Za-z]+)*$/;

/**
 * A number written with its keypad letters, which the API cannot read (it
 * reads digits only; sent, it was looked up as a domain and answered clean /
 * allow): the keypad shape, three digits or more before the letters, three
 * letters or more, 7 to 15 digits once each letter is dialled. Until 0.5.0
 * any digits-then-letters string was one, so `5G-ROUTER-01`,
 * `2FA-TOKEN-123` or `+1 415 555 2671 cell` came with advice to dial their
 * letters — a billed lookup of a number that does not exist. They now get the
 * generic refusal, and a labelled number is read as the number (`phoneForm`).
 */
function isVanityNumber(value: string): boolean {
  if (value.length > 32 || !KEYPAD_NUMBER.test(value)) return false;
  const digits = value.replace(/\D/g, "").length;
  const letters = value.replace(/[^A-Za-z]/g, "").length;
  return (
    digits >= 3 &&
    letters >= 3 &&
    digits + letters >= 7 &&
    digits + letters <= 15
  );
}

/** ASCII-only lowercasing, byte for byte what Rust's `to_ascii_lowercase` does. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function bytes(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

/** RFC 5322 atext plus `.`, and any non-ASCII letter or digit (SMTPUTF8). */
const LOCAL_PART = /^[A-Za-z0-9!#$%&'*+=?^_`{|}~.\-\p{L}\p{N}]+$/u;
const DOMAIN_LABEL = /^[\p{L}\p{N}-]+$/u;

function isMailDomain(domain: string): boolean {
  if (bytes(domain) > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  return (
    labels.every(
      (l) =>
        l.length > 0 &&
        bytes(l) <= 63 &&
        !l.startsWith("-") &&
        !l.endsWith("-") &&
        DOMAIN_LABEL.test(l),
    ) &&
    [...tld].length >= 2 &&
    !/^\d+$/.test(tld)
  );
}

/**
 * The lowercased address, or `undefined`. Exactly one `@`, no `://`, no `/`,
 * no whitespace — so `http://user@host/` stays a URL — a 1-64 octet local
 * part and a domain of two or more hostname labels whose last is not numeric.
 */
export function parseEmail(value: string): string | undefined {
  if (
    bytes(value) > 254 ||
    value.includes("://") ||
    value.includes("/") ||
    /\s/.test(value)
  ) {
    return undefined;
  }
  const address = asciiLower(value);
  const at = address.indexOf("@");
  if (at <= 0 || address.indexOf("@", at + 1) !== -1) return undefined;
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  if (bytes(local) > 64 || !LOCAL_PART.test(local) || !isMailDomain(domain))
    return undefined;
  return address;
}

const DOTTED_QUAD = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Phone-shaped: not an IP or a dotted quad, no letters, only digits, spaces
 * and `+ - . ( )`, `+` only first, a digit last, 7-15 digits once a `+` or
 * `00` international prefix is removed.
 */
export function isPhoneNumber(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > 32 ||
    isIP(value) !== 0 ||
    DOTTED_QUAD.test(value) ||
    !/^[0-9 +\-.()]+$/.test(value)
  ) {
    return false;
  }
  const first = value[0];
  const last = value[value.length - 1];
  if (
    value.slice(1).includes("+") ||
    !(first === "+" || first === "(" || /\d/.test(first)) ||
    !/\d/.test(last) ||
    count(value, "(") > 1 ||
    count(value, ")") > 1
  ) {
    return false;
  }
  let digits = value.replace(/\D/g, "");
  if (first !== "+" && digits.startsWith("00")) digits = digits.slice(2);
  return digits.length >= 7 && digits.length <= 15;
}

const UNICODE_SPACE = /\p{Zs}/gu;
/** Every dash a word processor or a web page substitutes, and the minus sign. */
const UNICODE_DASH = /[\p{Pd}\u2212]/gu;
const PHONE_EXTENSION = /(?:[x#]|ext\.?|extn\.?|extension)\s*\d{1,6}$/i;

const LINE_LABELS =
  "cell|cellular|mobile|mob|office|work|home|fax|tel|phone|main|direct|landline|desk|pager|whatsapp|portable|bureau|fixe|domicile";
/**
 * What a contact sheet writes after a number to say which line it is:
 * `cell`, `office`, `fax`, `(mob)`, `(m)`, after a space or a bracket. A word
 * glued to the digits (`2671cell`) is not one.
 */
const LINE_LABEL = new RegExp(
  `(?:\\(\\s*(?:${LINE_LABELS}|[a-z])\\.?\\s*\\)|\\b(?:${LINE_LABELS})\\.?)$`,
  "i",
);
/** Longest value a line label is looked for on: a number and its label. */
const MAX_LABELLED_NUMBER = 64;

/**
 * The value without a trailing line label and the separators before it
 * (`+1 415 555 2671, mobile` → `+1 415 555 2671`), or `undefined` when it
 * carries none.
 */
function withoutLineLabel(s: string): string | undefined {
  if (s.length > MAX_LABELLED_NUMBER) return undefined;
  const m = LINE_LABEL.exec(s);
  if (!m || m.index === 0) return undefined;
  if (!m[0].startsWith("(") && !/[\s,;:/-]/.test(s[m.index - 1]))
    return undefined;
  let end = m.index;
  while (end > 0 && /[\s,;:/-]/.test(s[end - 1])) end -= 1;
  return s.slice(0, end);
}

/**
 * The form of a number as typed by a person or a typesetter, brought to what
 * the API's recogniser reads — so the number, not a domain, is looked up:
 *
 * - no-break and thin spaces (French typography: `+33 6 12…`) → space;
 * - non-breaking hyphens, en dashes, the minus sign → `-`;
 * - `030/1234567` (German) → space, unless the value also has a `.`, which
 *   makes it a CIDR or a path rather than a number;
 * - `(+33) 6 12…` → `+33 6 12…`;
 * - `+44 (0)20 …` → `+44 20 …`: the national trunk prefix, not dialled from
 *   abroad, which read as a digit made another subscriber's number;
 * - a trailing extension (`x123`, `ext. 123`) is dropped: listings carry the
 *   line, not the extension;
 * - a trailing line label (`cell`, `office`, `fax`, `(mob)`) is dropped when
 *   what is left is a number the rule reads: `+1 415 555 2671 cell` was
 *   refused as a number written with letters.
 */
export function phoneForm(value: string): string {
  const s = value.replace(UNICODE_SPACE, " ").replace(UNICODE_DASH, "-");
  const form = numberForm(s);
  if (isPhoneNumber(form)) return form;
  const unlabelled = withoutLineLabel(s);
  if (unlabelled === undefined) return form;
  const bare = numberForm(unlabelled);
  return isPhoneNumber(bare) ? bare : form;
}

function numberForm(typed: string): string {
  let s = typed;
  if (s.includes("/") && !s.includes(".")) s = s.replace(/\//g, " ");
  const ext = PHONE_EXTENSION.exec(s);
  if (ext && /\d/.test(s.slice(0, ext.index))) s = s.slice(0, ext.index);
  s = s
    .trim()
    .replace(/^\(\s*\+\s*(\d{1,3})\s*\)\s*/, "+$1 ")
    .replace(/^(\+\s*\d{1,3})[\s-]*\(0\)\s*/, "$1 ");
  return s.replace(/ {2,}/g, " ").trim();
}

/**
 * `sha256:<hex>` (an OCI digest), `SHA256: <hex>`, `MD5=<hex>`: how reports
 * label a hash. The label defeated the digest match and the value was
 * looked up as the domain `sha256`. `0x` is dropped only after a label: a
 * bare `0x` + 40 hex digits is an Ethereum address, not a SHA-1.
 */
const LABELLED_HASH =
  /^(md5|imphash|sha-?1|sha-?256|sha-?384|sha-?512)(?:\s*[:=]\s*|\s+)(?:0x)?([0-9a-f]+)$/i;
const LABEL_LENGTH: Record<string, number> = {
  md5: 32,
  imphash: 32,
  sha1: 40,
  sha256: 64,
  sha384: 96,
  sha512: 128,
};
const LABEL_NAME: Record<string, string> = {
  md5: "MD5",
  imphash: "imphash",
  sha1: "SHA-1",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};

const NOTHING_CHARGED = "Nothing was sent and no request was charged.";

function refused(
  input: string,
  value: string,
  message: string,
  looksLike?: RefusedIndicator["looksLike"],
): RefusedIndicator {
  return {
    ok: false,
    input,
    value,
    ...(looksLike ? { looksLike } : {}),
    message: `${message} ${NOTHING_CHARGED}`,
  };
}

/** A digest, a hash the API cannot index, or `undefined` when not hex-shaped. */
function typeHash(input: string, value: string): Classification | undefined {
  const digest = HEX.test(value) ? DIGEST_LENGTH[value.length] : undefined;
  if (digest) return { ok: true, kind: "hash", value, input, hashType: digest };
  const unsupported =
    unsupportedHash(value) ??
    (!isIpOrCidr(value) && isSsdeep(value) ? "ssdeep" : undefined);
  if (!unsupported) return undefined;
  return {
    ok: false,
    input,
    value,
    looksLike: "hash",
    unsupportedHash: unsupported,
    message: `${UNSUPPORTED_LABEL[unsupported](value.length)} cannot be looked up: only ${SUPPORTED_HASHES} file hashes are indexed. Send the file's SHA-256 (or MD5 / SHA-1) instead. ${NOTHING_CHARGED}`,
  };
}

/**
 * Refang, then type. Order matters and follows the API's: a 32/40/64-hex
 * digest first (a labelled one too), then what the API cannot index
 * (refused), an IP, a URL with a scheme (so a URL with userinfo stays one), a
 * phone number (before a scheme-less URL: `030/1234567` is a number), a
 * scheme-less URL, an email address, and a domain.
 *
 * The domain is an allowlist (`isHostname`, with an optional `:port`), and a
 * URL must have such a host or an IP. Everything else is refused, not sent
 * as a domain: an `@` the address rule rejects (`Name <a@b>` is unwrapped
 * first, `"john doe"@x.com` and `user@localhost` are not), digits and
 * separators the phone rule rejects, a number written with letters,
 * whitespace, brackets or a scheme left over. The API would look each one up
 * as a domain that never exists and answer "not listed" — a clean / allow
 * verdict on an address or a number.
 */
export function classifyIndicator(raw: string): Classification {
  const input = raw.trim();
  const tooLong = `indicator is longer than ${MAX_INDICATOR_CHARS} characters.`;
  if (input.length > MAX_INDICATOR_CHARS) return refused(input, "", tooLong);
  const normalized = input.normalize("NFKC");
  if (normalized.length > MAX_INDICATOR_CHARS)
    return refused(input, "", tooLong);
  const value = refangNormalized(normalized);
  if (!value) return refused(input, value, "indicator is empty.");
  const contact = contactRefusal(input, value);
  if (contact) return contact;

  const labelled = LABELLED_HASH.exec(value);
  if (labelled) {
    const label = labelled[1].toLowerCase().replace("-", "");
    const hex = labelled[2];
    if (hex.length !== LABEL_LENGTH[label]) {
      return refused(
        input,
        hex,
        `${input} is labelled ${LABEL_NAME[label]} but carries ${hex.length} hexadecimal characters, not ${LABEL_LENGTH[label]}; send the digest alone.`,
        "hash",
      );
    }
    return typeHash(input, hex) as Classification;
  }
  const hash = typeHash(input, value);
  if (hash) return hash;

  if (isIpOrCidr(value)) return { ok: true, kind: "ip", value, input };
  const url = normalizeSchemeUrl(value);
  if (url) return { ok: true, kind: "url", value: url, input };
  if (url === null) {
    return refused(
      input,
      value,
      `${value} is not a URL the API can look up: its host must be a dotted domain name or an IP address. Send the URL as it would be opened, e.g. https://example.com/path.`,
    );
  }
  const phone = phoneForm(value);
  if (isPhoneNumber(phone))
    return { ok: true, kind: "phone", value: phone, input };
  const schemeless = schemelessUrl(value);
  if (schemeless) return { ok: true, kind: "url", value: schemeless, input };
  const email = parseEmail(value);
  if (email) return { ok: true, kind: "email", value: email, input };

  if (value.includes("@")) {
    return refused(
      input,
      value,
      `${value} is not an email address the API can look up (one @, a dotted domain, no spaces, quotes or brackets). Send the bare address, e.g. user@example.com.`,
      "email",
    );
  }
  if (isVanityNumber(phone)) {
    return refused(
      input,
      value,
      `${value} reads as a phone number written with letters, which the API cannot look up. If it is one, send its digits (each letter is its keypad digit: ABC 2, DEF 3, GHI 4, JKL 5, MNO 6, PQRS 7, TUV 8, WXYZ 9), e.g. +18003569377.`,
      "phone",
    );
  }
  if (NUMERIC_SHAPE.test(phone) && /\d/.test(phone)) {
    return refused(
      input,
      value,
      `${value} is neither an IP address nor a phone number the API can look up (7 to 15 digits, + only first). Send an IP as a dotted quad, or a number in E.164 form such as +33612345678, or in national form with country.`,
      "phone",
    );
  }
  const domain = value.startsWith("[") ? undefined : authorityForm(value);
  if (domain) return { ok: true, kind: "domain", value: domain, input };
  return refused(
    input,
    value,
    `${value} is not an IP, domain, URL, file hash, email address or phone number the API can look up: a domain is dotted labels of letters, digits and hyphens (with an optional :port). Send the bare indicator.`,
  );
}

/**
 * `country` for a national-format phone number: an ISO 3166-1 alpha-2 code,
 * uppercased. `undefined` when absent, `null` when present but malformed.
 */
export function normalizeCountry(raw: unknown): string | undefined | null {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "string") return null;
  const code = raw.trim();
  if (code === "") return undefined;
  return /^[A-Za-z]{2}$/.test(code) ? code.toUpperCase() : null;
}
