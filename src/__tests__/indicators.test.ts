/** Tests for the local indicator typing shared by check_indicator and check_indicators. */
import { domainToASCII, domainToUnicode } from "node:url";
import { describe, expect, it } from "vitest";
import {
  classifyIndicator,
  isHostname,
  isPhoneNumber,
  MAX_INDICATOR_CHARS,
  normalizeCountry,
  parseEmail,
  phoneForm,
  refang,
} from "../indicators.js";

function kind(raw: string) {
  const c = classifyIndicator(raw);
  return c.ok
    ? c.kind
    : `refused:${c.unsupportedHash ?? c.looksLike ?? (c.value ? "other" : "empty")}`;
}

function value(raw: string) {
  return classifyIndicator(raw).value;
}

describe("refang", () => {
  it("undoes the usual defanging", () => {
    expect(refang("hxxps://evil[.]com/login")).toBe("https://evil.com/login");
    expect(refang("hXXp[:]//evil(.)com[/]x")).toBe("http://evil.com/x");
    expect(refang("evil{.}example[dot]com")).toBe("evil.example.com");
    expect(refang("evil [.] com")).toBe("evil.com");
    expect(refang("1[.]2[.]3[.]4")).toBe("1.2.3.4");
    expect(refang("user[@]evil[.]com")).toBe("user@evil.com");
    expect(refang("user [at] evil (dot) com")).toBe("user@evil.com");
    expect(refang("evil\\.com")).toBe("evil.com");
  });

  it("strips what surrounds an indicator in prose, and only that", () => {
    expect(refang("  <evil.com>  ")).toBe("evil.com");
    expect(refang('"evil.com",')).toBe("evil.com");
    expect(refang("'evil.com'.")).toBe("evil.com");
    expect(refang("(evil.com)")).toBe("evil.com");
    expect(refang("[2001:db8::1]")).toBe("2001:db8::1");
    expect(refang("evil.com.")).toBe("evil.com");
    expect(refang("​evil.com﻿")).toBe("evil.com");
    expect(refang("mailto:Bob@Example.com")).toBe("Bob@Example.com");
    expect(refang("tel:+33612345678")).toBe("+33612345678");
    // Balanced brackets belong to the value.
    expect(refang("(415) 555-2671")).toBe("(415) 555-2671");
    expect(refang("https://en.wikipedia.org/wiki/Foo_(bar)")).toBe(
      "https://en.wikipedia.org/wiki/Foo_(bar)",
    );
    expect(refang("see https://evil.com/x)")).toBe("see https://evil.com/x");
    // A plain scheme is left alone (classifyIndicator normalises the URL).
    expect(refang("HTTPS://Evil.com/")).toBe("HTTPS://Evil.com/");
  });

  it("lowercases the scheme it refangs: HXXPS made httpS, read as the host https", () => {
    expect(refang("HXXPS://EVIL[.]COM/login")).toBe("https://EVIL.COM/login");
    expect(refang("HXXP://evil[.]com")).toBe("http://evil.com");
    expect(refang("hXXpS://evil[.]com")).toBe("https://evil.com");
  });

  it("reads full-width forms as ASCII (NFKC) before anything else", () => {
    expect(refang("０９０−１２３４−５６７８")).toBe("090−1234−5678");
    expect(refang("user＠evil.com")).toBe("user@evil.com");
    expect(refang("ｅｖｉｌ［．］ｃｏｍ")).toBe("evil.com");
  });

  it("drops every contact scheme, with or without //, and a spreadsheet's marker", () => {
    const cases: Array<[string, string]> = [
      ["tel://+14155552671", "+14155552671"],
      ["sms:+14155552671", "+14155552671"],
      ["SMS:+14155552671?body=Your%20code", "+14155552671"],
      ["sms://+14155552671", "+14155552671"],
      ["callto:+14155552671", "+14155552671"],
      ["callto://+14155552671", "+14155552671"],
      ["sip:+14155552671@carrier.example;user=phone", "+14155552671"],
      ["sips:+14155552671", "+14155552671"],
      ["mailto://user@evil.com", "user@evil.com"],
      ["MAILTO://user@evil.com?subject=x", "user@evil.com"],
      ["=+14155552671", "+14155552671"],
      ['="+14155552671"', "+14155552671"],
      ["'+14155552671", "+14155552671"],
    ];
    for (const [typed, bare] of cases) expect(refang(typed), typed).toBe(bare);
    // A SIP address is not a number: left for the refusal.
    expect(refang("sip:alice@example.com")).toBe("sip:alice@example.com");
    // A quoted value keeps its pair of quotes to strip.
    expect(refang("'evil.com'.")).toBe("evil.com");
  });

  it("takes the address out of a display name or a mailto: link with fields", () => {
    expect(refang("Billing <billing@evil.com>")).toBe("billing@evil.com");
    expect(refang('"Doe, John" <John@Evil.com>')).toBe("John@Evil.com");
    expect(refang("Billing <billing[@]evil[.]com>,")).toBe("billing@evil.com");
    expect(refang("mailto:billing@evil.com?subject=Invoice&body=x")).toBe(
      "billing@evil.com",
    );
    expect(refang("mailto:billing%40evil.com")).toBe("billing@evil.com");
    expect(refang('"mailto:X@Y.com".')).toBe("X@Y.com");
    // A URL's angle brackets are not a display name.
    expect(refang("https://a.example/?q=<b@c.com>")).toBe(
      "https://a.example/?q=<b@c.com>",
    );
  });

  it("drops RFC 3966 parameters from a tel: link", () => {
    expect(refang("tel:+1-415-555-2671;ext=12")).toBe("+1-415-555-2671");
    expect(refang("<tel:+33612345678;phone-context=+33>")).toBe("+33612345678");
  });

  it("stays linear on hostile input (was quadratic: 20,000 brackets took 9 s)", () => {
    for (const hostile of [
      `a${")".repeat(20_000)}`,
      `${"(".repeat(10_000)}a${")".repeat(10_000)}`,
      `a${" ".repeat(20_000)}b[.]c`,
      "a[.]".repeat(5_000),
      "<a@".repeat(5_000),
      `<${"@".repeat(20_000)}`,
      `x <${"a@".repeat(10_000)}>`,
    ]) {
      const started = performance.now();
      refang(hostile);
      classifyIndicator(hostile);
      expect(performance.now() - started, hostile.slice(0, 12)).toBeLessThan(
        250,
      );
    }
  });

  it("types a hostile 100-item batch in well under a second (the display-name pattern was quadratic)", () => {
    // `<` then 2,047 `@`: 7 ms an item under `<([^<>\s]*@[^<>\s]*)>`, 2 s for
    // a batch typed three times per call.
    const hostile = [
      `<${"@".repeat(MAX_INDICATOR_CHARS - 1)}`,
      `a <${"@".repeat(MAX_INDICATOR_CHARS - 4)}`,
      `<${"a".repeat(1_000)}@${"b".repeat(MAX_INDICATOR_CHARS - 1_003)}`,
    ];
    for (const item of hostile) {
      const started = performance.now();
      for (let i = 0; i < 100; i += 1) classifyIndicator(item);
      expect(performance.now() - started, item.slice(0, 12)).toBeLessThan(150);
    }
  });

  it("refuses input past the length bound before any pattern runs, NFKC expansion included", () => {
    expect(
      classifyIndicator("a".repeat(MAX_INDICATOR_CHARS + 1)),
    ).toMatchObject({ ok: false, value: "" });
    // U+FDFA is one character and eighteen once NFKC-normalised.
    const expands = "\uFDFA".repeat(200);
    expect(expands.normalize("NFKC").length).toBeGreaterThan(
      MAX_INDICATOR_CHARS,
    );
    const c = classifyIndicator(expands);
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.message).toMatch(/longer than 2048/);
  });
});

describe("classifyIndicator", () => {
  it("types the four historical kinds as before", () => {
    expect(kind("8.8.8.8")).toBe("ip");
    expect(kind("2001:db8::1")).toBe("ip");
    expect(kind("https://a.b/c")).toBe("url");
    expect(kind("a.b/c")).toBe("url");
    expect(kind("a.b")).toBe("domain");
    expect(kind("d41d8cd98f00b204e9800998ecf8427e")).toBe("hash");
    expect(kind("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe("hash");
    expect(kind("e".repeat(64))).toBe("hash");
  });

  it("reads an IPv4-mapped IPv6 address, a bracketed one and a CIDR as IPs", () => {
    // The old /^[0-9a-f:]+$/ test made `::ffff:1.2.3.4` a domain.
    expect(kind("::ffff:1.2.3.4")).toBe("ip");
    expect(kind("[2001:db8::1]")).toBe("ip");
    expect(value("[2001:db8::1]")).toBe("2001:db8::1");
    expect(kind("10.0.0.0/8")).toBe("ip");
    expect(kind("2001:db8::/32")).toBe("ip");
    expect(kind("10.0.0.0/33")).toBe("url");
  });

  it("recognises defanged indicators and sends the refanged value", () => {
    expect(classifyIndicator("hxxps://evil[.]com/login")).toMatchObject({
      ok: true,
      kind: "url",
      value: "https://evil.com/login",
      input: "hxxps://evil[.]com/login",
    });
    expect(classifyIndicator("evil[.]com")).toMatchObject({
      kind: "domain",
      value: "evil.com",
    });
    expect(classifyIndicator("45[.]148[.]10[.]242")).toMatchObject({
      kind: "ip",
      value: "45.148.10.242",
    });
    expect(classifyIndicator("Billing[@]Paypa1-Secure[.]com")).toMatchObject({
      kind: "email",
      value: "billing@paypa1-secure.com",
    });
  });

  it("types email addresses by the API's rule, lowercased", () => {
    expect(classifyIndicator("Scam@Example.COM")).toMatchObject({
      kind: "email",
      value: "scam@example.com",
    });
    expect(kind("first.last+tag@mail.example.co.uk")).toBe("email");
    expect(kind("josé@exemple.fr")).toBe("email");
    // A URL with userinfo stays a URL.
    expect(kind("http://user@evil.example/")).toBe("url");
    expect(kind("Billing <Billing@Evil.com>")).toBe("email");
    expect(value("Billing <Billing@Evil.com>")).toBe("billing@evil.com");
    expect(value("mailto:billing@evil.com?subject=Invoice")).toBe(
      "billing@evil.com",
    );
  });

  it("refuses an @ the address rule rejects instead of sending it as a domain", () => {
    // Each went down the domain path, missed, and came back clean / allow.
    for (const notAnAddress of [
      '"john doe"@example.com',
      "user@[192.0.2.1]",
      "user@localhost",
      "user@1.2.3.4",
      "user@evil.com/",
      "user@evil.example/path",
      "a@@b.com",
      `${"a".repeat(65)}@example.com`,
      "user@-bad.example",
    ]) {
      const c = classifyIndicator(notAnAddress);
      expect(kind(notAnAddress), notAnAddress).toBe("refused:email");
      if (!c.ok) {
        expect(c.message).toContain("Send the bare address");
        expect(c.message).toContain("no request was charged");
      }
    }
  });

  it("types phone numbers by the API's rule", () => {
    for (const phone of [
      "+14155552671",
      "+1 (415) 555-2671",
      "(415) 555-2671",
      "415.555.2671",
      "4155552671",
      "06 12 34 56 78",
      "0033612345678",
      "+33 6 12 34 56 78",
      "tel:+44 20 7946 0958",
    ]) {
      expect(kind(phone), phone).toBe("phone");
    }
    for (const notPhone of [
      "123456", // six digits
      "+1234567890123456", // sixteen digits
      "1+4155552671", // `+` not first
      "192.168.100.200", // an IP
      "999.999.999.999", // a dotted quad
      "(415)) 555-2671", // two closing brackets
      "415-555-2671-", // ends on a separator
    ]) {
      expect(kind(notPhone), notPhone).not.toBe("phone");
    }
    expect(isPhoneNumber("+0612345678")).toBe(true);
    expect(isPhoneNumber("00 1 415 555 2671")).toBe(true);
    expect(isPhoneNumber("0012345")).toBe(false); // 5 digits once 00 is dropped
  });

  it("reads numbers as typeset, and sends the form the API's rule reads", () => {
    const cases: Array<[string, string]> = [
      ["+33\u00a06\u00a012\u00a034\u00a056\u00a078", "+33 6 12 34 56 78"], // NBSP
      ["+33\u202f6\u202f12\u202f34\u202f56\u202f78", "+33 6 12 34 56 78"], // narrow NBSP
      ["+1 415\u2011555\u20112671", "+1 415-555-2671"], // non-breaking hyphen
      ["+1 415\u2013555\u20132671", "+1 415-555-2671"], // en dash
      ["+1 415\u2212555\u22122671", "+1 415-555-2671"], // minus sign
      ["(+33) 6 12 34 56 78", "+33 6 12 34 56 78"],
      ["(+44) 20 7946 0958", "+44 20 7946 0958"],
      ["+44 (0)20 7946 0958", "+44 20 7946 0958"],
      ["tel:+1-415-555-2671;ext=12", "+1-415-555-2671"],
      ["+1 (415) 555-2671 x123", "+1 (415) 555-2671"],
      ["+1 415 555 2671 ext. 99", "+1 415 555 2671"],
      ["030/12345678", "030 12345678"],
    ];
    for (const [typed, sent] of cases) {
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: "phone",
        value: sent,
      });
    }
    // A CIDR or a path keeps its slash.
    expect(phoneForm("10.0.0.0/33")).toBe("10.0.0.0/33");
  });

  it("refuses digits and separators the phone rule rejects instead of sending them as a domain", () => {
    for (const notPhone of [
      "123456",
      "1234",
      "123/456",
      "999.999.999.999",
      "415-555-2671-",
    ]) {
      expect(kind(notPhone), notPhone).toBe("refused:phone");
    }
  });

  it("refuses what no hostname can hold instead of sending it as a domain", () => {
    for (const junk of [
      "evil.com (malware)",
      "evil .com",
      `${"(".repeat(40)}evil.com${")".repeat(40)}`,
    ]) {
      expect(kind(junk), junk).toBe("refused:other");
    }
    // Still domains, as before.
    expect(kind("evil.com:8080")).toBe("domain");
    expect(kind("_dmarc.example.com")).toBe("domain");
    // Not an ssdeep (the block size is not 3·2ⁿ), and not a hostname either.
    expect(kind("100:abcdef:ghij")).toBe("refused:other");
  });

  it("types a domain by an allowlist, and refuses every other shape without a request", () => {
    for (const domain of [
      "evil.com",
      "EVIL.example.CO.UK",
      "_dmarc.example.com",
      "1-800-flowers.com",
      "xn--mnchen-3ya.de",
      "münchen.de",
      "evil.com:8080",
      `${"a".repeat(63)}.com`,
      // A label may start or end with a hyphen: browsers, the url crate and
      // ingestion (`idna` with hyphens allowed) all take these hosts.
      "-evil.com",
      "evil-.com",
    ]) {
      expect(kind(domain), domain).toBe("domain");
    }
    // Full-width letters and dots are the ASCII domain once normalised, and
    // an ideographic full stop separates labels as IDNA reads it.
    expect(classifyIndicator("ｅｖｉｌ．ｃｏｍ")).toMatchObject({
      kind: "domain",
      value: "evil.com",
      input: "ｅｖｉｌ．ｃｏｍ",
    });
    expect(value("evil。example｡com")).toBe("evil.example.com");
    for (const notADomain of [
      "evil", // one label
      "localhost",
      "foo/bar", // a path after a host that is none
      "*.evil.com",
      "evil..com",
      "evil.123", // numeric last label
      "evil.com-", // no top-level domain starts or ends with a hyphen
      "evil.-com",
      "evil.com:99999",
      "evil.com:",
      "a:b:c.com",
      "ev!l.com",
      "evil.com%2fx",
      `${"a".repeat(64)}.com`,
      `${"a.".repeat(127)}com`, // 257 characters
      "callto:skypeuser",
    ]) {
      const c = classifyIndicator(notADomain);
      expect(c.ok, notADomain).toBe(false);
      if (!c.ok) expect(c.message).toContain("no request was charged");
    }
    expect(isHostname("evil.com")).toBe(true);
    expect(isHostname("evil")).toBe(false);
  });

  it("types a host whose label starts or ends with a hyphen as a host (was refused)", () => {
    // Tumblr, Blogspot and GitHub user names make such hosts; ingestion
    // stores them and the API looks them up. Refused, a listed phishing host
    // lost its block verdict.
    for (const host of [
      "secure-login-.blogspot.com",
      "foo-.tumblr.com",
      "-foo.example.com",
    ]) {
      expect(classifyIndicator(host), host).toMatchObject({
        ok: true,
        kind: "domain",
        value: host,
      });
      expect(isHostname(host), host).toBe(true);
    }
    expect(classifyIndicator("https://foo-.tumblr.com/post/1")).toMatchObject({
      ok: true,
      kind: "url",
      value: "https://foo-.tumblr.com/post/1",
    });
    expect(classifyIndicator("foo-.tumblr.com/x")).toMatchObject({
      ok: true,
      kind: "url",
      value: "foo-.tumblr.com/x",
    });
    expect(classifyIndicator("-foo.example.com:8443")).toMatchObject({
      ok: true,
      kind: "domain",
    });
  });

  it("drops the root dot after a URL's host, as the bare domain loses it (was refused)", () => {
    // Browsers open `evil.com.`, a known way past string blocklists, and
    // ingestion stores the name without the dot.
    const cases: Array<[string, string, string]> = [
      ["http://evil.com./login", "url", "http://evil.com/login"],
      ["https://evil.com.:8443/x", "url", "https://evil.com:8443/x"],
      ["HTTPS://EVIL.COM./X", "url", "https://evil.com/X"],
      ["https:/evil.com./x", "url", "https://evil.com/x"],
      ["https://münchen.de./x", "url", "https://münchen.de/x"],
      ["meow://EVIL.COM./x", "url", "meow://evil.com/x"],
      ["http://1.2.3.4./x", "url", "http://1.2.3.4/x"],
      ["www.evil.com./", "url", "www.evil.com/"],
      ["evil.com./path", "url", "evil.com/path"],
      ["evil.com.:8080/path", "url", "evil.com:8080/path"],
      ["evil.com.:8080", "domain", "evil.com:8080"],
      ["evil.com.", "domain", "evil.com"],
    ];
    for (const [typed, k, sent] of cases) {
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: k,
        value: sent,
        input: typed,
      });
    }
    // One root dot, not an empty label.
    for (const bad of ["http://evil.com../x", "evil.com..:8080/x"]) {
      expect(classifyIndicator(bad).ok, bad).toBe(false);
    }
  });

  it("reads contact values in full-width, URI and spreadsheet forms as what they are", () => {
    // Each was typed a domain or a URL, sent, billed and answered clean / allow.
    const cases: Array<[string, string, string]> = [
      ["０９０−１２３４−５６７８", "phone", "090-1234-5678"],
      ["user＠evil.com", "email", "user@evil.com"],
      ["sms:+14155552671", "phone", "+14155552671"],
      ["callto:+14155552671", "phone", "+14155552671"],
      ["tel://+14155552671", "phone", "+14155552671"],
      ["mailto://user@evil.com", "email", "user@evil.com"],
      ["=+14155552671", "phone", "+14155552671"],
      ['="+1 415 555 2671"', "phone", "+1 415 555 2671"],
      ["'+14155552671", "phone", "+14155552671"],
      ["sip:+14155552671@carrier.example;user=phone", "phone", "+14155552671"],
      ["＋３３　６　１２　３４　５６　７８", "phone", "+33 6 12 34 56 78"],
    ];
    for (const [typed, k, sent] of cases) {
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: k,
        value: sent,
        input: typed,
      });
    }
    // A SIP address is not a mailbox: refused, not sent as a domain.
    expect(kind("sip:alice@example.com")).toBe("refused:email");
  });

  it("refuses a number written with keypad letters instead of sending it as a domain", () => {
    for (const vanity of [
      "+1-800-FLOWERS",
      "1-800-FLOWERS",
      "+1 (800) CALL-NOW",
    ]) {
      const c = classifyIndicator(vanity);
      expect(kind(vanity), vanity).toBe("refused:phone");
      if (!c.ok) {
        expect(c.message).toContain("written with letters");
        expect(c.message).toContain("no request was charged");
      }
    }
    // A domain that spells a number is still a domain.
    expect(kind("1-800-flowers.com")).toBe("domain");
  });

  it("sends a URL as the API reads it: lowercased scheme and host, bracketed IPv6, no userinfo", () => {
    const cases: Array<[string, string]> = [
      ["HXXPS://EVIL[.]COM/login", "https://evil.com/login"],
      ["HTTPS://PHISH.EXAMPLE/login", "https://phish.example/login"],
      ["Https://Phish.Example/Login", "https://phish.example/Login"],
      ["https:/evil.com/login", "https://evil.com/login"],
      ["HTTP:/evil.com", "http://evil.com/"],
      ["http://[2001:db8::1]/x", "http://[2001:db8::1]/x"],
      ["http://[2001:DB8:0::1]:8080/x", "http://[2001:db8::1]:8080/x"],
      // An IDN host keeps the form it was typed in, lowercased.
      ["https://münchen.de/x", "https://münchen.de/x"],
      ["HTTPS://MÜNCHEN.DE/X", "https://münchen.de/X"],
      ["https://xn--mnchen-3ya.de/x", "https://xn--mnchen-3ya.de/x"],
      [
        "https://Sub.xn--mnchen-3ya.münchen.de:8443/x",
        "https://sub.xn--mnchen-3ya.münchen.de:8443/x",
      ],
      ["http://paypal.com@evil.example/", "http://evil.example/"],
      ["http://user:pass@evil.example/x", "http://evil.example/x"],
      ["http://evil.com%2F@good.example/", "http://good.example/"],
      ["meow://EVIL.COM/X", "meow://evil.com/X"],
      ["https://evil.com", "https://evil.com/"],
    ];
    for (const [typed, sent] of cases) {
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: "url",
        value: sent,
        input: typed,
      });
    }
    // Scheme-less URLs are sent as typed; the API takes their host.
    expect(value("evil.com/login")).toBe("evil.com/login");
    expect(kind("[2001:db8::1]/x")).toBe("url");
  });

  it("refuses a scheme URL whose host the API cannot look up", () => {
    for (const bad of [
      "https://evil",
      "https://localhost/x",
      "file:///etc/passwd",
      "https://a b.com/",
      "https://[not-an-ip]/x",
      "evil.com://x",
      "http://1.2.3.4.5.6/",
    ]) {
      const c = classifyIndicator(bad);
      expect(c.ok, bad).toBe(false);
      if (!c.ok) expect(c.message).toContain("no request was charged");
    }
  });

  it("reads a labelled hash by its digest", () => {
    const sha256 = "a".repeat(64);
    for (const labelled of [
      `sha256:${sha256}`,
      `SHA256: ${sha256}`,
      `SHA-256 = ${sha256}`,
      `sha256 ${sha256}`,
      `sha256:0x${sha256}`,
    ]) {
      expect(classifyIndicator(labelled), labelled).toMatchObject({
        ok: true,
        kind: "hash",
        value: sha256,
        hashType: "sha256",
        input: labelled,
      });
    }
    expect(classifyIndicator(`MD5:${"c".repeat(32)}`)).toMatchObject({
      kind: "hash",
      hashType: "md5",
    });
    expect(classifyIndicator(`imphash=${"d".repeat(32)}`)).toMatchObject({
      kind: "hash",
      hashType: "md5",
    });
    expect(kind(`SHA-512: ${"f".repeat(128)}`)).toBe("refused:sha512");
    // A label that does not match the digest is refused, not guessed.
    const mismatch = classifyIndicator(`sha256:${"a".repeat(40)}`);
    expect(mismatch).toMatchObject({ ok: false, looksLike: "hash" });
    if (!mismatch.ok)
      expect(mismatch.message).toMatch(/labelled SHA-256 but carries 40/);
    // A bare 0x + 40 hex is an Ethereum address, not a SHA-1.
    expect(kind(`0x${"e".repeat(40)}`)).not.toBe("hash");
  });

  it("refuses digests and fuzzy hashes the API does not index, without charging", () => {
    const cases: Array<[string, string, RegExp]> = [
      ["f".repeat(128), "sha512", /SHA-512/],
      ["c".repeat(96), "sha384", /SHA-384/],
      [`T1${"A".repeat(70)}`, "tlsh", /TLSH/],
      ["b".repeat(70), "tlsh", /TLSH/],
      [
        "3072:C3JkrZsKoLLBSmvZ7GNu8YJ5/eH9MSu:C3JkrZsKoLl0dnJ1eH9M",
        "ssdeep",
        /ssdeep/,
      ],
      ["a".repeat(33), "hex", /33-character hexadecimal/],
    ];
    for (const [raw, type, label] of cases) {
      const c = classifyIndicator(raw);
      expect(c.ok, raw).toBe(false);
      if (c.ok) continue;
      expect(c.unsupportedHash).toBe(type);
      expect(c.message).toMatch(label);
      expect(c.message).toContain("MD5, SHA-1 or SHA-256");
      expect(c.message).toContain("no request was charged");
    }
    // A block size that is not 3·2ⁿ is not an ssdeep.
    expect(kind("100:abcdef:ghij")).not.toBe("refused:ssdeep");
    expect(kind("f".repeat(128))).toBe("refused:sha512");
  });

  it("refuses an empty value", () => {
    expect(classifyIndicator(" [.] ")).toMatchObject({ ok: false });
    expect(classifyIndicator("''")).toMatchObject({ ok: false });
  });

  it("sends a bare host without the code points IDNA ignores (was sent as typed: a miss, clean / allow)", () => {
    // Each is validated on its IDNA form, `evil.com`, and was sent as typed;
    // the URL form of the same host was already normalised by the parser.
    for (const ignored of [
      "­", // soft hyphen
      "͏", // combining grapheme joiner
      "᠋",
      "᠏", // Mongolian free variation selectors
      "⁤", // invisible plus
      "︀",
      "️", // variation selectors
      "\u{1BCA0}",
      "\u{1BCA3}", // shorthand format controls
      "\u{E0100}",
      "\u{E01EF}", // variation selectors supplement
    ]) {
      const typed = `ev${ignored}il.com`;
      const label = `U+${ignored.codePointAt(0)?.toString(16)}`;
      expect(classifyIndicator(typed), label).toMatchObject({
        ok: true,
        kind: "domain",
        value: "evil.com",
        input: typed,
      });
      expect(value(`${typed}:8443`), label).toBe("evil.com:8443");
      expect(value(`${typed}/login`), label).toBe("evil.com/login");
      expect(value(`https://${typed}/login`), label).toBe(
        "https://evil.com/login",
      );
      expect(value(`user@${typed}`), label).toBe("user@evil.com");
    }
    // A non-ASCII label goes out in its IDNA form, as a browser opens it:
    // `ẞ` is what this Node's UTS46 makes of it (`ss` under ICU's transitional
    // mapping up to Node 22, `ß` under the non-transitional one Node 24 uses),
    // and a `u` + diaeresis a grapheme joiner kept apart (NFKC left them
    // apart; dropping the joiner decomposes the `ü`) is `ü`.
    expect(value("evẞl.com")).toBe(domainToUnicode(domainToASCII("evẞl.com")));
    expect(["evssl.com", "evßl.com"]).toContain(value("evẞl.com"));
    expect(value("mu͏̈nchen.de")).toBe("münchen.de");
    expect(value("MÜNCHEN.de")).toBe("münchen.de");
    // A host typed in ASCII, or already in its IDNA form, is sent as typed.
    expect(value("EVIL.example.CO.UK")).toBe("EVIL.example.CO.UK");
    expect(value("münchen.de")).toBe("münchen.de");
    expect(value("xn--mnchen-3ya.de")).toBe("xn--mnchen-3ya.de");
  });

  it("refuses a tel:, sms:, callto: or sip: link that holds no number instead of sending its rest as a domain", () => {
    // `callto:` carries Skype names; `john.doe` was sent as the domain
    // john.doe and answered clean / allow, and `callto://john.doe` as a URL
    // on that host.
    for (const [typed, looksLike] of [
      ["callto:john.doe", "phone"],
      ["callto://john.doe", "phone"],
      ["CALLTO://John.Doe?call", "phone"],
      ["sms:hello", "phone"],
      ["sms://evil.com", "phone"],
      ["tel://evil.com/x", "phone"],
      ["tel:evil.com", "phone"],
      ["<callto:john.doe>", "phone"],
      // A number's suffixes and wrappers are undone on the rest, never
      // enough to make a name or a host a number.
      ["tel:<evil.com>", "phone"],
      ['tel:"evil.com"', "phone"],
      ["tel:evil.com x123", "phone"],
      ["tel:1evil.com x123", "phone"],
      ["callto:john.doe (m)", "phone"],
      ["callto:john.doe cell", "phone"],
      ["tel:evil.com/", "phone"],
      ["sip://alice@example.com", "email"],
      ["sips:alice@example.com", "email"],
      ["mailto:john.doe", "email"],
      ["mailto://evil.com", "email"],
    ] as const) {
      const c = classifyIndicator(typed);
      expect(c, typed).toMatchObject({ ok: false, looksLike, input: typed });
      if (!c.ok) {
        expect(c.message, typed).toMatch(/: link /);
        expect(c.message, typed).toContain("no request was charged");
      }
    }
    // A link that holds a number or an address is still read as one.
    for (const [typed, k, sent] of [
      ["callto:+14155552671", "phone", "+14155552671"],
      ["callto://+1 415 555 2671", "phone", "+1 415 555 2671"],
      ["tel:+1-415-555-2671;ext=12", "phone", "+1-415-555-2671"],
      ["(tel:+14155552671),", "phone", "+14155552671"],
      ["tel:%2B14155552671", "phone", "+14155552671"],
      ["sms:+14155552671?body=hi", "phone", "+14155552671"],
      ["sms:+14155552671&body=hi", "phone", "+14155552671"],
      ["mailto:billing%40evil.com", "email", "billing@evil.com"],
    ] as const) {
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: k,
        value: sent,
      });
    }
  });

  it("reads a typeset number inside a tel:, sms: or callto: link as it reads the bare number", () => {
    // The number-shape test on a link's rest ran before the typesetting was
    // undone: each of these was refused as "not to a phone number" although
    // the bare number types as one, and so did the link before that test.
    for (const [typed, bare, sent] of [
      ["tel:030/1234567", "030/1234567", "030 1234567"],
      ["Tel: 030/1234567", "030/1234567", "030 1234567"],
      ["sms:030/1234567", "030/1234567", "030 1234567"],
      ["tel:+1–415–555–2671", "+1–415–555–2671", "+1-415-555-2671"],
      ["tel:+1‑415‑555‑2671", "+1‑415‑555‑2671", "+1-415-555-2671"],
      ["callto:+1–415–555–2671", "+1–415–555–2671", "+1-415-555-2671"],
      [
        "tel:０９０−１２３４−５６７８",
        "０９０−１２３４−５６７８",
        "090-1234-5678",
      ],
      ["tel:+81 90−1234−5678", "+81 90−1234−5678", "+81 90-1234-5678"],
      ["Tel: +1 415 555 2671 x123", "+1 415 555 2671 x123", "+1 415 555 2671"],
      [
        "tel:+1 415 555 2671 ext. 12",
        "+1 415 555 2671 ext. 12",
        "+1 415 555 2671",
      ],
      ["Tel: +1 415 555 2671 #204", "+1 415 555 2671 #204", "+1 415 555 2671"],
      [
        "tel:+33%C2%A06%C2%A012%C2%A034%C2%A056%C2%A078",
        "+33 6 12 34 56 78",
        "+33 6 12 34 56 78",
      ],
      ["callto://+14155552671/", "+14155552671/", "+14155552671"],
      ["tel://+1-415-555-2671/", "+1-415-555-2671/", "+1-415-555-2671"],
      ["tel:<+14155552671>", "<+14155552671>", "+14155552671"],
      ['tel:"+1 415 555 2671"', '"+1 415 555 2671"', "+1 415 555 2671"],
      ["Tel: 415-555-2671 (mob)", "415-555-2671 (mob)", "415-555-2671"],
      [
        "tel:+44 20 7946 0958 office",
        "+44 20 7946 0958 office",
        "+44 20 7946 0958",
      ],
    ] as const) {
      expect(classifyIndicator(bare), bare).toMatchObject({
        ok: true,
        kind: "phone",
        value: sent,
      });
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: "phone",
        value: sent,
        input: typed,
      });
    }
    // A keypad number in a link keeps the keypad advice, not the contact
    // refusal that says the link holds no number.
    for (const typed of ["tel:1-800-FLOWERS", "tel:+1 (800) CALL-NOW"]) {
      const c = classifyIndicator(typed);
      expect(kind(typed), typed).toBe("refused:phone");
      if (!c.ok) expect(c.message, typed).toContain("keypad");
    }
    // A defanged address in a percent-encoded mailto: is still an address.
    expect(classifyIndicator("mailto:user%5Bat%5Devil.com")).toMatchObject({
      ok: true,
      kind: "email",
      value: "user@evil.com",
    });
    expect(
      classifyIndicator("mailto:user%20%5B%20at%20%5D%20evil.com"),
    ).toMatchObject({ ok: true, kind: "email", value: "user@evil.com" });
  });

  it("types a number with a trailing label as the number, and keeps keypad advice for the keypad shape only", () => {
    // Refused as vanity numbers until now, with advice to dial their letters.
    for (const [typed, sent] of [
      ["+1 415 555 2671 cell", "+1 415 555 2671"],
      ["415-555-2671 (mob)", "415-555-2671"],
      ["+1 415 555 2671 office", "+1 415 555 2671"],
      ["+33 1 23 45 67 89 (fax)", "+33 1 23 45 67 89"],
      ["+44 20 7946 0958, mobile", "+44 20 7946 0958"],
      ["+1 415 555 2671 x12 (office)", "+1 415 555 2671"],
    ] as const) {
      expect(classifyIndicator(typed), typed).toMatchObject({
        ok: true,
        kind: "phone",
        value: sent,
        input: typed,
      });
    }
    // Alphanumeric IDs and labels: the generic refusal, never keypad advice.
    for (const id of [
      "0800 FREE CALL",
      "5G-ROUTER-01",
      "2FA-TOKEN-123",
      "3D-SECURE-2024",
      "5G-ROUTER",
      "1-800-356-FLOW cell", // a label only comes off a valid number
    ]) {
      const c = classifyIndicator(id);
      expect(c.ok, id).toBe(false);
      if (!c.ok) {
        expect(c.message, id).not.toMatch(/keypad|written with letters/);
        expect(c.message, id).toContain("no request was charged");
      }
    }
    // The keypad shape: letters only as the trailing run after digit groups.
    for (const vanity of [
      "+1-800-FLOWERS",
      "1-800-FLOWERS",
      "1-800-GOT-JUNK",
      "+1 (800) CALL-NOW",
      "1-800-356-FLOW",
    ]) {
      const c = classifyIndicator(vanity);
      expect(kind(vanity), vanity).toBe("refused:phone");
      if (!c.ok) expect(c.message, vanity).toContain("keypad");
    }
  });
});

describe("parseEmail", () => {
  it("mirrors the Rust recogniser's edges", () => {
    expect(parseEmail("A@B.CO")).toBe("a@b.co");
    expect(parseEmail("a@b.c")).toBeUndefined(); // one-letter TLD
    expect(parseEmail("a@b.123")).toBeUndefined(); // numeric TLD
    expect(parseEmail("a b@c.com")).toBeUndefined();
    expect(parseEmail("a@b..com")).toBeUndefined();
  });
});

describe("normalizeCountry", () => {
  it("uppercases a two-letter code and flags anything else", () => {
    expect(normalizeCountry("fr")).toBe("FR");
    expect(normalizeCountry(" GB ")).toBe("GB");
    expect(normalizeCountry(undefined)).toBeUndefined();
    expect(normalizeCountry("")).toBeUndefined();
    expect(normalizeCountry("FRA")).toBeNull();
    expect(normalizeCountry(33)).toBeNull();
  });
});
