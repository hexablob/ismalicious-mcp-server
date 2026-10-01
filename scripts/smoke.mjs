#!/usr/bin/env node
/**
 * End-to-end smoke over stdio against a stub API.
 *
 * Spawns dist/index.js, drives initialize → tools/list → tools/call get_cve →
 * a tools/call check_indicator that is cancelled mid-flight, and checks that
 * the cancelled call never gets a response (the spec forbids one). Also
 * checks what only the real process shows: the tool name on the wire, the
 * unauthenticated pre-warm after initialize, a repeated call answered from
 * the result cache, an email address sent as one (refanged, lowercased, at
 * the `fast` level) and a SHA-512 refused before any request. Runs in CI
 * after `pnpm build`; needs nothing but Node.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "..", "dist", "index.js");
const emailUnknownFixture = join(
  here,
  "..",
  "src",
  "__tests__",
  "fixtures",
  "check-email-unknown.json",
);

function fail(msg) {
  console.error(`smoke: FAIL ${msg}`);
  process.exit(1);
}

const seen = [];
const stub = createServer((req, res) => {
  const url = new URL(req.url, "http://stub");
  seen.push({
    method: req.method,
    path: url.pathname,
    query: url.searchParams,
    headers: req.headers,
  });
  if (
    url.pathname === "/api/cve" &&
    url.searchParams.get("id") === "CVE-2021-44228"
  ) {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("X-Monthly-Usage", "3");
    res.setHeader("X-Monthly-Limit", "1000");
    res.end(
      JSON.stringify({
        id: "CVE-2021-44228",
        description: "Log4Shell",
        severity: "CRITICAL",
        cvssScore: 10,
        isKev: true,
        kev: { listed: true, dateAdded: "2021-12-10" },
        epssScore: 0.97,
      }),
    );
    return;
  }
  if (
    url.pathname === "/api/check" &&
    (url.searchParams.get("query") ?? "").includes("@")
  ) {
    // What the API answers for an address nobody lists: the real body,
    // held to the handler's output by apps/rust-api/tests/fast_check.rs.
    res.setHeader("Content-Type", "application/json");
    res.end(readFileSync(emailUnknownFixture));
    return;
  }
  if (url.pathname === "/api/check") {
    // Never answers on its own: the client is expected to cancel.
    const timer = setTimeout(() => {
      res.setHeader("Content-Type", "application/json");
      res.end("{}");
    }, 8000);
    req.on("close", () => clearTimeout(timer));
    return;
  }
  res.statusCode = 404;
  res.end('{"error":"not found"}');
});

await new Promise((r) => stub.listen(0, "127.0.0.1", r));
const port = stub.address().port;

const child = spawn(process.execPath, [entry], {
  env: {
    ...process.env,
    ISMALICIOUS_API_BASE: `http://127.0.0.1:${port}/api`,
    ISMALICIOUS_API_KEY: "smoke",
    ISMALICIOUS_API_SECRET: "smoke",
  },
  stdio: ["pipe", "pipe", "inherit"],
});

const responses = new Map();
let buffer = "";
child.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  let nl;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined) responses.set(msg.id, msg);
  }
});

function send(msg) {
  child.stdin.write(`${JSON.stringify(msg)}\n`);
}

function waitFor(id, ms = 5000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      if (responses.has(id)) return resolve(responses.get(id));
      if (Date.now() - started > ms)
        return reject(new Error(`no response for id ${id}`));
      setTimeout(tick, 20);
    };
    tick();
  });
}

const overall = setTimeout(() => fail("timed out"), 20000);

try {
  send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "smoke", version: "0" },
    },
  });
  const init = await waitFor(1);
  if (init.result?.protocolVersion !== "2025-06-18")
    fail(`protocolVersion echo: ${JSON.stringify(init)}`);
  if (
    !init.result?.capabilities?.tools ||
    !init.result?.capabilities?.resources
  )
    fail("capabilities");
  send({ jsonrpc: "2.0", method: "notifications/initialized" });

  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const list = await waitFor(2);
  const names = list.result.tools.map((t) => t.name);
  for (const n of [
    "scan_before_use",
    "check_url",
    "check_indicator",
    "get_cve",
    "recent_cves",
    "search_indicators",
    "check_indicators",
    "check_password_exposure",
  ]) {
    if (!names.includes(n)) fail(`tools/list missing ${n}: ${names.join(",")}`);
  }
  if (names.includes("bootstrap_key"))
    fail("bootstrap_key listed although a key is configured");

  send({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "get_cve", arguments: { id: "cve-2021-44228" } },
  });
  const cve = await waitFor(3);
  if (cve.result?.isError) fail(`get_cve isError: ${JSON.stringify(cve)}`);
  const cveBody = JSON.parse(cve.result.content[0].text);
  if (cveBody.kev?.listed !== true || cveBody.epss?.score !== 0.97)
    fail(`get_cve projection: ${cve.result.content[0].text}`);

  const cveCalls = () => seen.filter((r) => r.path === "/api/cve");
  if (cveCalls()[0]?.headers["x-ismalicious-tool"] !== "get_cve")
    fail(`X-Ismalicious-Tool: ${JSON.stringify(cveCalls()[0]?.headers)}`);
  const warm = seen.filter((r) => r.path === "/api/health");
  if (
    warm.length !== 1 ||
    warm[0].method !== "GET" ||
    warm[0].headers["x-api-key"] !== undefined
  )
    fail(`prewarm: ${JSON.stringify(warm)}`);

  send({
    jsonrpc: "2.0",
    id: 6,
    method: "tools/call",
    params: { name: "get_cve", arguments: { id: "CVE-2021-44228" } },
  });
  const again = JSON.parse((await waitFor(6)).result.content[0].text);
  if (cveCalls().length !== 1 || again._cache?.cached !== true)
    fail(`cache: ${cveCalls().length} calls, ${JSON.stringify(again._cache)}`);

  const checkCalls = () => seen.filter((r) => r.path === "/api/check");
  send({
    jsonrpc: "2.0",
    id: 7,
    method: "tools/call",
    params: {
      name: "check_indicator",
      arguments: { indicator: "Nobody[@]Example[.]org" },
    },
  });
  const email = await waitFor(7);
  const emailBody = JSON.parse(email.result.content[0].text);
  if (
    email.result.isError ||
    emailBody.type !== "email" ||
    emailBody.verdict !== "unknown" ||
    emailBody.recommendedAction !== "unverified" ||
    emailBody.email?.mx !== null
  )
    fail(`check_indicator email: ${email.result.content[0].text}`);
  const emailQuery = checkCalls()[0]?.query;
  if (
    emailQuery?.get("query") !== "nobody@example.org" ||
    emailQuery?.get("enrichment") !== "fast" ||
    checkCalls()[0]?.headers["x-ismalicious-tool"] !== "check_indicator"
  )
    fail(`check_indicator email request: ${emailQuery}`);

  send({
    jsonrpc: "2.0",
    id: 8,
    method: "tools/call",
    params: {
      name: "check_indicator",
      arguments: { indicator: "f".repeat(128) },
    },
  });
  const sha512 = await waitFor(8);
  if (
    !sha512.result.isError ||
    JSON.parse(sha512.result.content[0].text).error !== "invalid_params" ||
    checkCalls().length !== 1
  )
    fail(`check_indicator SHA-512: ${JSON.stringify(sha512)}`);

  send({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "check_indicator", arguments: { indicator: "1.2.3.4" } },
  });
  await new Promise((r) => setTimeout(r, 300));
  send({
    jsonrpc: "2.0",
    method: "notifications/cancelled",
    params: { requestId: 4, reason: "smoke" },
  });
  await new Promise((r) => setTimeout(r, 1200));
  if (responses.has(4))
    fail(
      `cancelled request 4 still got a response: ${JSON.stringify(responses.get(4))}`,
    );

  send({
    jsonrpc: "2.0",
    id: 5,
    method: "resources/read",
    params: { uri: "ismalicious://quota" },
  });
  const quota = await waitFor(5);
  const quotaBody = JSON.parse(quota.result.contents[0].text);
  if (quotaBody.requests?.monthly?.limit !== 1000)
    fail(`quota resource: ${quota.result.contents[0].text}`);

  console.log(
    "smoke: ok (initialize, prewarm, tools/list, get_cve, tool header, cache, email check, SHA-512 refusal, cancellation, quota resource)",
  );
} finally {
  clearTimeout(overall);
  child.stdin.end();
  stub.close();
  setTimeout(() => child.kill("SIGTERM"), 200);
}
