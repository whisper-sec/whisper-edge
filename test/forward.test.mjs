// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { forwardFetch, DEFAULT_FORWARD_URL, WhisperError } from "../dist/index.js";

const AUTH = "Basic dzpldF9TRUNSRVQ="; // Basic base64("w:et_SECRET") — a pre-built header, never a raw bearer

/** A fetch stub that replays a fixed sequence of Responses (one per call), capturing every call. */
function sequence(responses) {
 const calls = [];
 let i = 0;
 const fn = async (url, init) => {
 calls.push({ url: String(url), init });
 const r = responses[Math.min(i, responses.length - 1)];
 i++;
 return typeof r === "function" ? r() : r;
 };
 return { fn, calls };
}

function problemResponse(status, body = { error: "x", detail: "x", status }) {
 return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/problem+json" } });
}

// ── request shaping ──────────────────────────────────────────────────────────────────────────

test("forwardFetch POSTs to the default gateway with the right headers for a GET target", async () => {
 const { fn, calls } = sequence([new Response("2a04:2a01::abcd", { status: 200 })]);
 const f = forwardFetch(AUTH, { fetch: fn });
 const res = await f("https://v6.ident.me");
 assert.equal(res.status, 200);
 assert.equal(await res.text(), "2a04:2a01::abcd");
 assert.equal(calls.length, 1);
 assert.equal(calls[0].url, DEFAULT_FORWARD_URL);
 assert.equal(calls[0].init.method, "GET"); // mirrored on the outer request
 assert.equal(calls[0].init.headers.get("authorization"), AUTH);
 assert.equal(calls[0].init.headers.get("x-whisper-target"), "https://v6.ident.me/");
 assert.equal(calls[0].init.headers.get("x-whisper-method"), "GET");
});

test("forwardFetch mirrors a POST method and body, and sets Content-Length via the caller's body", async () => {
 const { fn, calls } = sequence([new Response("{}", { status: 200 })]);
 const f = forwardFetch(AUTH, { fetch: fn });
 await f("https://api.example.com/things", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' });
 assert.equal(calls[0].init.method, "POST");
 assert.equal(calls[0].init.headers.get("x-whisper-target"), "https://api.example.com/things");
 assert.equal(calls[0].init.headers.get("x-whisper-method"), "POST");
 assert.equal(calls[0].init.headers.get("content-type"), "application/json");
 assert.ok(calls[0].init.body instanceof Uint8Array);
 assert.equal(Buffer.from(calls[0].init.body).toString("utf8"), '{"a":1}');
});

test("forwardFetch honours a forwardUrl override (pre-prod / self-host)", async () => {
 const { fn, calls } = sequence([new Response("ok", { status: 200 })]);
 const f = forwardFetch(AUTH, { fetch: fn, forwardUrl: "https://staging.example.com/forward" });
 await f("https://v6.ident.me");
 assert.equal(calls[0].url, "https://staging.example.com/forward");
});

test("forwardFetch rejects a non-https target with a clear 400 (never silently downgrades)", async () => {
 const f = forwardFetch(AUTH, { fetch: async () => new Response("", { status: 200 }) });
 await assert.rejects(() => f("http://plain.example.com"), (e) => e instanceof WhisperError && e.status === 400);
});

// ── 407-retry ───────────────────────────────────────────────────────────────────────────

test("retries a 407 (token not yet propagated) and succeeds once the gateway catches up", async () => {
 const { fn, calls } = sequence([
 () => problemResponse(407),
 () => problemResponse(407),
 () => new Response("2a04:2a01::abcd", { status: 200, headers: { "x-whisper-egress-source": "2a04:2a01::abcd" } }),
 ]);
 const f = forwardFetch(AUTH, { fetch: fn, retryDelayMs: 5 });
 const res = await f("https://v6.ident.me");
 assert.equal(res.status, 200);
 assert.equal(res.headers.get("x-whisper-egress-source"), "2a04:2a01::abcd");
 assert.equal(calls.length, 3); // 2 x 407 then the 200 — every attempt hit the gateway again
});

test("a non-407 failure (e.g. 502) is NOT retried — returned immediately", async () => {
 const { fn, calls } = sequence([() => problemResponse(502)]);
 const f = forwardFetch(AUTH, { fetch: fn, retryDelayMs: 5 });
 const res = await f("https://v6.ident.me");
 assert.equal(res.status, 502);
 assert.equal(calls.length, 1);
});

test("exhausting the retry budget on a persistent 407 throws a clear, actionable WhisperError", async () => {
 const { fn, calls } = sequence([() => problemResponse(407)]); // every attempt still 407
 const f = forwardFetch(AUTH, { fetch: fn, retries: 3, retryDelayMs: 5 });
 await assert.rejects(
 () => f("https://v6.ident.me"),
 (e) => e instanceof WhisperError && e.status === 407 && /propagate/.test(e.message),
 );
 assert.equal(calls.length, 3); // used the whole (short, capped) retry budget, no more
});

test("the retry budget and delay are configurable", async () => {
 const { fn, calls } = sequence([() => problemResponse(407)]);
 const f = forwardFetch(AUTH, { fetch: fn, retries: 5, retryDelayMs: 1 });
 await assert.rejects(() => f("https://v6.ident.me"), WhisperError);
 assert.equal(calls.length, 5);
});

// ── real Node transport (no injected `fetch`) — regression coverage for the undici 407 behaviour (nodejs/undici#2896) ────────────────
//
// On Node, `fetch()` (undici) turns a direct, non-proxied HTTP 407 response into an opaque
// `TypeError: fetch failed` network error instead of a normal Response (nodejs/undici#2896),
// so forwardFetch bypasses it for its own request via node:http/node:https when the caller
// hasn't injected a custom `fetch`. These tests run a REAL local http server and deliberately
// do NOT pass `{ fetch }`, so they exercise that exact Node-native code path — the one the
// mocked-fetch tests above cannot reach (a mock fetch never runs into the undici behaviour).

/** Start a plain http server whose responder is swapped per-test; returns { url, close, calls }. */
function localServer() {
 let handler = (_req, res) => res.writeHead(200).end("ok");
 const calls = [];
 const server = createServer((req, res) => {
 const chunks = [];
 req.on("data", (c) => chunks.push(c));
 req.on("end", () => {
 calls.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
 handler(req, res);
 });
 });
 return new Promise((resolve) => {
 server.listen(0, "127.0.0.1", () => {
 const { port } = server.address();
 resolve({
 url: `http://127.0.0.1:${port}/forward`,
 calls,
 setHandler: (fn) => { handler = fn; },
 close: () => new Promise((r) => server.close(r)),
 });
 });
 });
}

test("Node path: a real 407 from the gateway is retried (not thrown as an opaque network error)", async () => {
 const srv = await localServer();
 try {
 let hits = 0;
 srv.setHandler((_req, res) => {
 hits++;
 if (hits < 3) return res.writeHead(407, { "content-type": "application/problem+json" }).end('{"error":"proxy_authentication_required","status":407}');
 res.writeHead(200, { "x-whisper-egress-source": "2a04:2a01::abcd" }).end("2a04:2a01::abcd");
 });
 const f = forwardFetch(AUTH, { forwardUrl: srv.url, retryDelayMs: 5 }); // no `fetch` override — real Node path
 const res = await f("https://v6.ident.me");
 assert.equal(res.status, 200);
 assert.equal(await res.text(), "2a04:2a01::abcd");
 assert.equal(hits, 3); // 2 real 407s were correctly observed and retried, not thrown
 } finally {
 await srv.close();
 }
});

test("Node path: a persistent real 407 exhausts the retry budget with the same clear WhisperError", async () => {
 const srv = await localServer();
 try {
 srv.setHandler((_req, res) => res.writeHead(407, { "content-type": "application/problem+json" }).end('{"error":"proxy_authentication_required","status":407}'));
 const f = forwardFetch(AUTH, { forwardUrl: srv.url, retries: 3, retryDelayMs: 5 });
 await assert.rejects(
 () => f("https://v6.ident.me"),
 (e) => e instanceof WhisperError && e.status === 407 && /propagate/.test(e.message),
 );
 assert.equal(srv.calls.length, 3);
 } finally {
 await srv.close();
 }
});

test("Node path: headers, method, and body reach the gateway intact over the real transport", async () => {
 const srv = await localServer();
 try {
 srv.setHandler((_req, res) => res.writeHead(200).end("ok"));
 const f = forwardFetch(AUTH, { forwardUrl: srv.url });
 await f("https://api.example.com/things", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' });
 assert.equal(srv.calls.length, 1);
 const call = srv.calls[0];
 assert.equal(call.method, "POST");
 assert.equal(call.headers["authorization"], AUTH);
 assert.equal(call.headers["x-whisper-target"], "https://api.example.com/things");
 assert.equal(call.headers["x-whisper-method"], "POST");
 assert.equal(call.headers["content-type"], "application/json");
 assert.equal(call.headers["content-length"], "7");
 assert.equal(call.body, '{"a":1}');
 } finally {
 await srv.close();
 }
});

test("Node path: a non-407 status (e.g. 502) passes straight through, unretried", async () => {
 const srv = await localServer();
 try {
 let hits = 0;
 srv.setHandler((_req, res) => { hits++; res.writeHead(502, { "content-type": "application/problem+json" }).end('{"error":"connect_failure","status":502}'); });
 const f = forwardFetch(AUTH, { forwardUrl: srv.url, retryDelayMs: 5 });
 const res = await f("https://v6.ident.me");
 assert.equal(res.status, 502);
 assert.equal(hits, 1);
 } finally {
 await srv.close();
 }
});

test("Node path: a genuine connection failure (nothing listening) is a clear WhisperError, not a hang", async () => {
 const f = forwardFetch(AUTH, { forwardUrl: "http://127.0.0.1:1", retries: 1 });
 await assert.rejects(() => f("https://v6.ident.me"), (e) => e instanceof WhisperError && e.status === 0);
});

test("Node path: an explicitly injected `fetch` is honoured verbatim, bypassing the native transport", async () => {
 const { fn, calls } = sequence([() => problemResponse(502)]);
 // A real local server would answer 200 here — proving the injected mock (not the server) won.
 const srv = await localServer();
 try {
 srv.setHandler((_req, res) => res.writeHead(200).end("should not be hit"));
 const f = forwardFetch(AUTH, { fetch: fn, forwardUrl: srv.url });
 const res = await f("https://v6.ident.me");
 assert.equal(res.status, 502); // came from the injected mock, not the local server
 assert.equal(calls.length, 1);
 assert.equal(srv.calls.length, 0);
 } finally {
 await srv.close();
 }
});
