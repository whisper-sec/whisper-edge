// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
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
