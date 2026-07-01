// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { verify, verifyDetails, resolve, rdap, WhisperError } from "../dist/index.js";

/** A tiny fetch stub: records the URL/init and returns a canned Response. */
function stub(status, body, capture) {
  return async (url, init) => {
    if (capture) capture.push({ url: String(url), init });
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return new Response(status === 204 ? null : text, { status, headers: { "content-type": "application/json" } });
  };
}

test("verify true when the server says is_whisper_agent", async () => {
  const calls = [];
  const ok = await verify("2a04:2a01::1", { fetch: stub(200, { is_whisper_agent: true, dane_ok: true }, calls) });
  assert.equal(ok, true);
  // Keyless: the address goes in ?ip=, and NO auth header is sent.
  assert.match(calls[0].url, /\/verify-identity\?ip=2a04:2a01::1$/);
  assert.equal(calls[0].init.headers["x-api-key"], undefined);
  assert.equal(calls[0].init.headers.authorization, undefined);
});

test("verifyDetails returns null on 404 (not an agent)", async () => {
  const v = await verifyDetails("2001:db8::99", { fetch: stub(404, { is_whisper_agent: false }) });
  assert.equal(v, null);
});

test("resolve folds the verdict into a friendly view", async () => {
  const r = await resolve("2a04:2a01::1", {
    fetch: stub(200, { is_whisper_agent: true, fqdn: "scout.agents.whisper.online.", operator: "acme", dane_ok: true, jws_ok: true, verified_at: 123 }),
  });
  assert.equal(r.isWhisperAgent, true);
  assert.equal(r.fqdn, "scout.agents.whisper.online"); // trailing dot trimmed
  assert.equal(r.operator, "acme");
  assert.equal(r.daneOk, true);
  assert.match(r.rdapUrl, /\/ip\/2a04:2a01::1$/);
});

test("rdap returns null on 404, object on 200", async () => {
  assert.equal(await rdap("2001:db8::1", { fetch: stub(404, "") }), null);
  const obj = await rdap("2a04:2a01::1", { fetch: stub(200, { handle: "2a04:2a01::1", name: "scout" }) });
  assert.equal(obj.name, "scout");
});

test("empty address is a clear 400 WhisperError, not an opaque failure", async () => {
  await assert.rejects(() => verifyDetails("  ", { fetch: stub(200, {}) }), (e) => e instanceof WhisperError && e.status === 400);
});

test("timeout surfaces a WhisperError (no hang)", async () => {
  const slow = () => new Promise(() => {}); // never resolves
  await assert.rejects(() => verify("2a04:2a01::1", { fetch: slow, timeoutMs: 20 }), (e) => e instanceof WhisperError);
});
