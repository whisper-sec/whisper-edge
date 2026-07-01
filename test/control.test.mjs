// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { control, WhisperControl, WhisperError } from "../dist/index.js";

function stub(status, body, capture) {
  return async (url, init) => {
    if (capture) capture.push({ url: String(url), init, sentBody: init.body });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
}

test("constructing without a key throws a clear 401", () => {
  assert.throws(() => control("  "), (e) => e instanceof WhisperError && e.status === 401);
});

test("control() and new WhisperControl() are equivalent", () => {
  assert.ok(control("whisper_live_EXAMPLE") instanceof WhisperControl);
});

test("list POSTs the right Cypher with X-API-Key (key never in the URL)", async () => {
  const calls = [];
  const c = control("whisper_live_EXAMPLE", { fetch: stub(200, { ok: true, result: { columns: ["agent"], rows: [["scout"]] } }, calls) });
  const res = await c.list();
  assert.deepEqual(res.records, [{ agent: "scout" }]);
  const { url, init, sentBody } = calls[0];
  assert.equal(url, "https://graph.whisper.security/api/query");
  assert.equal(init.method, "POST");
  assert.equal(init.headers["x-api-key"], "whisper_live_EXAMPLE");
  assert.equal(JSON.parse(sentBody).query, "CALL whisper.agents({op:'list', args:{kind:'agents'}})");
  assert.ok(!url.includes("whisper_live_EXAMPLE")); // key is never in the URL
});

test("register builds op:register with label + contact_email", async () => {
  const calls = [];
  const c = control("k", { fetch: stub(200, { ok: true, result: { columns: ["agent", "api_key"], rows: [["scout", "whisper_live_EXAMPLE_new"]] } }, calls) });
  const res = await c.register({ name: "scout", email: "ops@acme.co" });
  assert.equal(res.records[0].api_key, "whisper_live_EXAMPLE_new");
  assert.equal(JSON.parse(calls[0].sentBody).query, "CALL whisper.agents({op:'register', args:{contact_email:'ops@acme.co',label:'scout'}})");
});

test("agent() selects by address when the selector has a colon, else by id", async () => {
  const calls = [];
  const c = control("k", { fetch: stub(200, { ok: true, result: { columns: [], rows: [] } }, calls) });
  await c.agent("2a04:2a01::1");
  await c.agent("scout-1");
  assert.match(JSON.parse(calls[0].sentBody).query, /args:\{address:'2a04:2a01::1'\}/);
  assert.match(JSON.parse(calls[1].sentBody).query, /args:\{agent:'scout-1'\}/);
});

test("a control failure surfaces the server's detail as a WhisperError", async () => {
  const c = control("k", { fetch: stub(403, { ok: false, error: { detail: "scope admin:dns required", status: 403 } }) });
  await assert.rejects(() => c.revoke("scout"), (e) => e instanceof WhisperError && e.status === 403 && e.detail === "scope admin:dns required");
});

test("policy with no args reads back (empty args map)", async () => {
  const calls = [];
  const c = control("k", { fetch: stub(200, { ok: true, result: { columns: ["key", "value"], rows: [["default", "allow"]] } }, calls) });
  const res = await c.policy();
  assert.deepEqual(res.records, [{ key: "default", value: "allow" }]);
  assert.equal(JSON.parse(calls[0].sentBody).query, "CALL whisper.agents({op:'policy', args:{}})");
});
