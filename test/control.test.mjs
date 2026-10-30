// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { control, WhisperControl, WhisperError, NotFoundError } from "../dist/index.js";

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
  assert.equal(url, "https://graph.whisper.online/api/query");
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

// Nothing revoked: the plane says it two ways, and both must reject with NotFoundError
// carrying the server's own message. Never a bare 404, never a success.
const notFoundErr = { code: "NOT_FOUND", message: "nothing was revoked: no agent of yours matches 'ag_gone'", retryable: false };
const rowCols = ["op", "ok", "status", "result", "error", "retry_after", "elapsed_ms"];
const isNotFoundErr = (e) =>
  e instanceof NotFoundError && e instanceof WhisperError && e.code === "NOT_FOUND" && e.status === 404 && e.retryable === false;

for (const [name, status, body] of [
  ["front door, object row", 200, { columns: rowCols, rows: [{ op: "revoke", ok: false, status: 404, result: null, error: notFoundErr, retry_after: null, elapsed_ms: 3 }] }],
  ["front door, positional row", 200, { columns: rowCols, rows: [["revoke", false, 404, null, notFoundErr, null, 3]] }],
  ["flat envelope on HTTP 404", 404, { ok: false, status: 404, result: null, error: notFoundErr }],
]) {
  test(`revoke: NOT_FOUND (${name}) rejects with NotFoundError and the server's message`, async () => {
    const c = control("k", { fetch: stub(status, body) });
    await assert.rejects(() => c.revoke("ag_gone"), (e) => isNotFoundErr(e) && e.message === notFoundErr.message);
  });
}

for (const [name, cols, row] of [
  ["status", ["agent", "status"], ["ag_gone", "not_found"]],
  ["under item", ["item"], [{ agent: "ag_gone", status: "NOT_FOUND" }]],
]) {
  test(`revoke: an older plane's ok row with not_found (${name}) rejects with NotFoundError`, async () => {
    const c = control("k", { fetch: stub(200, { ok: true, status: 200, result: { columns: cols, rows: [row] } }) });
    await assert.rejects(() => c.revoke("ag_gone"), (e) => isNotFoundErr(e) && /nothing was revoked.*ag_gone/.test(e.message));
  });
}

test("revoke: a bare 404 with no NOT_FOUND code is a plain WhisperError", async () => {
  const c = control("k", { fetch: stub(404, { title: "Not Found", status: 404, detail: "no such route" }) });
  await assert.rejects(() => c.revoke("ag_gone"), (e) => e instanceof WhisperError && !(e instanceof NotFoundError) && e.detail === "no such route");
});

test("revoke: the NOT_FOUND code on a 403 is not NotFoundError", async () => {
  const c = control("k", { fetch: stub(403, { ok: false, status: 403, error: { code: "NOT_FOUND", message: "odd", retryable: false } }) });
  await assert.rejects(() => c.revoke("ag_gone"), (e) => e instanceof WhisperError && !(e instanceof NotFoundError) && e.status === 403);
});

test("a failure inside the front-door row rejects with the server's code and message", async () => {
  const c = control("k", { fetch: stub(200, { columns: rowCols, rows: [{ op: "policy", ok: false, status: 403, result: null, error: { code: "FORBIDDEN", message: "this key lacks dns:policy:write", retryable: false } }] }) });
  await assert.rejects(
    () => c.policy({ default: "deny" }),
    (e) => e instanceof WhisperError && e.code === "FORBIDDEN" && e.status === 403 && e.retryable === false && e.message === "this key lacks dns:policy:write",
  );
});

test("revoke: a real revoke in the front-door row resolves with its record", async () => {
  const c = control("k", { fetch: stub(200, { columns: rowCols, rows: [{ op: "revoke", ok: true, status: 200, result: { columns: ["agent", "status"], rows: [["ag_1", "revoked"]] }, error: null }] }) });
  const res = await c.revoke("ag_1");
  assert.deepEqual(res.records, [{ agent: "ag_1", status: "revoked" }]);
});
