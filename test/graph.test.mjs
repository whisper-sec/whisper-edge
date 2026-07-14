// SPDX-License-Identifier: MIT
// Tests for the KEYED graph namespace. The network is stubbed: no real key, no real call.
import { test } from "node:test";
import assert from "node:assert/strict";
import { graph, WhisperGraph, control, WhisperError } from "../dist/index.js";

// A fetch stub that captures every request and replies with `body` at `status`.
function stub(status, body, capture) {
  return async (url, init) => {
    if (capture) capture.push({ url: String(url), init, sentBody: init.body, headers: init.headers });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
}

// The graph endpoint's native envelope: object-rows + a statistics block.
const IDENTIFY_ENVELOPE = {
  columns: ["host", "vendor_id", "canonical_name", "category", "roles", "host_class", "band"],
  rows: [
    { host: "api.openai.com", vendor_id: "openai", canonical_name: "OpenAI", category: "AI", roles: ["ORIGIN_AS"], host_class: "service", band: "high" },
  ],
  statistics: { rowCount: 1, executionTimeMs: 12 },
};

test("constructing the graph without a key throws a clear 401", () => {
  assert.throws(() => graph("  "), (e) => e instanceof WhisperError && e.status === 401);
});

test("graph() and new WhisperGraph() are equivalent", () => {
  assert.ok(graph("whisper_live_EXAMPLE") instanceof WhisperGraph);
  assert.ok(new WhisperGraph("whisper_live_EXAMPLE") instanceof WhisperGraph);
});

test("a direct method POSTs {query, parameters} with X-API-Key (key never in the URL)", async () => {
  const calls = [];
  const g = graph("whisper_live_EXAMPLE", { fetch: stub(200, IDENTIFY_ENVELOPE, calls) });
  const res = await g.identify();
  // Object-rows are surfaced verbatim in GraphResult.rows.
  assert.deepEqual(res.columns, IDENTIFY_ENVELOPE.columns);
  assert.equal(res.rows.length, 1);
  assert.equal(res.rows[0].vendor_id, "openai");
  assert.equal(res.statistics.rowCount, 1);
  assert.equal(res.status, 200);

  const { url, init, sentBody, headers } = calls[0];
  assert.equal(url, "https://graph.whisper.security/api/query");
  assert.equal(init.method, "POST");
  assert.equal(headers["x-api-key"], "whisper_live_EXAMPLE");
  const parsed = JSON.parse(sentBody);
  assert.equal(parsed.query, "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band");
  assert.deepEqual(parsed.parameters, { v: "api.openai.com" }); // default applied
  assert.ok(!url.includes("whisper_live_EXAMPLE")); // key is never in the URL
});

test("a direct method binds the caller's value as a $-parameter (no splicing)", async () => {
  const calls = [];
  const g = graph("k", { fetch: stub(200, { columns: ["apex"], rows: [{ apex: "foo.co.uk" }], statistics: {} }, calls) });
  await g.pslTldplusone("www.foo.co.uk");
  const parsed = JSON.parse(calls[0].sentBody);
  assert.equal(parsed.query, "CALL whisper.psl.tldPlusOne($v) YIELD apex");
  assert.deepEqual(parsed.parameters, { v: "www.foo.co.uk" });
});

test("a hostile value cannot break out (bound, not interpolated)", async () => {
  const calls = [];
  const g = graph("k", { fetch: stub(200, { columns: [], rows: [], statistics: {} }, calls) });
  const evil = "x') RETURN 1 // ";
  await g.identify(evil);
  const parsed = JSON.parse(calls[0].sentBody);
  // The query text is the fixed catalog Cypher; the value lives ONLY in parameters.
  assert.ok(!parsed.query.includes("RETURN 1"));
  assert.equal(parsed.parameters.v, evil);
});

test("a no-param direct method (dbSchema) sends an empty parameters map", async () => {
  const calls = [];
  const g = graph("k", { fetch: stub(200, { columns: ["type"], rows: [{ type: "HOSTNAME" }], statistics: {} }, calls) });
  await g.dbSchema();
  const parsed = JSON.parse(calls[0].sentBody);
  assert.equal(parsed.query, "CALL db.schema()");
  assert.deepEqual(parsed.parameters, {});
});

test("the raw query() escape hatch posts arbitrary Cypher + params", async () => {
  const calls = [];
  const g = graph("k", { fetch: stub(200, { columns: ["n"], rows: [{ n: 1 }], statistics: { rowCount: 1 } }, calls) });
  const res = await g.query("MATCH (n) RETURN count(n) AS n", { limit: 5 });
  assert.equal(res.rows[0].n, 1);
  const parsed = JSON.parse(calls[0].sentBody);
  assert.equal(parsed.query, "MATCH (n) RETURN count(n) AS n");
  assert.deepEqual(parsed.parameters, { limit: 5 });
});

test("control(key).graph reaches the same code as graph(key), bound to the same key", async () => {
  const calls = [];
  const c = control("whisper_live_SHARED", { fetch: stub(200, IDENTIFY_ENVELOPE, calls) });
  const res = await c.graph.identify();
  assert.equal(res.rows[0].vendor_id, "openai");
  assert.equal(calls[0].headers["x-api-key"], "whisper_live_SHARED");
  // The accessor is memoised: same instance every read.
  assert.equal(c.graph, c.graph);
});

test("a flow method surfaces a clear workflow-runner-not-wired WhisperError (501)", async () => {
  let fetched = false;
  const g = graph("k", { fetch: async () => { fetched = true; return new Response("{}"); } });
  await assert.rejects(
    () => g.attackPath(),
    (e) => e instanceof WhisperError && e.status === 501 && /workflow runner/i.test(e.message) && /run_workflow \(attack-path\)/.test(e.message),
  );
  assert.equal(fetched, false); // a stub never touches the network
});

test("submit (direct-but-incomplete) is stubbed toward graph.query()", async () => {
  const g = graph("k", { fetch: async () => new Response("{}") });
  await assert.rejects(
    () => g.submit(),
    (e) => e instanceof WhisperError && e.status === 501 && /graph\.query\(\)/.test(e.message),
  );
});

test("a >=400 status surfaces the server's detail as a WhisperError", async () => {
  const g = graph("k", { fetch: stub(403, { detail: "scope graph:read required", status: 403 }) });
  await assert.rejects(
    () => g.identify(),
    (e) => e instanceof WhisperError && e.status === 403 && e.detail === "scope graph:read required",
  );
});

test("a multi-param flow method keeps its typed shape (attackPath value+other)", async () => {
  const g = graph("k", { fetch: async () => new Response("{}") });
  // Both positional params accepted; still rejects as a 501 stub.
  await assert.rejects(() => g.attackPath("paypal.com", "paypa1.com"), (e) => e.status === 501);
});
