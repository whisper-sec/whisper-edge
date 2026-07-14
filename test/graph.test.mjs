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

// An SSE stub: returns `blocks` (each an {event,data} pair) as one text/event-stream body.
function sseStub(blocks, capture, status = 200) {
  const text = blocks.map((b) => `event: ${b.event}\ndata: ${JSON.stringify(b.data)}\n\n`).join("");
  return async (url, init) => {
    if (capture) capture.push({ url: String(url), init, sentBody: init.body, headers: init.headers });
    return new Response(text, { status, headers: { "content-type": "text/event-stream" } });
  };
}

// A representative typosquat run: an anchor graph delta, one step with rows, and complete.
const TYPOSQUAT_SSE = [
  { event: "start", data: { slug: "typosquat" } },
  { event: "graph", data: { stepId: "__anchor", index: -1, delta: { nodes: [{ id: "paypal.com", type: "HOSTNAME", anchor: true }], edges: [] }, anchorIds: ["paypal.com"] } },
  { event: "step-start", data: { id: "registered", title: "Registered look-alikes", index: 0 } },
  { event: "step", data: { id: "registered", title: "Registered look-alikes", status: "done", cypher: "CALL whisper.variants($domain) ...", columns: ["variant", "method", "confidence"], rows: [{ variant: "paypad.com", method: "BITSQUATTING", confidence: 0.9 }] } },
  { event: "graph", data: { stepId: "registered", index: 0, delta: { nodes: [{ id: "paypad.com", type: "HOSTNAME" }], edges: [{ from: "paypal.com", to: "paypad.com", label: "look-alike" }] } } },
  { event: "complete", data: { slug: "typosquat", totalLatencyMs: 421 } },
];

test("a flow method EXECUTES via the gallery runner and aggregates the SSE stream", async () => {
  const calls = [];
  const g = graph("whisper_live_EXAMPLE", { fetch: sseStub(TYPOSQUAT_SSE, calls) });
  const res = await g.typosquat("paypal.com");
  // Aggregated: steps in order, the headline table, and a de-duplicated graph.
  assert.equal(res.slug, "typosquat");
  assert.equal(res.steps.length, 1);
  assert.equal(res.steps[0].id, "registered");
  assert.equal(res.anchor.id, "registered");
  assert.deepEqual(res.columns, ["variant", "method", "confidence"]);
  assert.equal(res.rows[0].variant, "paypad.com");
  assert.equal(res.graph.nodes.length, 2); // paypal.com (anchor) + paypad.com
  assert.equal(res.graph.edges.length, 1);
  assert.equal(res.totalLatencyMs, 421);
  assert.equal(res.events.length, TYPOSQUAT_SSE.length);
  assert.equal(res.status, 200);
  // Wire: POSTed to the flow-run endpoint with X-API-Key (never in the URL); value mapped.
  const { url, init, sentBody, headers } = calls[0];
  assert.equal(url, "https://console.whisper.security/api/gallery/run");
  assert.equal(init.method, "POST");
  assert.equal(headers["x-api-key"], "whisper_live_EXAMPLE");
  assert.ok(!url.includes("whisper_live_EXAMPLE"));
  const parsed = JSON.parse(sentBody);
  assert.equal(parsed.slug, "typosquat");
  assert.equal(parsed.value, "paypal.com"); // first input -> anchor value
  // Only the runner's keys are sent (slug/value/paramValues); an inputs/params echo would
  // be ignored and the flow would fall back to its default anchor, so we never send it.
  assert.equal(parsed.inputs, undefined);
  assert.equal(parsed.params, undefined);
  assert.equal(parsed.paramValues, undefined); // a single-input flow has no extra params
});

test("a flow's tunable params + extra inputs ride in paramValues (attackPath value+other)", async () => {
  const calls = [];
  const g = graph("k", { fetch: sseStub([{ event: "complete", data: { slug: "attack-path" } }], calls) });
  const res = await g.attackPath("paypal.com", "paypa1.com", { level: "deep" });
  assert.equal(res.slug, "attack-path");
  const parsed = JSON.parse(calls[0].sentBody);
  assert.equal(parsed.value, "paypal.com"); // first input -> value
  assert.equal(parsed.paramValues.other, "paypa1.com"); // second input -> paramValues
  assert.equal(parsed.paramValues.level, "deep"); // tunable param -> paramValues
});

test("onFlowEvent observes each SSE event as it streams; a throwing observer never breaks the run", async () => {
  const seen = [];
  const g = graph("k", {
    fetch: sseStub(TYPOSQUAT_SSE),
    onFlowEvent: (event) => { seen.push(event); throw new Error("observer boom"); },
  });
  const res = await g.typosquat();
  assert.deepEqual(seen, ["start", "graph", "step-start", "step", "graph", "complete"]);
  assert.equal(res.rows[0].variant, "paypad.com"); // run still completed
});

test("a flow run surfacing an `error` event rejects as a clear WhisperError", async () => {
  const g = graph("k", { fetch: sseStub([{ event: "error", data: { message: "step 2 timed out" } }]) });
  await assert.rejects(
    () => g.attackSurface(),
    (e) => e instanceof WhisperError && /step 2 timed out/.test(e.message),
  );
});

test("a flow run non-2xx (AuthRequired) surfaces the JSON problem as a WhisperError", async () => {
  const g = graph("k", { fetch: stub(401, { error: "AuthRequired", message: "Sign in to run workflows." }) });
  await assert.rejects(
    () => g.attackSurface(),
    (e) => e instanceof WhisperError && e.status === 401 && /Sign in to run workflows/.test(e.message),
  );
});

test("submit EXECUTES as a direct verb, POSTing exactly the three params its Cypher binds", async () => {
  const calls = [];
  const g = graph("k", { fetch: stub(200, { columns: ["observation_id", "accepted"], rows: [{ observation_id: "obs_1", accepted: true }], statistics: { rowCount: 1 } }, calls) });
  const res = await g.submit("indicator", "ip", "203.0.113.5");
  assert.equal(res.rows[0].accepted, true);
  const parsed = JSON.parse(calls[0].sentBody);
  assert.equal(parsed.query, "CALL whisper.submit({kind:$kind, identifier_kind:$identifier_kind, value:$value})");
  assert.deepEqual(parsed.parameters, { kind: "indicator", identifier_kind: "ip", value: "203.0.113.5" });
});

test("a >=400 status surfaces the server's detail as a WhisperError", async () => {
  const g = graph("k", { fetch: stub(403, { detail: "scope graph:read required", status: 403 }) });
  await assert.rejects(
    () => g.identify(),
    (e) => e instanceof WhisperError && e.status === 403 && e.detail === "scope graph:read required",
  );
});
