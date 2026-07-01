// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeEnvelope } from "../dist/index.js";

test("shape 1: explicit ok:true with a result", () => {
  const env = decodeEnvelope({ ok: true, status: 200, result: { columns: ["a"], rows: [["x"], ["y"]] } }, 200);
  assert.equal(env.ok, true);
  assert.equal(env.status, 200);
  assert.deepEqual(env.result.records, [{ a: "x" }, { a: "y" }]);
});

test("shape 1: ok:false yields a problem", () => {
  const env = decodeEnvelope({ ok: false, status: 403, error: { detail: "scope denied", status: 403 } }, 403);
  assert.equal(env.ok, false);
  assert.equal(env.problem.detail, "scope denied");
  assert.equal(env.problem.status, 403);
});

test("shape 2: live Neo4j row wrapper decodes as success", () => {
  const env = decodeEnvelope({ rows: [{ result: { columns: ["addr"], rows: [["2a04:2a01::1"]] } }] }, 200);
  assert.equal(env.ok, true);
  assert.deepEqual(env.result.records, [{ addr: "2a04:2a01::1" }]);
});

test("shape 3: bare RFC-7807 problem", () => {
  const env = decodeEnvelope({ title: "Unauthorized", detail: "bad key", status: 401 }, 401);
  assert.equal(env.ok, false);
  assert.equal(env.problem.detail, "bad key");
});

test("empty/shapeless object is a successful empty result (fail-open read)", () => {
  const env = decodeEnvelope({}, 200);
  assert.equal(env.ok, true);
  assert.deepEqual(env.result.records, []);
});

test("non-object body from a >=400 status is a fault", () => {
  const env = decodeEnvelope("gateway timeout", 504);
  assert.equal(env.ok, false);
  assert.equal(env.problem.status, 504);
});
