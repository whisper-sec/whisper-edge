// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAgentsQuery, escapeCypherString, quoteCypherString, cypherMap, lit } from "../dist/index.js";

test("escapeCypherString doubles quotes and backslashes (order-safe)", () => {
  assert.equal(escapeCypherString("Tim O'Reilly"), "Tim O''Reilly");
  assert.equal(escapeCypherString("a\\b"), "a\\\\b");
  // A breakout attempt stays trapped inside the literal.
  assert.equal(escapeCypherString("'}}) RETURN 1 //"), "''}}) RETURN 1 //");
  // A trailing backslash cannot escape the closing quote.
  assert.equal(quoteCypherString("x\\"), "'x\\\\'");
});

test("lit renders each JS type as the right Cypher literal", () => {
  assert.equal(lit("hi"), "'hi'");
  assert.equal(lit(true), "true");
  assert.equal(lit(false), "false");
  assert.equal(lit(42), "42");
  assert.equal(lit(1.5), "1.5");
  assert.equal(lit(null), "null");
  assert.equal(lit(undefined), "null");
  assert.equal(lit(["a", "b"]), "['a','b']");
  assert.equal(lit(NaN), "null");
});

test("cypherMap sorts keys deterministically and drops undefined", () => {
  assert.equal(cypherMap({ b: 1, a: "x" }), "{a:'x',b:1}");
  assert.equal(cypherMap({}), "{}");
  assert.equal(cypherMap({ keep: 1, skip: undefined }), "{keep:1}");
  // Nested maps sort too.
  assert.equal(cypherMap({ z: { n: 2, m: 1 } }), "{z:{m:1,n:2}}");
});

test("buildAgentsQuery is well-formed, deterministic, injection-proof", () => {
  assert.equal(buildAgentsQuery("list", {}), "CALL whisper.agents({op:'list', args:{}})");
  assert.equal(buildAgentsQuery("list"), "CALL whisper.agents({op:'list', args:{}})");
  assert.equal(
    buildAgentsQuery("identity", { label: "scout", contact_email: "a@b.co" }),
    "CALL whisper.agents({op:'identity', args:{contact_email:'a@b.co',label:'scout'}})",
  );
  // A hostile label cannot break out of the args map.
  const q = buildAgentsQuery("identity", { label: "'}) RETURN 1 //" });
  assert.equal(q, "CALL whisper.agents({op:'identity', args:{label:'''}) RETURN 1 //'}})");
  assert.ok(!q.includes("RETURN 1 //'}})") || q.includes("'''"));
});
