// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Faithful port of the Whisper CLI's Cypher literal builder. Robustness Principle
// (RFC 761): conservative in what we EMIT — every leaf string is escaped so a value can
// never break out of the surrounding map/list, however hostile the input.

/**
 * Render `s` safe to embed inside a single-quoted Cypher literal. openCypher escapes a
 * single quote by DOUBLING it; a backslash is doubled too so a trailing backslash can
 * never escape the closing quote. Order matters: backslashes first, then quotes.
 * Returns the INNER text only (no surrounding quotes).
 */
export function escapeCypherString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/'/g, "''");
}

/** Return `s` as a complete single-quoted, escaped Cypher string literal. */
export function quoteCypherString(s: string): string {
  return "'" + escapeCypherString(s) + "'";
}

/**
 * Render an arbitrary JS value as a Cypher literal:
 *   string → quoted+escaped · boolean → true/false · number → decimal ·
 *   null/undefined → null · Array → bracketed list · object → brace map (keys sorted).
 * Every leaf string flows through quoteCypherString, so nothing can inject.
 */
export function lit(v: unknown): string {
  if (v === null || v === undefined) return "null";
  switch (typeof v) {
    case "string":
      return quoteCypherString(v);
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) return "null"; // NaN/Infinity are not valid Cypher literals
      return Number.isInteger(v) ? v.toString() : String(v);
    case "bigint":
      return v.toString();
    case "object":
      if (Array.isArray(v)) return "[" + v.map(lit).join(",") + "]";
      return cypherMap(v as Record<string, unknown>);
    default:
      // Anything unrecognised is rendered as its string form, quoted — never injectable.
      return quoteCypherString(String(v));
  }
}

/**
 * Render a plain object as a Cypher map literal `{k1:v1,k2:v2}`. Keys are emitted in
 * SORTED order so the produced query is deterministic (stable for tests, caches, logs).
 * `undefined`-valued keys are dropped. An empty map renders as `{}`.
 */
export function cypherMap(m: Record<string, unknown>): string {
  const keys = Object.keys(m)
    .filter((k) => m[k] !== undefined)
    .sort();
  if (keys.length === 0) return "{}";
  return "{" + keys.map((k) => `${k}:${lit(m[k])}`).join(",") + "}";
}

/**
 * Build the one control-plane verb:
 *
 *   CALL whisper.agents({op:'<op>', args:{...}})
 *
 * `args` may be omitted/empty (rendered as `{}`). Both `op` and every arg value are
 * escaped, so the produced Cypher is always well-formed and injection-proof.
 */
export function buildAgentsQuery(op: string, args?: Record<string, unknown>): string {
  const argsLit = args && Object.keys(args).length > 0 ? cypherMap(args) : "{}";
  return `CALL whisper.agents({op:${quoteCypherString(op)}, args:${argsLit}})`;
}
