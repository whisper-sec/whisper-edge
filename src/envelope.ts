// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Faithful port of the Whisper CLI envelope decoder. Liberal in what we ACCEPT: the
// control plane may reply in the documented `{ok,status,result,error}` shape, the live
// Neo4j `{rows:[{result:{...}}]}` wrapper, or a bare RFC-7807 problem - all decode here.

import type { ControlResult, Problem } from "./types.js";

interface RawResult {
  columns?: string[];
  rows?: unknown[][];
}

/** Turn a raw {columns,rows} result into column-keyed record maps. */
function toRecords(r: RawResult | null | undefined): Array<Record<string, unknown>> {
  if (!r || !Array.isArray(r.rows)) return [];
  const cols = r.columns ?? [];
  return r.rows.map((row) => {
    const m: Record<string, unknown> = {};
    for (let i = 0; i < cols.length; i++) if (i < row.length) m[cols[i]] = row[i];
    return m;
  });
}

/** A decoded envelope: ok flag, status, the tabular result, or a problem. */
export interface Envelope {
  ok: boolean;
  status: number;
  result: ControlResult | null;
  problem: Problem | null;
  raw: unknown;
}

function pickString(o: Record<string, unknown>, k: string): string | undefined {
  const v = o[k];
  return typeof v === "string" ? v : undefined;
}

function asProblem(o: Record<string, unknown>, status: number): Problem {
  // The plane's own errors are {code, message, retryable}; RFC 7807 ones use detail/title.
  const p: Problem = {
    type: pickString(o, "type"),
    title: pickString(o, "title"),
    detail: pickString(o, "detail") ?? pickString(o, "message"),
    status: typeof o.status === "number" ? o.status : status,
  };
  const code = pickString(o, "code");
  if (code) p.code = code;
  if (typeof o.retryable === "boolean") p.retryable = o.retryable;
  if (Array.isArray(o.suggestions)) p.suggestions = o.suggestions.filter((s) => typeof s === "string") as string[];
  if (!p.detail && !p.title && !p.type) p.detail = "control plane reported failure";
  return p;
}

/**
 * The per-op envelope row of the live table, `{op, ok, status, result, error, ...}`, as an
 * object row or a positional one aligned to the top-level columns; else null. A row only
 * counts when it has a boolean `ok` and one of op/result/error, so a plain result row with a
 * column that happens to be called `ok` is not mistaken for it.
 */
function envelopeRow(o: Record<string, unknown>): Record<string, unknown> | null {
  const rows = Array.isArray(o.rows) ? (o.rows as unknown[]) : null;
  if (!rows || rows.length === 0) return null;
  let row = rows[0];
  if (Array.isArray(row) && Array.isArray(o.columns)) {
    const m: Record<string, unknown> = {};
    (o.columns as unknown[]).forEach((c, i) => { if (typeof c === "string" && i < (row as unknown[]).length) m[c] = (row as unknown[])[i]; });
    row = m;
  }
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  const r = row as Record<string, unknown>;
  return typeof r.ok === "boolean" && ("op" in r || "result" in r || "error" in r) ? r : null;
}

function makeResult(r: RawResult, status: number, raw: unknown): ControlResult {
  return {
    columns: r.columns ?? [],
    rows: r.rows ?? [],
    records: toRecords(r),
    raw,
    status,
  };
}

/**
 * Decode a control-plane reply body into a normalised Envelope, accepting all three wire
 * shapes (Postel: liberal in what we accept). `httpStatus` seeds the status when the body
 * omits it.
 */
export function decodeEnvelope(body: unknown, httpStatus: number): Envelope {
  const env: Envelope = { ok: false, status: httpStatus, result: null, problem: null, raw: body };

  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    // A non-object body from a >=400 status is a fault; otherwise a shapeless success.
    if (httpStatus >= 400) {
      env.problem = { status: httpStatus, detail: "control plane returned a non-JSON error reply" };
      return env;
    }
    env.ok = true;
    env.result = makeResult({}, httpStatus, body);
    return env;
  }

  const o = body as Record<string, unknown>;
  if (typeof o.status === "number") env.status = o.status;

  // Shape 1: an explicit ok flag.
  if (typeof o.ok === "boolean") {
    env.ok = o.ok;
    if (env.ok) {
      env.result = makeResult((o.result as RawResult) ?? {}, env.status, body);
    } else {
      env.problem = o.error && typeof o.error === "object"
        ? asProblem(o.error as Record<string, unknown>, env.status)
        : asProblem(o, env.status);
    }
    return env;
  }

  // Shape 2a: the live table whose first row is the per-op envelope. Its ok/status/error
  // decide, exactly as a flat envelope's would: a failure inside the row (the front door
  // answers HTTP 200 with the 404 or 403 in the row) is a failure, never an empty success.
  const er = envelopeRow(o);
  if (er) {
    if (typeof er.status === "number") env.status = er.status;
    env.ok = er.ok as boolean;
    if (env.ok) {
      env.result = makeResult((er.result as RawResult) ?? {}, env.status, body);
    } else {
      env.problem = er.error && typeof er.error === "object"
        ? asProblem(er.error as Record<string, unknown>, env.status)
        : asProblem({}, env.status);
    }
    return env;
  }

  // Shape 3: a bare problem object (error present, or no result/rows but problem-ish).
  const hasProblemFields = ["detail", "title", "type", "error"].some((k) => k in o);
  const hasResult = o.result && typeof o.result === "object";
  const rows = Array.isArray(o.rows) ? (o.rows as unknown[]) : null;
  if ((o.error && typeof o.error === "object") || (!hasResult && !rows && hasProblemFields)) {
    env.problem = o.error && typeof o.error === "object"
      ? asProblem(o.error as Record<string, unknown>, env.status)
      : asProblem(o, env.status);
    return env;
  }

  // Shape 2: the Neo4j row wrapper, or a top-level result with no ok flag → success.
  env.ok = true;
  if (hasResult) {
    env.result = makeResult(o.result as RawResult, env.status, body);
  } else if (rows && rows.length > 0 && rows[0] && typeof rows[0] === "object" && "result" in (rows[0] as object)) {
    env.result = makeResult((rows[0] as { result: RawResult }).result ?? {}, env.status, body);
  } else {
    // An empty, shapeless-but-valid object: a successful empty result (fail-open read).
    env.result = makeResult({}, env.status, body);
  }
  return env;
}
