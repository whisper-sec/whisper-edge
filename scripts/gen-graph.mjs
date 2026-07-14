// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Generate src/graph.ts from the Whisper catalog (the single source of truth). Reads
// sdk-methods.json (the functional bits: method name, params, cypher/runVia, returns,
// mode) and catalog.json (the human bits: purpose, why, columns), both index-aligned,
// and emits one typed method per catalog entry plus a raw graph.query() escape hatch.
//
// Run:  node scripts/gen-graph.mjs [path-to-whisper-catalog]
// Default catalog path is ../whisper-catalog relative to this repo.
//
// Every direct entry (mode:direct with a real Cypher) POSTs its parameterised Cypher to
// /api/query; every flow entry (mode:flow, cypher:null) and the incomplete submit stub is
// emitted as a clear WhisperError that names the workflow runner it runs through, so the
// generated SDK never blocks on an engine it cannot yet reach.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const catalogDir = resolve(process.argv[2] ?? join(repoRoot, "..", "whisper-catalog"));

const sdk = JSON.parse(readFileSync(join(catalogDir, "sdk-methods.json"), "utf8"));
const catalog = JSON.parse(readFileSync(join(catalogDir, "catalog.json"), "utf8"));

if (sdk.methods.length !== catalog.entries.length) {
  throw new Error(`method/entry count mismatch: ${sdk.methods.length} vs ${catalog.entries.length}`);
}

// No em-dashes anywhere (Kaveh's rule): normalise any non-ASCII typography that slipped into
// the catalog prose to a plain-ASCII equivalent (mirrors the Python generator's _sanitize),
// and never emit a "/* ... */" that could break the JS block comment. Escape sequences only,
// so this generator source itself stays pure ASCII.
function clean(s) {
  return String(s ?? "")
    .replace(/\u2014/g, ", ")           // em dash -> comma
    .replace(/\u2013/g, "-")            // en dash -> hyphen
    .replace(/[\u2018\u2019]/g, "'")    // single curly quotes -> straight '
    .replace(/[\u201c\u201d]/g, '"')    // double curly quotes -> straight "
    .replace(/\u2026/g, "...")          // ellipsis -> ...
    .replace(/\u00a0/g, " ")            // non-breaking space -> normal space
    .replace(/\*\//g, "* /")
    .trim();
}

function jsString(s) {
  return JSON.stringify(String(s));
}

// A JS identifier that is safe as a positional parameter name in a method signature.
function paramIdent(name) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : `_${name.replace(/[^A-Za-z0-9_$]/g, "_")}`;
}

function docBlock(lines) {
  const body = lines
    .filter((l) => l !== null && l !== undefined)
    .map((l) => (l === "" ? "   *" : `   * ${l}`))
    .join("\n");
  return `  /**\n${body}\n   */`;
}

function methodDoc(entry, m) {
  const lines = [clean(entry.purpose || entry.summary || m.method)];
  const why = clean(entry.why);
  if (why && why !== clean(entry.purpose)) {
    lines.push("");
    lines.push(...wrap(why, 92));
  }
  lines.push("");
  const cols = (m.returns || []).join(", ");
  if (m.mode === "direct" && m.cypher && !isIncomplete(m.cypher)) {
    lines.push(`KEYED. Cypher: ${clean(m.cypher)}`);
    if (cols) lines.push(`Returns columns: ${cols}.`);
  } else if (m.mode === "direct") {
    lines.push("KEYED. The full parameter set for this write is not yet enumerated in the");
    lines.push("catalog, so this method throws a clear WhisperError (501). Use graph.query()");
    lines.push("with your own Cypher, or the console run endpoint.");
  } else {
    lines.push(`KEYED. Runs via the workflow runner: ${clean(m.runVia || "run_workflow")}.`);
    lines.push("Not yet exposed as a raw Cypher read over /api/query, so this method");
    lines.push("throws a clear WhisperError (501). Use graph.query() for a direct read.");
    if (cols) lines.push(`When wired it will return columns: ${cols}.`);
  }
  return docBlock(lines);
}

// Wrap prose to a width so the generated doc comments stay readable.
function wrap(text, width) {
  const words = text.split(/\s+/);
  const out = [];
  let line = "";
  for (const w of words) {
    if (line === "") line = w;
    else if ((line + " " + w).length <= width) line += " " + w;
    else {
      out.push(line);
      line = w;
    }
  }
  if (line) out.push(line);
  return out;
}

// The catalog marks submit direct but its Cypher carries a placeholder comment for the
// indicator/feedback fields (not enumerated), so it cannot be POSTed verbatim: treat it
// as a stub that points at graph.query(), exactly like a flow entry.
function isIncomplete(cypher) {
  return typeof cypher === "string" && (cypher.includes("/*") || cypher.includes("..."));
}

function directMethod(entry, m) {
  const params = m.params || [];
  const sigParts = params.map((p) => {
    const id = paramIdent(p.name);
    const def = p.default;
    return def === undefined ? `${id}: string` : `${id}: string = ${jsString(def)}`;
  });
  sigParts.push("reqOpts?: RequestOptions");
  const paramObj =
    params.length === 0
      ? "{}"
      : `{ ${params.map((p) => `${p.name}: ${paramIdent(p.name)}`).join(", ")} }`;
  const cypher = jsString(clean(m.cypher));
  return (
    `${methodDoc(entry, m)}\n` +
    `  ${m.method}(${sigParts.join(", ")}): Promise<GraphResult> {\n` +
    `    return this.runDirect(${cypher}, ${paramObj}, reqOpts);\n` +
    `  }`
  );
}

function stubMethod(entry, m) {
  const params = m.params || [];
  const sigParts = params.map((p) => {
    const id = paramIdent(p.name);
    const def = p.default;
    return def === undefined ? `${id}?: string` : `${id}: string = ${jsString(def)}`;
  });
  sigParts.push("reqOpts?: RequestOptions");
  // Reference the params/opts so noUnusedParameters stays happy without changing the shape.
  const voids = [...params.map((p) => paramIdent(p.name)), "reqOpts"].map((n) => `void ${n};`).join(" ");
  const via = clean(m.runVia || "run_workflow");
  const msg =
    m.mode === "direct"
      ? `${m.method}: the full parameter set for this call is not yet enumerated in the catalog. Use graph.query() with your own Cypher, or the console run endpoint.`
      : `${m.method} runs via the workflow runner (${via}), not a raw Cypher read; it is not yet exposed over /api/query. Use the console/agent run endpoint, or graph.query() for a direct read.`;
  return (
    `${methodDoc(entry, m)}\n` +
    `  ${m.method}(${sigParts.join(", ")}): Promise<GraphResult> {\n` +
    `    ${voids}\n` +
    `    return Promise.reject(new WhisperError(${jsString(msg)}, { status: 501 }));\n` +
    `  }`
  );
}

const methods = sdk.methods
  .map((m, i) => {
    const entry = catalog.entries[i];
    const isDirect = m.mode === "direct" && m.cypher && !isIncomplete(m.cypher);
    return isDirect ? directMethod(entry, m) : stubMethod(entry, m);
  })
  .join("\n\n");

const header = `// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// GENERATED by scripts/gen-graph.mjs from the Whisper catalog. Do not edit by hand: change
// the catalog (or the generator) and re-run \`node scripts/gen-graph.mjs\`.
//
// The KEYED GRAPH namespace: the Whisper security graph, one typed method per catalog verb,
// POSTed to graph.whisper.security/api/query. It is Cypher, so it is KEYED (Kaveh's rule:
// if it is Cypher it needs an API key). This is the SAME auth path as the control plane,
// the key travels only as X-API-Key, never in a URL or a log. The keyless surface
// (verify / resolve / rdap) stays pure HTTPS and never touches this namespace.
//
// Wire shape: the graph endpoint replies { columns, rows, statistics } where each row is an
// OBJECT keyed by column name, so this namespace parses that object-row shape itself and
// returns a GraphResult; it does NOT route through the control-plane envelope decoder
// (that one expects array-rows and would silently mangle these results). Pure fetch, zero
// dependencies.

import { WhisperError, doFetch, parseJson, readCappedText } from "./http.js";
import { endpointsFor } from "./keyless.js";
import type { GraphParams, GraphResult, GraphStatistics, RequestOptions } from "./types.js";

const USER_AGENT = "whisper-edge/0.3";

/** Options for creating a graph client (same shape as the rest of the SDK). */
export interface GraphOptions extends RequestOptions {}

interface RawGraphBody {
  columns?: unknown;
  rows?: unknown;
  statistics?: unknown;
  detail?: unknown;
  title?: unknown;
}

/** Normalise the graph endpoint's object-row envelope into a {@link GraphResult}. */
function decodeGraph(body: unknown, status: number): GraphResult {
  const o = (body && typeof body === "object" ? body : {}) as RawGraphBody;
  const columns = Array.isArray(o.columns) ? o.columns.map((c) => String(c)) : [];
  const rows = Array.isArray(o.rows)
    ? o.rows.map((r) => (r && typeof r === "object" && !Array.isArray(r) ? (r as Record<string, unknown>) : { value: r }))
    : [];
  const statistics = (o.statistics && typeof o.statistics === "object" ? o.statistics : {}) as GraphStatistics;
  return { columns, rows, statistics, raw: body, status };
}
`;

const classShell = `
/**
 * The Whisper security graph, authenticated with an owner API key. Every method runs one
 * catalog verb against /api/query and returns a {@link GraphResult}. Direct verbs POST a
 * parameterised Cypher read; flow verbs (multi-step workflows) throw a clear 501 until the
 * workflow runner is exposed here, so nothing blocks. Reachable both standalone via
 * graph(key) and as control(key).graph, bound to the same key.
 */
export class WhisperGraph {
  private readonly key: string;
  private readonly opts: GraphOptions;

  constructor(apiKey: string, opts: GraphOptions = {}) {
    const k = (apiKey ?? "").trim();
    if (k === "") {
      throw new WhisperError("no API key, the graph is keyed, pass your whisper_live_ key (never hard-code it; read it from the environment)", { status: 401 });
    }
    this.key = k;
    this.opts = opts;
  }

  private merge(extra?: RequestOptions): RequestOptions {
    return { ...this.opts, ...extra, endpoints: { ...this.opts.endpoints, ...extra?.endpoints } };
  }

  /**
   * POST a parameterised Cypher read to the graph endpoint and decode the object-row
   * envelope. \`params\` are bound server-side as $-parameters (never spliced into the query),
   * so a value can never break out of the Cypher, however hostile. The key rides only as
   * the X-API-Key header. Any >=400 status surfaces the server's clear detail as a
   * WhisperError (Postel: a clear error, never an opaque 500).
   */
  private async runDirect(cypher: string, params: GraphParams, reqOpts?: RequestOptions): Promise<GraphResult> {
    const o = this.merge(reqOpts);
    const url = endpointsFor(o).control;
    const resp = await doFetch(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          "user-agent": USER_AGENT,
          "x-api-key": this.key,
        },
        body: JSON.stringify({ query: cypher, parameters: params }),
      },
      o,
      "graph",
    );
    const text = await readCappedText(resp);
    const body = parseJson(text, "graph", resp.status);
    if (resp.status >= 400) {
      const p = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
      const detail = typeof p.detail === "string" ? p.detail : typeof p.title === "string" ? p.title : \`graph returned status \${resp.status}\`;
      throw new WhisperError(detail, {
        status: resp.status,
        detail: typeof p.detail === "string" ? p.detail : undefined,
        title: typeof p.title === "string" ? p.title : undefined,
        type: typeof p.type === "string" ? p.type : undefined,
      });
    }
    return decodeGraph(body, resp.status);
  }

  /**
   * The raw escape hatch: run an arbitrary Cypher read against the graph with your own
   * \`params\` (bound as $-parameters). KEYED. Use this for any verb this SDK stubs (a flow
   * workflow, or submit's full field set) or for a query the catalog does not name.
   */
  query(cypher: string, params: GraphParams = {}, reqOpts?: RequestOptions): Promise<GraphResult> {
    return this.runDirect(cypher, params, reqOpts);
  }
`;

const factory = `
/** Create a graph client bound to \`apiKey\`. Sugar for \`new WhisperGraph(apiKey, opts)\`. */
export function graph(apiKey: string, opts?: GraphOptions): WhisperGraph {
  return new WhisperGraph(apiKey, opts);
}
`;

const out = `${header}${classShell}\n${methods.split("\n").map((l) => (l === "" ? "" : l)).join("\n")}\n}\n${factory}`;

writeFileSync(join(repoRoot, "src", "graph.ts"), out);
const direct = sdk.methods.filter((m) => m.mode === "direct" && m.cypher && !isIncomplete(m.cypher)).length;
console.log(`wrote src/graph.ts: ${sdk.methods.length} methods (${direct} direct, ${sdk.methods.length - direct} stubbed) + query()`);
