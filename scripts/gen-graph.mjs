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
// /api/query and returns a GraphResult; every flow entry (mode:flow) runs through the
// gallery runner over SSE and returns the aggregated FlowResult. Both are KEYED. Every
// method's JSDoc carries an @see link to its canonical docs page.

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

// The docs base for the @see links. The catalog's graph block is the SSOT; fall back to
// the sdk-methods copy, then the canonical host, so a link is always emitted.
const DOCS_BASE = String(catalog.graph?.docsBase || sdk.docsBase || "https://www.whisper.security").replace(/\/$/, "");

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

// The set of $-parameters a Cypher body actually binds. A direct method only takes (and
// only sends) the params its query references, so a verb whose catalog `params` over-lists
// (e.g. submit, which enumerates its whole optional field set but binds just three) still
// emits a clean signature that POSTs exactly what the fixed query reads.
function cypherRefs(cypher) {
  const set = new Set();
  const re = /\$([A-Za-z_][A-Za-z0-9_]*)/g;
  let m;
  while ((m = re.exec(String(cypher ?? ""))) !== null) set.add(m[1]);
  return set;
}

// The canonical docs URL for an entry: sdk-methods carries a prebuilt `docsUrl`; else build
// it from DOCS_BASE + the entry's docPath. Always present, so every method gets an @see.
function docsUrlFor(entry, m) {
  if (m && typeof m.docsUrl === "string" && m.docsUrl) return m.docsUrl;
  const p = String(entry?.docPath || m?.docPath || "");
  return p ? `${DOCS_BASE}${p.startsWith("/") ? "" : "/"}${p}` : DOCS_BASE;
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
    // Safety net: a direct entry whose Cypher still carries an un-enumerated placeholder
    // stays a clear 501 stub. No current catalog entry hits this.
    lines.push("KEYED. The full parameter set for this call is not yet enumerated in the");
    lines.push("catalog, so this method throws a clear WhisperError (501). Use graph.query()");
    lines.push("with your own Cypher, or the console run endpoint.");
  } else {
    // FLOW: executes via the gallery runner and streams its steps back over SSE, aggregated
    // into a FlowResult. Not a single Cypher read - a multi-step investigation.
    lines.push(`KEYED. Multi-step FLOW: runs via the gallery runner (${clean(entry.id)}) over`);
    lines.push("SSE and aggregates the streamed steps into a FlowResult.");
    const knobs = (entry.params || [])
      .map((p) => (p.default !== undefined && p.default !== null ? `${p.name}=${p.default}` : p.name))
      .join(", ");
    if (knobs) lines.push(`Tunable params (pass as \`params\`): ${knobs}.`);
    if (cols) lines.push(`Headline columns: ${cols}.`);
  }
  // Every method links to its canonical docs page.
  lines.push("");
  lines.push(`@see ${docsUrlFor(entry, m)}`);
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
  // Only the params the fixed Cypher actually binds become the method signature (and the
  // POSTed parameters). Every direct verb but submit already lists exactly its refs, so
  // this is a no-op for them; submit narrows from its full optional field set to the three
  // its canonical query reads (kind, identifier_kind, value).
  const refs = cypherRefs(m.cypher);
  const params = (m.params || []).filter((p) => refs.has(p.name));
  const sigParts = params.map((p) => {
    const id = paramIdent(p.name);
    const def = p.default;
    return def === undefined || def === null ? `${id}: string` : `${id}: string = ${jsString(def)}`;
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

// A FLOW method: runs the catalog flow through the gallery runner and returns the
// aggregated SSE result. sdk-methods lists the flow's INPUTS as its positional params (by
// paramName); the first input is the anchor, the rest ride as params. The flow's tunable
// knobs (level / depth / instanceType) come in via the trailing `params` object.
function flowMethod(entry, m) {
  const inputs = m.params || [];
  const sigParts = inputs.map((p) => {
    const id = paramIdent(p.name);
    const def = p.default;
    return def === undefined || def === null ? `${id}?: string` : `${id}: string = ${jsString(def)}`;
  });
  sigParts.push("params: FlowParams = {}");
  sigParts.push("reqOpts?: RequestOptions");
  const inputObj =
    inputs.length === 0
      ? "{}"
      : `{ ${inputs.map((p) => `${jsString(p.name)}: ${paramIdent(p.name)}`).join(", ")} }`;
  const slug = jsString(String(entry.id));
  return (
    `${methodDoc(entry, m)}\n` +
    `  ${m.method}(${sigParts.join(", ")}): Promise<FlowResult> {\n` +
    `    return this.runFlow(${slug}, ${inputObj}, params, reqOpts);\n` +
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
    if (m.mode === "direct" && m.cypher && !isIncomplete(m.cypher)) return directMethod(entry, m);
    if (m.mode === "flow") return flowMethod(entry, m);
    // Safety net: a direct-but-incomplete write stays a clear 501 stub (no current entry).
    return stubMethod(entry, m);
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

import { WhisperError, doFetch, parseJson, readCappedText, resolveFetch } from "./http.js";
import { endpointsFor } from "./keyless.js";
import type {
  FlowParams,
  FlowResult,
  FlowStep,
  GraphParams,
  GraphResult,
  GraphStatistics,
  RequestOptions,
} from "./types.js";

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
 * catalog verb. Direct verbs POST a parameterised Cypher read to /api/query and return a
 * {@link GraphResult}; flow verbs (multi-step investigations) run through the gallery
 * runner over SSE and return the aggregated {@link FlowResult}. The raw {@link query}
 * escape hatch runs arbitrary Cypher. Reachable both standalone via graph(key) and as
 * control(key).graph, bound to the same key.
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
   * \`params\` (bound as $-parameters). KEYED. Use this for any query the catalog does not
   * name, or a bespoke form of a named verb (e.g. a submit \`feedback\` with the full
   * optional field set, or an \`UNWIND $records\` batch submit).
   */
  query(cypher: string, params: GraphParams = {}, reqOpts?: RequestOptions): Promise<GraphResult> {
    return this.runDirect(cypher, params, reqOpts);
  }

  /**
   * Run a catalog FLOW (a multi-step investigation) through the gallery runner and
   * aggregate its Server-Sent-Events stream into a {@link FlowResult}. \`inputs\` are the
   * flow's typed entities keyed by name; the FIRST is the anchor the graph is built around,
   * every other input rides in the run's params. \`params\` are the flow's tunable knobs
   * (level / depth / instanceType, ...). KEYED: the key travels only as X-API-Key. Pass
   * \`reqOpts.onFlowEvent\` to observe each SSE event as it arrives (progressive rendering);
   * the returned promise still resolves with the full aggregate. An \`error\` event, or any
   * >=400, surfaces as a clear WhisperError (Postel: a clear error, never an opaque 500).
   * The default timeout is 120s (flows are multi-step); override via \`reqOpts.timeoutMs\`.
   */
  async runFlow(
    slug: string,
    inputs: Record<string, string | string[]> = {},
    params: FlowParams = {},
    reqOpts?: RequestOptions,
  ): Promise<FlowResult> {
    const o = this.merge(reqOpts);
    const url = endpointsFor(o).flowRun;

    // The runner's wire contract is {slug, value, paramValues}: \`value\` is the ONE primary
    // entity (a host / IP / ASN), or \`values\` for a bulk list; \`paramValues\` carries every
    // other input plus every tuning knob. So the FIRST input becomes the anchor \`value\`, and
    // every other input and every flow param rides in \`paramValues\`. A nullish input is
    // skipped so the flow's own default applies (Postel: sensible defaults, liberal in what
    // we accept). We send ONLY the keys the runner reads: an \`inputs\`/\`params\` map is
    // silently ignored, so the flow would fall back to its default anchor.
    const paramValues: Record<string, unknown> = {};
    let value: string | undefined;
    let values: string[] | undefined;
    let first = true;
    for (const [name, val] of Object.entries(inputs)) {
      if (val === undefined || val === null) continue;
      if (first) {
        if (Array.isArray(val)) values = val.map((x) => String(x));
        else value = String(val);
        first = false;
      } else {
        paramValues[name] = val;
      }
    }
    for (const [k, v] of Object.entries(params)) paramValues[k] = v;
    const body: Record<string, unknown> = { slug };
    if (value !== undefined) body.value = value;
    if (values !== undefined) body.values = values;
    if (Object.keys(paramValues).length > 0) body.paramValues = paramValues;

    // A flow is a long-lived SSE read, so we drive the timeout + abort ourselves (doFetch's
    // one-shot timeout would abort mid-stream). The clock covers the whole run.
    const f = resolveFetch(o);
    const timeoutMs = o.timeoutMs ?? 120_000;
    const ac = new AbortController();
    const onAbort = () => ac.abort((o.signal as AbortSignal).reason);
    if (o.signal) {
      if (o.signal.aborted) ac.abort(o.signal.reason);
      else o.signal.addEventListener("abort", onAbort, { once: true });
    }
    let timer: ReturnType<typeof setTimeout>;
    const timeoutErr = new WhisperError(\`flow \${slug} timed out after \${timeoutMs}ms\`, { status: 0 });
    timer = setTimeout(() => ac.abort(timeoutErr), timeoutMs);

    let resp: Response;
    try {
      resp = await f(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "text/event-stream",
          "user-agent": USER_AGENT,
          "x-whisper-client": USER_AGENT,
          "x-api-key": this.key,
        },
        body: JSON.stringify(body),
        signal: ac.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      if (o.signal) o.signal.removeEventListener("abort", onAbort);
      if (err instanceof WhisperError) throw err;
      if (ac.signal.reason instanceof WhisperError) throw ac.signal.reason;
      const reason = (ac.signal.reason instanceof Error ? ac.signal.reason.message : undefined) ?? (err as Error)?.message;
      throw new WhisperError(\`flow \${slug} unreachable: \${reason ?? "network error"}\`, { status: 0 });
    }

    try {
      // A non-2xx is a JSON problem (AuthRequired / FlowNotFound / ...), not an event stream.
      if (resp.status >= 400) {
        const text = await readCappedText(resp);
        const b = (parseJson(text, "flow", resp.status) ?? {}) as Record<string, unknown>;
        const detail =
          typeof b.message === "string" ? b.message :
          typeof b.detail === "string" ? b.detail :
          \`flow returned status \${resp.status}\`;
        throw new WhisperError(detail, {
          status: resp.status,
          detail: typeof b.detail === "string" ? b.detail : undefined,
          title: typeof b.error === "string" ? b.error : undefined,
        });
      }
      return await this.aggregateSse(resp, slug, o);
    } finally {
      clearTimeout(timer);
      if (o.signal) o.signal.removeEventListener("abort", onAbort);
    }
  }

  /**
   * Consume an SSE Response into a {@link FlowResult}. A tiny line reader (zero deps): split
   * the stream on blank lines, read the \`event:\`/\`data:\` fields, and fold each event into
   * the aggregate (steps in order, a de-duplicated graph, the final presentation payload).
   * Prefers the streaming body reader; falls back to buffering the whole body where a
   * runtime does not expose a readable stream - both yield the identical aggregate.
   */
  private async aggregateSse(resp: Response, slug: string, o: RequestOptions): Promise<FlowResult> {
    const onEvent = o.onFlowEvent;
    const events: Array<{ event: string; data: unknown }> = [];
    const steps: FlowStep[] = [];
    const graph = { nodes: [] as Array<Record<string, unknown>>, edges: [] as Array<Record<string, unknown>> };
    const seenNodes = new Set<string>();
    const seenEdges = new Set<string>();
    let present: unknown;
    let totalLatencyMs: number | undefined;
    let runError: string | undefined;

    const handleBlock = (block: string) => {
      let event = "message";
      const dataLines: string[] = [];
      for (const line of block.split("\\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
      }
      const dataStr = dataLines.join("\\n");
      if (dataStr === "") return;
      let data: unknown;
      try { data = JSON.parse(dataStr); } catch { data = dataStr; }
      events.push({ event, data });
      // A caller's observer must never break the run.
      try { onEvent?.(event, data); } catch { /* swallow */ }

      const d = (data && typeof data === "object" ? data : {}) as Record<string, unknown>;
      if (event === "step") {
        const id = String(d.id ?? "");
        // The internal presentation step carries the FormatOutput, not a table.
        if (id === "__present") { present = d.output; return; }
        steps.push({
          id,
          title: typeof d.title === "string" ? d.title : undefined,
          status: typeof d.status === "string" ? d.status : undefined,
          cypher: typeof d.cypher === "string" ? d.cypher : undefined,
          columns: Array.isArray(d.columns) ? d.columns.map((c) => String(c)) : undefined,
          rows: Array.isArray(d.rows) ? (d.rows as Array<Record<string, unknown>>) : undefined,
          output: d.output,
        });
      } else if (event === "graph") {
        const delta = (d.delta && typeof d.delta === "object" ? d.delta : {}) as { nodes?: unknown[]; edges?: unknown[] };
        for (const n of Array.isArray(delta.nodes) ? delta.nodes : []) {
          const node = (n && typeof n === "object" ? n : {}) as Record<string, unknown>;
          const nid = String(node.id ?? "");
          if (nid !== "" && seenNodes.has(nid)) continue;
          if (nid !== "") seenNodes.add(nid);
          graph.nodes.push(node);
        }
        for (const e of Array.isArray(delta.edges) ? delta.edges : []) {
          const edge = (e && typeof e === "object" ? e : {}) as Record<string, unknown>;
          const k = \`\${edge.from} \${edge.label ?? ""} \${edge.to}\`;
          if (seenEdges.has(k)) continue;
          seenEdges.add(k);
          graph.edges.push(edge);
        }
      } else if (event === "complete") {
        if (typeof d.totalLatencyMs === "number") totalLatencyMs = d.totalLatencyMs;
      } else if (event === "error") {
        runError = typeof d.message === "string" ? d.message : "flow run failed";
      }
    };

    const body = resp.body as ReadableStream<Uint8Array> | null;
    if (body && typeof body.getReader === "function") {
      const reader = body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const blocks = buf.split("\\n\\n");
        buf = blocks.pop() ?? "";
        for (const b of blocks) if (b.trim() !== "") handleBlock(b);
      }
      buf += decoder.decode();
      if (buf.trim() !== "") handleBlock(buf);
    } else {
      const text = await readCappedText(resp);
      for (const b of text.split("\\n\\n")) if (b.trim() !== "") handleBlock(b);
    }

    if (runError !== undefined) throw new WhisperError(\`flow \${slug}: \${runError}\`, { status: 502 });

    // The headline table is the last step that returned rows; else the last step.
    let anchor: FlowStep | null = null;
    for (let i = steps.length - 1; i >= 0; i--) {
      if ((steps[i].rows?.length ?? 0) > 0) { anchor = steps[i]; break; }
    }
    if (anchor === null && steps.length > 0) anchor = steps[steps.length - 1];

    return {
      slug,
      steps,
      anchor,
      columns: anchor?.columns ?? [],
      rows: anchor?.rows ?? [],
      graph,
      present,
      totalLatencyMs,
      events,
      status: resp.status,
    };
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
const flow = sdk.methods.filter((m) => m.mode === "flow").length;
const stub = sdk.methods.length - direct - flow;
console.log(
  `wrote src/graph.ts: ${sdk.methods.length} methods (${direct} direct via /api/query, ` +
    `${flow} flow via gallery/run SSE${stub ? `, ${stub} stubbed` : ""}) + query() raw`,
);
