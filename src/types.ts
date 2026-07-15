// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

/**
 * Canonical Whisper endpoints. `control` is the ONE control-plane surface (it takes an
 * API key); `rdap` and `verify` are the public, KEYLESS surfaces. Every field is
 * overridable (Postel: liberal in what we accept - but a sane zero-config default).
 */
export interface Endpoints {
  /** Control plane: POST here with `{query}` + an API key. */
  control: string;
  /** Public RDAP base (RFC 9083): GET `/ip/<addr>`, `/domain/<fqdn>`. */
  rdap: string;
  /** Public verify base: GET `/verify-identity?ip=<addr>`. */
  verify: string;
  /** Catalog FLOW runner: POST `{slug, inputs, params}` + an API key; result streams over SSE. */
  flowRun: string;
}

/**
 * Per-call knobs. All optional - the common case is zero-config. `fetch` lets you inject
 * a runtime's fetch (or a mock in tests); by default the global `fetch` is used, which
 * exists in every target runtime (Workers, Deno, Vercel, Netlify, Lambda 18+, Supabase).
 */
export interface RequestOptions {
  /** Abort the request after this many milliseconds (default 10000). */
  timeoutMs?: number;
  /** An external AbortSignal; merged with the internal timeout. */
  signal?: AbortSignal;
  /** Override the runtime fetch (tests, custom transports). Defaults to global fetch. */
  fetch?: typeof fetch;
  /** Override any endpoint (pre-prod / self-host). */
  endpoints?: Partial<Endpoints>;
  /**
   * Observe each Server-Sent-Event of a FLOW run as it arrives (progressive rendering).
   * The returned promise still resolves with the full aggregate; an observer that throws
   * is swallowed so it can never break the run.
   */
  onFlowEvent?: (event: string, data: unknown) => void;
}

/**
 * The full server-side verdict from the KEYLESS verify surface: the whole Whisper-agent
 * trust chain (reverse-DNS PTR + forward-confirm AAAA + the DANE-EE TLSA pin + the JWS
 * identity doc) folded into one answer. `dane_ok` is the load-bearing field - DANE
 * (DNSSEC-anchored TLSA) is the trust anchor for an agent cert, not a public CA.
 */
export interface VerifyVerdict {
  is_whisper_agent: boolean;
  fqdn?: string;
  operator?: string;
  tenant?: string;
  dane_ok?: boolean;
  jws_ok?: boolean;
  verified_at?: number;
  detail?: string;
  /** Verbatim evidence object (address, ptr, the dane sub-object, RDAP/identity URLs). */
  evidence?: unknown;
  [k: string]: unknown;
}

/** A folded, friendly identity view - the ergonomic result of `resolve()`. */
export interface ResolvedIdentity {
  address: string;
  isWhisperAgent: boolean;
  fqdn: string | null;
  operator: string | null;
  tenant: string | null;
  daneOk: boolean;
  jwsOk: boolean;
  verifiedAt: number | null;
  /** The public RDAP URL for this address (fetch it for the full record). */
  rdapUrl: string;
}

/** An RDAP object (RFC 9083) - a stable, public JSON schema returned verbatim. */
export type RdapObject = Record<string, unknown>;

/** The RFC-7807 problem the control plane returns on failure. */
export interface Problem {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  suggestions?: string[];
}

/** A normalised control-plane result: column names + rows + the ergonomic record view. */
export interface ControlResult {
  columns: string[];
  rows: unknown[][];
  /** Column-keyed maps, one per row - the form you usually read. */
  records: Array<Record<string, unknown>>;
  /** The verbatim JSON body the server returned (no field loss). */
  raw: unknown;
  /** The (effective) HTTP/envelope status. */
  status: number;
}

/** Cypher $-parameters, keyed by name, for a graph query (values are bound, never spliced). */
export type GraphParams = Record<string, unknown>;

/**
 * One catalog entry as returned by `graph().recipes()`: everything needed to discover and
 * call a graph verb. `keyless: true` verbs serve with NO API key at all (rate-limited);
 * keyed ones need a key. `docsUrl` is the verb's canonical reference page. Baked from the
 * Whisper query catalog at build time: no key, no network.
 */
export interface Recipe {
  /** The method name on WhisperGraph (e.g. "assess", "typosquat"). */
  method: string;
  /** True when the verb serves with no API key (a key lifts the rate limit). */
  keyless: boolean;
  /** "direct" = one Cypher read; "flow" = a multi-step investigation over SSE. */
  mode: "direct" | "flow";
  /** A one-line summary of what the verb answers. */
  summary: string;
  /** Positional parameter names, in order. */
  params: string[];
  /** The canonical docs page for this verb. */
  docsUrl: string;
}

/** Query statistics the graph endpoint returns alongside the rows. */
export interface GraphStatistics {
  /** Number of rows in the result. */
  rowCount?: number;
  /** Server-side execution time in milliseconds. */
  executionTimeMs?: number;
  [k: string]: unknown;
}

/**
 * A result from the KEYED graph endpoint (POST /api/query). Unlike {@link ControlResult},
 * the graph envelope returns each row as an OBJECT keyed by column name, so `rows` here is
 * an array of column-keyed maps (read them directly). `columns` preserves column order,
 * `statistics` carries the row count + timing, and `raw` is the verbatim body (no loss).
 */
export interface GraphResult {
  /** Column names in order. */
  columns: string[];
  /** One column-keyed map per row (the graph envelope's native, object-row shape). */
  rows: Array<Record<string, unknown>>;
  /** Row count + execution time reported by the server. */
  statistics: GraphStatistics;
  /** The verbatim JSON body the server returned (no field loss). */
  raw: unknown;
  /** The (effective) HTTP status. */
  status: number;
}

/**
 * User-tunable FLOW parameters (e.g. `level`, `depth`, `instanceType`), keyed by name.
 * Merged over the flow's declared defaults and coerced server-side; a value is bound,
 * never spliced into a query.
 */
export type FlowParams = Record<string, string | number | boolean | string[]>;

/** One step of a catalog FLOW run - a `step` SSE event, in the order the runner emitted it. */
export interface FlowStep {
  /** The step id (a flow-local slug, e.g. "verdict", "registered"). */
  id: string;
  /** Human title, when the step carries one. */
  title?: string;
  /** Terminal status the runner reported (e.g. "done"). */
  status?: string;
  /** The Cypher this step ran (present on query steps). */
  cypher?: string;
  /** Column names for this step's table, in order. */
  columns?: string[];
  /** This step's rows, each an object keyed by column name. */
  rows?: Array<Record<string, unknown>>;
  /** A structured presentation payload, when the step produced one. */
  output?: unknown;
  [k: string]: unknown;
}

/**
 * The aggregated result of a catalog FLOW (a multi-step investigation) run through the
 * gallery runner over SSE. `steps` is every step in order; `columns`/`rows` are the
 * headline table (the last step that returned rows) for a quick read; `graph` is the
 * unioned node/edge picture the runner streamed; `present` is the runner's final
 * presentation payload, if any; `events` is the verbatim SSE record (no field loss).
 */
export interface FlowResult {
  /** The flow slug that ran. */
  slug: string;
  /** Every `step` event, in order (the internal `__present` step is folded into `present`). */
  steps: FlowStep[];
  /** The headline step (the last one that returned rows), or null if none did. */
  anchor: FlowStep | null;
  /** The headline table's columns (from `anchor`). */
  columns: string[];
  /** The headline table's rows (from `anchor`), each keyed by column name. */
  rows: Array<Record<string, unknown>>;
  /** The unioned graph the runner streamed (nodes + edges, de-duplicated). */
  graph: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> };
  /** The runner's final presentation payload (the `__present` step's output), if any. */
  present?: unknown;
  /** Total server-side run latency, when the `complete` event reported it. */
  totalLatencyMs?: number;
  /** The verbatim SSE event record: every `{event, data}` in order (no field loss). */
  events: Array<{ event: string; data: unknown }>;
  /** The (effective) HTTP status of the run request. */
  status: number;
}
