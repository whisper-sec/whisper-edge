// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The CONTROL tier: the full agent control plane, unlocked with an API key. One verb —
// CALL whisper.agents({op, args}) — POSTed to graph.whisper.security/api/query. The key
// is sent as X-API-Key and is NEVER logged or echoed. Pure fetch, zero dependencies.

import { buildAgentsQuery } from "./cypher.js";
import { decodeEnvelope } from "./envelope.js";
import { WhisperError, doFetch, parseJson, readCappedText } from "./http.js";
import { endpointsFor } from "./keyless.js";
import type { ControlResult, RequestOptions } from "./types.js";

const USER_AGENT = "whisper-edge/0.2";

/** Options for creating a control client. */
export interface ControlOptions extends RequestOptions {}

export interface RegisterArgs {
  /** The agent's human name (surfaced by list + RDAP). */
  name: string;
  /** Optional opt-in public contact email (surfaced in RDAP). */
  email?: string;
}

export interface IdentityArgs {
  name?: string;
  email?: string;
  /** Release (IRREVERSIBLE) the /128 at this address. */
  release?: boolean;
  address?: string;
}

export interface PolicyArgs {
  /** Names to block (default action stays as configured). */
  block?: string[];
  /** Names to allow. */
  allow?: string[];
  /** Default action: "allow" | "deny". */
  default?: "allow" | "deny";
}

export interface LogsArgs {
  /** Narrow to one agent (id or /128 address). */
  agent?: string;
  /** "dns" | "conn" | "alloc" | "all" (omit for all). */
  kind?: string;
  /** Window start (epoch-ms, RFC-3339, or relative like "-1h"). */
  from?: string;
  /** Window end. */
  to?: string;
  /** Max rows (default 1000, cap 10k). */
  limit?: number;
}

/**
 * The Whisper control plane, authenticated with an owner API key. Every method runs one
 * `whisper.agents` op and returns the normalised {@link ControlResult}. Confined to YOUR
 * tenant by the key. Runs in any fetch runtime — no CLI, no Node built-ins.
 */
export class WhisperControl {
  private readonly key: string;
  private readonly opts: ControlOptions;

  constructor(apiKey: string, opts: ControlOptions = {}) {
    const k = (apiKey ?? "").trim();
    if (k === "") {
      throw new WhisperError("no API key — pass your whisper_live_ key (never hard-code it; read it from the environment)", { status: 401 });
    }
    this.key = k;
    this.opts = opts;
  }

  private merge(extra?: RequestOptions): RequestOptions {
    return { ...this.opts, ...extra, endpoints: { ...this.opts.endpoints, ...extra?.endpoints } };
  }

  /** Run an arbitrary control-plane Cypher query and return the normalised result. */
  async query(cypher: string, reqOpts?: RequestOptions): Promise<ControlResult> {
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
        body: JSON.stringify({ query: cypher }),
      },
      o,
      "control plane",
    );
    const text = await readCappedText(resp);
    const body = parseJson(text, "control plane", resp.status);
    const env = decodeEnvelope(body, resp.status);
    if (!env.ok || env.problem) {
      const p = env.problem ?? { status: env.status };
      throw new WhisperError(p.detail ?? p.title ?? `control plane returned status ${p.status ?? env.status}`, p);
    }
    return env.result ?? { columns: [], rows: [], records: [], raw: body, status: env.status };
  }

  /** Run `CALL whisper.agents({op, args})` and return the normalised result. */
  agents(op: string, args?: Record<string, unknown>, reqOpts?: RequestOptions): Promise<ControlResult> {
    return this.query(buildAgentsQuery(op, args), reqOpts);
  }

  /**
   * Mint a BRAND-NEW agent with its own routable /128 AND its own API key (op:register).
   * The new key appears in the returned record as `api_key` and is shown ONCE — capture it.
   */
  register(args: RegisterArgs, reqOpts?: RequestOptions): Promise<ControlResult> {
    const name = (args.name ?? "").trim();
    if (name === "") throw new WhisperError("register needs a name", { status: 400 });
    const a: Record<string, unknown> = { label: name };
    if (args.email?.trim()) a.contact_email = args.email.trim();
    return this.agents("register", a, reqOpts);
  }

  /** Create (or, with `release`, tear down) the caller's own /128 identity (op:identity). */
  identity(args: IdentityArgs = {}, reqOpts?: RequestOptions): Promise<ControlResult> {
    const a: Record<string, unknown> = {};
    if (args.name?.trim()) a.label = args.name.trim();
    if (args.email?.trim()) a.contact_email = args.email.trim();
    if (args.release) a.release = true;
    if (args.address?.trim()) a.address = args.address.trim();
    return this.agents("identity", a, reqOpts);
  }

  /** List your agents (kind: "agents" | "records" | "identities"; default "agents"). */
  list(kind = "agents", reqOpts?: RequestOptions): Promise<ControlResult> {
    return this.agents("list", { kind }, reqOpts);
  }

  /** Per-agent detail + live counters. `selector` is an agent id or a /128 address. */
  agent(selector: string, reqOpts?: RequestOptions): Promise<ControlResult> {
    const s = (selector ?? "").trim();
    if (s === "") throw new WhisperError("agent needs an <agent|address>", { status: 400 });
    const a: Record<string, unknown> = s.includes(":") ? { address: s } : { agent: s };
    return this.agents("agent", a, reqOpts);
  }

  /** Read (no args) or set the caller's per-tenant DNS resolver policy (op:policy). */
  policy(args: PolicyArgs = {}, reqOpts?: RequestOptions): Promise<ControlResult> {
    const a: Record<string, unknown> = {};
    if (args.block?.length) a.block = args.block;
    if (args.allow?.length) a.allow = args.allow;
    if (args.default) a.default = args.default;
    return this.agents("policy", a, reqOpts);
  }

  /** Query recent DNS / connection / allocation activity from warm storage (op:logs). */
  logs(args: LogsArgs = {}, reqOpts?: RequestOptions): Promise<ControlResult> {
    const a: Record<string, unknown> = {};
    if (args.agent?.trim()) a.agent = args.agent.trim();
    if (args.kind?.trim()) a.kind = args.kind.trim();
    if (args.from?.trim()) a.from = args.from.trim();
    if (args.to?.trim()) a.to = args.to.trim();
    if (typeof args.limit === "number" && args.limit > 0) a.limit = args.limit;
    return this.agents("logs", a, reqOpts);
  }

  /** Fetch egress-connection info for an agent (op:connect). `selector` is optional. */
  connect(selector?: string, reqOpts?: RequestOptions): Promise<ControlResult> {
    const a: Record<string, unknown> = {};
    if (selector?.trim()) a.agent = selector.trim();
    return this.agents("connect", a, reqOpts);
  }

  /** FULLY revoke an agent — withdraw its /128, PTR, tokens, and API key (op:revoke). */
  revoke(agent: string, reqOpts?: RequestOptions): Promise<ControlResult> {
    const s = (agent ?? "").trim();
    if (s === "") throw new WhisperError("revoke needs an <agent>", { status: 400 });
    return this.agents("revoke", { agent: s }, reqOpts);
  }
}

/** Create a control client bound to `apiKey`. Sugar for `new WhisperControl(apiKey, opts)`. */
export function control(apiKey: string, opts?: ControlOptions): WhisperControl {
  return new WhisperControl(apiKey, opts);
}
