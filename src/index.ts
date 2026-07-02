// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// whisper-edge — a dependency-free Whisper agent-identity SDK for serverless & edge
// runtimes (Cloudflare Workers, Vercel, Deno, Netlify, AWS Lambda, Supabase Edge).
//
// Two tiers, one Postel-shaped rule:
// • KEYLESS — verify / verifyDetails / resolve / rdap / rdapDomain. Pure HTTPS, no key.
// • CONTROL — control(apiKey).{register,identity,list,agent,policy,logs,connect,revoke}.
//
// Nothing here imports a Node built-in; the only runtime requirement is a global `fetch`,
// which every target provides. Zero runtime dependencies.

export { verify, verifyDetails, resolve, rdap, rdapDomain, DEFAULT_ENDPOINTS } from "./keyless.js";
export { control, WhisperControl } from "./control.js";
export type { ControlOptions, RegisterArgs, IdentityArgs, PolicyArgs, LogsArgs } from "./control.js";
export { WhisperError } from "./http.js";

// EGRESS — route real traffic out through an agent's routable /128 (in-process, no CLI, no proxy).
// Auto-selects a raw-socket CONNECT tunnel (Node/Deno/Cloudflare Workers) or, on fetch-only
// sandboxes with no raw-socket API (Vercel Edge, Netlify Edge, …), the fetch-forward gateway.
export { agentEgress } from "./egress.js";
export type { AgentEgress, EgressOptions, EgressTransport } from "./egress.js";
export { detectRuntime } from "./tunnel.js";
export type { EgressRuntime, TunnelSocket } from "./tunnel.js";
export { DEFAULT_FORWARD_URL, forwardFetch } from "./forward.js";
export type { ForwardOptions } from "./forward.js";

// Low-level building blocks, exported for power users who craft their own queries.
export { buildAgentsQuery, escapeCypherString, quoteCypherString, cypherMap, lit } from "./cypher.js";
export { decodeEnvelope } from "./envelope.js";
export type { Envelope } from "./envelope.js";

export type {
 Endpoints,
 RequestOptions,
 VerifyVerdict,
 ResolvedIdentity,
 RdapObject,
 Problem,
 ControlResult,
} from "./types.js";
