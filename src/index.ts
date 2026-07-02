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

export { verify, verifyDetails, resolve, rdap, rdapDomain, DEFAULT_ENDPOINTS } from "./keyless.ts";
export { control, WhisperControl } from "./control.ts";
export type { ControlOptions, RegisterArgs, IdentityArgs, PolicyArgs, LogsArgs } from "./control.ts";
export { WhisperError } from "./http.ts";

// EGRESS — route real traffic out through an agent's routable /128 (in-process, no CLI, no proxy).
// Auto-selects a raw-socket CONNECT tunnel (Node/Deno/Cloudflare Workers) or, on fetch-only
// sandboxes with no raw-socket API (Vercel Edge, Netlify Edge, …), the fetch-forward gateway.
export { agentEgress } from "./egress.ts";
export type { AgentEgress, EgressOptions, EgressTransport } from "./egress.ts";
export { detectRuntime } from "./tunnel.ts";
export type { EgressRuntime, TunnelSocket } from "./tunnel.ts";
export { DEFAULT_FORWARD_URL, forwardFetch } from "./forward.ts";
export type { ForwardOptions } from "./forward.ts";

// Low-level building blocks, exported for power users who craft their own queries.
export { buildAgentsQuery, escapeCypherString, quoteCypherString, cypherMap, lit } from "./cypher.ts";
export { decodeEnvelope } from "./envelope.ts";
export type { Envelope } from "./envelope.ts";

export type {
 Endpoints,
 RequestOptions,
 VerifyVerdict,
 ResolvedIdentity,
 RdapObject,
 Problem,
 ControlResult,
} from "./types.ts";
