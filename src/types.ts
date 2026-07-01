// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

/**
 * Canonical Whisper endpoints. `control` is the ONE control-plane surface (it takes an
 * API key); `rdap` and `verify` are the public, KEYLESS surfaces. Every field is
 * overridable (Postel: liberal in what we accept — but a sane zero-config default).
 */
export interface Endpoints {
  /** Control plane: POST here with `{query}` + an API key. */
  control: string;
  /** Public RDAP base (RFC 9083): GET `/ip/<addr>`, `/domain/<fqdn>`. */
  rdap: string;
  /** Public verify base: GET `/verify-identity?ip=<addr>`. */
  verify: string;
}

/**
 * Per-call knobs. All optional — the common case is zero-config. `fetch` lets you inject
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
}

/**
 * The full server-side verdict from the KEYLESS verify surface: the whole Whisper-agent
 * trust chain (reverse-DNS PTR + forward-confirm AAAA + the DANE-EE TLSA pin + the JWS
 * identity doc) folded into one answer. `dane_ok` is the load-bearing field — DANE
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

/** A folded, friendly identity view — the ergonomic result of `resolve()`. */
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

/** An RDAP object (RFC 9083) — a stable, public JSON schema returned verbatim. */
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
  /** Column-keyed maps, one per row — the form you usually read. */
  records: Array<Record<string, unknown>>;
  /** The verbatim JSON body the server returned (no field loss). */
  raw: unknown;
  /** The (effective) HTTP/envelope status. */
  status: number;
}
