// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The KEYLESS tier: pure HTTPS, no API key, no CLI, no dependencies. Runs anywhere fetch
// runs. It exposes exactly the same public facts as RDAP, keyed by address/name.

import { WhisperError, doFetch, parseJson, readCappedText } from "./http.ts";
import type { Endpoints, RdapObject, RequestOptions, ResolvedIdentity, VerifyVerdict } from "./types.ts";

/** Canonical public endpoints. Overridable per call via `opts.endpoints`. */
export const DEFAULT_ENDPOINTS: Endpoints = {
  control: "https://graph.whisper.security/api/query",
  rdap: "https://rdap.whisper.online",
  verify: "https://rdap.whisper.online",
};

const USER_AGENT = "whisper-edge/0.3";

export function endpointsFor(opts?: RequestOptions): Endpoints {
  return { ...DEFAULT_ENDPOINTS, ...(opts?.endpoints ?? {}) };
}

/** Percent-encode a query value defensively (a v6 ':' is query-safe and left readable). */
function escapeQuery(s: string): string {
  return s.replace(/%/g, "%25").replace(/ /g, "%20").replace(/#/g, "%23").replace(/&/g, "%26");
}

/** Trim one trailing slash from a base URL. */
function trimBase(u: string): string {
  return u.endsWith("/") ? u.slice(0, -1) : u;
}

/**
 * The full server-side verdict for an agent `address` (its /128 — identity is IP-anchored),
 * or `null` if it is not a Whisper agent. KEYLESS. A 200 → the verdict; a 404 → `null`; a
 * 400 (not a valid address) or any other fault → a WhisperError with the server's clear
 * message. The server never returns a 500. For a forward name, use {@link rdapDomain}.
 */
export async function verifyDetails(address: string, opts?: RequestOptions): Promise<VerifyVerdict | null> {
  const addr = (address ?? "").trim();
  if (addr === "") throw new WhisperError("verify needs an agent address (its /128)", { status: 400 });
  const base = trimBase(endpointsFor(opts).verify);
  const url = `${base}/verify-identity?ip=${escapeQuery(addr)}`;
  const resp = await doFetch(url, { method: "GET", headers: { accept: "application/json", "user-agent": USER_AGENT } }, opts, "verify-identity");
  const text = await readCappedText(resp, 1 << 20);
  if (resp.status === 404) return null;
  const body = parseJson(text, "verify-identity", resp.status);
  if (resp.status >= 400 || body === null || typeof body !== "object") {
    const detail = (body as Record<string, unknown> | null)?.detail;
    throw new WhisperError(typeof detail === "string" ? detail : `verify-identity failed (HTTP ${resp.status})`, { status: resp.status });
  }
  const v = body as VerifyVerdict;
  return v.is_whisper_agent ? v : null;
}

/**
 * Is `address` a real Whisper agent? A boolean convenience over {@link verifyDetails}.
 * KEYLESS. Note: `true` means "is an agent"; inspect the verdict for how strongly it
 * verified (DANE is the load-bearing leg — use {@link resolve} or {@link verifyDetails}).
 */
export async function verify(address: string, opts?: RequestOptions): Promise<boolean> {
  const v = await verifyDetails(address, opts);
  return v !== null && v.is_whisper_agent === true;
}

/**
 * Resolve `address` to a folded, friendly identity view (fqdn, operator, tenant, and the
 * DANE/JWS grades), or `null` if it is not a Whisper agent. KEYLESS. This is the one-call
 * "who is this address" helper.
 */
export async function resolve(address: string, opts?: RequestOptions): Promise<ResolvedIdentity | null> {
  const v = await verifyDetails(address, opts);
  if (!v) return null;
  const base = trimBase(endpointsFor(opts).rdap);
  return {
    address: (address ?? "").trim(),
    isWhisperAgent: v.is_whisper_agent === true,
    fqdn: typeof v.fqdn === "string" ? v.fqdn.replace(/\.$/, "") : null,
    operator: typeof v.operator === "string" ? v.operator : null,
    tenant: typeof v.tenant === "string" ? v.tenant : null,
    daneOk: v.dane_ok === true,
    jwsOk: v.jws_ok === true,
    verifiedAt: typeof v.verified_at === "number" ? v.verified_at : null,
    rdapUrl: `${base}/ip/${escapeQuery((address ?? "").trim())}`,
  };
}

async function rdapFetch(kind: "ip" | "domain", target: string, opts: RequestOptions | undefined, query?: string): Promise<RdapObject | null> {
  const t = (target ?? "").trim();
  if (t === "") throw new WhisperError("RDAP needs a target (an address or a name)", { status: 400 });
  const base = trimBase(endpointsFor(opts).rdap);
  let url = `${base}/${kind}/${escapeQuery(t)}`;
  if (query && query.trim() !== "") url += `?${query.trim()}`;
  const resp = await doFetch(url, { method: "GET", headers: { accept: "application/rdap+json", "user-agent": USER_AGENT } }, opts, "RDAP");
  const text = await readCappedText(resp, 4 << 20);
  if (resp.status === 404) return null;
  const body = parseJson(text, "RDAP", resp.status);
  if (resp.status >= 400) {
    const detail = (body as Record<string, unknown> | null)?.detail;
    throw new WhisperError(typeof detail === "string" ? detail : `RDAP failed (HTTP ${resp.status})`, { status: resp.status });
  }
  return (body as RdapObject) ?? null;
}

/**
 * The public RDAP object (RFC 9083) for a /128 `address`, or `null` if none. KEYLESS.
 * `query` is appended verbatim (e.g. `"history"` or `"time=<instant>"`) for historical RDAP.
 */
export function rdap(address: string, opts?: RequestOptions, query?: string): Promise<RdapObject | null> {
  return rdapFetch("ip", address, opts, query);
}

/** The public RDAP object for a forward `fqdn`, or `null` if none. KEYLESS. */
export function rdapDomain(fqdn: string, opts?: RequestOptions, query?: string): Promise<RdapObject | null> {
  return rdapFetch("domain", fqdn, opts, query);
}
