// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The FETCH-FORWARD egress transport. For runtimes with no raw-socket API
// (fetch-only sandboxes — Vercel Edge, Netlify Edge, and anything `detectRuntime()` cannot place
// on Node/Deno/Cloudflare Workers), a raw CONNECT tunnel is impossible: there is no socket to open.
// Instead we route the WHOLE request through one small, server-side HTTPS hop:
//
// <method> https://forward.whisper.online/forward
// Authorization: Basic base64("w:"+<et_ bearer>) (same credential as the CONNECT proxy)
// X-Whisper-Target: <the absolute https:// URL being fetched>
// X-Whisper-Method: <the method — mirrored on the outer request too, belt-and-braces>
//
// The gateway egresses server-side sourced from the agent's routable Whisper /128 and streams
// the target's response straight back, stamped with `X-Whisper-Egress-Source: <the /128>`. One
// HTTPS hop, no local proxy, no raw socket needed — this is the ONLY egress path that works in
// literally every fetch runtime, including ones that will never grow a raw-socket API.
//
// — a freshly-minted egress token can take up to ~45s to propagate to every gateway
// node, and a 407 in that window means "not recognised HERE yet", not "bad token" —
// so we retry a short, capped number of times with a small fixed delay. In practice this
// converges in one or two extra attempts (a different node, or the same node once it catches
// up); we do not wait out the full 45s on every call, only enough hops to very likely land on
// a node that already knows the token.
//
// Robustness Principle (RFC 761): conservative in what we EMIT — the auth header carries the
// bearer and nothing else about it is ever logged; liberal in what we ACCEPT — string | URL |
// Request inputs, any HTTP method, and a persistent 407 surfaces a clear, actionable error
// instead of an opaque proxy failure.

import { doFetch, WhisperError } from "./http.js";
import { normaliseRequest } from "./tunnel.js";
import type { RequestOptions } from "./types.js";

/** The canonical fetch-forward gateway. Overridable for pre-prod / self-host. */
export const DEFAULT_FORWARD_URL = "https://forward.whisper.online/forward";

/** Default retry budget: short and capped — a handful of quick attempts, not a 45s wait. */
const DEFAULT_RETRIES = 4;
const DEFAULT_RETRY_DELAY_MS = 1500;

/** Options for {@link forwardFetch}. */
export interface ForwardOptions extends RequestOptions {
 /** Override the fetch-forward gateway URL (pre-prod / self-host). Default {@link DEFAULT_FORWARD_URL}. */
 forwardUrl?: string;
 /** Max attempts on a 407 "token not yet propagated" response. Default 4. */
 retries?: number;
 /** Delay between retries, ms — kept short and capped (~1-2s apart). Default 1500. */
 retryDelayMs?: number;
}

function sleep(ms: number): Promise<void> {
 return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Build a `fetch`-compatible function that routes every request through the fetch-forward
 * gateway, authenticated with an already-built `Basic base64("w:"+bearer)` auth header
 * value (e.g. from `parseProxy(http_proxy).auth` — the SAME credential the CONNECT-tunnel
 * transport uses). Retries a 407 with a short capped backoff.
 *
 * This is a low-level building block — most callers get it for free via {@link agentEgress},
 * which auto-selects it on fetch-only runtimes. Use it directly only if you already hold a
 * pre-built `Authorization` header value (e.g. from a custom `op:connect` call).
 */
export function forwardFetch(authHeader: string, opts: ForwardOptions = {}): typeof fetch {
 const forwardUrl = opts.forwardUrl ?? DEFAULT_FORWARD_URL;
 const retries = Math.max(1, opts.retries ?? DEFAULT_RETRIES);
 const retryDelayMs = Math.max(0, opts.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS);

 const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
 const { url, method, headers, body } = await normaliseRequest(input, init);
 if (url.protocol !== "https:") {
 throw new WhisperError(
 `fetch-forward: unsupported URL scheme "${url.protocol}" (the gateway forwards https: targets only)`,
 { status: 400 },
 );
 }
 // The gateway's own credential takes this header slot (Proxy-Authorization isn't forwardable
 // through a plain fetch on every runtime); if YOUR target itself needs bearer auth, carry it
 // in a different header or embed it in the target URL — this slot belongs to the gateway.
 headers.set("authorization", authHeader);
 headers.set("x-whisper-target", url.href);
 headers.set("x-whisper-method", method); // belt-and-braces: the gateway mirrors the outer method too

 // Cast: Uint8Array is a valid BufferSource/BodyInit at runtime on every target fetch
 // implementation; TS's DOM lib types pin BodyInit to a concrete ArrayBuffer-backed generic
 // that our shared, runtime-agnostic Uint8Array (from normaliseRequest) doesn't structurally match.
 const outBody = (body ?? undefined) as BodyInit | undefined;
 let resp: Response | undefined;
 for (let attempt = 1; attempt <= retries; attempt++) {
 resp = await doFetch(forwardUrl, { method, headers, body: outBody }, opts, "fetch-forward");
 if (resp.status !== 407) return resp;
 if (attempt < retries) await sleep(retryDelayMs);
 }
 // A freshly-minted token can take up to ~45s to reach every gateway node; a 407 still seen
 // after the whole (short, capped) retry budget is worth a clear, actionable error rather
 // than handing back an opaque proxy-auth failure.
 const waited = ((retries - 1) * retryDelayMs) / 1000;
 throw new WhisperError(
 `fetch-forward: the gateway still rejected the egress token after ${retries} attempts (~${waited}s) — ` +
 "a freshly-minted token can take up to ~45s to propagate to every gateway node; wait a moment and " +
 "retry, or mint a fresh token via connect()",
 { status: 407 },
 );
 };
 return impl as unknown as typeof fetch;
}
