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
import { detectRuntime, normaliseRequest } from "./tunnel.js";
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

// Node's built-in `fetch` (undici) turns ANY direct, non-proxied HTTP 407 response into an
// opaque `TypeError: fetch failed` network error instead of handing back a normal Response —
// an over-strict reading of the Fetch spec's proxy-authentication step that Firefox's fetch and
// curl do not apply outside an actual CONNECT-proxied request (nodejs/undici#2896, "wontfix": by
// design). The fetch-forward gateway legitimately answers with a real 407 while an egress token
// is still propagating (see the retry loop below), so on Node that 407 is unobservable through
// `fetch()` — the caller here always ends up in the generic-network-error branch and the
// propagation retry can never run. There is no way to opt undici's `fetch()` out of this per
// request, so on Node we bypass it for this ONE call and speak `node:http`/`node:https`
// directly, which is not subject to the Fetch algorithm and returns 407 like any other status.
// Skipped when the caller injects their own `fetch` (tests, custom transports) — that override
// is honoured verbatim, per Postel: liberal in what we accept.
// Minimal structural shape of `node:http`/`node:https` — the project ships no @types/node (it is
// dependency-free, see tunnel.ts's Node adapter for the same pattern), so this is hand-typed to
// exactly what we use rather than pulling in the real (much larger) node typings.
interface NodeHttpResponseLike {
 statusCode?: number;
 statusMessage?: string;
 headers: Record<string, string | string[] | undefined>;
 on(ev: "data", fn: (chunk: Uint8Array) => void): void;
 on(ev: "end", fn: () => void): void;
 on(ev: "error", fn: (e: Error) => void): void;
}
interface NodeHttpRequestLike {
 on(ev: "error", fn: (e: Error) => void): void;
 setTimeout(ms: number, fn: () => void): void;
 destroy(e?: Error): void;
 end(chunk?: Uint8Array): void;
}
interface NodeHttpModuleLike {
 request(
 url: URL,
 options: { method: string; headers: Record<string, string> },
 cb: (res: NodeHttpResponseLike) => void,
 ): NodeHttpRequestLike;
}

async function nodeForwardFetch(
 url: URL,
 init: { method: string; headers: Headers; body?: Uint8Array },
 opts: RequestOptions | undefined,
 what: string,
): Promise<Response> {
 const modName = url.protocol === "http:" ? "node:h" + "ttp" : "node:htt" + "ps";
 const { request } = (await import(modName)) as NodeHttpModuleLike;
 const timeoutMs = opts?.timeoutMs ?? 10_000;
 const headers: Record<string, string> = {};
 init.headers.forEach((v, k) => { headers[k] = v; });
 if (init.body) headers["content-length"] = String(init.body.length);

 return new Promise<Response>((resolve, reject) => {
 let settled = false;
 const done = (fn: () => void) => { if (!settled) { settled = true; fn(); } };
 const req = request(url, { method: init.method, headers }, (res) => {
 const chunks: Uint8Array[] = [];
 res.on("data", (c) => chunks.push(c));
 res.on("end", () => done(() => {
 const respHeaders = new Headers();
 for (const [k, v] of Object.entries(res.headers)) {
 if (v === undefined) continue;
 for (const one of Array.isArray(v) ? v : [v]) {
 try { respHeaders.append(k, one); } catch { /* platform-forbidden header — skip */ }
 }
 }
 const status = res.statusCode ?? 502;
 const nullBody = status === 204 || status === 304 || status < 200;
 const total = chunks.reduce((n, c) => n + c.length, 0);
 const bodyBytes = new Uint8Array(total);
 let off = 0;
 for (const c of chunks) { bodyBytes.set(c, off); off += c.length; }
 resolve(new Response(nullBody ? null : bodyBytes, {
 status,
 statusText: res.statusMessage,
 headers: respHeaders,
 }));
 }));
 res.on("error", (e) => done(() => reject(new WhisperError(`${what} unreachable: ${e.message}`, { status: 0 }))));
 });
 req.on("error", (e) => done(() => reject(new WhisperError(`${what} unreachable: ${e.message}`, { status: 0 }))));
 req.setTimeout(timeoutMs, () => req.destroy(new Error(`${what} timed out after ${timeoutMs}ms`)));
 if (opts?.signal) {
 const onAbort = () => req.destroy(new Error(`${what} aborted`));
 if (opts.signal.aborted) { done(() => reject(new WhisperError(`${what} aborted`, { status: 0 }))); return; }
 opts.signal.addEventListener("abort", onAbort, { once: true });
 }
 if (init.body) req.end(init.body); else req.end();
 });
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

 // Node's fetch cannot observe this gateway's 407 (see nodeForwardFetch above) — bypass it
 // there, UNLESS the caller injected their own `fetch` (tests, custom transports), which is
 // always honoured verbatim.
 let forwardUrlObj: URL | null = null;
 if (!opts.fetch && detectRuntime() === "node") {
 try {
 forwardUrlObj = new URL(forwardUrl);
 } catch {
 throw new WhisperError(`fetch-forward: unparseable forwardUrl "${forwardUrl}"`, { status: 400 });
 }
 }

 let resp: Response | undefined;
 for (let attempt = 1; attempt <= retries; attempt++) {
 resp = forwardUrlObj
 ? await nodeForwardFetch(forwardUrlObj, { method, headers, body: body ?? undefined }, opts, "fetch-forward")
 : await doFetch(forwardUrl, { method, headers, body: outBody }, opts, "fetch-forward");
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
