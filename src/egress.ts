// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// REAL egress execution. `agentEgress(apiKey, selector?)` calls the control plane's `op:connect`,
// then returns a `fetch` that routes EVERY request out through the agent's routable Whisper /128 -
// in-process, with NO CLI and NO local proxy. It is runtime-adaptive: on Node it uses an
// undici ProxyAgent when present (else a built-in `node:net`/`node:tls` CONNECT tunnel); on Deno
// and Cloudflare Workers it opens the CONNECT tunnel over their raw-socket primitives.
//
// The egress bearer returned by `op:connect` is consumed HERE to open the tunnel and is NEVER
// returned to the caller, logged, or persisted - it lives only inside this module's closures.

import { control } from "./control.js";
import { WhisperError } from "./http.js";
import { DEFAULT_FORWARD_URL, forwardFetch } from "./forward.js";
import type { RequestOptions } from "./types.js";
import {
 detectRuntime,
 normaliseRequest,
 openTunnel,
 parseProxy,
 supportsNestedTls,
 tunnelHttp,
} from "./tunnel.js";
import type { EgressRuntime, ProxyEndpoint, TunnelSocket } from "./tunnel.js";

const USER_AGENT = "whisper-edge/0.3";

/** Options for {@link agentEgress}. Extends the shared request knobs with the egress tier. */
export interface EgressOptions extends RequestOptions {
 /** Egress transport to request from `op:connect`. `socks5` (default) and `anyip` both yield an HTTP-CONNECT proxy. */
 tier?: "socks5" | "anyip";
 /**
 * Force the underlying egress transport instead of auto-detecting it from the runtime.
 * `"auto"` (default) opens a raw-socket CONNECT tunnel on Node/Deno/Cloudflare Workers and
 * falls back to the fetch-forward gateway everywhere else - fetch-only sandboxes like
 * Vercel Edge and Netlify Edge, which expose no raw-socket API at all.
 */
 transport?: "auto" | "socket" | "forward";
 /** fetch-forward gateway URL override (pre-prod / self-host). Default {@link DEFAULT_FORWARD_URL}. */
 forwardUrl?: string;
 /** fetch-forward retry attempts on a 407 "not yet propagated" response. Default 4. */
 retries?: number;
 /** fetch-forward delay between retries, ms (kept short and capped). Default 1500. */
 retryDelayMs?: number;
}

/** SAFE, secret-free metadata about an established egress transport (no bearer, ever). */
export interface EgressTransport {
 /** The requested egress tier (e.g. `socks5`). */
 tier: string;
 /** The agent's routable Whisper /128 - the source address your traffic will present. */
 address: string;
 /** The agent's fully-qualified name (reverse-DNS confirms the identity). */
 fqdn: string;
 /** The runtime the egress is running on. */
 runtime: EgressRuntime;
 /** True when the bearer is sent to the proxy INSIDE TLS end-to-end (Node); false on single-TLS edge runtimes. */
 tokenProtected: boolean;
 /** Human-readable description of the transport mechanism (for logs/debugging - carries no secret). */
 mechanism: string;
}

/** The result of {@link agentEgress}: a source-bound `fetch`, safe metadata, and a raw-tunnel escape hatch. */
export interface AgentEgress {
 /** A `fetch` that routes every request out through the agent /128. Drop-in for the global `fetch`. */
 fetch: typeof fetch;
 /** Secret-free description of the transport (never carries the bearer). */
 transport: EgressTransport;
 /**
 * Open a raw, source-bound tunnel socket to `host:port` (TLS by default) for advanced use -
 * a byte stream that egresses from the /128. You own it; call `close()` when done.
 */
 connect(host: string, port: number, tls?: boolean): Promise<TunnelSocket>;
 /** Release any pooled transport resources (e.g. an undici dispatcher). Idempotent. */
 close(): void;
}

/** Try an in-process undici ProxyAgent (Node only). Returns null if undici isn't importable. */
async function undiciTransport(httpProxy: string): Promise<{ fetch: typeof fetch; close: () => void } | null> {
 try {
 // Non-literal specifier: undici is optional (the built-in raw tunnel works without it),
 // and this keeps tsc from requiring it as a dependency. On Deno/Workers this throws → caught.
 const undici = (await import("und" + "ici")) as {
 ProxyAgent?: new (u: string) => { close(): void };
 fetch?: (i: unknown, o: unknown) => Promise<Response>;
 };
 if (!undici || typeof undici.ProxyAgent !== "function") return null;
 const dispatcher = new undici.ProxyAgent(httpProxy);
 // Use undici's OWN fetch (version-matched to its ProxyAgent). Passing a standalone-undici
 // dispatcher to the runtime's built-in fetch can mismatch across undici majors.
 const undiciFetch = typeof undici.fetch === "function"
 ? undici.fetch
 : (globalThis.fetch as unknown as (i: unknown, o: unknown) => Promise<Response>);
 const f = ((input: unknown, init?: unknown) =>
 undiciFetch(input, {...(init as object | undefined), dispatcher })) as unknown as typeof fetch;
 return { fetch: f, close: () => { try { dispatcher.close(); } catch { /* already closed */ } } };
 } catch {
 return null;
 }
}

/** Build a `fetch` that runs each request over a fresh source-bound CONNECT tunnel. */
function tunnelFetch(
 runtime: EgressRuntime,
 proxy: ProxyEndpoint,
 encryptProxyLeg: boolean,
 timeoutMs: number,
): typeof fetch {
 const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
 const { url, method, headers, body } = await normaliseRequest(input, init);
 if (url.protocol !== "https:" && url.protocol !== "http:") {
 throw new WhisperError(`egress: unsupported URL scheme "${url.protocol}" (use http: or https:)`, { status: 400 });
 }
 const target = {
 host: url.hostname,
 port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80,
 tls: url.protocol === "https:",
 };

 let sock: TunnelSocket | null = null;
 let timer: ReturnType<typeof setTimeout> | undefined;
 // On any early exit (timeout / abort / fault) close the socket so we never leak a tunnel.
 const fail = (reason: WhisperError) => { try { sock?.close(); } catch { /* already closed */ } return reason; };
 const external = init?.signal;
 try {
 const run = (async () => {
 sock = await openTunnel(runtime, proxy, target, encryptProxyLeg);
 return tunnelHttp(sock, url, method, headers, body, USER_AGENT);
 })();
 const timeout = new Promise<never>((_, reject) => {
 timer = setTimeout(() => reject(fail(new WhisperError(`egress request timed out after ${timeoutMs}ms`, { status: 0 }))), timeoutMs);
 });
 const races: Array<Promise<Response>> = [run, timeout];
 if (external) {
 races.push(new Promise<never>((_, reject) => {
 const onAbort = () => reject(fail(new WhisperError("egress request aborted", { status: 0 })));
 if (external.aborted) onAbort();
 else external.addEventListener("abort", onAbort, { once: true });
 }));
 }
 return await Promise.race(races);
 } catch (e) {
 if (e instanceof WhisperError) throw e;
 throw fail(new WhisperError(`egress request failed: ${(e as Error)?.message ?? "transport error"}`, { status: 502 }));
 } finally {
 clearTimeout(timer);
 }
 };
 return impl as unknown as typeof fetch;
}

/**
 * Establish REAL egress for an agent and return a `fetch` bound to its /128.
 *
 * ```ts
 * const egress = await agentEgress(process.env.WHISPER_API_KEY!);
 * const who = await egress.fetch("https://rdap.whisper.online/egress-ip").then(r => r.json());
 * // who.ip === egress.transport.address → the request left from YOUR agent's /128
 * ```
 *
 * @param apiKey your `whisper_live_`/`whisper-` owner key (read it from a secret - never hard-code).
 * @param selector an agent id or `/128` to egress as; omit to reuse the most-recent agent.
 * @param opts `{ tier, timeoutMs, endpoints, fetch }` - all optional (zero-config by default).
 */
export async function agentEgress(apiKey: string, selector?: string, opts: EgressOptions = {}): Promise<AgentEgress> {
 const c = control(apiKey, opts);
 const args: Record<string, unknown> = { tier: opts.tier ?? "socks5" };
 if (selector && selector.trim()) args.agent = selector.trim();
 const res = await c.agents("connect", args, opts);
 const rec = res.records[0] ?? {};

 const httpProxy = typeof rec.http_proxy === "string" ? rec.http_proxy : "";
 const address = typeof rec.address === "string" ? rec.address : "";
 const fqdn = typeof rec.fqdn === "string" ? rec.fqdn.replace(/\.$/, "") : "";
 const tier = typeof rec.tier === "string" ? rec.tier : (opts.tier ?? "socks5");
 if (!httpProxy) {
 throw new WhisperError(
 "egress: this tier did not return an HTTP-CONNECT proxy - request tier 'socks5' (the default) or 'anyip' for in-process fetch egress",
 { status: 400 },
 );
 }

 const runtime = detectRuntime();
 const proxy = parseProxy(httpProxy);
 const timeoutMs = opts.timeoutMs ?? 30_000;
 const encryptProxyLeg = supportsNestedTls(runtime); // Node nests TLS → bearer encrypted to the proxy

 // Auto-select fetch-forward on any runtime with no raw-socket API (detectRuntime()
 // can only place Node/Deno/Cloudflare Workers on a socket transport - everything else,
 // including fetch-only sandboxes like Vercel Edge and Netlify Edge, has none). `opts.transport`
 // lets a caller force either side explicitly.
 const wantForward = opts.transport === "forward" || (opts.transport !== "socket" && runtime === "unknown");

 let boundFetch: typeof fetch;
 let closeTransport = () => { /* neither transport keeps pooled state outside undici */ };
 let mechanism: string;
 let tokenProtected: boolean;

 if (wantForward) {
 boundFetch = forwardFetch(proxy.auth, {
...opts,
 forwardUrl: opts.forwardUrl,
 retries: opts.retries,
 retryDelayMs: opts.retryDelayMs,
 timeoutMs,
 });
 mechanism = `fetch-forward gateway (POST ${opts.forwardUrl ?? DEFAULT_FORWARD_URL} - one HTTPS hop)`;
 tokenProtected = true; // the credential rides inside the HTTPS session to the gateway itself
 } else {
 // Node fast-path: a real undici ProxyAgent fetch (full redirect/stream fidelity) when available.
 const undici = runtime === "node" ? await undiciTransport(httpProxy) : null;
 if (undici) {
 boundFetch = undici.fetch;
 closeTransport = undici.close;
 mechanism = "undici ProxyAgent (HTTPS-CONNECT proxy)";
 tokenProtected = proxy.tls; // undici does TLS-to-proxy → bearer encrypted
 } else {
 boundFetch = tunnelFetch(runtime, proxy, encryptProxyLeg, timeoutMs);
 mechanism =
 runtime === "node" ? "node:net + node:tls CONNECT tunnel (nested TLS)"
 : runtime === "deno" ? "Deno.connect + Deno.startTls CONNECT tunnel"
 : runtime === "workers" ? "cloudflare:sockets CONNECT tunnel"
 : "unsupported runtime";
 tokenProtected = encryptProxyLeg && proxy.tls;
 }
 }

 const transport: EgressTransport = { tier, address, fqdn, runtime, tokenProtected, mechanism };
 return {
 fetch: boundFetch,
 transport,
 connect: (host: string, port: number, tls = true) => {
 if (wantForward) {
 return Promise.reject(new WhisperError(
 "egress: this runtime has no raw-socket API and the fetch-forward gateway relays whole HTTP " +
 "requests, not an arbitrary byte stream - use egress.fetch() (already routed through " +
 "fetch-forward) instead, or run on Node, Deno, or Cloudflare Workers for a raw connect()",
 { status: 501 },
 ));
 }
 return openTunnel(runtime, proxy, { host, port, tls }, encryptProxyLeg);
 },
 close: closeTransport,
 };
}
