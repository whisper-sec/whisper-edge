// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The EGRESS transport: a runtime-adaptive HTTP-CONNECT tunnel that routes a request through
// the agent's routable Whisper /128. It speaks the SAME wire on three socket primitives —
// Node's `node:net`/`node:tls`, Deno's `Deno.connect`/`Deno.startTls`, and Cloudflare's
// `cloudflare:sockets` `connect()`/`startTls()` — so egress works in-process, with NO CLI and
// NO local proxy process, on every serverless & edge runtime that exposes raw sockets.
//
// Robustness Principle (RFC 761): conservative in what we EMIT — the CONNECT preamble and the
// forwarded request are strict HTTP/1.1; the egress bearer is used to open the tunnel and is
// NEVER returned, logged, or persisted (it lives only inside this module's closures). Liberal
// in what we ACCEPT — string | URL | Request inputs, both chunked and Content-Length framing,
// and a clear error (never an opaque hang) on any transport fault.

import { WhisperError } from "./http.js";

/** The runtimes we can open a raw socket on (everything else is fetch-only — see {@link detectRuntime}). */
export type EgressRuntime = "node" | "deno" | "workers" | "unknown";

/**
 * A minimal duplex byte stream over ONE connection, uniform across runtimes. `read()` yields the
 * next chunk or `null` at EOF; `write()` sends bytes; `startTls()` upgrades THIS connection to TLS
 * and returns the upgraded socket (the old handle must not be used after).
 */
export interface TunnelSocket {
 read(): Promise<Uint8Array | null>;
 write(bytes: Uint8Array): Promise<void>;
 startTls(hostname: string): Promise<TunnelSocket>;
 close(): void;
}

/** A parsed egress proxy endpoint. `auth` is the ready-to-send `Proxy-Authorization` value. */
export interface ProxyEndpoint {
 host: string;
 port: number;
 /** The proxy speaks TLS (an `https://` proxy) — its leg can be encrypted where the runtime allows it. */
 tls: boolean;
 /** `Basic base64(user:pass)` — carries the egress bearer; NEVER expose or log this. */
 auth: string;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Concatenate two byte arrays. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
 const out = new Uint8Array(a.length + b.length);
 out.set(a);
 out.set(b, a.length);
 return out;
}

/** Index just past the first CRLFCRLF (end of an HTTP header block), or -1. */
function endOfHeaders(b: Uint8Array): number {
 for (let i = 0; i + 3 < b.length; i++) {
 if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i + 4;
 }
 return -1;
}

/** base64 of an ASCII string, on whichever primitive the runtime provides. */
function base64(s: string): string {
 const g = globalThis as unknown as { btoa?: (x: string) => string; Buffer?: { from(x: string, e: string): { toString(e: string): string } } };
 if (typeof g.btoa === "function") return g.btoa(s);
 if (g.Buffer) return g.Buffer.from(s, "binary").toString("base64");
 // Last-resort tiny encoder (all target runtimes have btoa or Buffer, so this is defensive only).
 const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 let out = "";
 for (let i = 0; i < s.length; i += 3) {
 const a = s.charCodeAt(i), b = i + 1 < s.length ? s.charCodeAt(i + 1) : 0, c = i + 2 < s.length ? s.charCodeAt(i + 2) : 0;
 out += t[a >> 2] + t[((a & 3) << 4) | (b >> 4)] + (i + 1 < s.length ? t[((b & 15) << 2) | (c >> 6)] : "=") + (i + 2 < s.length ? t[c & 63] : "=");
 }
 return out;
}

/**
 * Parse the `op:connect` `http_proxy` field (`https://w:<et_bearer>@egress.whisper.online`) into a
 * {@link ProxyEndpoint}. The userinfo becomes `Proxy-Authorization: Basic base64(user:pass)` — the
 * exact form the egress proxy expects. The bearer never leaves this object.
 */
export function parseProxy(httpProxy: string): ProxyEndpoint {
 let u: URL;
 try {
 u = new URL(httpProxy);
 } catch {
 throw new WhisperError("egress: the control plane returned an unparseable proxy endpoint", { status: 502 });
 }
 const tls = u.protocol === "https:";
 const user = decodeURIComponent(u.username);
 const pass = decodeURIComponent(u.password);
 const auth = "Basic " + base64(user + ":" + pass);
 return { host: u.hostname, port: u.port ? Number(u.port) : tls ? 443 : 80, tls, auth };
}

/**
 * Detect the current runtime from its globals. Order matters: Deno and Workers ship a partial
 * `process` shim, so they are tested before Node.
 */
export function detectRuntime(): EgressRuntime {
 const g = globalThis as Record<string, unknown>;
 const deno = g.Deno as { connect?: unknown } | undefined;
 if (deno && typeof deno.connect === "function") return "deno";
 const nav = g.navigator as { userAgent?: string } | undefined;
 if (nav && nav.userAgent === "Cloudflare-Workers") return "workers";
 const proc = g.process as { versions?: { node?: string } } | undefined;
 if (proc && proc.versions && proc.versions.node) return "node";
 return "unknown";
}

/** True iff this runtime can wrap TLS-inside-TLS (only Node's `tls.connect({socket})` can). */
export function supportsNestedTls(runtime: EgressRuntime): boolean {
 return runtime === "node";
}

// ── Node adapter (node:net + node:tls) ───────────────────────────────────────────────────────
// Pull-based reads (attach a one-shot listener, then pause) so no bytes are buffered by us across
// a startTls() — `tls.connect({socket})` then owns the underlying stream cleanly (nested TLS OK).

function nodeSock(s: NodeSocketLike): TunnelSocket {
 return {
 read() {
 return new Promise<Uint8Array | null>((resolve, reject) => {
 const onData = (d: Uint8Array) => { done(); resolve(new Uint8Array(d)); };
 const onEnd = () => { done(); resolve(null); };
 const onErr = (e: Error) => { done(); reject(e); };
 const done = () => { s.off("data", onData); s.off("end", onEnd); s.off("error", onErr); s.off("close", onEnd); s.pause(); };
 s.on("data", onData); s.on("end", onEnd); s.on("error", onErr); s.on("close", onEnd); s.resume();
 });
 },
 write(bytes) {
 return new Promise<void>((resolve, reject) => s.write(bytes, (e?: Error | null) => (e ? reject(e) : resolve())));
 },
 async startTls(hostname) {
 s.removeAllListeners("data"); s.removeAllListeners("end"); s.removeAllListeners("error"); s.removeAllListeners("close");
 const tls = (await import("node:t" + "ls")) as { connect(o: unknown): NodeSocketLike };
 const t = tls.connect({ socket: s, servername: hostname });
 await new Promise<void>((resolve, reject) => { t.once("secureConnect", () => resolve()); t.once("error", reject); });
 t.pause();
 return nodeSock(t);
 },
 close() { try { s.destroy(); } catch { /* already closed */ } },
 };
}

interface NodeSocketLike {
 on(ev: string, fn: (...a: never[]) => void): void;
 off(ev: string, fn: (...a: never[]) => void): void;
 once(ev: string, fn: (...a: never[]) => void): void;
 removeAllListeners(ev: string): void;
 write(b: Uint8Array, cb: (e?: Error | null) => void): void;
 pause(): void;
 resume(): void;
 destroy(): void;
 setNoDelay?(v: boolean): void;
}

async function nodeOpen(host: string, port: number): Promise<TunnelSocket> {
 const net = (await import("node:n" + "et")) as { connect(o: unknown): NodeSocketLike };
 const s = net.connect({ host, port });
 await new Promise<void>((resolve, reject) => { s.once("connect", () => resolve()); s.once("error", reject); });
 s.setNoDelay?.(true);
 s.pause();
 return nodeSock(s);
}

// ── Deno adapter (Deno.connect + Deno.startTls) ──────────────────────────────────────────────

interface DenoConnLike {
 read(p: Uint8Array): Promise<number | null>;
 write(p: Uint8Array): Promise<number>;
 close(): void;
}
interface DenoNs {
 connect(o: { hostname: string; port: number }): Promise<DenoConnLike>;
 startTls(c: DenoConnLike, o: { hostname: string }): Promise<DenoConnLike>;
}

function denoSock(conn: DenoConnLike): TunnelSocket {
 const D = (globalThis as unknown as { Deno: DenoNs }).Deno;
 return {
 async read() {
 const b = new Uint8Array(16384);
 const n = await conn.read(b);
 return n === null ? null : b.subarray(0, n);
 },
 async write(bytes) {
 let off = 0;
 while (off < bytes.length) off += await conn.write(bytes.subarray(off));
 },
 async startTls(hostname) {
 return denoSock(await D.startTls(conn, { hostname }));
 },
 close() { try { conn.close(); } catch { /* already closed */ } },
 };
}

async function denoOpen(host: string, port: number): Promise<TunnelSocket> {
 const D = (globalThis as unknown as { Deno: DenoNs }).Deno;
 return denoSock(await D.connect({ hostname: host, port }));
}

// ── Cloudflare Workers adapter (cloudflare:sockets) ──────────────────────────────────────────

interface CfSocket {
 readable: ReadableStream<Uint8Array>;
 writable: WritableStream<Uint8Array>;
 startTls(): CfSocket;
 close(): Promise<void> | void;
}

function workersSock(socket: CfSocket): TunnelSocket {
 const reader = socket.readable.getReader();
 const writer = socket.writable.getWriter();
 return {
 async read() {
 const { value, done } = await reader.read();
 return done ? null : (value as Uint8Array);
 },
 async write(bytes) { await writer.write(bytes); },
 async startTls(_hostname) {
 // workerd's startTls() takes no arguments (the server name follows the tunneled target).
 // Release this layer's stream locks, then wrap the upgraded socket (which re-locks them).
 reader.releaseLock();
 writer.releaseLock();
 return workersSock(socket.startTls());
 },
 close() { try { void socket.close(); } catch { /* already closed */ } },
 };
}

async function workersOpen(host: string, port: number): Promise<TunnelSocket> {
 const mod = (await import("cloudflare:sockets")) as { connect(a: { hostname: string; port: number }, o: { secureTransport: string; allowHalfOpen: boolean }): CfSocket };
 const socket = mod.connect({ hostname: host, port }, { secureTransport: "starttls", allowHalfOpen: false });
 return workersSock(socket);
}

/** Open a raw TCP socket on the detected runtime, or fail with a clear, actionable error. */
export async function openSocket(runtime: EgressRuntime, host: string, port: number): Promise<TunnelSocket> {
 switch (runtime) {
 case "node": return nodeOpen(host, port);
 case "deno": return denoOpen(host, port);
 case "workers": return workersOpen(host, port);
 default:
 throw new WhisperError(
 "egress: this runtime has no raw-socket API, so a raw connect() cannot run here. " +
 "egress.fetch() already auto-routes through the fetch-forward gateway on this runtime — " +
 "use that instead, or run on Node, Deno, or Cloudflare Workers for a raw connect().",
 { status: 501 },
 );
 }
}

/** Read from `sock` until the HTTP header terminator, returning [headerText, leftoverBodyBytes]. */
async function readHead(sock: TunnelSocket, cap = 256 * 1024): Promise<[string, Uint8Array]> {
 let buf: Uint8Array = new Uint8Array(0);
 for (;;) {
 const at = endOfHeaders(buf);
 if (at >= 0) return [dec.decode(buf.subarray(0, at)), buf.subarray(at)];
 if (buf.length > cap) throw new WhisperError("egress: response header block too large", { status: 502 });
 const chunk = await sock.read();
 if (chunk === null) {
 if (buf.length === 0) throw new WhisperError("egress: connection closed before any response", { status: 502 });
 return [dec.decode(buf), new Uint8Array(0)];
 }
 buf = concat(buf, chunk);
 }
}

/**
 * Open the CONNECT tunnel to `target` through `proxy` on the given runtime and return a socket that
 * is ready to speak the TARGET's application protocol. When `encryptProxyLeg` is true (Node), the
 * proxy leg is TLS so the bearer is encrypted end-to-end; otherwise the CONNECT preamble is sent on
 * the clear leg to the proxy (the only option on runtimes that cannot nest TLS). `targetTls` adds
 * the target's TLS layer inside the tunnel.
 */
export async function openTunnel(
 runtime: EgressRuntime,
 proxy: ProxyEndpoint,
 target: { host: string; port: number; tls: boolean },
 encryptProxyLeg: boolean,
): Promise<TunnelSocket> {
 let sock = await openSocket(runtime, proxy.host, proxy.port);
 try {
 if (encryptProxyLeg && proxy.tls) sock = await sock.startTls(proxy.host);
 const preamble =
 `CONNECT ${target.host}:${target.port} HTTP/1.1\r\n` +
 `Host: ${target.host}:${target.port}\r\n` +
 `Proxy-Authorization: ${proxy.auth}\r\n` +
 `Proxy-Connection: keep-alive\r\n\r\n`;
 await sock.write(enc.encode(preamble));
 const [head] = await readHead(sock);
 const status = Number(head.split(" ")[1] || 0);
 if (status < 200 || status >= 300) {
 const line = head.split("\r\n")[0] || `status ${status}`;
 const msg =
 status === 407 ? "egress: the proxy rejected the credential (407) — the egress token is invalid or expired"
 : status === 429 ? "egress: the agent hit its connection cap (429) — retry shortly"
 : `egress: the proxy refused the tunnel — ${line}`;
 throw new WhisperError(msg, { status });
 }
 if (target.tls) sock = await sock.startTls(target.host);
 return sock;
 } catch (e) {
 sock.close();
 throw e;
 }
}

/** Normalise a fetch input+init into the pieces the tunnel client needs. */
export async function normaliseRequest(
 input: string | URL | Request,
 init?: RequestInit,
): Promise<{ url: URL; method: string; headers: Headers; body: Uint8Array | null }> {
 let url: URL, method: string, headers: Headers, body: Uint8Array | null = null;
 const isRequest = typeof input === "object" && input !== null && "url" in input && "clone" in input;
 if (isRequest) {
 const r = input as Request;
 url = new URL(r.url);
 method = (init?.method ?? r.method ?? "GET").toUpperCase();
 headers = new Headers(r.headers);
 if (init?.headers) new Headers(init.headers as HeadersInit).forEach((v, k) => headers.set(k, v));
 const src = init && "body" in init ? (init as RequestInit) : r;
 const ab = await new Response((src as { body?: BodyInit | null }).body ?? null).arrayBuffer();
 if (ab.byteLength) body = new Uint8Array(ab);
 } else {
 url = input instanceof URL ? input : new URL(String(input));
 method = (init?.method ?? "GET").toUpperCase();
 headers = new Headers(init?.headers as HeadersInit | undefined);
 if (init?.body != null) body = new Uint8Array(await new Response(init.body as BodyInit).arrayBuffer());
 }
 return { url, method, headers, body };
}

/**
 * Perform ONE HTTP/1.1 request over an already-open tunnel `sock` and return a WHATWG {@link
 * Response}. Handles both `Transfer-Encoding: chunked` and `Content-Length` framing, and falls back
 * to read-until-EOF (we send `Connection: close`). Body size is capped defensively.
 */
export async function tunnelHttp(
 sock: TunnelSocket,
 url: URL,
 method: string,
 headers: Headers,
 body: Uint8Array | null,
 userAgent: string,
 cap = 16 << 20,
): Promise<Response> {
 const h = new Headers(headers);
 h.set("host", url.host);
 if (!h.has("accept")) h.set("accept", "*/*");
 if (!h.has("user-agent")) h.set("user-agent", userAgent);
 h.set("connection", "close");
 if (body) h.set("content-length", String(body.length));
 else h.delete("content-length");

 let head = `${method} ${url.pathname}${url.search} HTTP/1.1\r\n`;
 h.forEach((v, k) => { head += `${k}: ${v}\r\n`; });
 head += "\r\n";
 await sock.write(enc.encode(head));
 if (body) await sock.write(body);

 const [headText, leftover] = await readHead(sock);
 const lines = headText.split("\r\n");
 const statusLine = lines[0] || "HTTP/1.1 502";
 const parts = statusLine.split(" ");
 const status = Number(parts[1] || 502);
 const statusText = parts.slice(2).join(" ");
 const respHeaders = new Headers();
 for (let i = 1; i < lines.length; i++) {
 const idx = lines[i].indexOf(":");
 if (idx <= 0) continue;
 const k = lines[i].slice(0, idx).trim();
 const v = lines[i].slice(idx + 1).trim();
 try { respHeaders.append(k, v); } catch { /* skip a header the platform forbids setting */ }
 }

 const chunked = (respHeaders.get("transfer-encoding") || "").toLowerCase().includes("chunked");
 const clHeader = respHeaders.get("content-length");
 const contentLength = clHeader != null ? Number(clHeader) : null;

 let bodyBytes: Uint8Array;
 if (chunked) {
 bodyBytes = await readChunked(sock, leftover, cap);
 } else if (contentLength != null && Number.isFinite(contentLength)) {
 bodyBytes = await readN(sock, leftover, contentLength, cap);
 } else {
 bodyBytes = await readToEnd(sock, leftover, cap);
 }

 sock.close();
 // Headers that describe the ON-THE-WIRE framing must not ride on the decoded Response body.
 respHeaders.delete("transfer-encoding");
 respHeaders.delete("content-encoding");
 respHeaders.delete("content-length");
 const nullBody = status === 204 || status === 304 || status < 200;
 // Copy into a fresh ArrayBuffer-backed view so it satisfies BodyInit across TS lib versions.
 return new Response(nullBody ? null : new Uint8Array(bodyBytes), { status, statusText, headers: respHeaders });
}

async function readN(sock: TunnelSocket, seed: Uint8Array, n: number, cap: number): Promise<Uint8Array> {
 let buf = seed;
 while (buf.length < n) {
 if (buf.length > cap) throw new WhisperError("egress: response body exceeded the cap", { status: 502 });
 const chunk = await sock.read();
 if (chunk === null) break;
 buf = concat(buf, chunk);
 }
 return buf.subarray(0, Math.min(n, buf.length));
}

async function readToEnd(sock: TunnelSocket, seed: Uint8Array, cap: number): Promise<Uint8Array> {
 let buf = seed;
 for (;;) {
 if (buf.length > cap) throw new WhisperError("egress: response body exceeded the cap", { status: 502 });
 const chunk = await sock.read();
 if (chunk === null) return buf;
 buf = concat(buf, chunk);
 }
}

async function readChunked(sock: TunnelSocket, seed: Uint8Array, cap: number): Promise<Uint8Array> {
 let buf = seed;
 let out: Uint8Array = new Uint8Array(0);
 const need = async (n: number) => {
 while (buf.length < n) {
 const chunk = await sock.read();
 if (chunk === null) return false;
 buf = concat(buf, chunk);
 }
 return true;
 };
 for (;;) {
 // read the chunk-size line
 let nl = -1;
 for (;;) {
 nl = indexOfCRLF(buf);
 if (nl >= 0) break;
 const chunk = await sock.read();
 if (chunk === null) return out;
 buf = concat(buf, chunk);
 }
 const size = parseInt(dec.decode(buf.subarray(0, nl)).trim(), 16);
 buf = buf.subarray(nl + 2);
 if (!Number.isFinite(size) || size <= 0) return out; // last chunk (0) or malformed → stop
 if (!(await need(size + 2))) return out;
 out = concat(out, buf.subarray(0, size));
 if (out.length > cap) throw new WhisperError("egress: response body exceeded the cap", { status: 502 });
 buf = buf.subarray(size + 2); // skip the trailing CRLF
 }
}

/** Index of the first CRLF, or -1. */
function indexOfCRLF(b: Uint8Array): number {
 for (let i = 0; i + 1 < b.length; i++) if (b[i] === 13 && b[i + 1] === 10) return i;
 return -1;
}
