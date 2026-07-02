// SPDX-License-Identifier: MIT
import { test } from "node:test";
import assert from "node:assert/strict";
import { agentEgress, detectRuntime, WhisperError } from "../dist/index.js";
import { parseProxy, tunnelHttp, normaliseRequest } from "../dist/tunnel.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** A mock TunnelSocket: replays `responseText` (optionally split into N-byte chunks) and captures writes. */
function mockSocket(responseText, chunkSize = 0) {
 const bytes = enc.encode(responseText);
 const chunks = [];
 if (chunkSize > 0) for (let i = 0; i < bytes.length; i += chunkSize) chunks.push(bytes.subarray(i, i + chunkSize));
 else chunks.push(bytes);
 let i = 0;
 const writes = [];
 const sock = {
 async read() { return i < chunks.length ? chunks[i++] : null; },
 async write(b) { writes.push(b); },
 async startTls() { return sock; },
 close() { sock.closed = true; },
 closed: false,
 };
 return { sock, writes };
}
const written = (writes) => writes.map((w) => dec.decode(w)).join("");

// ── parseProxy ────────────────────────────────────────────────────────────────────────────

test("parseProxy extracts host/port/tls and builds Basic auth from the userinfo", () => {
 const p = parseProxy("https://w:et_SECRETTOKEN@egress.whisper.online");
 assert.equal(p.host, "egress.whisper.online");
 assert.equal(p.port, 443); // https default
 assert.equal(p.tls, true);
 assert.ok(p.auth.startsWith("Basic "));
 // The bearer is carried ONLY inside the base64 auth, exactly as the proxy expects: base64("w:"+token).
 const decoded = Buffer.from(p.auth.slice("Basic ".length), "base64").toString("utf8");
 assert.equal(decoded, "w:et_SECRETTOKEN");
});

test("parseProxy honours an explicit port and http scheme", () => {
 const p = parseProxy("http://w:tok@proxy.example:8080");
 assert.equal(p.port, 8080);
 assert.equal(p.tls, false);
});

test("parseProxy fails clearly on garbage (never an opaque throw)", () => {
 assert.throws(() => parseProxy("not a url"), (e) => e instanceof WhisperError && e.status === 502);
});

// ── detectRuntime ─────────────────────────────────────────────────────────────────────────

test("detectRuntime identifies Node in this test process", () => {
 assert.equal(detectRuntime(), "node");
});

// ── tunnelHttp: framing ─────────────────────────────────────────────────────────────────────

test("tunnelHttp parses a Content-Length response", async () => {
 const body = '{"ip":"2a04:2a01::1"}';
 const { sock } = mockSocket(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
 const resp = await tunnelHttp(sock, new URL("https://rdap.whisper.online/egress-ip"), "GET", new Headers(), null, "ua");
 assert.equal(resp.status, 200);
 assert.equal(resp.headers.get("content-type"), "application/json");
 assert.deepEqual(await resp.json(), { ip: "2a04:2a01::1" });
 assert.equal(sock.closed, true); // the socket is closed after one request
});

test("tunnelHttp de-chunks a Transfer-Encoding: chunked response", async () => {
 const { sock } = mockSocket("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
 const resp = await tunnelHttp(sock, new URL("https://x/y"), "GET", new Headers(), null, "ua");
 assert.equal(await resp.text(), "hello world");
});

test("tunnelHttp reads to EOF when there is no length or chunking", async () => {
 const { sock } = mockSocket("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsome body bytes");
 const resp = await tunnelHttp(sock, new URL("https://x/y"), "GET", new Headers(), null, "ua");
 assert.equal(await resp.text(), "some body bytes");
});

test("tunnelHttp reassembles a response delivered in tiny 3-byte chunks", async () => {
 const body = "chunky-stream-body";
 const { sock } = mockSocket(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`, 3);
 const resp = await tunnelHttp(sock, new URL("https://x/y"), "GET", new Headers(), null, "ua");
 assert.equal(await resp.text(), body);
});

test("tunnelHttp gives a 204 a null body", async () => {
 const { sock } = mockSocket("HTTP/1.1 204 No Content\r\n\r\n");
 const resp = await tunnelHttp(sock, new URL("https://x/y"), "GET", new Headers(), null, "ua");
 assert.equal(resp.status, 204);
 assert.equal(await resp.text(), "");
});

// ── tunnelHttp: request emission ─────────────────────────────────────────────────────────────

test("tunnelHttp emits a strict HTTP/1.1 request line, Host, and Connection: close", async () => {
 const { sock, writes } = mockSocket("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
 await tunnelHttp(sock, new URL("https://rdap.whisper.online/egress-ip?x=1"), "GET", new Headers({ accept: "application/json" }), null, "whisper-edge/test");
 const req = written(writes);
 assert.match(req, /^GET \/egress-ip\?x=1 HTTP\/1\.1\r\n/);
 assert.match(req, /\r\nhost: rdap\.whisper\.online\r\n/i);
 assert.match(req, /\r\nconnection: close\r\n/i);
 assert.match(req, /\r\naccept: application\/json\r\n/i);
 assert.ok(!/content-length/i.test(req)); // no body → no content-length
});

test("tunnelHttp sends a body with a correct Content-Length", async () => {
 const { sock, writes } = mockSocket("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
 const payload = enc.encode('{"hello":"world"}');
 await tunnelHttp(sock, new URL("https://x/api"), "POST", new Headers({ "content-type": "application/json" }), payload, "ua");
 const req = written(writes);
 assert.match(req, /^POST \/api HTTP\/1\.1\r\n/);
 assert.match(req, new RegExp(`\\r\\ncontent-length: ${payload.length}\\r\\n`, "i"));
 assert.match(req, /\{"hello":"world"\}$/); // body follows the headers
});

// ── normaliseRequest ─────────────────────────────────────────────────────────────────────────

test("normaliseRequest accepts a string, a URL, and a Request (Postel: liberal input)", async () => {
 const a = await normaliseRequest("https://x/a");
 assert.equal(a.url.href, "https://x/a");
 assert.equal(a.method, "GET");
 const b = await normaliseRequest(new URL("https://x/b"), { method: "post" });
 assert.equal(b.method, "POST");
 const c = await normaliseRequest(new Request("https://x/c", { method: "PUT", body: "z" }));
 assert.equal(c.method, "PUT");
 assert.equal(dec.decode(c.body), "z");
});

// ── agentEgress: control-plane guard + SECRET HYGIENE ─────────────────────────────────────────

/** A control-plane fetch stub returning one `op:connect` row. */
function connectStub(record) {
 const columns = Object.keys(record);
 const rows = [columns.map((k) => record[k])];
 return async () => new Response(JSON.stringify({ ok: true, result: { columns, rows } }), { status: 200, headers: { "content-type": "application/json" } });
}

test("agentEgress fails clearly when the tier returns no HTTP-CONNECT proxy", async () => {
 const fetch = connectStub({ tier: "wireguard", address: "2a04:2a01::9", fqdn: "w.agents.whisper.online" });
 await assert.rejects(
 () => agentEgress("whisper_live_EXAMPLE", undefined, { fetch }),
 (e) => e instanceof WhisperError && /HTTP-CONNECT proxy/.test(e.message),
 );
});

// ── two-tier gating: egress is a KEYED tier — no key ⇒ a clear, helpful error, never opaque ──

test("agentEgress with no API key fails clearly (401) — egress is the keyed tier", async () => {
 await assert.rejects(
 () => agentEgress(""),
 (e) => e instanceof WhisperError && e.status === 401 && /API key/.test(e.message),
 );
 await assert.rejects(() => agentEgress(" "), (e) => e instanceof WhisperError && e.status === 401);
});

// ── fetch-forward transport: auto-selected on fetch-only runtimes, forceable via opts ──

test("agentEgress({transport:'forward'}) routes egress.fetch through the fetch-forward gateway", async () => {
 const connectFetch = connectStub({
 tier: "socks5",
 address: "2a04:2a01::abcd",
 fqdn: "scout.agents.whisper.online.",
 http_proxy: "https://w:et_TOPSECRET@egress.whisper.online",
 });
 const forwardCalls = [];
 // One injected fetch serves BOTH the control-plane connect() call and the forward-gateway
 // call — exactly like a real runtime, where both ride the same global fetch.
 const fetchStub = async (url, init) => {
 const u = String(url);
 if (u.includes("forward.whisper.online")) {
 forwardCalls.push({ url: u, init });
 return new Response("2a04:2a01::abcd", { status: 200, headers: { "x-whisper-egress-source": "2a04:2a01::abcd" } });
 }
 return connectFetch(url, init);
 };
 const egress = await agentEgress("whisper_live_EXAMPLE", undefined, { fetch: fetchStub, transport: "forward" });
 assert.match(egress.transport.mechanism, /fetch-forward/);
 assert.equal(egress.transport.tokenProtected, true);
 const res = await egress.fetch("https://v6.ident.me");
 assert.equal(await res.text(), "2a04:2a01::abcd");
 assert.equal(res.headers.get("x-whisper-egress-source"), "2a04:2a01::abcd");
 assert.equal(forwardCalls.length, 1);
 assert.equal(forwardCalls[0].init.headers.get("x-whisper-target"), "https://v6.ident.me/");
 // The bearer only ever appears inside the (opaque, base64) Authorization header sent to the
 // gateway — never in the transport object, never as a bare string anywhere observable.
 assert.ok(forwardCalls[0].init.headers.get("authorization").startsWith("Basic "));
 assert.ok(!JSON.stringify(egress.transport).includes("et_TOPSECRET"));
 egress.close();
});

test("agentEgress({transport:'forward'}).connect() has no raw-socket equivalent — fails clearly, not silently", async () => {
 const connectFetch = connectStub({
 tier: "socks5",
 address: "2a04:2a01::abcd",
 fqdn: "scout.agents.whisper.online.",
 http_proxy: "https://w:et_TOPSECRET@egress.whisper.online",
 });
 const egress = await agentEgress("whisper_live_EXAMPLE", undefined, { fetch: connectFetch, transport: "forward" });
 await assert.rejects(
 () => egress.connect("example.com", 443),
 (e) => e instanceof WhisperError && e.status === 501 && /fetch-forward/.test(e.message),
 );
 egress.close();
});

test("agentEgress returns a secret-free transport (the et_ bearer is NEVER exposed)", async () => {
 const fetch = connectStub({
 tier: "socks5",
 address: "2a04:2a01::abcd",
 fqdn: "scout.agents.whisper.online.",
 http_proxy: "https://w:et_TOPSECRET@egress.whisper.online",
 connection_string: "socks5h://w:et_TOPSECRET@connect.whisper.online:443",
 socks5_endpoint: "connect.whisper.online:443",
 });
 const egress = await agentEgress("whisper_live_EXAMPLE", undefined, { fetch });
 assert.equal(egress.transport.address, "2a04:2a01::abcd");
 assert.equal(egress.transport.fqdn, "scout.agents.whisper.online"); // trailing dot trimmed
 assert.equal(egress.transport.runtime, "node");
 assert.equal(egress.transport.tokenProtected, true); // Node nests TLS → bearer encrypted to the proxy
 // The whole handle + transport must not carry the bearer, the raw proxy URL, or the connection string.
 const blob = JSON.stringify(egress.transport);
 assert.ok(!/et_TOPSECRET/.test(blob), "bearer leaked into transport");
 assert.ok(!/http_proxy|connection_string|socks5_endpoint/.test(blob), "secret field leaked into transport");
 assert.deepEqual(
 Object.keys(egress.transport).sort(),
 ["address", "fqdn", "mechanism", "runtime", "tier", "tokenProtected"],
 );
 assert.equal(typeof egress.fetch, "function");
 assert.equal(typeof egress.connect, "function");
 egress.close();
});
