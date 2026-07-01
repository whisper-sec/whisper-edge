<p align="center">
  <img src="logo.png" alt="Whisper" width="96" height="96">
</p>

<h1 align="center">whisper-edge</h1>

<p align="center">
  Agent identity <b>and real egress</b> for serverless & edge runtimes — <b>zero dependencies</b>, one <code>fetch</code>.<br>
  Verify who an agent is with <b>no key</b>; run the full control plane and route traffic from an agent's routable /128 <b>with</b> one.
</p>

```ts
import { verify, agentEgress } from "whisper-edge";

if (await verify(addr)) { /* keyless — it's a real, cryptographically-verifiable Whisper agent */ }

const egress = await agentEgress(process.env.WHISPER_API_KEY!);   // with a key — real egress
const who = await egress.fetch("https://api.example.com/whoami"); // this request LEAVES from your agent's /128
```

Runs unchanged on **Cloudflare Workers, Vercel, Deno, Netlify, AWS Lambda, and Supabase Edge
Functions**. No Node built-ins to install, no CLI, no local proxy process — the egress transport
runs **in-process** on each runtime's own socket primitive.

---

## Install

```bash
npm i whisper-edge          # Node / Cloudflare / Vercel / Netlify / Lambda
```

```ts
import { verify, resolve, control, agentEgress } from "npm:whisper-edge@^0.2.0"; // Deno / Supabase
```

## Two tiers (+ egress)

Whisper is **Postel-shaped**: with **no key** you can already verify and resolve any agent
identity (the same public facts RDAP exposes); with **your key** the full control plane unlocks —
mint agents, set policy, read logs, revoke — **and** you can route real traffic out through an
agent's routable `/128`.

### Keyless — verify / resolve / RDAP

```ts
import { verify, verifyDetails, resolve, rdap, rdapDomain } from "whisper-edge";

await verify("2a04:2a01::1");            // → boolean: is this a Whisper agent?
await verifyDetails("2a04:2a01::1");     // → full verdict (dane_ok, jws_ok, …) or null
await resolve("2a04:2a01::1");           // → { fqdn, operator, tenant, daneOk, jwsOk, … } or null
await rdap("2a04:2a01::1");              // → the public RDAP object (RFC 9083) or null
await rdapDomain("scout.agents.whisper.online"); // → the forward-name RDAP object or null
```

`verify` runs the **whole trust chain server-side** — reverse-DNS PTR, forward-confirm AAAA, the
**DANE-EE TLSA pin** (DNSSEC-anchored — the trust anchor for an agent cert, not a public CA), and
the JWS identity doc — and folds it into one answer. `daneOk` is the load-bearing field.

### Control — with your API key

```ts
import { control } from "whisper-edge";

const c = control(process.env.WHISPER_API_KEY!); // never hard-code it — read it from a secret

const created = await c.register({ name: "scout", email: "ops@acme.co" });
// created.records[0].address → your new routable /128 · .api_key → the new agent's key (shown once)

await c.list();                          // your agents (confined to your tenant)
await c.policy({ block: ["ads.example"], default: "allow" }); // per-tenant DNS policy
await c.logs({ kind: "dns", from: "-1h", limit: 200 });       // recent activity
await c.revoke("scout");                 // withdraw the /128, PTR, tokens, and key
```

### Egress — route traffic out through an agent's /128

```ts
import { agentEgress } from "whisper-edge";

const egress = await agentEgress(process.env.WHISPER_API_KEY!); // omit the arg → reuse most-recent agent
//              agentEgress(key, "<agent-id or /128>")          // …or pick a specific agent

const res  = await egress.fetch("https://rdap.whisper.online/egress-ip"); // keyless source-IP echo
const seen = (await res.json()).ip;                                       // what the internet saw

seen === egress.transport.address; // true → the request left from YOUR agent's routable /128
egress.close();                    // release pooled transport resources when done
```

`egress.fetch` is a drop-in for the global `fetch`: every request is source-bound to the agent's
`/128`, so a peer's reverse-DNS resolves the request back to the agent's identity. `agentEgress`
detects the runtime and uses its native socket primitive — **no CLI, no local proxy**:

| Runtime | Egress transport | Bearer on the wire |
|---|---|---|
| **Node** — AWS Lambda, Vercel (Node), Netlify Functions | `node:net` + `node:tls` CONNECT tunnel (or an undici `ProxyAgent` when undici is present) | **encrypted** to the proxy (nested TLS) |
| **Deno** — Deno Deploy, Supabase Edge | `Deno.connect` + `Deno.startTls` CONNECT tunnel | to the proxy on the clear leg¹ |
| **Cloudflare Workers** | `cloudflare:sockets` `connect()` CONNECT tunnel | to the proxy on the clear leg¹ |
| Fetch-only sandboxes — Vercel *Edge*, Netlify *Edge* | *(no raw sockets — see below)* | — |

`egress.transport` is **secret-free** — `{ tier, address, fqdn, runtime, tokenProtected, mechanism }`.
The per-agent egress bearer is used in-process to open the tunnel and is **never** returned, logged,
or persisted. For advanced use, `egress.connect(host, port)` opens a raw, source-bound tunnel
socket (a byte stream that egresses from the `/128`).

¹ Deno and Cloudflare Workers cannot layer TLS-inside-TLS, so the CONNECT preamble (which carries
the bearer) rides the clear leg to the proxy on those runtimes — reflected as
`tokenProtected: false`. Node nests TLS and keeps the bearer encrypted end-to-end. **Fetch-only
sandboxes** (Vercel *Edge*, Netlify *Edge*) expose no raw socket, so they can do keyless verify +
the control plane but **cannot egress in-process** — run egress on a Node/Deno function or route it
through a small backend fetch-forward gateway.

## Runtime examples

Copy-paste, deploy, done. Each sample is three-tier (`?addr=` keyless, `?egress` and `?op=list`
with a key).

| Runtime | Example |
|---|---|
| Cloudflare Workers | [`examples/cloudflare`](examples/cloudflare) |
| Vercel (Node) | [`examples/vercel`](examples/vercel) |
| Netlify Functions | [`examples/netlify`](examples/netlify) |
| Deno Deploy | [`examples/deno`](examples/deno) |
| AWS Lambda | [`examples/lambda`](examples/lambda) |
| Supabase Edge | [`examples/supabase`](examples/supabase) |

## Errors, timeouts, config

- Failures throw a **`WhisperError`** carrying the server's exact, secret-free message
  (`.status`, `.detail`, `.title`). A "not an agent" is **not** an error — `verify` returns
  `false`, `resolve`/`rdap` return `null`.
- Every call takes optional `{ timeoutMs, signal, fetch, endpoints }`. The default timeout never
  hangs, even if the runtime's `fetch` ignores `AbortSignal`.
- Inject `fetch` for tests or custom transports; override `endpoints` for pre-prod/self-host.

```ts
await verify(addr, { timeoutMs: 3000 });
await agentEgress(key, undefined, { tier: "socks5", timeoutMs: 20000 });
```

## API

Keyless: `verify` · `verifyDetails` · `resolve` · `rdap` · `rdapDomain`
Control: `control(apiKey)` → `register` · `identity` · `list` · `agent` · `policy` · `logs` · `connect` · `revoke` · `agents(op, args)` · `query(cypher)`
Egress: `agentEgress(apiKey, selector?, opts?)` → `{ fetch, transport, connect, close }` · `detectRuntime()`
Low-level: `buildAgentsQuery` · `escapeCypherString` · `decodeEnvelope` · `WhisperError`

Full types ship with the package (`whisper-edge` is written in TypeScript).

---

Get a key and learn more at **[whisper.online](https://whisper.online)** · MIT licensed.
