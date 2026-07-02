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

const egress = await agentEgress(process.env.WHISPER_API_KEY!); // with a key — real egress
const who = await egress.fetch("https://api.example.com/whoami"); // this request LEAVES from your agent's /128
```

Runs unchanged on **Cloudflare Workers, Vercel, Deno, Netlify, AWS Lambda, and Supabase Edge
Functions**. No Node built-ins to install, no CLI, no local proxy process — the egress transport
runs **in-process** on each runtime's own socket primitive.

---

## Install

```bash
npm i whisper-edge # Node / Cloudflare / Vercel / Netlify / Lambda
```

```ts
import { verify, resolve, control, agentEgress } from "npm:whisper-edge@^0.3.0"; // Deno / Supabase
```

## Two tiers (+ egress)

Whisper is **Postel-shaped**: with **no key** you can already verify and resolve any agent
identity (the same public facts RDAP exposes); with **your key** the full control plane unlocks —
mint agents, set policy, read logs, revoke — **and** you can route real traffic out through an
agent's routable `/128`.

### Keyless — verify / resolve / RDAP

```ts
import { verify, verifyDetails, resolve, rdap, rdapDomain } from "whisper-edge";

await verify("2a04:2a01::1"); // → boolean: is this a Whisper agent?
await verifyDetails("2a04:2a01::1"); // → full verdict (dane_ok, jws_ok, …) or null
await resolve("2a04:2a01::1"); // → { fqdn, operator, tenant, daneOk, jwsOk, … } or null
await rdap("2a04:2a01::1"); // → the public RDAP object (RFC 9083) or null
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
// created.records[0].address → your new routable /128 ·.api_key → the new agent's key (shown once)

await c.list(); // your agents (confined to your tenant)
await c.policy({ block: ["ads.example"], default: "allow" }); // per-tenant DNS policy
await c.logs({ kind: "dns", from: "-1h", limit: 200 }); // recent activity
await c.revoke("scout"); // withdraw the /128, PTR, tokens, and key
```

### Egress — route traffic out through an agent's /128

```ts
import { agentEgress } from "whisper-edge";

const egress = await agentEgress(process.env.WHISPER_API_KEY!); // omit the arg → reuse most-recent agent
// agentEgress(key, "<agent-id or /128>") // …or pick a specific agent

const res = await egress.fetch("https://rdap.whisper.online/egress-ip"); // keyless source-IP echo
const seen = (await res.json()).ip; // what the internet saw

seen === egress.transport.address; // true → the request left from YOUR agent's routable /128
egress.close(); // release pooled transport resources when done
```

`egress.fetch` is a drop-in for the global `fetch`: every request is source-bound to the agent's
`/128`, so a peer's reverse-DNS resolves the request back to the agent's identity. `agentEgress`
detects the runtime and picks the best transport it has — **no CLI, no local proxy, ever**:

| Runtime | Egress transport | Bearer on the wire |
|---|---|---|
| **Node** — AWS Lambda, Vercel (Node), Netlify Functions | `node:net` + `node:tls` CONNECT tunnel (or an undici `ProxyAgent` when undici is present) | **encrypted** to the proxy (nested TLS) |
| **Deno** — Deno Deploy, Supabase Edge | `Deno.connect` + `Deno.startTls` CONNECT tunnel | to the proxy on the clear leg¹ |
| **Cloudflare Workers** | `cloudflare:sockets` `connect()` CONNECT tunnel | to the proxy on the clear leg¹ |
| **Fetch-only sandboxes** — Vercel *Edge*, Netlify *Edge*, and anything else with no raw-socket API | **fetch-forward gateway** — one HTTPS hop through `forward.whisper.online/forward` | encrypted (plain HTTPS to the gateway) |

`egress.transport` is **secret-free** — `{ tier, address, fqdn, runtime, tokenProtected, mechanism }`.
The per-agent egress bearer is used in-process to authenticate the transport and is **never**
returned, logged, or persisted. For advanced use, `egress.connect(host, port)` opens a raw,
source-bound tunnel socket — except on the fetch-forward transport, which has no raw-socket
equivalent (the gateway relays whole HTTP requests, not an arbitrary byte stream) and throws a
clear error if you call it.

¹ Deno and Cloudflare Workers cannot layer TLS-inside-TLS, so the CONNECT preamble (which carries
the bearer) rides the clear leg to the proxy on those runtimes — reflected as
`tokenProtected: false`. Node nests TLS and keeps the bearer encrypted end-to-end.

### Fetch-forward — egress on fetch-only sandboxes

A raw CONNECT tunnel needs a raw socket. Runtimes that don't expose one — the *Edge* flavors of
Vercel and Netlify, and anything else `detectRuntime()` can't place on Node/Deno/Workers — can't
open one, full stop. `agentEgress` detects this and **auto-selects the fetch-forward transport**:
every request is instead POSTed (method mirrored) to `https://forward.whisper.online/forward` with
`Authorization: Basic base64("w:"+bearer)` and `X-Whisper-Target: <the real URL>`; the gateway
egresses server-side from the agent's `/128` and streams the target's response straight back,
stamped `X-Whisper-Egress-Source: <the /128>`. One HTTPS hop, zero raw sockets required — this is
the path that works in *every* fetch runtime that will ever exist, including ones that will never
grow a socket API. Force it explicitly with `{ transport: "forward" }` (or force the raw-socket
path with `{ transport: "socket" }`); the default, `"auto"`, follows the table above.

**Retry on 407.** A freshly-minted egress token needs a short window (up to ~45s) to
propagate to every gateway node — a 407 in that window means "not recognised on *this* node yet",
not "bad token". `agentEgress`/`forwardFetch` retry a 407 automatically: a handful of attempts
(default 4), ~1.5s apart, capped — enough hops to very likely land on a node that already knows
the token, without ever making a call hang for the full 45s. Tune it with `{ retries,
retryDelayMs }`; a persistent 407 after the whole budget throws a clear `WhisperError` telling you
to wait a moment or mint a fresh token.

```ts
import { agentEgress } from "whisper-edge";

// On Vercel Edge / Netlify Edge / any other fetch-only sandbox this is automatic — no config.
const egress = await agentEgress(process.env.WHISPER_API_KEY!, undefined, {
 transport: "forward", // force it anywhere, e.g. to test the gateway path from Node
 retries: 5, retryDelayMs: 1000,
});
const res = await egress.fetch("https://api.example.com/whoami");
```

## Runtime examples

Copy-paste, deploy, done. Each sample is three-tier (`?addr=` keyless, `?egress` and `?op=list`
with a key).

| Runtime | Example | Egress transport |
|---|---|---|
| Cloudflare Workers | [`examples/cloudflare`](examples/cloudflare) | `cloudflare:sockets` CONNECT tunnel |
| Vercel (Node) | [`examples/vercel`](examples/vercel) | `node:net`/`node:tls` CONNECT tunnel |
| Vercel Edge | [`examples/vercel-edge`](examples/vercel-edge) | fetch-forward gateway (auto) |
| Netlify Functions | [`examples/netlify`](examples/netlify) | `node:net`/`node:tls` CONNECT tunnel |
| Deno Deploy | [`examples/deno`](examples/deno) | `Deno.connect` CONNECT tunnel |
| AWS Lambda | [`examples/lambda`](examples/lambda) | `node:net`/`node:tls` CONNECT tunnel |
| Supabase Edge | [`examples/supabase`](examples/supabase) | `Deno.connect` CONNECT tunnel |

Real deploys of the `examples/*` samples onto live Vercel/Netlify/Cloudflare accounts are pending
(account-gated) — every transport above **is** proven end-to-end against the live gateway from a
plain Node process (see the SDK's own test suite + the e2e run in the release notes), which is
the same code path each example calls into.

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
