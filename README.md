<p align="center">
  <img src="logo.png" alt="Whisper" width="96" height="96">
</p>

<h1 align="center">whisper-edge</h1>

<p align="center">
  Agent identity for serverless & edge runtimes — <b>zero dependencies</b>, one <code>fetch</code>.<br>
  Verify who an agent is with <b>no key</b>; run the full control plane <b>with</b> one.
</p>

```ts
import { verify } from "whisper-edge";

if (await verify(addr)) {           // keyless — pure HTTPS, no key, no CLI
  // ...it's a real, cryptographically-verifiable Whisper agent
}
```

Runs unchanged on **Cloudflare Workers, Vercel, Deno, Netlify, AWS Lambda, and Supabase
Edge Functions** — anywhere there's a global `fetch`. No Node built-ins. Nothing to install
but this one package.

---

## Install

```bash
npm i whisper-edge          # Node / Cloudflare / Vercel / Netlify / Lambda
```

```ts
import { verify, resolve, rdap, control } from "npm:whisper-edge@^0.1.0"; // Deno / Supabase
```

## Two tiers

Whisper is **Postel-shaped**: with **no key** you can already verify and resolve any agent
identity (the same public facts RDAP exposes); with **your key** the full control plane
unlocks — mint agents, set policy, read logs, revoke.

### Keyless — verify / resolve / RDAP

```ts
import { verify, verifyDetails, resolve, rdap, rdapDomain } from "whisper-edge";

await verify("2a04:2a01::1");            // → boolean: is this a Whisper agent?
await verifyDetails("2a04:2a01::1");     // → full verdict (dane_ok, jws_ok, …) or null
await resolve("2a04:2a01::1");           // → { fqdn, operator, tenant, daneOk, jwsOk, … } or null
await rdap("2a04:2a01::1");              // → the public RDAP object (RFC 9083) or null
await rdapDomain("scout.agents.whisper.online"); // → the forward-name RDAP object (by name) or null
```

`verify` runs the **whole trust chain server-side** — reverse-DNS PTR, forward-confirm
AAAA, the **DANE-EE TLSA pin** (DNSSEC-anchored — the trust anchor for an agent cert, not a
public CA), and the JWS identity doc — and folds it into one answer. `daneOk` is the
load-bearing field.

### Control — with your API key

```ts
import { control } from "whisper-edge";

const c = control(process.env.WHISPER_API_KEY!); // never hard-code it — read it from a secret

const created = await c.register({ name: "scout", email: "ops@acme.co" });
// created.records[0].address → your new routable /128 · .api_key → the new agent's key (shown once)

await c.list();                          // your agents (confined to your tenant)
await c.agent("2a04:2a01::1");           // one agent's detail + live counters
await c.policy({ block: ["ads.example"], default: "allow" }); // per-tenant DNS policy
await c.logs({ kind: "dns", from: "-1h", limit: 200 });       // recent activity
await c.revoke("scout");                 // withdraw the /128, PTR, tokens, and key
```

Every control call runs the one control-plane verb —
`CALL whisper.agents({op, args})` — over HTTPS to `graph.whisper.security`, with your key
sent as `X-API-Key` (**never** in a URL, **never** logged). Each returns a normalised
result: `{ columns, rows, records, raw, status }`.

## Runtime examples

Copy-paste, deploy, done. Each sample is two-tier (`?addr=` keyless, `?op=list` with a key).

| Runtime | Example |
|---|---|
| Cloudflare Workers | [`examples/cloudflare`](examples/cloudflare) |
| Vercel (Edge) | [`examples/vercel`](examples/vercel) |
| Netlify Functions | [`examples/netlify`](examples/netlify) |
| Deno Deploy | [`examples/deno`](examples/deno) |
| AWS Lambda | [`examples/lambda`](examples/lambda) |
| Supabase Edge | [`examples/supabase`](examples/supabase) |

## Errors, timeouts, config

- Failures throw a **`WhisperError`** carrying the server's exact, secret-free message
  (`.status`, `.detail`, `.title`). A "not an agent" is **not** an error — `verify` returns
  `false`, `resolve`/`rdap` return `null`.
- Every call takes optional `{ timeoutMs, signal, fetch, endpoints }`. The default timeout
  is 10s and never hangs, even if the runtime's `fetch` ignores `AbortSignal`.
- Inject `fetch` for tests or custom transports; override `endpoints` for pre-prod/self-host.

```ts
await verify(addr, { timeoutMs: 3000 });
await resolve(addr, { fetch: myFetch, endpoints: { verify: "https://rdap.example" } });
```

## API

Keyless: `verify` · `verifyDetails` · `resolve` · `rdap` · `rdapDomain`
Control: `control(apiKey)` → `register` · `identity` · `list` · `agent` · `policy` · `logs`
· `connect` · `revoke` · `agents(op, args)` · `query(cypher)`
Low-level: `buildAgentsQuery` · `escapeCypherString` · `decodeEnvelope` · `WhisperError`

Full types ship with the package (`whisper-edge` is written in TypeScript).

---

Get a key and learn more at **[whisper.online](https://whisper.online)** · MIT licensed.
