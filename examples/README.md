# whisper-edge examples

One runnable sample per runtime. Each is the **same three-tier shape**: keyless identity by
default, the control plane and **real egress** when a `WHISPER_API_KEY` is present in the
platform's secrets.

| Runtime | File | Deploy | Egress mechanism |
|---|---|---|---|
| Cloudflare Workers | [`cloudflare/worker.ts`](cloudflare/worker.ts) | `wrangler deploy` | `cloudflare:sockets` CONNECT tunnel |
| Vercel (Node) | [`vercel/api/whisper.ts`](vercel/api/whisper.ts) | `vercel deploy` | `node:net`/`node:tls` CONNECT tunnel |
| Vercel Edge | [`vercel-edge/api/whisper.ts`](vercel-edge/api/whisper.ts) | `vercel deploy` | fetch-forward gateway (auto) |
| Netlify Functions | [`netlify/netlify/functions/whisper.mts`](netlify/netlify/functions/whisper.mts) | `netlify deploy` | `node:net`/`node:tls` CONNECT tunnel |
| Deno Deploy | [`deno/main.ts`](deno/main.ts) | `deployctl deploy main.ts` | `Deno.connect` + `Deno.startTls` tunnel |
| AWS Lambda | [`lambda/handler.mjs`](lambda/handler.mjs) | zip + Function URL | `node:net`/`node:tls` CONNECT tunnel |
| Supabase Edge | [`supabase/functions/whisper/index.ts`](supabase/functions/whisper/index.ts) | `supabase functions deploy whisper` | `Deno.connect` + `Deno.startTls` tunnel |

> **Deploy status:** the Vercel/Netlify/Cloudflare account-hosted deploys of these samples are
> pending (they need account access this SDK's maintainers don't have on hand yet). Every
> transport a sample calls into — including the Vercel Edge fetch-forward path — is proven
> end-to-end against the live gateway by the SDK's own test suite and a real e2e run from a plain
> Node process; the examples exercise the identical `agentEgress()`/`resolve()` calls.

Each sample answers three requests:

- **Keyless** (no key): `GET ?addr=<agent /128>` → `{ identity, rdap }`.
- **Egress** (with a key): `GET ?egress` → provisions/reuses your agent, fetches the keyless
 source-IP echo **through its /128**, and returns the observed source IP so you can **see** it is
 your `/128`:

 ```json
 { "agent": "2a04:2a01:…", "observedSourceIP": "2a04:2a01:…", "egressedFromYourAgent": true,
 "transport": { "tier": "socks5", "fqdn": "…", "runtime": "workers", "tokenProtected": false,
 "mechanism": "cloudflare:sockets CONNECT tunnel" } }
 ```

- **Control** (with a key): `GET ?op=list` → your agents (confined to your tenant).

> The API key lives in the platform's secret store — never in code, never in a query string,
> never logged. The per-agent egress bearer is used in-process only and is never returned or
> logged. Get a key at <https://whisper.online>.

**Runtime notes.** On Node (Lambda, Vercel Node, Netlify Functions), Deno (Deno Deploy, Supabase
Edge), and Cloudflare Workers, egress opens a raw CONNECT-tunnel socket. **Fetch-only sandboxes**
(the Vercel *Edge* runtime, Netlify *Edge*, and anything else with no raw-socket API) have no
socket to open — `agentEgress` detects this and automatically routes `egress.fetch` through the
**fetch-forward gateway** (`forward.whisper.online/forward`,) instead: the exact same call,
a different transport underneath, zero config either way. On Node the egress bearer is encrypted
to the proxy (nested TLS); on Deno/Workers, which cannot nest TLS, the CONNECT preamble rides the
clear leg to the proxy (`tokenProtected: false`); on fetch-forward the credential rides inside the
plain HTTPS session to the gateway (`tokenProtected: true`). A freshly-minted token can take up to
~45s to reach every gateway node — `agentEgress` retries a 407 automatically with a short, capped
backoff, so this is invisible in the common case.

Local sanity check with Deno (no deploy needed):

```bash
export WHISPER_API_KEY=whisper_live_… # optional — enables ?egress and ?op
deno run --allow-net --allow-env examples/deno/main.ts
# then: curl 'http://localhost:8000/?addr=<an agent /128>'
# curl 'http://localhost:8000/?egress' # see your traffic leave from your /128
```
