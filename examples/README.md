# whisper-edge examples

One runnable sample per runtime. Each is the **same three-tier shape**: keyless identity by
default, the control plane and **real egress** when a `WHISPER_API_KEY` is present in the
platform's secrets.

| Runtime | File | Deploy | Egress mechanism |
|---|---|---|---|
| Cloudflare Workers | [`cloudflare/worker.ts`](cloudflare/worker.ts) | `wrangler deploy` | `cloudflare:sockets` CONNECT tunnel |
| Vercel (Node) | [`vercel/api/whisper.ts`](vercel/api/whisper.ts) | `vercel deploy` | `node:net`/`node:tls` CONNECT tunnel |
| Netlify Functions | [`netlify/netlify/functions/whisper.mts`](netlify/netlify/functions/whisper.mts) | `netlify deploy` | `node:net`/`node:tls` CONNECT tunnel |
| Deno Deploy | [`deno/main.ts`](deno/main.ts) | `deployctl deploy main.ts` | `Deno.connect` + `Deno.startTls` tunnel |
| AWS Lambda | [`lambda/handler.mjs`](lambda/handler.mjs) | zip + Function URL | `node:net`/`node:tls` CONNECT tunnel |
| Supabase Edge | [`supabase/functions/whisper/index.ts`](supabase/functions/whisper/index.ts) | `supabase functions deploy whisper` | `Deno.connect` + `Deno.startTls` tunnel |

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

**Runtime notes.** Egress opens a raw socket, so it needs a runtime that exposes one: Node
(Lambda, Vercel Node, Netlify Functions), Deno (Deno Deploy, Supabase Edge), or Cloudflare
Workers. **Fetch-only sandboxes** (e.g. the Vercel *Edge* runtime, Netlify *Edge*) can still do
keyless verify + the control plane, but cannot egress in-process — run those on a Node/Deno
function, or route egress through a small backend. On Node the egress bearer is encrypted to the
proxy (nested TLS); on Deno/Workers, which cannot nest TLS, the CONNECT preamble rides the clear
leg to the proxy (`tokenProtected: false`).

Local sanity check with Deno (no deploy needed):

```bash
export WHISPER_API_KEY=whisper_live_…   # optional — enables ?egress and ?op
deno run --allow-net --allow-env examples/deno/main.ts
# then:  curl 'http://localhost:8000/?addr=<an agent /128>'
#        curl 'http://localhost:8000/?egress'      # see your traffic leave from your /128
```
