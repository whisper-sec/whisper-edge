# whisper-edge examples

One runnable sample per runtime. Each is the **same two-tier shape**: keyless identity by
default, the control plane when a `WHISPER_API_KEY` is present in the platform's secrets.

| Runtime | File | Deploy | Try |
|---|---|---|---|
| Cloudflare Workers | [`cloudflare/worker.ts`](cloudflare/worker.ts) | `wrangler deploy` | `/?addr=<agent /128>` · `/?op=list` |
| Vercel (Edge) | [`vercel/api/whisper.ts`](vercel/api/whisper.ts) | `vercel deploy` | `/api/whisper?addr=…` |
| Netlify Functions | [`netlify/netlify/functions/whisper.mts`](netlify/netlify/functions/whisper.mts) | `netlify deploy` | `/.netlify/functions/whisper?addr=…` |
| Deno Deploy | [`deno/main.ts`](deno/main.ts) | `deployctl deploy main.ts` | `/?addr=…` |
| AWS Lambda | [`lambda/handler.mjs`](lambda/handler.mjs) | zip + Function URL | `/?addr=…` |
| Supabase Edge | [`supabase/functions/whisper/index.ts`](supabase/functions/whisper/index.ts) | `supabase functions deploy whisper` | `/whisper?addr=…` |

**Keyless** (no key): `GET ?addr=<agent /128 address>` → `{ identity, rdap }`.
**Control** (with a key): set `WHISPER_API_KEY` as a platform secret, then `GET ?op=list`.

> The API key lives in the platform's secret store — never in code, never in a query
> string, never logged. Get one at <https://whisper.online>.

Local sanity check with Deno (no deploy needed):

```bash
deno run --allow-net --allow-env examples/deno/main.ts
# then:  curl 'http://localhost:8000/?addr=<an agent /128 address>'
```
