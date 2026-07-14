// SPDX-License-Identifier: MIT
// Whisper on Vercel Edge Functions: agent identity AND real egress, from a fetch-only sandbox.
// KEYLESS: GET /api/whisper?addr=<agent /128>
// EGRESS: GET /api/whisper?egress → fetch the source-IP echo THROUGH your agent's /128 (needs a key)
// CONTROL: GET /api/whisper?op=list (set WHISPER_API_KEY in Vercel env vars)
// The Edge runtime has no raw-socket API (no node:net, no Deno.connect, no cloudflare:sockets):
// agentEgress detects that and AUTOMATICALLY routes egress.fetch through the fetch-forward
// gateway instead. No config, no separate code path: this is the exact same call as the
// Node example, just running somewhere a raw CONNECT tunnel is impossible.
import { resolve, rdap, control, agentEgress } from "whisper-edge";

export const config = { runtime: "edge" };

const ECHO = "https://rdap.whisper.online/egress-ip";

export default async function handler(req: Request): Promise<Response> {
 const url = new URL(req.url);
 const key = process.env.WHISPER_API_KEY;

 if (url.searchParams.has("egress")) {
 if (!key) return Response.json({ error: "set WHISPER_API_KEY to egress" }, { status: 401 });
 const egress = await agentEgress(key, url.searchParams.get("egress") || undefined);
 const observed = (await (await egress.fetch(ECHO, { headers: { accept: "application/json" } })).json()) as { ip: string };
 return Response.json({
 agent: egress.transport.address,
 observedSourceIP: observed.ip,
 egressedFromYourAgent: observed.ip === egress.transport.address,
 transport: egress.transport, // { tier, fqdn, runtime:"unknown", mechanism:"fetch-forward gateway...", tokenProtected }
 });
 }

 const op = url.searchParams.get("op");
 if (op) {
 if (!key) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
 const res = op === "list" ? await control(key).list() : await control(key).agents(op, {});
 return Response.json({ op, records: res.records });
 }

 const addr = url.searchParams.get("addr");
 if (!addr) return new Response("usage: ?addr=<agent /128> | ?egress (needs key) | ?op=list (needs key)\n", { status: 400 });
 const identity = await resolve(addr);
 return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
}
