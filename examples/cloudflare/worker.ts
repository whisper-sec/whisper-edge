// SPDX-License-Identifier: MIT
// Whisper on Cloudflare Workers — agent identity AND real egress at the edge.
//   Deploy:  wrangler deploy      Dev:  wrangler dev
//   KEYLESS: GET /?addr=<agent /128>   → verify + resolve + RDAP (no key)
//   EGRESS:  GET /?egress             → fetch the source-IP echo THROUGH your agent's /128 (needs a key)
//   CONTROL: GET /?op=list            → your agents (needs a key)
// Egress runs on cloudflare:sockets — in-process, no CLI, no local proxy.
import { resolve, rdap, control, agentEgress } from "whisper-edge";

interface Env {
  // wrangler secret put WHISPER_API_KEY   (optional — keyless works without it)
  WHISPER_API_KEY?: string;
}

const ECHO = "https://rdap.whisper.online/egress-ip"; // keyless: reflects the OBSERVED source IP

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // EGRESS tier — prove the request LEFT from your agent's routable /128.
    if (url.searchParams.has("egress")) {
      if (!env.WHISPER_API_KEY) return Response.json({ error: "set WHISPER_API_KEY to egress" }, { status: 401 });
      const egress = await agentEgress(env.WHISPER_API_KEY, url.searchParams.get("egress") || undefined);
      try {
        const observed = (await (await egress.fetch(ECHO, { headers: { accept: "application/json" } })).json()) as { ip: string };
        return Response.json({
          agent: egress.transport.address,          // your routable Whisper /128
          observedSourceIP: observed.ip,            // what the internet saw
          egressedFromYourAgent: observed.ip === egress.transport.address,
          transport: egress.transport,              // secret-free: tier, fqdn, runtime, mechanism, tokenProtected
        });
      } finally {
        egress.close();
      }
    }

    // CONTROL tier — the full control plane (kept in a Worker secret, never in code).
    const op = url.searchParams.get("op");
    if (op) {
      if (!env.WHISPER_API_KEY) return Response.json({ error: "set WHISPER_API_KEY to use the control plane" }, { status: 401 });
      const c = control(env.WHISPER_API_KEY);
      const res = op === "list" ? await c.list() : await c.agents(op, {});
      return Response.json({ op, records: res.records });
    }

    // KEYLESS tier — pure HTTPS, no key, runs anywhere.
    const addr = url.searchParams.get("addr");
    if (!addr) return new Response("usage: ?addr=<agent /128>  |  ?egress (needs key)  |  ?op=list (needs key)\n", { status: 400 });
    const identity = await resolve(addr);
    return Response.json({ address: addr, identity, rdap: identity ? await rdap(addr) : null });
  },
};
